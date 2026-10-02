"""Enrolment-ceremony helpers for the authority console.

In the combined console (`role == "all"`) the ceremony reads every admin's and
the officer's raw private key from disk, exactly as before. In the isolated
deployment none of those files are mounted anywhere near the authority:

* each **admin's** key is unlocked from that admin's own keystore, using that
  admin's own passphrase supplied with the approval request, used once to
  sign, then dropped — no admin key is ever held in session memory, so one
  logged-in operator cannot approve on behalf of two admins;
* the **officer's CSR** is produced and self-signed on the officer's own
  workstation (`POST /officers/{id}/enrolment-request`) and handed over as a
  file in a per-officer inbox directory the authority can only read.
"""

from __future__ import annotations

import json
from pathlib import Path

from agent.keystore import unlock_keystore
from ca.keys import Identity, load_identity
from fastapi import HTTPException
from tscore.errors import TamperError
from tscore.hashing import sha3_256
from tscore.records import SignedSubmission

from web_api.config import Settings
from web_api.state import AppState


def admin_identity(
    settings: Settings, app_state: AppState, admin_id: str, passphrase: str | None
) -> Identity:
    """The signing identity for `admin_id`, authenticated by *that admin's*
    passphrase (isolated roles) or read from disk (role `all`)."""
    if settings.role == "all":
        return load_identity(settings.identity_dir / f"{admin_id}.json")
    if not passphrase:
        raise HTTPException(
            status_code=400, detail=f"{admin_id}'s passphrase is required to sign this action"
        )
    lockout = app_state.admin_lockout(admin_id)
    wait = lockout.retry_after()
    if wait > 0:
        app_state.events.add("admin_blocked", f"{admin_id}: backoff active")
        raise HTTPException(
            status_code=429,
            detail=f"too many failed attempts for {admin_id} — try again in {int(wait) + 1}s",
            headers={"Retry-After": str(int(wait) + 1)},
        )
    path = settings.keystore_dir / f"{admin_id}.keystore.json"
    if not path.exists():
        raise HTTPException(status_code=503, detail=f"no keystore provisioned for {admin_id!r}")
    try:
        identity = unlock_keystore(path, passphrase)
    except TamperError as exc:
        lockout.record_failure()
        app_state.events.add("admin_auth_failed", f"incorrect passphrase for {admin_id}")
        raise HTTPException(status_code=401, detail=f"incorrect passphrase for {admin_id}") from exc
    lockout.record_success()
    return identity


def csr_path(settings: Settings, officer_id: str) -> Path:
    return settings.enrol_inbox_dir / officer_id / "csr.json"


def write_csr(settings: Settings, officer_id: str, csr: SignedSubmission) -> str:
    """Officer side: publish the self-signed CSR for the authority. Returns the
    SHA3-256 of the envelope (the value the ledger proposal commits to)."""
    path = csr_path(settings, officer_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "envelope_cbor": csr.envelope_cbor.hex(),
                "signer_id": csr.signer_id,
                "signature": csr.signature.hex(),
            }
        )
    )
    return sha3_256(csr.envelope_cbor).hex()


def read_csr(settings: Settings, officer_id: str) -> SignedSubmission:
    path = csr_path(settings, officer_id)
    if not path.exists():
        raise HTTPException(
            status_code=404,
            detail=f"{officer_id!r} has not submitted an enrolment request from its workstation",
        )
    data = json.loads(path.read_text())
    if data.get("signer_id") != officer_id:
        raise HTTPException(status_code=400, detail="enrolment request signer does not match")
    return SignedSubmission(
        envelope_cbor=bytes.fromhex(data["envelope_cbor"]),
        signer_id=data["signer_id"],
        signature=bytes.fromhex(data["signature"]),
    )
