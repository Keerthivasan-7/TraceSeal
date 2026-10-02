"""Officer Inbox/Viewer (spec Section 14.4): unlock a seeded keystore, list
what's been distributed to that officer, open a document (a genuine decrypt
session against the key-release quorum), and view the assembled pages —
which exist only as in-memory numpy arrays for the session's lifetime,
never written to disk. `open`'s optional `claim_officer_id` also exposes
the forwarding-detection demo (`agent.demo_m4`'s scenario) as a real
endpoint: presenting another officer's cert_hash/wrapped-K_A and watching
it get denied.
"""

from __future__ import annotations

import io
from typing import Any

import numpy as np
from agent.decrypt import DecryptRequestDeniedError, ForwardedCopyError, open_document
from agent.keystore import unlock_keystore
from attacklab.distortions import print_scan_pipeline, screen_camera_pipeline
from ca.enrolment import build_and_self_sign_csr
from ca.keys import Identity
from ca.registry import load_registry, sig_public_key
from ca.seed import OFFICER_IDS
from fastapi import APIRouter, Depends, HTTPException, Response
from PIL import Image
from pydantic import BaseModel
from tscore.errors import TamperError
from tscore.records import DOMAIN_DOC_REGISTER

from web_api.authority import write_csr
from web_api.deps import AppStateDep, LedgerBackendDep, SettingsDep
from web_api.guards import officer_scope
from web_api.identity_status import current_cert_hash, is_revoked
from web_api.ledger_view import decode_record
from web_api.state import AppState, OpenSession

# Three routers so each role mounts only what it needs:
#   roster_router — read-only list of officers + enrolment status (any console)
#   agent_router  — one officer's documents/open/pages; pinned to that officer
#                   by `officer_scope` (path id == this backend's id == the
#                   session's id)
#   legacy_router — the original passphrase `unlock`/`lock`; role `all` only,
#                   the isolated officer console logs in via /session/login
roster_router = APIRouter(prefix="/officers", tags=["officers"])
agent_router = APIRouter(
    prefix="/officers", tags=["officers"], dependencies=[Depends(officer_scope)]
)
legacy_router = APIRouter(prefix="/officers", tags=["officers"])


@roster_router.get("")
def list_officers(app_state: AppStateDep, ledger: LedgerBackendDep) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for officer_id in OFFICER_IDS:
        cert_hash = current_cert_hash(ledger, officer_id)
        if cert_hash is None:
            status = "not enrolled"
        elif is_revoked(ledger, cert_hash):
            status = "revoked"
        else:
            status = "active"
        rows.append(
            {
                "officer_id": officer_id,
                "status": status,
                "unlocked": officer_id in app_state.officer_sessions,
            }
        )
    return rows


class UnlockRequest(BaseModel):
    passphrase: str


@legacy_router.post("/{officer_id}/unlock")
def unlock(
    officer_id: str, body: UnlockRequest, settings: SettingsDep, app_state: AppStateDep
) -> dict[str, Any]:
    if officer_id not in OFFICER_IDS:
        raise HTTPException(status_code=404, detail=f"unknown officer_id {officer_id!r}")
    keystore_path = settings.keystore_dir / f"{officer_id}.keystore.json"
    if not keystore_path.exists():
        raise HTTPException(status_code=404, detail=f"no keystore seeded for {officer_id!r}")
    try:
        identity = unlock_keystore(keystore_path, body.passphrase)
    except TamperError as exc:
        raise HTTPException(status_code=401, detail="incorrect passphrase") from exc
    app_state.officer_sessions[officer_id] = identity
    return {"officer_id": officer_id, "unlocked": True}


@legacy_router.post("/{officer_id}/lock")
def lock(officer_id: str, app_state: AppStateDep) -> dict[str, Any]:
    app_state.officer_sessions.pop(officer_id, None)
    stale_keys = [k for k in app_state.open_sessions if k.startswith(f"{officer_id}:")]
    for key in stale_keys:
        del app_state.open_sessions[key]
    return {"officer_id": officer_id, "unlocked": False}


def _require_unlocked(app_state: AppState, officer_id: str) -> Identity:
    identity = app_state.officer_sessions.get(officer_id)
    if identity is None:
        raise HTTPException(status_code=401, detail=f"{officer_id!r} has not unlocked a session")
    return identity


@agent_router.get("/{officer_id}/documents")
def list_documents(
    officer_id: str, settings: SettingsDep, ledger: LedgerBackendDep
) -> list[dict[str, Any]]:
    doc_ids: list[str] = []
    if settings.blob_dir.exists():
        for doc_dir in sorted(settings.blob_dir.iterdir()):
            wrapped_path = doc_dir / "wrapped_k_a" / f"{officer_id}.bin"
            package_path = doc_dir / "package.json"
            if wrapped_path.exists() and package_path.exists():
                doc_ids.append(doc_dir.name)

    details: dict[str, dict[str, Any]] = {}
    for record in ledger.query(domain=DOMAIN_DOC_REGISTER):
        decoded = decode_record(record)
        payload = decoded["payload"]
        if payload is not None and payload["doc_id"] in doc_ids:
            details[payload["doc_id"]] = {
                "positions_count": payload["positions_count"],
                "tardos_n": payload["tardos_n"],
                "tardos_c0": payload["tardos_c0"],
                "registered_at": decoded["created_at"],
            }

    return [{"doc_id": doc_id, **details.get(doc_id, {})} for doc_id in doc_ids]


class OpenRequest(BaseModel):
    claim_officer_id: str | None = None


@agent_router.post("/{officer_id}/documents/{doc_id}/open")
def open_doc(
    officer_id: str,
    doc_id: str,
    body: OpenRequest,
    settings: SettingsDep,
    ledger: LedgerBackendDep,
    app_state: AppStateDep,
) -> dict[str, Any]:
    identity = _require_unlocked(app_state, officer_id)

    claimed_officer_id = body.claim_officer_id or officer_id
    cert_hash_hex = current_cert_hash(ledger, claimed_officer_id)
    if cert_hash_hex is None:
        raise HTTPException(status_code=400, detail=f"{claimed_officer_id!r} is not enrolled")
    cert_hash = bytes.fromhex(cert_hash_hex)

    package_path = settings.blob_dir / doc_id / "package.json"
    wrapped_k_a_path = settings.blob_dir / doc_id / "wrapped_k_a" / f"{claimed_officer_id}.bin"
    if not package_path.exists() or not wrapped_k_a_path.exists():
        raise HTTPException(
            status_code=404, detail=f"no distributed copy for {claimed_officer_id!r} / {doc_id!r}"
        )

    def lookup_public_key(signer_id: str) -> tuple[str, bytes]:
        return sig_public_key(load_registry(settings.pki_dir / "registry.json"), signer_id)

    outbox_path = settings.demo_dir / "agent-state" / officer_id / "outbox.jsonl"
    keyrelease_url = settings.keyrelease_urls()[0]

    try:
        result = open_document(
            identity,
            doc_id,
            package_path,
            wrapped_k_a_path,
            cert_hash,
            keyrelease_url,
            ledger,
            lookup_public_key,
            outbox_path,
        )
    except DecryptRequestDeniedError as exc:
        raise HTTPException(
            status_code=403, detail=f"key-release node denied the request: {exc}"
        ) from exc
    except ForwardedCopyError as exc:
        raise HTTPException(
            status_code=403, detail=f"forwarding detected — OPEN_DENIED logged: {exc}"
        ) from exc

    app_state.open_sessions[f"{officer_id}:{doc_id}"] = OpenSession(
        session_id=result.session_id,
        doc_id=doc_id,
        officer_id=officer_id,
        receipt_tx_id=result.receipt_tx_id,
        pages=result.pages,
    )
    return {
        "session_id": result.session_id,
        "receipt_tx_id": result.receipt_tx_id,
        "page_count": len(result.pages),
    }


@agent_router.get("/{officer_id}/documents/{doc_id}/pages/{page_index}")
def get_page(officer_id: str, doc_id: str, page_index: int, app_state: AppStateDep) -> Response:
    session = app_state.open_sessions.get(f"{officer_id}:{doc_id}")
    if session is None:
        raise HTTPException(status_code=404, detail="document not open — call /open first")
    if page_index < 0 or page_index >= len(session.pages):
        raise HTTPException(status_code=404, detail=f"no page {page_index}")
    buf = io.BytesIO()
    Image.fromarray(session.pages[page_index]).save(buf, format="PNG")
    # A decrypted page must never sit in a browser HTTP cache: plaintext exists
    # only in memory for the life of the session (spec Section 7.4).
    return Response(
        content=buf.getvalue(), media_type="image/png", headers={"Cache-Control": "no-store"}
    )


@agent_router.post("/{officer_id}/documents/{doc_id}/pages/{page_index}/leak")
def capture_leak(
    officer_id: str,
    doc_id: str,
    page_index: int,
    app_state: AppStateDep,
    distortion: str = "screen_camera",
) -> Response:
    """SIMULATE an insider photographing their own screen: take the page this
    officer has open, push it through the attack lab's camera/scan model, and
    hand back a PNG. Nothing here is a real exfiltration channel — it exists so
    the demo can move a "leaked" file from this console to the investigator's,
    which cannot read this officer's decrypted pages. The page stays in memory;
    only the distorted copy leaves."""
    session = app_state.open_sessions.get(f"{officer_id}:{doc_id}")
    if session is None or page_index < 0 or page_index >= len(session.pages):
        raise HTTPException(status_code=404, detail="no such open page — open the document first")
    page = session.pages[page_index]
    rng = np.random.default_rng()
    if distortion == "screen_camera":
        captured = screen_camera_pipeline(page, rng)
    elif distortion == "print_scan":
        captured = print_scan_pipeline(page, rng)
    elif distortion == "none":
        captured = page
    else:
        raise HTTPException(status_code=400, detail=f"unknown distortion {distortion!r}")
    app_state.events.add("leak_simulated", f"{doc_id} page {page_index + 1} ({distortion})")
    buf = io.BytesIO()
    Image.fromarray(captured).save(buf, format="PNG")
    return Response(
        content=buf.getvalue(),
        media_type="image/png",
        headers={
            "Content-Disposition": f'attachment; filename="leak-{doc_id}-p{page_index + 1}.png"',
            "Cache-Control": "no-store",
        },
    )


@agent_router.post("/{officer_id}/enrolment-request")
def request_enrolment(
    officer_id: str, settings: SettingsDep, app_state: AppStateDep
) -> dict[str, str]:
    """Build and self-sign this officer's CSR *on their own workstation* and
    hand it to the enrolment authority as a file. The authority never sees the
    officer's private key — only a request whose signature proves they hold it."""
    identity = _require_unlocked(app_state, officer_id)
    csr = build_and_self_sign_csr(identity)
    csr_hash = write_csr(settings, officer_id, csr)
    app_state.events.add("enrolment_requested", f"CSR {csr_hash[:12]} submitted")
    return {"officer_id": officer_id, "csr_hash": csr_hash}
