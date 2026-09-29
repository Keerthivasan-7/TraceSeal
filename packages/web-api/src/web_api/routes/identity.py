"""Identity (spec Section 14.2): the registry, enrolment proposals with
live M-of-N approval progress, and a revocation flow. Every call here is a
thin wrapper over `ca.enrolment`'s real functions — no protocol logic
lives in this module.
"""

from __future__ import annotations

from typing import cast

from ca.enrolment import (
    build_and_self_sign_csr,
    count_verified_approvals,
    finalize_enrolment,
    finalize_revocation,
    propose_enrolment,
    propose_revocation,
    submit_approval,
)
from ca.keys import load_identity
from ca.registry import build_registry_entry, load_registry, save_registry
from ca.seed import ADMIN_IDS, ENROLL_QUORUM, OFFICER_IDS
from fastapi import APIRouter, HTTPException
from ledger.backend import LedgerBackend
from pydantic import BaseModel
from tscore.errors import VerificationError
from tscore.records import (
    DOMAIN_ENROLL_APPROVE,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_ENROLL_PROPOSE,
    DOMAIN_REVOKE_APPROVE,
    DOMAIN_REVOKE_FINAL,
    DOMAIN_REVOKE_PROPOSE,
)

from web_api.config import Settings
from web_api.deps import AppStateDep, LedgerBackendDep, SettingsDep
from web_api.identity_status import current_cert_hash, is_revoked
from web_api.ledger_view import decode_record

router = APIRouter(prefix="/identity", tags=["identity"])

_ADMIN_IDS_SET = set(ADMIN_IDS)


@router.get("/registry")
def get_registry(ledger: LedgerBackendDep) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for admin_id in ADMIN_IDS:
        rows.append({"identity_id": admin_id, "kind": "admin", "status": "active"})
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
                "identity_id": officer_id,
                "kind": "officer",
                "status": status,
                "cert_hash": cert_hash,
            }
        )
    return rows


def _finalized_proposal_tx_ids(ledger: LedgerBackend, domain: str) -> set[str]:
    """Every proposal tx_id a FINAL record already references — a proposal
    in this set is done, not pending, regardless of its own approval
    count (spec's Identity screen only lists what's still awaiting
    action)."""
    tx_ids: set[str] = set()
    for record in ledger.query(domain=domain):
        payload = decode_record(record)["payload"]
        if payload is not None:
            tx_ids.add(payload["proposal_tx_id"])
    return tx_ids


@router.get("/proposals")
def get_proposals(ledger: LedgerBackendDep) -> list[dict[str, object]]:
    finalized = _finalized_proposal_tx_ids(
        ledger, DOMAIN_ENROLL_FINAL
    ) | _finalized_proposal_tx_ids(ledger, DOMAIN_REVOKE_FINAL)

    proposals: list[dict[str, object]] = []
    for domain, approve_domain, kind in (
        (DOMAIN_ENROLL_PROPOSE, DOMAIN_ENROLL_APPROVE, "enrol"),
        (DOMAIN_REVOKE_PROPOSE, DOMAIN_REVOKE_APPROVE, "revoke"),
    ):
        for record in ledger.query(domain=domain):
            decoded = decode_record(record)
            if decoded["tx_id"] in finalized:
                continue
            approvals = count_verified_approvals(
                ledger, decoded["tx_id"], _ADMIN_IDS_SET, domain=approve_domain
            )
            proposals.append(
                {
                    **decoded,
                    "kind": kind,
                    "approvals": approvals,
                    "quorum_threshold": ENROLL_QUORUM,
                    "admin_count": len(ADMIN_IDS),
                }
            )
    return sorted(proposals, key=lambda p: cast(int, p["height"]), reverse=True)


class ProposeEnrolRequest(BaseModel):
    unit: str = "1st Unit"
    role: str = "analyst"


@router.post("/officers/{officer_id}/propose-enrol")
def propose_enrol(
    officer_id: str,
    body: ProposeEnrolRequest,
    ledger: LedgerBackendDep,
    settings: SettingsDep,
    app_state: AppStateDep,
) -> dict[str, str]:
    if officer_id not in OFFICER_IDS:
        raise HTTPException(status_code=404, detail=f"unknown officer_id {officer_id!r}")
    admin_identity = load_identity(settings.pki_dir / f"{ADMIN_IDS[0]}.json")
    officer_identity = load_identity(settings.pki_dir / f"{officer_id}.json")
    csr = build_and_self_sign_csr(officer_identity)
    try:
        tx_id = propose_enrolment(ledger, admin_identity, officer_id, body.unit, body.role, csr)
    except VerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    app_state.pending_csrs[tx_id] = csr
    return {"proposal_tx_id": tx_id}


class ApproveRequest(BaseModel):
    admin_id: str


@router.post("/proposals/{tx_id}/approve")
def approve_enrol(
    tx_id: str, body: ApproveRequest, ledger: LedgerBackendDep, settings: SettingsDep
) -> dict[str, str]:
    return _approve(tx_id, body.admin_id, DOMAIN_ENROLL_APPROVE, ledger, settings)


@router.post("/proposals/{tx_id}/approve-revoke")
def approve_revoke(
    tx_id: str, body: ApproveRequest, ledger: LedgerBackendDep, settings: SettingsDep
) -> dict[str, str]:
    return _approve(tx_id, body.admin_id, DOMAIN_REVOKE_APPROVE, ledger, settings)


def _approve(
    tx_id: str, admin_id: str, domain: str, ledger: LedgerBackend, settings: Settings
) -> dict[str, str]:
    if admin_id not in _ADMIN_IDS_SET:
        raise HTTPException(status_code=404, detail=f"unknown admin_id {admin_id!r}")
    admin_identity = load_identity(settings.pki_dir / f"{admin_id}.json")
    try:
        approval_tx_id = submit_approval(ledger, admin_identity, tx_id, domain=domain)
    except VerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"approval_tx_id": approval_tx_id}


@router.post("/proposals/{tx_id}/finalize")
def finalize_enrol(
    tx_id: str, ledger: LedgerBackendDep, settings: SettingsDep, app_state: AppStateDep
) -> dict[str, object]:
    csr = app_state.pending_csrs.get(tx_id)
    if csr is None:
        raise HTTPException(status_code=404, detail=f"no pending CSR cached for proposal {tx_id!r}")
    ca_identity = load_identity(settings.pki_dir / "ca-root.json")
    proposal_record = decode_record(ledger.get(tx_id))
    officer_id = proposal_record["payload"]["officer_id"]
    try:
        cert, signature = finalize_enrolment(
            ledger,
            ca_identity,
            officer_id,
            tx_id,
            csr,
            _ADMIN_IDS_SET,
            quorum_threshold=ENROLL_QUORUM,
        )
    except VerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    officer_identity = load_identity(settings.pki_dir / f"{officer_id}.json")
    registry = load_registry(settings.pki_dir / "registry.json")
    registry[officer_id] = build_registry_entry(
        officer_identity, certificate_cbor=cert.to_canonical_cbor(), certificate_signature=signature
    )
    save_registry(registry, settings.pki_dir / "registry.json")
    del app_state.pending_csrs[tx_id]
    return {"officer_id": officer_id, "status": "enrolled"}


class ProposeRevokeRequest(BaseModel):
    reason: str = "demo revocation"


@router.post("/officers/{officer_id}/propose-revoke")
def propose_revoke(
    officer_id: str, body: ProposeRevokeRequest, ledger: LedgerBackendDep, settings: SettingsDep
) -> dict[str, str]:
    if officer_id not in OFFICER_IDS:
        raise HTTPException(status_code=404, detail=f"unknown officer_id {officer_id!r}")
    cert_hash_hex = current_cert_hash(ledger, officer_id)
    if cert_hash_hex is None:
        raise HTTPException(status_code=400, detail=f"{officer_id!r} has no certificate on file")
    admin_identity = load_identity(settings.pki_dir / f"{ADMIN_IDS[0]}.json")
    try:
        tx_id = propose_revocation(
            ledger, admin_identity, officer_id, bytes.fromhex(cert_hash_hex), body.reason
        )
    except VerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"proposal_tx_id": tx_id}


@router.post("/proposals/{tx_id}/finalize-revoke")
def finalize_revoke(
    tx_id: str, ledger: LedgerBackendDep, settings: SettingsDep
) -> dict[str, object]:
    ca_identity = load_identity(settings.pki_dir / "ca-root.json")
    proposal_record = decode_record(ledger.get(tx_id))
    officer_id = proposal_record["payload"]["officer_id"]
    try:
        finalize_revocation(
            ledger, ca_identity, officer_id, tx_id, _ADMIN_IDS_SET, quorum_threshold=ENROLL_QUORUM
        )
    except VerificationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"officer_id": officer_id, "status": "revoked"}
