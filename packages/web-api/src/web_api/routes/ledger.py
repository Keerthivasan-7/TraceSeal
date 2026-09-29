"""Ledger (spec Section 14.7): integrity per replica, records (not a
block-explorer), and "view cryptographic proof" drill-downs. Every check
here is a real, live recomputation — nothing is cached or pre-baked.
"""

from __future__ import annotations

from ca.registry import load_registry
from fastapi import APIRouter, HTTPException, Query
from forensics.investigation import build_trust_roots
from tscore.errors import VerificationError
from tscore.evidence import LedgerRecordProof, verify_record_proof

from web_api.deps import LedgerBackendDep, LedgerClientDep, SettingsDep
from web_api.ledger_view import decode_record

router = APIRouter(prefix="/ledger", tags=["ledger"])


@router.get("/replicas")
def get_replicas(ledger_client: LedgerClientDep) -> dict[str, object]:
    report = ledger_client.verify_chain()
    return {
        "ok": report.ok,
        "consensus_height": report.consensus_height,
        "diverged_replica_ids": report.diverged_replica_ids,
        "replicas": [
            {
                "replica_id": s.replica_id,
                "height": s.height,
                "internally_valid": s.internally_valid,
                "first_bad_height": s.first_bad_height,
            }
            for s in report.replicas
        ],
    }


@router.get("/records")
def get_records(
    ledger: LedgerBackendDep,
    domain: str = Query(..., description="signing domain, e.g. traceseal/doc-register/v1"),
    limit: int = Query(100, ge=1, le=1000),
) -> list[dict[str, object]]:
    records = ledger.query(domain=domain)
    decoded = sorted((decode_record(r) for r in records), key=lambda d: -d["height"])
    return decoded[:limit]


@router.get("/records/{tx_id}/proof")
def get_record_proof(
    tx_id: str, ledger: LedgerBackendDep, settings: SettingsDep
) -> dict[str, object]:
    """"View cryptographic proof": fetches the record's real proof
    (submitter signature + quorum signatures included) and independently
    re-verifies it against the registry's own public keys — a genuine
    recomputation, not a cached VALID badge."""
    try:
        proof_wire = ledger.get_proof(tx_id)
    except Exception as exc:  # noqa: BLE001 - surfaced as a 404 below regardless of transport
        raise HTTPException(status_code=404, detail=f"no such record: {tx_id!r}") from exc

    registry = load_registry(settings.pki_dir / "registry.json")
    trust_roots = build_trust_roots(registry)
    proof = LedgerRecordProof(
        tx_id=proof_wire.tx_id,
        height=proof_wire.height,
        envelope_cbor=bytes.fromhex(proof_wire.envelope_cbor),
        submitter_id=proof_wire.submitter_id,
        submitter_signature=bytes.fromhex(proof_wire.submitter_signature),
        quorum_signer_ids=proof_wire.quorum_signer_ids,
        quorum_signatures=[bytes.fromhex(s) for s in proof_wire.quorum_signatures],
        prev_hash=bytes.fromhex(proof_wire.prev_hash),
        record_hash=bytes.fromhex(proof_wire.record_hash),
    )
    try:
        verify_record_proof(proof, trust_roots)
        verified, error = True, None
    except VerificationError as exc:
        verified, error = False, str(exc)

    decoded = decode_record(proof_wire)  # RecordProofWire has every RecordWire field
    decoded["verified"] = verified
    decoded["verification_error"] = error
    return decoded
