"""Command Center (spec Section 14.1): air-gap status, counts, per-replica
integrity badges, and a recent-events feed.
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_INVESTIGATION_OPENED,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_OPEN_DENIED,
    DOMAIN_OPEN_EVENT,
    DOMAIN_RECEIPT,
    DOMAIN_REPORT_ISSUED,
    DOMAIN_REVOKE_FINAL,
)

from web_api.deps import LedgerBackendDep, LedgerClientDep
from web_api.ledger_view import decode_record

router = APIRouter(prefix="/system", tags=["system"])

# Every domain the Command Center's counts/feed cares about — queried
# explicitly per domain rather than an unfiltered "whole chain" fetch,
# since `FabricLedgerClient.query` (spec Section 12, M6) has no unfiltered
# query at all; this way the same code works against either backend.
_FEED_DOMAINS = (
    DOMAIN_DOC_REGISTER,
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_RECEIPT,
    DOMAIN_OPEN_EVENT,
    DOMAIN_OPEN_DENIED,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_REVOKE_FINAL,
    DOMAIN_INVESTIGATION_OPENED,
    DOMAIN_REPORT_ISSUED,
)

_EGRESS_TEST_URL = "https://1.1.1.1"
_EGRESS_TEST_TIMEOUT_S = 2.0


@router.get("/status")
def get_status(ledger: LedgerBackendDep, ledger_client: LedgerClientDep) -> dict[str, object]:
    all_records = []
    for domain in _FEED_DOMAINS:
        all_records.extend(ledger.query(domain=domain))

    doc_ids = {
        decode_record(r)["payload"]["doc_id"] for r in ledger.query(domain=DOMAIN_DOC_REGISTER)
    }
    session_count = len(ledger.query(domain=DOMAIN_DECRYPT_REQUEST_LEDGER))
    opened_cases = {
        decode_record(r)["payload"]["case_id"]
        for r in ledger.query(domain=DOMAIN_INVESTIGATION_OPENED)
    }
    closed_cases = {
        decode_record(r)["payload"]["case_id"] for r in ledger.query(domain=DOMAIN_REPORT_ISSUED)
    }
    ledger_height = max((r.height for r in all_records), default=0)

    replicas: list[dict[str, object]] | None = None
    try:
        report = ledger_client.verify_chain()
        replicas = [
            {
                "replica_id": s.replica_id,
                "height": s.height,
                "internally_valid": s.internally_valid,
                "first_bad_height": s.first_bad_height,
            }
            for s in report.replicas
        ]
    except httpx.HTTPError:
        # Not on LedgerLite (e.g. LEDGER_BACKEND=fabric) or a replica is
        # unreachable — reported as "unavailable", never faked as healthy.
        replicas = None

    decoded = sorted((decode_record(r) for r in all_records), key=lambda d: -d["height"])

    return {
        "air_gap": {
            "network": "traceseal_internal (internal: true — no runtime egress)",
            "cloud_dependencies": "NONE",
        },
        "counts": {
            "documents": len(doc_ids),
            "sessions": session_count,
            "open_investigations": len(opened_cases - closed_cases),
            "ledger_height": ledger_height,
        },
        "replicas": replicas,
        "recent_events": decoded[:20],
    }


@router.get("/egress-test")
def get_egress_test() -> dict[str, object]:
    """A genuine, live outbound HTTP attempt from inside this container's
    own network namespace — the same mechanism `tests/integration`'s M0
    no-egress test proves, re-run on demand rather than shown as a cached
    badge."""
    try:
        httpx.get(_EGRESS_TEST_URL, timeout=_EGRESS_TEST_TIMEOUT_S)
    except httpx.HTTPError as exc:
        return {"egress_blocked": True, "detail": str(exc)}
    return {"egress_blocked": False, "detail": "outbound request succeeded — egress is NOT blocked"}
