"""Monitor (spec Section 14.5): a session timeline per document — request,
finality, grant, receipt, opens. `DecryptRequestLedgerRecord` is the only
record carrying both `doc_id` and `session_id` together, so it's the join
key: every other session-scoped record (`KEYGRANT_ISSUED`, `RECEIPT`,
`OPEN_EVENT`) is grouped back onto it via `session_id`.
`OpenDeniedRecord` carries neither a `session_id` (it's the forwarding-
detection event — a doc plus two cert hashes, not a session) and is shown
per-document instead of folded into any one session's timeline.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_OPEN_DENIED,
    DOMAIN_OPEN_EVENT,
    DOMAIN_RECEIPT,
)

from web_api.deps import LedgerBackendDep
from web_api.ledger_view import decode_record

router = APIRouter(prefix="/monitor", tags=["monitor"])


@router.get("/documents")
def list_documents(ledger: LedgerBackendDep) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for record in ledger.query(domain=DOMAIN_DOC_REGISTER):
        decoded = decode_record(record)
        payload = decoded["payload"]
        if payload is not None:
            docs.append(
                {
                    "doc_id": payload["doc_id"],
                    "tx_id": decoded["tx_id"],
                    "registered_at": decoded["created_at"],
                }
            )
    return sorted(docs, key=lambda d: d["registered_at"], reverse=True)


@router.get("/documents/{doc_id}/timeline")
def get_timeline(doc_id: str, ledger: LedgerBackendDep) -> dict[str, Any]:
    sessions: dict[str, dict[str, Any]] = {}

    for record in ledger.query(domain=DOMAIN_DECRYPT_REQUEST_LEDGER):
        decoded = decode_record(record)
        payload = decoded["payload"]
        if payload is None or payload["doc_id"] != doc_id:
            continue
        session_id = payload["session_id"]
        sessions[session_id] = {
            "session_id": session_id,
            "officer_id": payload["recipient_signer_id"],
            "events": [
                {
                    "stage": "request",
                    "tx_id": decoded["tx_id"],
                    "height": decoded["height"],
                    "created_at": decoded["created_at"],
                }
            ],
        }

    for domain, stage in (
        (DOMAIN_KEYGRANT_ISSUED, "keygrant"),
        (DOMAIN_RECEIPT, "receipt"),
        (DOMAIN_OPEN_EVENT, "open"),
    ):
        for record in ledger.query(domain=domain):
            decoded = decode_record(record)
            payload = decoded["payload"]
            if payload is None:
                continue
            session_id = payload.get("session_id")
            if session_id not in sessions:
                continue
            sessions[session_id]["events"].append(
                {
                    "stage": stage,
                    "tx_id": decoded["tx_id"],
                    "height": decoded["height"],
                    "created_at": decoded["created_at"],
                }
            )

    for session in sessions.values():
        session["events"].sort(key=lambda e: e["height"])

    open_denied: list[dict[str, Any]] = []
    for record in ledger.query(domain=DOMAIN_OPEN_DENIED):
        decoded = decode_record(record)
        payload = decoded["payload"]
        if payload is not None and payload["doc_id"] == doc_id:
            open_denied.append(
                {
                    "tx_id": decoded["tx_id"],
                    "height": decoded["height"],
                    "created_at": decoded["created_at"],
                    "presented_by": payload["presented_by"],
                    "owner": payload["owner"],
                }
            )

    ordered_sessions = sorted(
        sessions.values(), key=lambda s: s["events"][0]["height"] if s["events"] else 0
    )
    return {"doc_id": doc_id, "sessions": ordered_sessions, "open_denied": open_denied}
