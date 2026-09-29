"""Read-only, informational-only re-implementation of
`keyrelease.node.KeyReleaseNode._current_cert_hash`/`_check_not_revoked`'s
two ledger queries, for the Identity screen's active/revoked badges.

Deliberately duplicated rather than imported: those methods are private to
`KeyReleaseNode` and this is display logic only, with no security
consequences if it's ever slightly stale — the REAL enforcement stays
exactly where it already is (`keyrelease.node`, unmodified by M8). Never
add a caller that treats this module's output as authoritative for an
actual access decision.
"""

from __future__ import annotations

from ledger.backend import LedgerBackend
from tscore.records import DOMAIN_ENROLL_FINAL, DOMAIN_REVOKE_FINAL

from web_api.ledger_view import decode_record


def current_cert_hash(ledger: LedgerBackend, officer_id: str) -> str | None:
    """Hex `cert_hash` of the most recent `EnrollFinalRecord` for
    `officer_id`, or `None` if never enrolled."""
    latest_height = -1
    latest_cert_hash: str | None = None
    for record in ledger.query(domain=DOMAIN_ENROLL_FINAL):
        decoded = decode_record(record)
        payload = decoded["payload"]
        if payload is None or payload["officer_id"] != officer_id:
            continue
        if decoded["height"] > latest_height:
            latest_height = decoded["height"]
            latest_cert_hash = payload["cert_hash"]
    return latest_cert_hash


def is_revoked(ledger: LedgerBackend, cert_hash: str) -> bool:
    for record in ledger.query(domain=DOMAIN_REVOKE_FINAL):
        decoded = decode_record(record)
        payload = decoded["payload"]
        if payload is not None and payload["cert_hash"] == cert_hash:
            return True
    return False
