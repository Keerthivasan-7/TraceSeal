"""Decodes `RecordWire` envelopes into JSON-safe view models for the UI —
display-only, never re-verifies signatures (that's `/ledger/records/{tx_id}
/proof`'s job, backed by `tscore.evidence.verify_record_proof`). One
`domain -> CanonicalCBORModel` registry so the Ledger and Monitor screens
share the exact same decode path.
"""

from __future__ import annotations

from typing import Any

from ledger.wire import RecordProofWire, RecordWire
from tscore.cbor import CanonicalCBORModel
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_ENROLL_APPROVE,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_ENROLL_PROPOSE,
    DOMAIN_INVESTIGATION_OPENED,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_OPEN_DENIED,
    DOMAIN_OPEN_EVENT,
    DOMAIN_RECEIPT,
    DOMAIN_REPORT_ISSUED,
    DOMAIN_REVOKE_APPROVE,
    DOMAIN_REVOKE_FINAL,
    DOMAIN_REVOKE_PROPOSE,
    ApprovalRecord,
    DecryptRequestLedgerRecord,
    DocRegisterRecord,
    EnrollFinalRecord,
    EnrollProposeRecord,
    InvestigationOpenedRecord,
    KeyGrantIssuedRecord,
    OpenDeniedRecord,
    OpenEventRecord,
    ReceiptRecord,
    ReportIssuedRecord,
    RevokeFinalRecord,
    RevokeProposeRecord,
)
from tscore.schemas import SignedEnvelope

DOMAIN_MODELS: dict[str, type[CanonicalCBORModel]] = {
    DOMAIN_DOC_REGISTER: DocRegisterRecord,
    DOMAIN_DECRYPT_REQUEST_LEDGER: DecryptRequestLedgerRecord,
    DOMAIN_KEYGRANT_ISSUED: KeyGrantIssuedRecord,
    DOMAIN_RECEIPT: ReceiptRecord,
    DOMAIN_OPEN_EVENT: OpenEventRecord,
    DOMAIN_OPEN_DENIED: OpenDeniedRecord,
    DOMAIN_ENROLL_PROPOSE: EnrollProposeRecord,
    DOMAIN_ENROLL_APPROVE: ApprovalRecord,
    DOMAIN_ENROLL_FINAL: EnrollFinalRecord,
    DOMAIN_REVOKE_PROPOSE: RevokeProposeRecord,
    DOMAIN_REVOKE_APPROVE: ApprovalRecord,
    DOMAIN_REVOKE_FINAL: RevokeFinalRecord,
    DOMAIN_INVESTIGATION_OPENED: InvestigationOpenedRecord,
    DOMAIN_REPORT_ISSUED: ReportIssuedRecord,
}


def _to_jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, dict):
        return {k: _to_jsonable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_to_jsonable(v) for v in value]
    return value


def decode_record(record: RecordWire | RecordProofWire) -> dict[str, Any]:
    """One record, decoded for display: envelope metadata plus its typed
    payload (or `None` for a domain this view doesn't know how to decode —
    still shown, just without a parsed payload)."""
    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(record.envelope_cbor))
    model = DOMAIN_MODELS.get(envelope.domain)
    payload = (
        _to_jsonable(model.from_canonical_cbor(envelope.payload).model_dump()) if model else None
    )
    return {
        "tx_id": record.tx_id,
        "height": record.height,
        "domain": envelope.domain,
        "submitter_id": record.submitter_id,
        "created_at": record.created_at,
        "quorum_signer_ids": record.quorum_signer_ids,
        "payload": payload,
    }
