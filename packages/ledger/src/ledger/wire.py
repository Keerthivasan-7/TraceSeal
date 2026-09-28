"""HTTP wire models (hex-encoded `str` fields, not raw `bytes`).

Pydantic v2's default JSON serialization for a `bytes` field assumes the
bytes are UTF-8 text (it does not base64/hex-encode automatically) and
raises on arbitrary binary data — confirmed directly before writing this:
``PydanticSerializationError: invalid utf-8 sequence``. So every field that
carries raw bytes over HTTP is `str` (hex) here, converted to/from
`bytes` explicitly at the FastAPI route boundary in `service.py`.
"""

from __future__ import annotations

from pydantic import BaseModel
from tscore.records import SignedSubmission


class SubmissionWire(BaseModel):
    envelope_cbor: str  # hex
    signer_id: str
    signature: str  # hex

    @classmethod
    def from_submission(cls, submission: SignedSubmission) -> SubmissionWire:
        return cls(
            envelope_cbor=submission.envelope_cbor.hex(),
            signer_id=submission.signer_id,
            signature=submission.signature.hex(),
        )

    def to_submission(self) -> SignedSubmission:
        return SignedSubmission(
            envelope_cbor=bytes.fromhex(self.envelope_cbor),
            signer_id=self.signer_id,
            signature=bytes.fromhex(self.signature),
        )


class CoSignResponse(BaseModel):
    replica_id: str
    signature: str  # hex


class FinalizeRequest(BaseModel):
    submission: SubmissionWire
    quorum_signer_ids: list[str]
    quorum_signatures: list[str]  # hex


class RecordWire(BaseModel):
    height: int
    tx_id: str
    envelope_cbor: str  # hex
    submitter_id: str
    quorum_signer_ids: list[str]
    quorum_signatures: list[str]  # hex
    prev_hash: str  # hex
    record_hash: str  # hex
    created_at: float
