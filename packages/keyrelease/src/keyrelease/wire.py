"""HTTP wire models specific to key-release (hex-encoded `str` fields, same
reasoning as `ledger.wire` — Pydantic v2 doesn't base64/hex-encode `bytes`
fields for JSON automatically). `/register-share` and `/decrypt-request`
reuse `ledger.wire.SubmissionWire` directly, since they carry the same
signed-envelope shape.
"""

from __future__ import annotations

from pydantic import BaseModel


class ReleaseShareRequest(BaseModel):
    session_id: str
    doc_id: str


class ReleaseShareResponse(BaseModel):
    node_id: str
    share_x: int
    share_ys: str  # hex
    signature: str  # hex


class DecryptResponse(BaseModel):
    wrapped_grant: str  # hex
