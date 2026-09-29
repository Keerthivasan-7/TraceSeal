"""Ledger hash-chain arithmetic (spec Section 12), shared verbatim between
`ledger` (write/replicate time) and `tscore.evidence`/the standalone
verifier (read/re-verify time) — a single source of truth so the two can
never drift (docs/DECISIONS.md ADR-0029). Kept separate from
`tscore.evidence` (no numpy/pydantic here) so `ledger` never has to import
either just to get this one hash function.
"""

from __future__ import annotations

from tscore.hashing import sha3_256


def compute_record_hash(
    prev_hash: bytes, tx_id: str, envelope_cbor: bytes, quorum_signer_ids: list[str]
) -> bytes:
    parts = [prev_hash, tx_id.encode(), envelope_cbor, ",".join(quorum_signer_ids).encode()]
    return sha3_256(b"|".join(parts))
