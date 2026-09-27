"""Canonical (deterministic) CBOR encoding on top of ``cbor2`` (spec Section 3).

``cbor2``'s ``canonical=True`` mode implements RFC 7049 Section 3.9 canonical
CBOR: map keys are sorted by their encoded byte representation and integers
use their shortest encoding, so encoding the same logical value always
produces the same bytes. Every signed structure in TraceSeal must be
encoded this way, since ML-DSA/SLH-DSA signatures are computed over the
encoded bytes.
"""

from __future__ import annotations

from typing import Any, Self

import cbor2
from pydantic import BaseModel


def canonical_dumps(obj: Any) -> bytes:
    result: bytes = cbor2.dumps(obj, canonical=True)
    return result


def canonical_loads(data: bytes) -> Any:
    return cbor2.loads(data)


class CanonicalCBORModel(BaseModel):
    """Pydantic v2 base class adding canonical-CBOR (de)serialisation."""

    def to_canonical_cbor(self) -> bytes:
        return canonical_dumps(self.model_dump(mode="python"))

    @classmethod
    def from_canonical_cbor(cls, data: bytes) -> Self:
        return cls.model_validate(canonical_loads(data))
