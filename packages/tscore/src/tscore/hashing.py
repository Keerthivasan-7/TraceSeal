"""SHA3-256 hashing helper, shared wherever the spec says "H(x)"."""

from __future__ import annotations

import hashlib


def sha3_256(data: bytes) -> bytes:
    return hashlib.sha3_256(data).digest()
