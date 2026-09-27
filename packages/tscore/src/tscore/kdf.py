"""HKDF-SHA3-256 with explicit, versioned domain-separated info strings
(spec Section 3)."""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_DOMAIN_PREFIX = b"traceseal"


def domain_info(component: str, *parts: bytes, version: int = 1) -> bytes:
    """Build a versioned, unambiguous ``info`` string for :func:`derive`.

    Each part is length-prefixed (4-byte big-endian) so that, unlike plain
    concatenation, distinct part boundaries can never collide (e.g.
    ``(b"ab", b"c")`` vs ``(b"a", b"bc")`` always produce different info
    strings). Example:
        >>> domain_info("variant", doc_id, idx.to_bytes(2, "big"), bytes([bit]))
    """
    out = bytearray()
    out += _DOMAIN_PREFIX
    out += f"/v{version}/{component}/".encode()
    for part in parts:
        out += len(part).to_bytes(4, "big")
        out += part
    return bytes(out)


def derive(ikm: bytes, info: bytes, *, length: int = 32, salt: bytes | None = None) -> bytes:
    """Derive ``length`` bytes from ``ikm`` via HKDF-SHA3-256."""
    hkdf = HKDF(algorithm=hashes.SHA3_256(), length=length, salt=salt, info=info)
    return hkdf.derive(ikm)
