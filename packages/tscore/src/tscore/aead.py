"""AES-256-GCM helper (spec Section 3).

Nonces are always random and 96 bits. AAD is always the SHA3-256 hash of a
caller-supplied header, never the raw header, so header size never leaks
into the AEAD tag computation cost and callers cannot accidentally pass
oversized AAD.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tscore.errors import TamperError

KEY_LEN = 32  # AES-256
NONCE_LEN = 12  # 96 bits


def _aad(header: bytes) -> bytes:
    return hashlib.sha3_256(header).digest()


def seal(key: bytes, plaintext: bytes, header: bytes) -> bytes:
    """Encrypt ``plaintext`` under a fresh random nonce.

    Returns ``nonce || ciphertext_with_tag``. ``header`` is authenticated
    (via its SHA3-256 hash as AAD) but not encrypted or included verbatim
    in the output — callers must supply the same header bytes on open.
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"AES-256-GCM key must be {KEY_LEN} bytes, got {len(key)}")
    nonce = os.urandom(NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, _aad(header))
    return nonce + ciphertext


def open_(key: bytes, sealed: bytes, header: bytes) -> bytes:
    """Decrypt data produced by :func:`seal`, or raise :class:`TamperError`."""
    if len(key) != KEY_LEN:
        raise ValueError(f"AES-256-GCM key must be {KEY_LEN} bytes, got {len(key)}")
    if len(sealed) < NONCE_LEN:
        raise TamperError("sealed payload shorter than the nonce")
    nonce, ciphertext = sealed[:NONCE_LEN], sealed[NONCE_LEN:]
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, _aad(header))
    except InvalidTag as exc:
        raise TamperError("AES-GCM authentication failed") from exc
