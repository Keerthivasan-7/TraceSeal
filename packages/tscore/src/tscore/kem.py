"""ML-KEM-768 KEM-DEM construction (spec Section 3).

Every key-wrapping operation in TraceSeal (K_A to a recipient, Shamir
shares to a Key-Release node, KeyGrants) uses the same shape:
encapsulate against the recipient's ML-KEM public key, run the shared
secret through HKDF-SHA3-256 with a domain-separated ``info`` string, then
seal the actual payload with AES-256-GCM under the derived key.

Wire format of :func:`kem_seal`'s output::

    u32be(len(kem_ciphertext)) || kem_ciphertext || nonce || aead_ciphertext
"""

from __future__ import annotations

from dataclasses import dataclass

import oqs

from tscore.aead import KEY_LEN, open_, seal
from tscore.errors import TamperError, UnsupportedAlgorithmError
from tscore.kdf import derive

ML_KEM_768 = "ML-KEM-768"

_LEN_PREFIX = 4  # bytes, big-endian


def _require_enabled(alg: str) -> None:
    if alg not in oqs.get_enabled_kem_mechanisms():
        raise UnsupportedAlgorithmError(
            f"KEM algorithm {alg!r} is not enabled by this liboqs build"
        )


@dataclass(frozen=True)
class KemKeyPair:
    alg: str
    public_key: bytes
    secret_key: bytes


def generate_keypair(alg: str = ML_KEM_768) -> KemKeyPair:
    _require_enabled(alg)
    with oqs.KeyEncapsulation(alg) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return KemKeyPair(alg=alg, public_key=public_key, secret_key=secret_key)


def kem_seal(
    recipient_public_key: bytes,
    plaintext: bytes,
    *,
    header: bytes,
    info: bytes,
    alg: str = ML_KEM_768,
) -> bytes:
    """Encapsulate to ``recipient_public_key`` and seal ``plaintext`` under the
    resulting key. ``header`` is authenticated as AEAD AAD (see
    :mod:`tscore.aead`); ``info`` domain-separates the HKDF step (see
    :func:`tscore.kdf.domain_info`)."""
    _require_enabled(alg)
    with oqs.KeyEncapsulation(alg) as kem:
        raw_ciphertext, raw_shared_secret = kem.encap_secret(recipient_public_key)
    kem_ciphertext: bytes = bytes(raw_ciphertext)
    shared_secret: bytes = bytes(raw_shared_secret)
    key = derive(shared_secret, info, length=KEY_LEN)
    sealed = seal(key, plaintext, header)
    return len(kem_ciphertext).to_bytes(_LEN_PREFIX, "big") + kem_ciphertext + sealed


def kem_open(
    recipient_secret_key: bytes,
    framed: bytes,
    *,
    header: bytes,
    info: bytes,
    alg: str = ML_KEM_768,
) -> bytes:
    """Inverse of :func:`kem_seal`."""
    _require_enabled(alg)
    if len(framed) < _LEN_PREFIX:
        raise TamperError("framed KEM-DEM payload shorter than the length prefix")
    kem_ct_len = int.from_bytes(framed[:_LEN_PREFIX], "big")
    kem_ciphertext = framed[_LEN_PREFIX : _LEN_PREFIX + kem_ct_len]
    sealed = framed[_LEN_PREFIX + kem_ct_len :]
    if len(kem_ciphertext) != kem_ct_len:
        raise TamperError("framed KEM-DEM payload truncated")
    with oqs.KeyEncapsulation(alg, recipient_secret_key) as kem:
        shared_secret = kem.decap_secret(kem_ciphertext)
    key = derive(shared_secret, info, length=KEY_LEN)
    return open_(key, sealed, header)
