"""ML-DSA-65 and SLH-DSA-SHA2-128s signing (spec Section 3).

ML-DSA-65 is used for all operational signatures (decrypt requests,
receipts, ledger records, node co-signatures). SLH-DSA-SHA2-128s is
reserved for the offline root CA and ledger checkpoints, which sign rarely
and benefit from SLH-DSA's more conservative, hash-based security
assumptions.
"""

from __future__ import annotations

from dataclasses import dataclass

import oqs

from tscore.errors import UnsupportedAlgorithmError

ML_DSA_65 = "ML-DSA-65"
# liboqs-python's mechanism string for this FIPS 205 algorithm is
# "SLH_DSA_PURE_SHA2_128S" (underscored, with the "PURE" qualifier
# distinguishing it from the SLH-DSA prehash variants) — not a
# hyphenated "SLH-DSA-SHA2-128s" like the ML-KEM/ML-DSA strings.
# Confirmed against `oqs.get_enabled_sig_mechanisms()` on liboqs 0.16.0.
SLH_DSA_SHA2_128S = "SLH_DSA_PURE_SHA2_128S"


def _require_enabled(alg: str) -> None:
    if alg not in oqs.get_enabled_sig_mechanisms():
        raise UnsupportedAlgorithmError(
            f"signature algorithm {alg!r} is not enabled by this liboqs build"
        )


@dataclass(frozen=True)
class SigKeyPair:
    alg: str
    public_key: bytes
    secret_key: bytes


def generate_keypair(alg: str) -> SigKeyPair:
    """Generate a keypair for ``alg`` (e.g. :data:`ML_DSA_65`)."""
    _require_enabled(alg)
    with oqs.Signature(alg) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return SigKeyPair(alg=alg, public_key=public_key, secret_key=secret_key)


def sign(alg: str, secret_key: bytes, message: bytes) -> bytes:
    """Sign ``message`` with a private key previously produced for ``alg``."""
    _require_enabled(alg)
    with oqs.Signature(alg, secret_key) as signer:
        return bytes(signer.sign(message))


def verify(alg: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Return ``True`` iff ``signature`` over ``message`` verifies under ``public_key``."""
    _require_enabled(alg)
    with oqs.Signature(alg) as verifier:
        return bool(verifier.verify(message, signature, public_key))
