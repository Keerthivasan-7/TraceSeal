"""Direct certificate issuance (M3 scope — no ledger quorum yet, see
docs/DECISIONS.md ADR-0011 and the M3 plan's scoping decisions).
"""

from __future__ import annotations

import time

from tscore.records import Certificate

from ca.keys import Identity


def issue_certificate(
    ca_identity: Identity, subject_id: str, sig_public_key: bytes, kem_public_key: bytes
) -> tuple[Certificate, bytes]:
    """Issue a certificate for ``subject_id``, signed by ``ca_identity``.
    Returns ``(certificate, signature_over_its_canonical_cbor_bytes)``."""
    from tscore.sig import sign

    cert = Certificate(
        subject_id=subject_id,
        ml_dsa_public_key=sig_public_key,
        ml_kem_public_key=kem_public_key,
        issuer_id=ca_identity.identity_id,
        issued_at=time.time(),
    )
    signature = sign(ca_identity.sig_alg, ca_identity.sig_secret_key, cert.to_canonical_cbor())
    return cert, signature


def verify_certificate(
    cert: Certificate, signature: bytes, ca_sig_alg: str, ca_public_key: bytes
) -> bool:
    from tscore.sig import verify

    return verify(ca_sig_alg, ca_public_key, cert.to_canonical_cbor(), signature)
