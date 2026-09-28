"""Base signed-structure schema (spec Section 3 and Section 8).

Concrete per-protocol record payloads (``Certificate``, ``DocRegisterRecord``,
``DecryptRequest``, ...) live in :mod:`tscore.records` — added in M3,
the milestone that actually needs them (ADR-0004's lazy-build policy;
ADR-0011 on why they live in this shared library rather than in any one
service package).
"""

from __future__ import annotations

import os
import secrets

from pydantic import Field

from tscore.cbor import CanonicalCBORModel

NONCE_LEN = 16


class SignedEnvelope(CanonicalCBORModel):
    """The common shape every signed TraceSeal structure carries.

    - ``version``: schema version of this envelope shape.
    - ``domain``: a signing-context string (e.g.
      ``"traceseal/decrypt-request/v1"``) that prevents a signature meant
      for one message type from verifying against another.
    - ``nonce``: unique per signed structure, prevents replay.
    - ``payload``: the canonical-CBOR-encoded concrete record.
    """

    version: int = Field(default=1, ge=1)
    domain: str = Field(min_length=1)
    nonce: bytes = Field(min_length=16)
    payload: bytes


def make_envelope(domain: str, payload: CanonicalCBORModel) -> SignedEnvelope:
    """Wrap ``payload`` in a fresh envelope with a random nonce."""
    return SignedEnvelope(
        domain=domain, nonce=secrets.token_bytes(NONCE_LEN), payload=payload.to_canonical_cbor()
    )


def sign_envelope(alg: str, secret_key: bytes, envelope: SignedEnvelope) -> bytes:
    """Sign the envelope's exact canonical-CBOR bytes.

    Imports `tscore.sig` (and transitively `oqs`) lazily, inside the
    function body: `oqs` triggers a slow liboqs auto-build attempt the
    instant it's imported (see `packages/tscore/tests/conftest.py`), so
    merely importing this module (as every consumer of `SignedEnvelope`
    does, whether or not it ever signs anything) must not pull that in.
    """
    from tscore.sig import sign

    return sign(alg, secret_key, envelope.to_canonical_cbor())


def verify_envelope_bytes(
    alg: str, public_key: bytes, envelope_cbor: bytes, signature: bytes
) -> bool:
    """Verify ``signature`` over the *raw* canonical-CBOR bytes of an
    envelope — never against a reconstructed/re-encoded object, so a
    signature can only ever validate the exact bytes that were signed."""
    from tscore.sig import verify

    return verify(alg, public_key, envelope_cbor, signature)


def random_session_id() -> str:
    return f"S-{os.urandom(8).hex()}"
