"""Base signed-structure schema (spec Section 3 and Section 8).

Concrete per-protocol record types (``ENROLL_PROPOSE``, ``DOC_REGISTER``,
``DecryptRequest``, ledger blocks, ...) are defined in the package that
implements that protocol step, each built on :class:`SignedEnvelope`.
Defining them here now would be speculative ahead of the milestones that
actually need them.
"""

from __future__ import annotations

from pydantic import Field

from tscore.cbor import CanonicalCBORModel


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
