"""Concrete signed-record payloads for the M3 protocol (spec Sections 3, 7.2,
7.3, 8). Added now because M3 is the milestone that needs them — see
ADR-0004 (the lazy-build policy) and ADR-0011 (why they live here, in the
shared library, rather than in any one service package: every one of these
is produced by one service and consumed by at least one other, so they're
a shared contract, not any single package's implementation detail).

Every record here is the ``payload`` carried inside a :class:`SignedEnvelope`
(``tscore.schemas``) — the envelope supplies ``version``/``domain``/``nonce``
uniformly, so these payload models only hold their own semantic fields.
:class:`SignedSubmission` is the wire shape used to submit a signed envelope
anywhere (the ledger, a key-release node): it carries the *exact* canonical
CBOR bytes that were signed, not a reconstructed object, so the receiver
verifies the signature against precisely what the signer signed.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from tscore.cbor import CanonicalCBORModel
from tscore.errors import VerificationError
from tscore.schemas import SignedEnvelope, make_envelope, sign_envelope, verify_envelope_bytes

DOMAIN_CERTIFICATE = "traceseal/certificate/v1"
DOMAIN_DOC_REGISTER = "traceseal/doc-register/v1"
DOMAIN_DECRYPT_REQUEST = "traceseal/decrypt-request/v1"
DOMAIN_DECRYPT_REQUEST_LEDGER = "traceseal/decrypt-request-ledger/v1"
DOMAIN_KEYGRANT_ISSUED = "traceseal/keygrant-issued/v1"
DOMAIN_RECEIPT = "traceseal/receipt/v1"
DOMAIN_SHARE_RELEASE = "traceseal/share-release/v1"
DOMAIN_SHARE_REGISTRATION = "traceseal/share-registration/v1"
DOMAIN_CSR = "traceseal/csr/v1"
DOMAIN_ENROLL_PROPOSE = "traceseal/enroll-propose/v1"
DOMAIN_ENROLL_APPROVE = "traceseal/enroll-approve/v1"
DOMAIN_ENROLL_FINAL = "traceseal/enroll-final/v1"
DOMAIN_REVOKE_PROPOSE = "traceseal/revoke-propose/v1"
DOMAIN_REVOKE_APPROVE = "traceseal/revoke-approve/v1"
DOMAIN_REVOKE_FINAL = "traceseal/revoke-final/v1"
DOMAIN_OPEN_EVENT = "traceseal/open-event/v1"
DOMAIN_OPEN_DENIED = "traceseal/open-denied/v1"

# Must track keyrelease.node.QUORUM_THRESHOLD exactly (that module imports
# this constant rather than hardcoding its own, specifically so a client's
# independent re-verification threshold can never silently drift from
# key-release's real issuance threshold).
KEY_RELEASE_QUORUM_THRESHOLD = 3


class Certificate(CanonicalCBORModel):
    subject_id: str = Field(min_length=1)
    ml_dsa_public_key: bytes
    ml_kem_public_key: bytes
    issuer_id: str = Field(min_length=1)
    issued_at: float


class CertificateSigningRequest(CanonicalCBORModel):
    """What an officer's agent builds and self-signs locally (spec Section
    7.1 step 1), carried as a :class:`SignedSubmission` under
    ``DOMAIN_CSR`` whose signature verifies directly against its OWN
    embedded public key — proof the officer holds the matching secret key,
    checkable before any registry/ledger entry for this officer exists to
    look one up in. Handed to an admin out-of-band; only its hash ever
    reaches :class:`EnrollProposeRecord`."""

    subject_id: str = Field(min_length=1)
    ml_dsa_public_key: bytes
    ml_kem_public_key: bytes


class EnrollProposeRecord(CanonicalCBORModel):
    """An admin's proposal to admit a new officer (spec Section 7.1 step 2).
    ``csr_hash`` is ``sha3_256`` over the officer's self-signed CSR
    submission's exact ``envelope_cbor`` — binds this proposal to one
    specific CSR content-addressably without putting key material on the
    ledger twice."""

    officer_id: str = Field(min_length=1)
    unit: str = Field(min_length=1)
    role: str = Field(min_length=1)
    csr_hash: bytes


class ApprovalRecord(CanonicalCBORModel):
    """A single approver's vote for a previously-submitted PROPOSE record,
    referenced by its ledger ``tx_id`` (content-addressed, so an approval
    can only ever mean "I approve this exact proposal", never a
    same-named-but-different one — e.g. a swapped CSR). Reused, via
    distinct domains (``DOMAIN_ENROLL_APPROVE`` / ``DOMAIN_REVOKE_APPROVE``),
    for both the enrolment and revocation ceremonies, which are otherwise
    identical M-of-N quorum shapes."""

    proposal_tx_id: str = Field(min_length=1)


class EnrollFinalRecord(CanonicalCBORModel):
    """The CA's own attestation that quorum was reached and a certificate
    issued (spec Section 7.1 step 4). ``proposal_tx_id`` ties this back to
    the exact ``EnrollProposeRecord`` it finalizes; ``cert_hash`` is what
    every other service checks against — the certificate bytes themselves
    travel to the officer out-of-band, never through the ledger."""

    officer_id: str = Field(min_length=1)
    proposal_tx_id: str = Field(min_length=1)
    cert_hash: bytes


class RevokeProposeRecord(CanonicalCBORModel):
    """Mirrors :class:`EnrollProposeRecord` (spec Section 7.1 step 5)."""

    officer_id: str = Field(min_length=1)
    cert_hash: bytes
    reason: str = Field(min_length=1)


class RevokeFinalRecord(CanonicalCBORModel):
    """Mirrors :class:`EnrollFinalRecord`."""

    officer_id: str = Field(min_length=1)
    proposal_tx_id: str = Field(min_length=1)
    cert_hash: bytes


class DocRegisterRecord(CanonicalCBORModel):
    doc_id: str = Field(min_length=1)
    package_hash: bytes
    recipient_cert_hashes: list[bytes]
    policy_hash: bytes
    positions_count: int = Field(ge=0)
    tardos_n: int = Field(ge=1)
    tardos_c0: int = Field(ge=2)
    tardos_eps1: float = Field(gt=0.0, lt=1.0)


class DecryptRequest(CanonicalCBORModel):
    """What the *recipient* builds and signs (spec Section 7.3 step 1)."""

    doc_id: str = Field(min_length=1)
    package_hash: bytes
    recipient_cert_hash: bytes
    session_id: str = Field(min_length=1)
    agent_time: float


class DecryptRequestLedgerRecord(CanonicalCBORModel):
    """What the key-release *coordinator* submits to the ledger (spec
    Section 7.3 step 4: "DECRYPT_REQUEST{request, signature,
    codeword_commitment}") — the recipient's original signed
    :class:`DecryptRequest`, verbatim (its own envelope bytes + signature,
    so anyone can independently re-verify the recipient really signed it),
    plus the freshly-assigned Tardos codeword's commitment. Submitted under
    the *coordinator's* signature, not the recipient's — the coordinator is
    attesting "I received this and computed this commitment", which is a
    different claim than the recipient's own."""

    doc_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    recipient_envelope_cbor: bytes
    recipient_signer_id: str = Field(min_length=1)
    recipient_signature: bytes
    codeword_commitment: bytes


class ShareRegistrationPayload(CanonicalCBORModel):
    """Sender registers one Key-Release node's Shamir share for a document,
    plus the document's Tardos bias vector. Sent directly to that node
    (not through the ledger — the payload is confidential and the
    ledger's job is the public audit trail, not secret transport); both
    fields are KEM-wrapped to the node's own ML-KEM key so only that node
    can read them. ``wrapped_share`` is this node's own distinct Shamir
    share of ``K_B || S_v``; ``wrapped_bias_vector`` is the *same*
    plaintext bias vector sent to every node (not secret-shared — see
    ``tscore.release_secret`` for why)."""

    doc_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)
    wrapped_share: bytes
    wrapped_bias_vector: bytes


class KeyGrant(CanonicalCBORModel):
    """The coordinator's response to a successful `DecryptRequest` (spec
    Section 7.3 step 5): `K_B` plus exactly the codeword-selected variant
    key per position, KEM-wrapped whole to the recipient's ML-KEM key
    before transport (the wrapping itself happens outside this model, at
    the KEM-DEM layer — this is the plaintext payload once unwrapped)."""

    session_id: str = Field(min_length=1)
    k_b: bytes
    variant_keys: list[bytes]  # variant_keys[i] is the key for position i's codeword-selected bit


class ShareReleaseRecord(CanonicalCBORModel):
    """A key-release node's own attestation that it verified finality and
    released its share for ``session_id`` — one of these per contributing
    node backs the co-signatures on a KeyGrantIssuedRecord."""

    session_id: str = Field(min_length=1)
    node_id: str = Field(min_length=1)


class KeyGrantIssuedRecord(CanonicalCBORModel):
    """Co-signed by the contributing key-release nodes (spec Section 7.3
    step 5): ``contributing_signatures[i]`` is
    ``contributing_node_ids[i]``'s own ML-DSA signature over
    ``sha3_256(f"{doc_id}|{session_id}|{node_id}")``, attesting "I released
    my share for this session" — not just a claimed list of names."""

    session_id: str = Field(min_length=1)
    grant_ciphertext_hash: bytes
    contributing_node_ids: list[str]
    contributing_signatures: list[bytes]


class ReceiptRecord(CanonicalCBORModel):
    session_id: str = Field(min_length=1)
    assembled_pages_hash: bytes


class SealedHeader(CanonicalCBORModel):
    """Minted per-session by the key-release quorum at `KeyGrant`-issuance
    time (spec Section 7.4) and co-signed directly (raw ML-DSA over this
    model's own canonical CBOR bytes — the same attestation-signing pattern
    as :class:`KeyGrantIssuedRecord`'s ``contributing_signatures``, NOT a
    :class:`SignedEnvelope`). Never submitted to the ledger itself — it
    travels only in the ``/decrypt-request`` HTTP response, alongside the
    wrapped grant. ``policy_id`` reuses the document's own
    ``DocRegisterRecord.policy_hash``, not a separate concept."""

    doc_id: str = Field(min_length=1)
    recipient_cert_hash: bytes
    session_id: str = Field(min_length=1)
    policy_id: bytes


class OpenEventRecord(CanonicalCBORModel):
    """Logged by the recipient-agent when a `SealedHeader` names this
    agent's own identity (spec Section 7.4: match -> proceed + log)."""

    session_id: str = Field(min_length=1)
    doc_id: str = Field(min_length=1)


class OpenDeniedRecord(CanonicalCBORModel):
    """Logged by the recipient-agent when a `SealedHeader` names a
    *different* recipient than its own identity — the forwarding-detection
    event (spec Section 7.4)."""

    doc_id: str = Field(min_length=1)
    presented_by: bytes
    owner: bytes


class SignedSubmission(BaseModel):
    """Wire format for submitting a signed envelope anywhere (the ledger,
    a key-release node). ``envelope_cbor`` is the exact canonical-CBOR
    bytes of a :class:`tscore.schemas.SignedEnvelope` — the receiver
    verifies ``signature`` against these bytes directly, never against a
    reconstructed/re-encoded object."""

    envelope_cbor: bytes
    signer_id: str = Field(min_length=1)
    signature: bytes


class QuorumCertificate(BaseModel):
    signer_ids: list[str]
    signatures: list[bytes]

    def model_post_init(self, __context: object) -> None:
        if len(self.signer_ids) != len(self.signatures):
            raise ValueError("signer_ids and signatures must be the same length")


def make_submission(
    alg: str, secret_key: bytes, signer_id: str, domain: str, payload: CanonicalCBORModel
) -> SignedSubmission:
    """Wrap ``payload`` in a fresh :class:`SignedEnvelope`, sign it, and
    return the wire-ready :class:`SignedSubmission`."""
    envelope = make_envelope(domain, payload)
    envelope_cbor = envelope.to_canonical_cbor()
    signature = sign_envelope(alg, secret_key, envelope)
    return SignedSubmission(envelope_cbor=envelope_cbor, signer_id=signer_id, signature=signature)


def open_submission(
    alg: str, public_key: bytes, submission: SignedSubmission
) -> SignedEnvelope:
    """Verify ``submission``'s signature over its exact envelope bytes and
    return the decoded envelope, or raise :class:`tscore.errors.VerificationError`."""
    if not verify_envelope_bytes(
        alg, public_key, submission.envelope_cbor, submission.signature
    ):
        raise VerificationError(
            f"signature verification failed for signer {submission.signer_id!r}"
        )
    return SignedEnvelope.from_canonical_cbor(submission.envelope_cbor)
