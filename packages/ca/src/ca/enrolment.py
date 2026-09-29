"""Enrolment and revocation ceremony (spec Section 7.1) — a script/library
workflow submitting ordinary signed records to the existing LedgerLite
cluster, not a dedicated admin service (docs/DECISIONS.md ADR-0019: this
doesn't need live multi-party coordination the way key-release's threshold
secret reconstruction does — it's just "accumulate M distinct signatures on
the ledger over time").

Officers build+self-sign a `CertificateSigningRequest` locally; a fixed
admin submits `ENROLL_PROPOSE`; at least `quorum_threshold` DISTINCT admins
submit `ENROLL_APPROVE`; the CA then independently re-verifies the CSR and
recomputes the approval count itself (never trusts a caller-supplied count,
ADR-0023) before issuing a real certificate and writing `ENROLL_FINAL`.
Revocation mirrors this exactly via `REVOKE_PROPOSE`/`REVOKE_APPROVE`/
`REVOKE_FINAL`, reusing the same `ApprovalRecord` and quorum-counting logic
under different domains.
"""

from __future__ import annotations

from ledger.backend import LedgerBackend
from ledger.wire import RecordWire
from tscore.cbor import CanonicalCBORModel
from tscore.errors import VerificationError
from tscore.hashing import sha3_256
from tscore.records import (
    DOMAIN_CSR,
    DOMAIN_ENROLL_APPROVE,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_ENROLL_PROPOSE,
    DOMAIN_REVOKE_APPROVE,
    DOMAIN_REVOKE_FINAL,
    DOMAIN_REVOKE_PROPOSE,
    ApprovalRecord,
    Certificate,
    CertificateSigningRequest,
    EnrollFinalRecord,
    EnrollProposeRecord,
    RevokeFinalRecord,
    RevokeProposeRecord,
    SignedSubmission,
    make_submission,
    open_submission,
)
from tscore.schemas import SignedEnvelope

from ca.issue import issue_certificate
from ca.keys import DEFAULT_SIG_ALG, Identity

DEFAULT_QUORUM_THRESHOLD = 2  # spec's stated default: 2 of 3, configurable
DEFAULT_WAIT_TIMEOUT_S = 30.0


def _decode_payload[T: CanonicalCBORModel](record: RecordWire, model: type[T]) -> T:
    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(record.envelope_cbor))
    return model.from_canonical_cbor(envelope.payload)


def build_and_self_sign_csr(officer_identity: Identity) -> SignedSubmission:
    """The officer-side half of spec 7.1 step 1: build a CSR from an
    already-generated keypair and self-sign it. Handed to an admin
    out-of-band (never submitted to the ledger itself; only its hash
    reaches `EnrollProposeRecord`)."""
    assert officer_identity.kem_alg is not None and officer_identity.kem_public_key is not None
    csr = CertificateSigningRequest(
        subject_id=officer_identity.identity_id,
        ml_dsa_public_key=officer_identity.sig_public_key,
        ml_kem_public_key=officer_identity.kem_public_key,
    )
    return make_submission(
        officer_identity.sig_alg,
        officer_identity.sig_secret_key,
        officer_identity.identity_id,
        DOMAIN_CSR,
        csr,
    )


def _verify_csr_self_signature(
    csr_submission: SignedSubmission, expected_subject_id: str
) -> CertificateSigningRequest:
    """Verify `csr_submission`'s signature against its OWN embedded public
    key — proof the officer holds the matching secret key. This is
    deliberately NOT a registry lookup: no registry/ledger entry certifies
    this officer yet, that's the whole point of the ceremony that follows."""
    unverified_envelope = SignedEnvelope.from_canonical_cbor(csr_submission.envelope_cbor)
    csr = CertificateSigningRequest.from_canonical_cbor(unverified_envelope.payload)
    if csr.subject_id != expected_subject_id:
        raise VerificationError(
            f"CSR subject_id {csr.subject_id!r} != expected {expected_subject_id!r}"
        )
    if csr_submission.signer_id != csr.subject_id:
        raise VerificationError("CSR submission signer_id does not match its own subject_id")
    open_submission(DEFAULT_SIG_ALG, csr.ml_dsa_public_key, csr_submission)
    return csr


def propose_enrolment(
    ledger_client: LedgerBackend,
    admin_identity: Identity,
    officer_id: str,
    unit: str,
    role: str,
    csr_submission: SignedSubmission,
    *,
    wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
) -> str:
    """Spec 7.1 step 2. Returns the proposal's tx_id — every later
    APPROVE/FINAL references this exact value, so an approval can only ever
    mean "I approve this exact proposal"."""
    _verify_csr_self_signature(csr_submission, officer_id)
    csr_hash = sha3_256(csr_submission.envelope_cbor)
    record = EnrollProposeRecord(officer_id=officer_id, unit=unit, role=role, csr_hash=csr_hash)
    submission = make_submission(
        admin_identity.sig_alg,
        admin_identity.sig_secret_key,
        admin_identity.identity_id,
        DOMAIN_ENROLL_PROPOSE,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=wait_timeout_s)
    return tx_id


def submit_approval(
    ledger_client: LedgerBackend,
    approver_identity: Identity,
    proposal_tx_id: str,
    *,
    domain: str,
    wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
) -> str:
    """Spec 7.1 step 3 (and its revocation mirror). `domain` is
    `DOMAIN_ENROLL_APPROVE` or `DOMAIN_REVOKE_APPROVE` — the same
    `ApprovalRecord` shape serves both ceremonies."""
    record = ApprovalRecord(proposal_tx_id=proposal_tx_id)
    submission = make_submission(
        approver_identity.sig_alg,
        approver_identity.sig_secret_key,
        approver_identity.identity_id,
        domain,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=wait_timeout_s)
    return tx_id


def count_verified_approvals(
    ledger_client: LedgerBackend,
    proposal_tx_id: str,
    admin_ids: set[str],
    *,
    domain: str,
) -> int:
    """Recomputed fresh from the ledger's current state every call — never
    trusts a caller-supplied count (docs/DECISIONS.md ADR-0023). A record's
    presence in `/chain` already means every ledger replica independently
    verified its submitter's signature before it could be finalized there
    (same trust boundary `keyrelease.node.release_share` relies on for its
    own finality check); the ledger itself has no domain-specific ACL, so
    filtering to the fixed `admin_ids` allowlist is this function's own job,
    done fresh every time, not cached."""
    approvers: set[str] = set()
    for record in ledger_client.query(domain=domain):
        approval = _decode_payload(record, ApprovalRecord)
        if approval.proposal_tx_id != proposal_tx_id:
            continue
        if record.submitter_id not in admin_ids:
            continue
        approvers.add(record.submitter_id)
    return len(approvers)


def finalize_enrolment(
    ledger_client: LedgerBackend,
    ca_identity: Identity,
    officer_id: str,
    proposal_tx_id: str,
    csr_submission: SignedSubmission,
    admin_ids: set[str],
    *,
    quorum_threshold: int = DEFAULT_QUORUM_THRESHOLD,
    wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
) -> tuple[Certificate, bytes]:
    """Spec 7.1 step 4. Re-verifies the CSR self-signature AND that its
    hash matches the proposal's committed `csr_hash` (rejects a
    swapped-CSR attack — approving one proposal doesn't let a different CSR
    be finalized under it), requires quorum, issues the certificate, and
    writes `EnrollFinalRecord`. Returns `(certificate, ca_signature)` —
    same shape as `ca.issue.issue_certificate`; the certificate travels to
    the officer out-of-band, only its hash goes on the ledger."""
    proposal_record = ledger_client.get(proposal_tx_id)
    proposal = _decode_payload(proposal_record, EnrollProposeRecord)
    if proposal.officer_id != officer_id:
        raise VerificationError(
            f"proposal {proposal_tx_id!r} is for {proposal.officer_id!r}, not {officer_id!r}"
        )

    csr = _verify_csr_self_signature(csr_submission, officer_id)
    if sha3_256(csr_submission.envelope_cbor) != proposal.csr_hash:
        raise VerificationError(
            "CSR does not match the hash committed in the proposal (swapped-CSR attack)"
        )

    approvals = count_verified_approvals(
        ledger_client, proposal_tx_id, admin_ids, domain=DOMAIN_ENROLL_APPROVE
    )
    if approvals < quorum_threshold:
        raise VerificationError(
            f"only {approvals} distinct admin approvals for {proposal_tx_id!r}, "
            f"need >= {quorum_threshold}"
        )

    cert, signature = issue_certificate(
        ca_identity, officer_id, csr.ml_dsa_public_key, csr.ml_kem_public_key
    )
    cert_hash = sha3_256(cert.to_canonical_cbor())
    final_record = EnrollFinalRecord(
        officer_id=officer_id, proposal_tx_id=proposal_tx_id, cert_hash=cert_hash
    )
    submission = make_submission(
        ca_identity.sig_alg,
        ca_identity.sig_secret_key,
        ca_identity.identity_id,
        DOMAIN_ENROLL_FINAL,
        final_record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=wait_timeout_s)
    return cert, signature


def propose_revocation(
    ledger_client: LedgerBackend,
    admin_identity: Identity,
    officer_id: str,
    cert_hash: bytes,
    reason: str,
    *,
    wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
) -> str:
    """Mirrors `propose_enrolment` (spec 7.1 step 5)."""
    record = RevokeProposeRecord(officer_id=officer_id, cert_hash=cert_hash, reason=reason)
    submission = make_submission(
        admin_identity.sig_alg,
        admin_identity.sig_secret_key,
        admin_identity.identity_id,
        DOMAIN_REVOKE_PROPOSE,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=wait_timeout_s)
    return tx_id


def finalize_revocation(
    ledger_client: LedgerBackend,
    ca_identity: Identity,
    officer_id: str,
    proposal_tx_id: str,
    admin_ids: set[str],
    *,
    quorum_threshold: int = DEFAULT_QUORUM_THRESHOLD,
    wait_timeout_s: float = DEFAULT_WAIT_TIMEOUT_S,
) -> None:
    """Mirrors `finalize_enrolment`, with no certificate to issue. CA-signed
    for symmetry with enrolment — the CA is already the one universally-
    trusted authority in this system."""
    proposal_record = ledger_client.get(proposal_tx_id)
    proposal = _decode_payload(proposal_record, RevokeProposeRecord)
    if proposal.officer_id != officer_id:
        raise VerificationError(
            f"proposal {proposal_tx_id!r} is for {proposal.officer_id!r}, not {officer_id!r}"
        )

    approvals = count_verified_approvals(
        ledger_client, proposal_tx_id, admin_ids, domain=DOMAIN_REVOKE_APPROVE
    )
    if approvals < quorum_threshold:
        raise VerificationError(
            f"only {approvals} distinct admin approvals for {proposal_tx_id!r}, "
            f"need >= {quorum_threshold}"
        )

    final_record = RevokeFinalRecord(
        officer_id=officer_id, proposal_tx_id=proposal_tx_id, cert_hash=proposal.cert_hash
    )
    submission = make_submission(
        ca_identity.sig_alg,
        ca_identity.sig_secret_key,
        ca_identity.identity_id,
        DOMAIN_REVOKE_FINAL,
        final_record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=wait_timeout_s)
