import pytest

from tscore.records import (
    ApprovalRecord,
    Certificate,
    CertificateSigningRequest,
    DocRegisterRecord,
    EnrollFinalRecord,
    EnrollProposeRecord,
    OpenDeniedRecord,
    OpenEventRecord,
    QuorumCertificate,
    RevokeFinalRecord,
    RevokeProposeRecord,
    SealedHeader,
    SignedSubmission,
)


def test_certificate_canonical_cbor_round_trip() -> None:
    cert = Certificate(
        subject_id="officer-a",
        ml_dsa_public_key=b"\x01" * 32,
        ml_kem_public_key=b"\x02" * 32,
        issuer_id="root-ca",
        issued_at=1700000000.0,
    )
    restored = Certificate.from_canonical_cbor(cert.to_canonical_cbor())
    assert restored == cert


def test_doc_register_record_validates_eps1_range() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        DocRegisterRecord(
            doc_id="doc-1",
            package_hash=b"\x00" * 32,
            recipient_cert_hashes=[b"\x00" * 32],
            policy_hash=b"\x00" * 32,
            positions_count=10,
            tardos_n=5,
            tardos_c0=3,
            tardos_eps1=1.5,  # invalid: must be in (0, 1)
        )


def test_quorum_certificate_requires_matching_lengths() -> None:
    with pytest.raises(ValueError, match="same length"):
        QuorumCertificate(signer_ids=["a", "b"], signatures=[b"sig1"])


def test_quorum_certificate_accepts_matching_lengths() -> None:
    qc = QuorumCertificate(signer_ids=["a", "b"], signatures=[b"sig1", b"sig2"])
    assert qc.signer_ids == ["a", "b"]


def test_csr_canonical_cbor_round_trip() -> None:
    csr = CertificateSigningRequest(
        subject_id="officer-a", ml_dsa_public_key=b"\x01" * 32, ml_kem_public_key=b"\x02" * 32
    )
    assert CertificateSigningRequest.from_canonical_cbor(csr.to_canonical_cbor()) == csr


def test_csr_rejects_empty_subject_id() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CertificateSigningRequest(
            subject_id="", ml_dsa_public_key=b"\x01" * 32, ml_kem_public_key=b"\x02" * 32
        )


def test_enroll_propose_record_round_trip() -> None:
    record = EnrollProposeRecord(
        officer_id="officer-a", unit="1st Unit", role="analyst", csr_hash=b"\x03" * 32
    )
    assert EnrollProposeRecord.from_canonical_cbor(record.to_canonical_cbor()) == record


def test_approval_record_round_trip() -> None:
    record = ApprovalRecord(proposal_tx_id="deadbeef")
    assert ApprovalRecord.from_canonical_cbor(record.to_canonical_cbor()) == record


def test_enroll_final_record_round_trip() -> None:
    record = EnrollFinalRecord(
        officer_id="officer-a", proposal_tx_id="deadbeef", cert_hash=b"\x04" * 32
    )
    assert EnrollFinalRecord.from_canonical_cbor(record.to_canonical_cbor()) == record


def test_revoke_propose_and_final_round_trip() -> None:
    propose = RevokeProposeRecord(
        officer_id="officer-a", cert_hash=b"\x04" * 32, reason="lost device"
    )
    assert RevokeProposeRecord.from_canonical_cbor(propose.to_canonical_cbor()) == propose

    final = RevokeFinalRecord(
        officer_id="officer-a", proposal_tx_id="deadbeef", cert_hash=b"\x04" * 32
    )
    assert RevokeFinalRecord.from_canonical_cbor(final.to_canonical_cbor()) == final


def test_sealed_header_round_trip() -> None:
    header = SealedHeader(
        doc_id="doc-1",
        recipient_cert_hash=b"\x05" * 32,
        session_id="S-0001",
        policy_id=b"\x06" * 32,
    )
    assert SealedHeader.from_canonical_cbor(header.to_canonical_cbor()) == header


def test_open_event_and_denied_records_round_trip() -> None:
    event = OpenEventRecord(session_id="S-0001", doc_id="doc-1")
    assert OpenEventRecord.from_canonical_cbor(event.to_canonical_cbor()) == event

    denied = OpenDeniedRecord(doc_id="doc-1", presented_by=b"\x07" * 32, owner=b"\x08" * 32)
    assert OpenDeniedRecord.from_canonical_cbor(denied.to_canonical_cbor()) == denied


@pytest.mark.requires_liboqs
def test_make_and_open_submission_round_trip() -> None:
    from tscore.records import DocRegisterRecord, make_submission, open_submission
    from tscore.sig import ML_DSA_65, generate_keypair

    kp = generate_keypair(ML_DSA_65)
    payload = DocRegisterRecord(
        doc_id="doc-1",
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=10,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
    )
    submission = make_submission(
        ML_DSA_65, kp.secret_key, "sender-1", "traceseal/doc-register/v1", payload
    )
    envelope = open_submission(ML_DSA_65, kp.public_key, submission)
    restored = DocRegisterRecord.from_canonical_cbor(envelope.payload)
    assert restored == payload


@pytest.mark.requires_liboqs
def test_open_submission_rejects_wrong_key() -> None:
    from tscore.errors import VerificationError
    from tscore.records import DocRegisterRecord, make_submission, open_submission
    from tscore.sig import ML_DSA_65, generate_keypair

    kp = generate_keypair(ML_DSA_65)
    other = generate_keypair(ML_DSA_65)
    payload = DocRegisterRecord(
        doc_id="doc-1",
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=10,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
    )
    submission = make_submission(
        ML_DSA_65, kp.secret_key, "sender-1", "traceseal/doc-register/v1", payload
    )
    with pytest.raises(VerificationError):
        open_submission(ML_DSA_65, other.public_key, submission)


@pytest.mark.requires_liboqs
def test_open_submission_rejects_tampered_envelope() -> None:
    from tscore.errors import VerificationError
    from tscore.records import DocRegisterRecord, make_submission, open_submission
    from tscore.sig import ML_DSA_65, generate_keypair

    kp = generate_keypair(ML_DSA_65)
    payload = DocRegisterRecord(
        doc_id="doc-1",
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=10,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
    )
    submission = make_submission(
        ML_DSA_65, kp.secret_key, "sender-1", "traceseal/doc-register/v1", payload
    )
    tampered = SignedSubmission(
        envelope_cbor=submission.envelope_cbor[:-1] + bytes([submission.envelope_cbor[-1] ^ 0x01]),
        signer_id=submission.signer_id,
        signature=submission.signature,
    )
    with pytest.raises(VerificationError):
        open_submission(ML_DSA_65, kp.public_key, tampered)
