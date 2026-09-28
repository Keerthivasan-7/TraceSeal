import pytest

from tscore.records import (
    Certificate,
    DocRegisterRecord,
    QuorumCertificate,
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
