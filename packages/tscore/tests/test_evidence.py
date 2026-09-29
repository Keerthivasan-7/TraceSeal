"""Tests for tscore.evidence — the shared cryptographic re-verification
core used by both forensics (builder) and verifier (checker). Builds a
small, fully genuine, hand-signed evidence bundle directly (no
ledger/keyrelease services involved — tscore must never depend on those)
and checks both the happy path and every enumerated tampering case
(docs/SPEC.md Section 17's "fails on each tampering case")."""

from __future__ import annotations

import numpy as np
import pytest

pytestmark = pytest.mark.requires_liboqs

DOC_ID = "doc-test"
SESSION_ID = "S-0001"
CASE_ID = "case-0001"
N_POSITIONS = 8
IDENTITY_IDS = [
    "ledger-0", "ledger-1", "ledger-2", "ledger-3",
    "keyrelease-0", "keyrelease-1", "keyrelease-2",
    "officer-a", "forensics-1", "ca-root", "sender-1",
]


def _make_keys():  # type: ignore[no-untyped-def]
    from tscore.sig import ML_DSA_65, generate_keypair

    return {identity_id: generate_keypair(ML_DSA_65) for identity_id in IDENTITY_IDS}


def _trust_roots(keys):  # type: ignore[no-untyped-def]
    from tscore.evidence import PublicKeyEntry

    return [
        PublicKeyEntry(identity_id=i, role="test", sig_alg=kp.alg, sig_public_key=kp.public_key)
        for i, kp in keys.items()
    ]


def _ledger_record_proof(keys, submitter_id, domain, payload, *, height):  # type: ignore[no-untyped-def]
    from tscore.chain import compute_record_hash
    from tscore.evidence import LedgerRecordProof
    from tscore.records import make_submission
    from tscore.sig import sign as sig_sign

    submission = make_submission(
        keys[submitter_id].alg, keys[submitter_id].secret_key, submitter_id, domain, payload
    )
    prev_hash = b"\x00" * 32
    quorum_ids = ["ledger-0", "ledger-1", "ledger-2"]
    quorum_sigs = [
        sig_sign(keys[q].alg, keys[q].secret_key, submission.envelope_cbor) for q in quorum_ids
    ]
    record_hash = compute_record_hash(
        prev_hash, f"tx-{domain}-{height}", submission.envelope_cbor, quorum_ids
    )
    return LedgerRecordProof(
        tx_id=f"tx-{domain}-{height}",
        height=height,
        envelope_cbor=submission.envelope_cbor,
        submitter_id=submitter_id,
        submitter_signature=submission.signature,
        quorum_signer_ids=quorum_ids,
        quorum_signatures=quorum_sigs,
        prev_hash=prev_hash,
        record_hash=record_hash,
    )


def _resign(keys, bundle):  # type: ignore[no-untyped-def]
    from tscore.records import DOMAIN_EVIDENCE_BUNDLE, make_submission

    return make_submission(
        keys["forensics-1"].alg,
        keys["forensics-1"].secret_key,
        "forensics-1",
        DOMAIN_EVIDENCE_BUNDLE,
        bundle,
    )


def _build_genuine_signed_bundle():  # type: ignore[no-untyped-def]
    from tscore.evidence import EvidenceBundle, SuspectSessionEvidence
    from tscore.hashing import sha3_256
    from tscore.records import (
        DOMAIN_DECRYPT_REQUEST,
        DOMAIN_DECRYPT_REQUEST_LEDGER,
        DOMAIN_DOC_REGISTER,
        DOMAIN_ENROLL_FINAL,
        DOMAIN_INVESTIGATION_OPENED,
        DOMAIN_KEYGRANT_ISSUED,
        DOMAIN_RECEIPT,
        DecryptRequest,
        DecryptRequestLedgerRecord,
        DocRegisterRecord,
        EnrollFinalRecord,
        InvestigationOpenedRecord,
        KeyGrantIssuedRecord,
        ReceiptRecord,
        make_submission,
    )
    from tscore.release_secret import bias_vector_to_bytes
    from tscore.tardos import accuse
    from tscore.tardos import threshold as tardos_threshold

    keys = _make_keys()
    eps1 = 1e-4
    # Round-trip through the SAME float32 encoding the bundle actually
    # stores (tscore.release_secret.bias_vector_to_bytes) BEFORE computing
    # the "genuine" score — otherwise this test's own accuse() call would
    # use full float64 precision while verify_evidence_bundle recomputes
    # from the rounded float32 bytes, and the two could disagree by more
    # than the score-comparison tolerance for reasons that have nothing to
    # do with tampering.
    bias_vector_bytes = bias_vector_to_bytes(np.linspace(0.2, 0.8, N_POSITIONS))
    bias_vector = np.frombuffer(bias_vector_bytes, dtype=np.float32).astype(np.float64)
    codeword = np.array([0, 1, 0, 1, 0, 1, 0, 1], dtype=np.int8)
    salt = b"\x33" * 16
    observed = codeword.astype(np.float64)

    scores = accuse({SESSION_ID: codeword}, observed, bias_vector, eps1)
    z = tardos_threshold(N_POSITIONS, eps1)
    score = scores[SESSION_ID]

    investigation_opened_proof = _ledger_record_proof(
        keys,
        "forensics-1",
        DOMAIN_INVESTIGATION_OPENED,
        InvestigationOpenedRecord(case_id=CASE_ID, artifact_hash=b"\xaa" * 32),
        height=0,
    )
    doc_register_proof = _ledger_record_proof(
        keys,
        "sender-1",
        DOMAIN_DOC_REGISTER,
        DocRegisterRecord(
            doc_id=DOC_ID,
            package_hash=b"\x00" * 32,
            recipient_cert_hashes=[b"\x11" * 32],
            policy_hash=b"\x00" * 32,
            positions_count=N_POSITIONS,
            tardos_n=5,
            tardos_c0=3,
            tardos_eps1=eps1,
        ),
        height=1,
    )

    officer_request = DecryptRequest(
        doc_id=DOC_ID,
        package_hash=b"\x00" * 32,
        recipient_cert_hash=b"\x11" * 32,
        session_id=SESSION_ID,
        agent_time=0.0,
    )
    officer_submission = make_submission(
        keys["officer-a"].alg,
        keys["officer-a"].secret_key,
        "officer-a",
        DOMAIN_DECRYPT_REQUEST,
        officer_request,
    )
    commitment = sha3_256(
        DOC_ID.encode() + SESSION_ID.encode() + codeword.tobytes() + salt
    )
    decrypt_request_ledger_proof = _ledger_record_proof(
        keys,
        "keyrelease-0",
        DOMAIN_DECRYPT_REQUEST_LEDGER,
        DecryptRequestLedgerRecord(
            doc_id=DOC_ID,
            session_id=SESSION_ID,
            recipient_envelope_cbor=officer_submission.envelope_cbor,
            recipient_signer_id=officer_submission.signer_id,
            recipient_signature=officer_submission.signature,
            codeword_commitment=commitment,
        ),
        height=2,
    )

    from tscore.sig import sign as sig_sign

    contributing = ["keyrelease-0", "keyrelease-1", "keyrelease-2"]
    contributing_sigs = [
        sig_sign(
            keys[n].alg, keys[n].secret_key, sha3_256(f"{DOC_ID}|{SESSION_ID}|{n}".encode())
        )
        for n in contributing
    ]
    keygrant_issued_proof = _ledger_record_proof(
        keys,
        "keyrelease-0",
        DOMAIN_KEYGRANT_ISSUED,
        KeyGrantIssuedRecord(
            session_id=SESSION_ID,
            grant_ciphertext_hash=b"\x22" * 32,
            contributing_node_ids=contributing,
            contributing_signatures=contributing_sigs,
        ),
        height=3,
    )
    receipt_proof = _ledger_record_proof(
        keys,
        "officer-a",
        DOMAIN_RECEIPT,
        ReceiptRecord(session_id=SESSION_ID, assembled_pages_hash=b"\x44" * 32),
        height=4,
    )
    enroll_final_proof = _ledger_record_proof(
        keys,
        "ca-root",
        DOMAIN_ENROLL_FINAL,
        EnrollFinalRecord(
            officer_id="officer-a", proposal_tx_id="tx-proposal", cert_hash=b"\x11" * 32
        ),
        height=5,
    )

    suspect = SuspectSessionEvidence(
        session_id=SESSION_ID,
        officer_id="officer-a",
        coordinator_node_id="keyrelease-0",
        accusation_score=score,
        accused=bool(score > z),
        revealed_codeword=codeword.tobytes(),
        revealed_salt=salt,
        decrypt_request_ledger_proof=decrypt_request_ledger_proof,
        keygrant_issued_proof=keygrant_issued_proof,
        receipt_proof=receipt_proof,
        enroll_final_proof=enroll_final_proof,
    )

    report_pdf_bytes = b"%PDF-fake-content-for-test"
    bundle = EvidenceBundle(
        case_id=CASE_ID,
        doc_id=DOC_ID,
        artifact_hash=b"\xaa" * 32,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=eps1,
        n_observed=N_POSITIONS,
        n_total_positions=N_POSITIONS,
        n_erasures=0,
        threshold=z,
        observed_bits=observed.tolist(),
        revealed_bias_vector=bias_vector_bytes,
        suspects=[suspect],
        investigation_opened_proof=investigation_opened_proof,
        doc_register_proof=doc_register_proof,
        report_pdf_hash=sha3_256(report_pdf_bytes),
        trust_roots=_trust_roots(keys),
        built_at=0.0,
    )
    signed = _resign(keys, bundle)
    return signed, bundle, report_pdf_bytes, keys


def test_verify_evidence_bundle_accepts_a_genuine_bundle() -> None:
    from tscore.evidence import verify_evidence_bundle

    signed, _bundle, report_pdf_bytes, _keys = _build_genuine_signed_bundle()
    verified = verify_evidence_bundle(signed, report_pdf_bytes=report_pdf_bytes)
    assert verified.case_id == CASE_ID
    assert verified.suspects[0].session_id == SESSION_ID


def test_verify_evidence_bundle_skips_pdf_check_when_not_provided() -> None:
    from tscore.evidence import verify_evidence_bundle

    signed, _bundle, _report_pdf_bytes, _keys = _build_genuine_signed_bundle()
    verify_evidence_bundle(signed)  # no report_pdf_bytes -> no PDF-hash check, no exception


def test_flipped_byte_in_bundle_cbor_is_always_caught() -> None:
    """Spec Section 18 demo step 9's exact scenario: flip one byte anywhere
    in bundle.cbor, expect verification to fail. WHICH check catches it
    depends on where the flip lands in the canonical-CBOR encoding — it
    might corrupt the structure enough to fail to even decode (a
    VerificationError, not a raw decode exception — see
    verify_evidence_bundle's try/except), or it might decode fine but fail
    the outer signature. Either way, it must never verify as VALID."""
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle
    from tscore.records import SignedSubmission

    signed, _bundle, report_pdf_bytes, _keys = _build_genuine_signed_bundle()
    tampered_cbor = bytearray(signed.envelope_cbor)
    tampered_cbor[-1] ^= 0x01
    tampered = SignedSubmission(
        envelope_cbor=bytes(tampered_cbor), signer_id=signed.signer_id, signature=signed.signature
    )
    with pytest.raises(VerificationError):
        verify_evidence_bundle(tampered, report_pdf_bytes=report_pdf_bytes)


def test_flipped_signature_byte_fails_outer_signature_check() -> None:
    """Same scenario as above, but targets the outer signature specifically
    (not the CBOR structure) — deterministically exercises the
    open_submission failure path rather than whichever check a structural
    corruption happens to hit first."""
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle
    from tscore.records import SignedSubmission

    signed, _bundle, report_pdf_bytes, _keys = _build_genuine_signed_bundle()
    tampered_sig = bytearray(signed.signature)
    tampered_sig[-1] ^= 0x01
    tampered = SignedSubmission(
        envelope_cbor=signed.envelope_cbor,
        signer_id=signed.signer_id,
        signature=bytes(tampered_sig),
    )
    with pytest.raises(VerificationError, match="signature"):
        verify_evidence_bundle(tampered, report_pdf_bytes=report_pdf_bytes)


def test_forged_record_hash_fails_hash_chain_check() -> None:
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle

    signed, bundle, report_pdf_bytes, keys = _build_genuine_signed_bundle()
    mutated = bundle.model_copy(
        update={
            "doc_register_proof": bundle.doc_register_proof.model_copy(
                update={"record_hash": b"\xff" * 32}
            )
        }
    )
    resigned = _resign(keys, mutated)
    with pytest.raises(VerificationError, match="record_hash"):
        verify_evidence_bundle(resigned, report_pdf_bytes=report_pdf_bytes)


def test_corrupted_quorum_signature_fails_quorum_check() -> None:
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle

    signed, bundle, report_pdf_bytes, keys = _build_genuine_signed_bundle()
    bad_sigs = list(bundle.doc_register_proof.quorum_signatures)
    bad_sigs[0] = b"\x00" * len(bad_sigs[0])
    mutated = bundle.model_copy(
        update={
            "doc_register_proof": bundle.doc_register_proof.model_copy(
                update={"quorum_signatures": bad_sigs}
            )
        }
    )
    resigned = _resign(keys, mutated)
    with pytest.raises(VerificationError, match="quorum signature"):
        verify_evidence_bundle(resigned, report_pdf_bytes=report_pdf_bytes)


def test_mismatched_revealed_codeword_fails_commitment_check() -> None:
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle

    signed, bundle, report_pdf_bytes, keys = _build_genuine_signed_bundle()
    bad_suspect = bundle.suspects[0].model_copy(update={"revealed_salt": b"\x99" * 16})
    mutated = bundle.model_copy(update={"suspects": [bad_suspect]})
    resigned = _resign(keys, mutated)
    with pytest.raises(VerificationError, match="codeword_commitment"):
        verify_evidence_bundle(resigned, report_pdf_bytes=report_pdf_bytes)


def test_mutated_accusation_score_fails_recompute_check() -> None:
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle

    signed, bundle, report_pdf_bytes, keys = _build_genuine_signed_bundle()
    bad_suspect = bundle.suspects[0].model_copy(
        update={"accusation_score": bundle.suspects[0].accusation_score + 100.0}
    )
    mutated = bundle.model_copy(update={"suspects": [bad_suspect]})
    resigned = _resign(keys, mutated)
    with pytest.raises(VerificationError, match="recomputed Tardos score"):
        verify_evidence_bundle(resigned, report_pdf_bytes=report_pdf_bytes)


def test_swapped_report_pdf_fails_hash_cross_check() -> None:
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle

    signed, _bundle, _report_pdf_bytes, _keys = _build_genuine_signed_bundle()
    with pytest.raises(VerificationError, match="report.pdf"):
        verify_evidence_bundle(signed, report_pdf_bytes=b"some other totally different pdf bytes")


def test_verify_record_proof_rejects_unknown_submitter() -> None:
    from tscore.errors import VerificationError
    from tscore.evidence import verify_record_proof
    from tscore.records import DOMAIN_INVESTIGATION_OPENED, InvestigationOpenedRecord

    keys = _make_keys()
    proof = _ledger_record_proof(
        keys,
        "forensics-1",
        DOMAIN_INVESTIGATION_OPENED,
        InvestigationOpenedRecord(case_id=CASE_ID, artifact_hash=b"\xaa" * 32),
        height=0,
    )
    with pytest.raises(VerificationError, match="no public key"):
        verify_record_proof(proof, [])
