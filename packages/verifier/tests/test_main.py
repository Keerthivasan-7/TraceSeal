"""CLI-level tests for `traceseal-verify`: exit codes and diagnostics for a
genuine bundle vs. a tampered one. Builds its own minimal, fully genuine
`.tsev` archive using ONLY `tscore` (this package's own dependency
constraint applies to its tests too — the Docker image never has
`forensics` installed to build one for it) — a deliberately smaller
version of `tscore/tests/test_evidence.py`'s hand-built bundle, since this
suite only needs one passing round trip plus the CLI/archive-format edges
`tscore`'s own tests don't cover: a REAL zip file on disk, and a
file-level tamper (case 6 of the M5 plan's tampering table — swapping
`report.pdf`, which nothing at the `tscore.evidence` unit-test level can
exercise since that hash cross-check only fires when the CLI actually
reads two separate files out of one archive)."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import numpy as np
import pytest

pytestmark = pytest.mark.requires_liboqs

DOC_ID = "doc-test"
SESSION_ID = "S-0001"
CASE_ID = "case-0001"
N_POSITIONS = 8
IDENTITY_IDS = [
    "ledger-0", "ledger-1", "ledger-2",
    "keyrelease-0", "keyrelease-1", "keyrelease-2",
    "officer-a", "forensics-1",
]


def _build_tsev(path: Path) -> None:
    from tscore.chain import compute_record_hash
    from tscore.evidence import (
        EvidenceBundle,
        LedgerRecordProof,
        PublicKeyEntry,
        SuspectSessionEvidence,
    )
    from tscore.hashing import sha3_256
    from tscore.records import (
        DOMAIN_DECRYPT_REQUEST,
        DOMAIN_DECRYPT_REQUEST_LEDGER,
        DOMAIN_DOC_REGISTER,
        DOMAIN_EVIDENCE_BUNDLE,
        DOMAIN_INVESTIGATION_OPENED,
        DOMAIN_KEYGRANT_ISSUED,
        DecryptRequest,
        DecryptRequestLedgerRecord,
        DocRegisterRecord,
        InvestigationOpenedRecord,
        KeyGrantIssuedRecord,
        make_submission,
    )
    from tscore.release_secret import bias_vector_to_bytes
    from tscore.sig import ML_DSA_65, generate_keypair
    from tscore.sig import sign as sig_sign
    from tscore.tardos import accuse
    from tscore.tardos import threshold as tardos_threshold

    keys = {i: generate_keypair(ML_DSA_65) for i in IDENTITY_IDS}
    trust_roots = [
        PublicKeyEntry(identity_id=i, role="test", sig_alg=kp.alg, sig_public_key=kp.public_key)
        for i, kp in keys.items()
    ]

    def ledger_proof(submitter_id: str, domain: str, payload, *, height: int) -> LedgerRecordProof:
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

    eps1 = 1e-4
    bias_vector_bytes = bias_vector_to_bytes(np.linspace(0.2, 0.8, N_POSITIONS))
    bias_vector = np.frombuffer(bias_vector_bytes, dtype=np.float32).astype(np.float64)
    codeword = np.array([0, 1, 0, 1, 0, 1, 0, 1], dtype=np.int8)
    salt = b"\x33" * 16
    observed = codeword.astype(np.float64)
    scores = accuse({SESSION_ID: codeword}, observed, bias_vector, eps1)
    z = tardos_threshold(N_POSITIONS, eps1)

    officer_submission = make_submission(
        keys["officer-a"].alg,
        keys["officer-a"].secret_key,
        "officer-a",
        DOMAIN_DECRYPT_REQUEST,
        DecryptRequest(
            doc_id=DOC_ID,
            package_hash=b"\x00" * 32,
            recipient_cert_hash=b"\x11" * 32,
            session_id=SESSION_ID,
            agent_time=0.0,
        ),
    )
    commitment = sha3_256(DOC_ID.encode() + SESSION_ID.encode() + codeword.tobytes() + salt)
    contributing = ["keyrelease-0", "keyrelease-1", "keyrelease-2"]
    contributing_sigs = [
        sig_sign(keys[n].alg, keys[n].secret_key, sha3_256(f"{DOC_ID}|{SESSION_ID}|{n}".encode()))
        for n in contributing
    ]

    suspect = SuspectSessionEvidence(
        session_id=SESSION_ID,
        officer_id="officer-a",
        coordinator_node_id="keyrelease-0",
        accusation_score=scores[SESSION_ID],
        accused=bool(scores[SESSION_ID] > z),
        revealed_codeword=codeword.tobytes(),
        revealed_salt=salt,
        decrypt_request_ledger_proof=ledger_proof(
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
        ),
        keygrant_issued_proof=ledger_proof(
            "keyrelease-0",
            DOMAIN_KEYGRANT_ISSUED,
            KeyGrantIssuedRecord(
                session_id=SESSION_ID,
                grant_ciphertext_hash=b"\x22" * 32,
                contributing_node_ids=contributing,
                contributing_signatures=contributing_sigs,
            ),
            height=3,
        ),
    )

    report_pdf_bytes = b"%PDF-fake-content-for-test"
    bundle = EvidenceBundle(
        case_id=CASE_ID,
        doc_id=DOC_ID,
        artifact_hash=b"\xaa" * 32,
        tardos_n=1,
        tardos_c0=2,
        tardos_eps1=eps1,
        n_observed=N_POSITIONS,
        n_total_positions=N_POSITIONS,
        n_erasures=0,
        threshold=z,
        observed_bits=observed.tolist(),
        revealed_bias_vector=bias_vector_bytes,
        suspects=[suspect],
        investigation_opened_proof=ledger_proof(
            "forensics-1",
            DOMAIN_INVESTIGATION_OPENED,
            InvestigationOpenedRecord(case_id=CASE_ID, artifact_hash=b"\xaa" * 32),
            height=0,
        ),
        doc_register_proof=ledger_proof(
            "keyrelease-0",
            DOMAIN_DOC_REGISTER,
            DocRegisterRecord(
                doc_id=DOC_ID,
                package_hash=b"\x00" * 32,
                recipient_cert_hashes=[b"\x11" * 32],
                policy_hash=b"\x00" * 32,
                positions_count=N_POSITIONS,
                tardos_n=1,
                tardos_c0=2,
                tardos_eps1=eps1,
            ),
            height=1,
        ),
        report_pdf_hash=sha3_256(report_pdf_bytes),
        trust_roots=trust_roots,
        built_at=0.0,
    )
    signed = make_submission(
        keys["forensics-1"].alg,
        keys["forensics-1"].secret_key,
        "forensics-1",
        DOMAIN_EVIDENCE_BUNDLE,
        bundle,
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bundle.cbor", signed.envelope_cbor)
        zf.writestr(
            "signature.json",
            json.dumps({"signer_id": signed.signer_id, "signature": signed.signature.hex()}),
        )
        zf.writestr("report.pdf", report_pdf_bytes)


def test_verify_tsev_accepts_a_genuine_bundle(tmp_path: Path) -> None:
    from verifier.main import verify_tsev

    path = tmp_path / "case.tsev"
    _build_tsev(path)
    ok, message = verify_tsev(path)
    assert ok, message
    assert CASE_ID in message


def test_verify_tsev_rejects_a_flipped_byte_in_bundle_cbor(tmp_path: Path) -> None:
    from verifier.main import verify_tsev

    genuine = tmp_path / "case.tsev"
    _build_tsev(genuine)
    with zipfile.ZipFile(genuine, "r") as zf:
        contents = {name: zf.read(name) for name in zf.namelist()}
    tampered_bundle = bytearray(contents["bundle.cbor"])
    tampered_bundle[-1] ^= 0x01
    contents["bundle.cbor"] = bytes(tampered_bundle)

    tampered = tmp_path / "case_tampered.tsev"
    with zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in contents.items():
            zf.writestr(name, data)

    ok, message = verify_tsev(tampered)
    assert not ok, message


def test_verify_tsev_rejects_a_swapped_report_pdf(tmp_path: Path) -> None:
    """Tampering case 6 (bundle.cbor untouched, only report.pdf swapped) —
    reachable only via a real file-level edit, exactly what this test does."""
    from verifier.main import verify_tsev

    genuine = tmp_path / "case.tsev"
    _build_tsev(genuine)
    with zipfile.ZipFile(genuine, "r") as zf:
        contents = {name: zf.read(name) for name in zf.namelist()}
    contents["report.pdf"] = b"%PDF-a-different-report-entirely"

    tampered = tmp_path / "case_swapped_pdf.tsev"
    with zipfile.ZipFile(tampered, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in contents.items():
            zf.writestr(name, data)

    ok, message = verify_tsev(tampered)
    assert not ok
    assert "report.pdf" in message


def test_verify_tsev_rejects_a_corrupted_archive(tmp_path: Path) -> None:
    from verifier.main import verify_tsev

    not_a_zip = tmp_path / "garbage.tsev"
    not_a_zip.write_bytes(b"not a zip file at all")
    ok, message = verify_tsev(not_a_zip)
    assert not ok
    assert message


def test_main_exits_zero_for_genuine_and_nonzero_for_tampered(
    tmp_path: Path, capsys, monkeypatch
) -> None:
    import sys

    from verifier.main import main

    genuine = tmp_path / "case.tsev"
    _build_tsev(genuine)

    monkeypatch.setattr(sys, "argv", ["traceseal-verify", str(genuine)])
    assert main() == 0
    assert "VALID" in capsys.readouterr().out

    missing = tmp_path / "does-not-exist.tsev"
    monkeypatch.setattr(sys, "argv", ["traceseal-verify", str(missing)])
    assert main() == 1
    assert "INVALID" in capsys.readouterr().out
