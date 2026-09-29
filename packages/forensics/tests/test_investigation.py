"""Full M5 investigation pipeline, wired against a real 4-replica ledger +
5-node key-release cluster in-process (no Docker), mirroring
`keyrelease/tests/test_integration.py`'s wiring pattern: seed a PKI
(including `forensics-1`), register a document, run one real decrypt
session, then run the actual investigation pipeline
(`open_investigation` -> `gather_candidate_codewords` ->
`forensics.pipeline.investigate` -> `build_evidence_bundle` ->
`issue_report` -> `write_tsev`) and confirm the result is a bundle that
`tscore.evidence.verify_evidence_bundle` genuinely, independently accepts
— and rejects once tampered, satisfying the same acceptance criterion as
`tscore/tests/test_evidence.py`, but end to end against real live
services rather than hand-built fixtures."""

from __future__ import annotations

import zipfile

import numpy as np
import pytest
from PIL import Image
from sender.assemble import assemble_document
from tscore.errors import VerificationError
from tscore.hashing import sha3_256
from tscore.release_secret import bias_vector_from_bytes
from tscore.tardos import sample_bias_vector

from forensics.investigation import (
    build_evidence_bundle,
    build_trust_roots,
    find_doc_register_proof,
    gather_candidate_codewords,
    issue_report,
    open_investigation,
    write_tsev,
)
from forensics.pipeline import investigate
from helpers import (
    InProcessKeyReleaseClient,
    build_keyrelease_nodes,
    build_ledger_client,
    register_all_shares,
    run_decrypt_session,
    seed_pki,
    submit_doc_register,
    submit_enroll_final,
)

pytestmark = pytest.mark.requires_liboqs

DOC_ID = "doc-1"
CASE_ID = "case-1"
SESSION_ID = "S-0001"


def _setup(tmp_path, variants):  # type: ignore[no-untyped-def]
    pki_dir = tmp_path / "pki"
    identities = seed_pki(pki_dir)
    ledger_client = build_ledger_client(pki_dir, tmp_path)
    submit_enroll_final(ledger_client, identities["ca"], "officer-a", identities["cert"])
    nodes = build_keyrelease_nodes(pki_dir, tmp_path, ledger_client)

    n_positions = len(variants.rendered_positions)
    rng = np.random.default_rng(0)
    bias_vector = sample_bias_vector(n_positions, cutoff=0.1, rng=rng)
    k_b, s_v = b"\x11" * 32, b"\x22" * 32
    register_all_shares(pki_dir, nodes, DOC_ID, k_b, s_v, bias_vector)
    submit_doc_register(ledger_client, pki_dir, DOC_ID, n_positions)

    cert_hash = sha3_256(identities["cert"].to_canonical_cbor())
    run_decrypt_session(pki_dir, nodes, DOC_ID, SESSION_ID, cert_hash)

    keyrelease_client = InProcessKeyReleaseClient(nodes)
    return pki_dir, ledger_client, keyrelease_client, identities


def _build_signed_bundle(tmp_path, variants):  # type: ignore[no-untyped-def]
    from ca.keys import load_identity
    from ca.registry import load_registry

    pki_dir, ledger_client, keyrelease_client, identities = _setup(tmp_path, variants)
    forensics_identity = load_identity(pki_dir / "forensics-1.json")
    registry = load_registry(pki_dir / "registry.json")

    candidates = gather_candidate_codewords(DOC_ID, ledger_client, keyrelease_client)
    assert len(candidates) == 1
    assert candidates[0].session_id == SESSION_ID
    assert candidates[0].officer_id == "officer-a"

    codeword = np.frombuffer(candidates[0].revealed_codeword, dtype=np.int8)
    page_index = 0
    pages = assemble_document(variants, codeword)
    img = Image.fromarray(pages[page_index])
    artifact = np.array(img)
    artifact_hash = sha3_256(artifact.tobytes())

    investigation_opened_proof = open_investigation(
        CASE_ID, artifact_hash, forensics_identity, ledger_client
    )
    doc_register_proof = find_doc_register_proof(ledger_client, DOC_ID)

    bias_vector_bytes = keyrelease_client.reveal_bias_vector(DOC_ID)
    n_positions = len(variants.rendered_positions)
    bias_vector = bias_vector_from_bytes(bias_vector_bytes, n_positions)

    report = investigate(
        artifact,
        page_index,
        variants,
        {candidates[0].session_id: codeword},
        bias_vector,
        eps1=1e-4,
    )
    assert SESSION_ID in report.accused_sessions

    trust_roots = build_trust_roots(registry)
    signed, bundle, report_pdf_bytes = build_evidence_bundle(
        case_id=CASE_ID,
        doc_id=DOC_ID,
        artifact_hash=artifact_hash,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
        n_observed=report.n_observed,
        n_total_positions=report.n_total_positions,
        n_erasures=report.n_erasures,
        threshold=report.threshold,
        observed_bits=[float(x) for x in report.observed_bits],
        revealed_bias_vector=bias_vector_bytes,
        candidates=candidates,
        scores=report.scores,
        accused_sessions=set(report.accused_sessions),
        investigation_opened_proof=investigation_opened_proof,
        doc_register_proof=doc_register_proof,
        trust_roots=trust_roots,
        forensics_identity=forensics_identity,
    )
    return signed, bundle, report_pdf_bytes, ledger_client, forensics_identity


def test_build_evidence_bundle_produces_a_bundle_that_independently_verifies(
    tmp_path, variants
) -> None:
    from tscore.evidence import verify_evidence_bundle

    signed, bundle, report_pdf_bytes, _ledger_client, _forensics_identity = _build_signed_bundle(
        tmp_path, variants
    )
    verified = verify_evidence_bundle(signed, report_pdf_bytes=report_pdf_bytes)
    assert verified.case_id == CASE_ID
    assert verified.suspects[0].session_id == SESSION_ID
    assert verified.suspects[0].accused


def test_issue_report_commits_a_downstream_ledger_record(tmp_path, variants) -> None:
    signed, bundle, report_pdf_bytes, ledger_client, forensics_identity = _build_signed_bundle(
        tmp_path, variants
    )
    tx_id = issue_report(
        CASE_ID, DOC_ID, signed, report_pdf_bytes, forensics_identity, ledger_client
    )
    record = ledger_client.get(tx_id)
    assert record.tx_id == tx_id


def test_write_tsev_round_trips_through_a_real_zip_file(tmp_path, variants) -> None:
    from tscore.evidence import verify_evidence_bundle
    from tscore.records import SignedSubmission

    signed, bundle, report_pdf_bytes, _ledger_client, _forensics_identity = _build_signed_bundle(
        tmp_path, variants
    )
    tsev_path = tmp_path / "case.tsev"
    write_tsev(tsev_path, signed, bundle, report_pdf_bytes)

    with zipfile.ZipFile(tsev_path, "r") as zf:
        assert set(zf.namelist()) == {"bundle.cbor", "bundle.json", "signature.json", "report.pdf"}
        envelope_cbor = zf.read("bundle.cbor")
        import json

        sig_data = json.loads(zf.read("signature.json"))
        pdf_bytes = zf.read("report.pdf")

    reconstructed = SignedSubmission(
        envelope_cbor=envelope_cbor,
        signer_id=sig_data["signer_id"],
        signature=bytes.fromhex(sig_data["signature"]),
    )
    verified = verify_evidence_bundle(reconstructed, report_pdf_bytes=pdf_bytes)
    assert verified.case_id == CASE_ID


def test_tampered_tsev_fails_verification(tmp_path, variants) -> None:
    from tscore.evidence import verify_evidence_bundle
    from tscore.records import SignedSubmission

    signed, bundle, report_pdf_bytes, _ledger_client, _forensics_identity = _build_signed_bundle(
        tmp_path, variants
    )
    tsev_path = tmp_path / "case.tsev"
    write_tsev(tsev_path, signed, bundle, report_pdf_bytes)

    with zipfile.ZipFile(tsev_path, "r") as zf:
        contents = {name: zf.read(name) for name in zf.namelist()}
    tampered_cbor = bytearray(contents["bundle.cbor"])
    tampered_cbor[-1] ^= 0x01

    import json

    sig_data = json.loads(contents["signature.json"])
    reconstructed = SignedSubmission(
        envelope_cbor=bytes(tampered_cbor),
        signer_id=sig_data["signer_id"],
        signature=bytes.fromhex(sig_data["signature"]),
    )
    with pytest.raises(VerificationError):
        verify_evidence_bundle(reconstructed, report_pdf_bytes=contents["report.pdf"])


def test_gather_candidate_codewords_rejects_a_forged_vault_reveal(tmp_path, variants) -> None:
    pki_dir, ledger_client, keyrelease_client, _identities = _setup(tmp_path, variants)

    real_reveal_commitment = keyrelease_client.reveal_commitment

    def forged_reveal_commitment(coordinator_node_id, session_id, doc_id):  # type: ignore[no-untyped-def]
        codeword, _salt, _commit_hash = real_reveal_commitment(
            coordinator_node_id, session_id, doc_id
        )
        return codeword, b"\xff" * 16, b"\x00" * 32

    keyrelease_client.reveal_commitment = forged_reveal_commitment  # type: ignore[assignment]
    with pytest.raises(VerificationError, match="commit_hash"):
        gather_candidate_codewords(DOC_ID, ledger_client, keyrelease_client)
