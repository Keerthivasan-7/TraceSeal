from __future__ import annotations

import io

from ca.keys import load_identity
from ca.seed import SENDER_ID
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ledger.client import LedgerClient
from PIL import Image
from sender.distribute import register_document
from sender.positions import select_positions
from sender.quality_gate import run_quality_gate
from sender.sample_doc import build_sample_document
from sender.variants import build_document_variants
from tscore.hashing import sha3_256

from web_api.config import Settings
from web_api.state import DistributeDraft


def _register_and_inject(
    app: FastAPI, ledger_client: LedgerClient, settings: Settings, doc_id: str
) -> None:
    """Registers a real DOC_REGISTER record (ledger only, no key-release
    needed) and injects the matching DistributeDraft into released_documents
    — mirrors what a real /distribute/release would have left behind,
    without needing a live key-release cluster in tests."""
    doc = build_sample_document()
    positions = select_positions(doc)
    variants = build_document_variants(doc, positions)
    doc.close()
    quality_report = run_quality_gate(variants)

    sender_identity = load_identity(settings.pki_dir / f"{SENDER_ID}.json")
    register_document(
        ledger_client,
        doc_id=doc_id,
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=sha3_256(b"x"),
        positions_count=len(positions),
        tardos_n=2,
        tardos_c0=2,
        tardos_eps1=1e-4,
        sender_sig_alg=sender_identity.sig_alg,
        sender_secret_key=sender_identity.sig_secret_key,
        sender_id=sender_identity.identity_id,
    )
    app.state.app_state.released_documents[doc_id] = DistributeDraft(
        draft_id="test-draft", doc_id=doc_id, variants=variants, quality_report=quality_report
    )


def _page_png_bytes(app: FastAPI, doc_id: str, page_index: int) -> bytes:
    variants = app.state.app_state.released_documents[doc_id].variants
    buf = io.BytesIO()
    Image.fromarray(variants.original_pages[page_index]).save(buf, format="PNG")
    return buf.getvalue()


def test_open_unreleased_doc_404s(client: TestClient) -> None:
    response = client.post(
        "/investigate/open",
        data={"doc_id": "doc-does-not-exist", "page_index": "0"},
        files={"file": ("leak.png", io.BytesIO(b"not a real image but unreachable"), "image/png")},
    )
    assert response.status_code == 404


def test_open_requires_file_or_officer(
    app: FastAPI, client: TestClient, ledger_client: LedgerClient, settings: Settings
) -> None:
    _register_and_inject(app, ledger_client, settings, "doc-investigate-1")
    response = client.post(
        "/investigate/open", data={"doc_id": "doc-investigate-1", "page_index": "0"}
    )
    assert response.status_code == 400
    assert "file" in response.json()["detail"]


def test_open_with_no_sessions_reports_nothing_to_accuse(
    app: FastAPI, client: TestClient, ledger_client: LedgerClient, settings: Settings
) -> None:
    """A real pipeline run: submits a real INVESTIGATION_OPENED record,
    finds the real DOC_REGISTER record, and queries the ledger for
    candidate sessions — all for real. Only the key-release-dependent
    vault reveal (needed once a candidate exists) never runs, since no
    officer ever opened this document, so this is the honest 400."""
    _register_and_inject(app, ledger_client, settings, "doc-investigate-2")
    png_bytes = _page_png_bytes(app, "doc-investigate-2", 0)

    response = client.post(
        "/investigate/open",
        data={"doc_id": "doc-investigate-2", "page_index": "0"},
        files={"file": ("leak.png", io.BytesIO(png_bytes), "image/png")},
    )
    assert response.status_code == 400
    assert "nothing to accuse" in response.json()["detail"]


def test_pipeline_endpoints_404_for_unknown_case(client: TestClient) -> None:
    assert client.get("/investigate/case-none/pipeline/detected-page").status_code == 404
    assert client.get("/investigate/case-none/pipeline/aligned-overlay").status_code == 404
    assert client.get("/investigate/case-none/pipeline/observations").status_code == 404


def test_issue_report_requires_existing_case(client: TestClient) -> None:
    response = client.post("/investigate/case-none/issue-report")
    assert response.status_code == 404


def test_downloads_404_before_report_issued(client: TestClient) -> None:
    assert client.get("/investigate/case-none/download/tsev").status_code == 404
    assert client.get("/investigate/case-none/download/report.pdf").status_code == 404
