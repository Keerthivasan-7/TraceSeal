from __future__ import annotations

import io

from fastapi.testclient import TestClient
from sender.sample_doc import build_sample_document

from helpers import enrol_officer


def _sample_pdf_bytes() -> bytes:
    doc = build_sample_document()
    data: bytes = doc.tobytes()
    doc.close()
    return data


def _analyze(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/distribute/analyze",
        files={"file": ("sample.pdf", io.BytesIO(_sample_pdf_bytes()), "application/pdf")},
    )
    assert response.status_code == 200, response.text
    result: dict[str, object] = response.json()
    return result


def test_analyze_returns_positions_and_quality_gate(client: TestClient) -> None:
    body = _analyze(client)
    assert body["draft_id"]
    assert body["doc_id"].startswith("doc-")
    assert body["page_count"] == 3
    assert body["positions_count"] > 0
    assert len(body["positions"]) == body["positions_count"]
    quality_gate = body["quality_gate"]
    assert quality_gate["passed"] is True


def test_analyze_rejects_non_pdf_upload(client: TestClient) -> None:
    response = client.post(
        "/distribute/analyze",
        files={"file": ("not-a-pdf.txt", io.BytesIO(b"hello world"), "text/plain")},
    )
    assert response.status_code == 400


def test_preview_page_returns_png(client: TestClient) -> None:
    body = _analyze(client)
    response = client.get(f"/distribute/{body['draft_id']}/pages/0")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert response.content[:8] == b"\x89PNG\r\n\x1a\n"


def test_release_unknown_draft_404s(client: TestClient) -> None:
    response = client.post(
        "/distribute/does-not-exist/release", json={"recipient_officer_ids": ["officer-a"]}
    )
    assert response.status_code == 404


def test_release_requires_at_least_one_recipient(client: TestClient) -> None:
    body = _analyze(client)
    response = client.post(
        f"/distribute/{body['draft_id']}/release", json={"recipient_officer_ids": []}
    )
    assert response.status_code == 400


def test_release_rejects_unenrolled_recipient(client: TestClient) -> None:
    body = _analyze(client)
    response = client.post(
        f"/distribute/{body['draft_id']}/release",
        json={"recipient_officer_ids": ["officer-a"]},
    )
    assert response.status_code == 400
    assert "not enrolled" in response.json()["detail"]


def test_release_rejects_revoked_recipient(client: TestClient) -> None:
    enrol_officer(client, "officer-a")
    propose = client.post(
        "/identity/officers/officer-a/propose-revoke", json={"reason": "test"}
    )
    tx_id = propose.json()["proposal_tx_id"]
    for admin_id in ("admin-1", "admin-2"):
        client.post(f"/identity/proposals/{tx_id}/approve-revoke", json={"admin_id": admin_id})
    finalize = client.post(f"/identity/proposals/{tx_id}/finalize-revoke")
    assert finalize.status_code == 200

    body = _analyze(client)
    response = client.post(
        f"/distribute/{body['draft_id']}/release",
        json={"recipient_officer_ids": ["officer-a"]},
    )
    assert response.status_code == 400
    assert "revoked" in response.json()["detail"]
