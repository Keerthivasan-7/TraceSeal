"""Officer console: capture a simulated screen photo of a page the officer
has open. In the isolated deployment the investigator cannot read an
officer's decrypted pages, so the demo's leak has to travel as a *file* from
one console to the other — as a real leak would."""

from __future__ import annotations

import io

import numpy as np
import pytest
from fastapi.testclient import TestClient
from ledger.client import LedgerClient
from PIL import Image

from role_helpers import PASSPHRASES, build_role_app, seed_role_keystores
from web_api.config import Settings
from web_api.state import OpenSession


@pytest.fixture
def opened(settings: Settings, ledger_client: LedgerClient):  # type: ignore[no-untyped-def]
    seed_role_keystores(settings, ["officer-a"])
    app = build_role_app(settings, ledger_client, "officer", "officer-a")
    with TestClient(app) as client:
        client.post("/session/login", json={"passphrase": PASSPHRASES["officer-a"]})
        page = np.full((220, 180, 3), 245, dtype=np.uint8)
        page[40:60, 20:160] = 20
        app.state.app_state.open_sessions["officer-a:doc-x"] = OpenSession(
            "s", "doc-x", "officer-a", "tx", [page]
        )
        yield client, app


def test_capture_returns_a_png_attachment_and_logs_it(opened) -> None:  # type: ignore[no-untyped-def]
    client, app = opened
    response = client.post(
        "/officers/officer-a/documents/doc-x/pages/0/leak?distortion=screen_camera"
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert "attachment" in response.headers["content-disposition"]
    assert "leak-doc-x-p1" in response.headers["content-disposition"]
    assert Image.open(io.BytesIO(response.content)).size[0] > 0
    assert any(e["kind"] == "leak_simulated" for e in app.state.app_state.events.recent())


@pytest.mark.parametrize("distortion", ["none", "print_scan"])
def test_other_distortions_work(opened, distortion: str) -> None:  # type: ignore[no-untyped-def]
    client, _ = opened
    response = client.post(
        f"/officers/officer-a/documents/doc-x/pages/0/leak?distortion={distortion}"
    )
    assert response.status_code == 200


def test_unknown_distortion_is_400(opened) -> None:  # type: ignore[no-untyped-def]
    client, _ = opened
    response = client.post("/officers/officer-a/documents/doc-x/pages/0/leak?distortion=magic")
    assert response.status_code == 400


def test_capture_needs_an_open_document_and_a_real_page(opened) -> None:  # type: ignore[no-untyped-def]
    client, _ = opened
    assert client.post("/officers/officer-a/documents/other/pages/0/leak").status_code == 404
    assert client.post("/officers/officer-a/documents/doc-x/pages/5/leak").status_code == 404
    assert client.post("/officers/officer-a/documents/doc-x/pages/-1/leak").status_code == 404


def test_capture_is_pinned_to_the_logged_in_officer(opened) -> None:  # type: ignore[no-untyped-def]
    client, _ = opened
    response = client.post("/officers/officer-b/documents/doc-x/pages/0/leak")
    assert response.status_code == 403


def test_capture_requires_login(settings: Settings, ledger_client: LedgerClient) -> None:
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as client:
        assert client.post("/officers/officer-a/documents/doc-x/pages/0/leak").status_code == 401


def test_decrypted_pages_are_never_cacheable(opened) -> None:  # type: ignore[no-untyped-def]
    client, _ = opened
    page = client.get("/officers/officer-a/documents/doc-x/pages/0")
    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    leak = client.post("/officers/officer-a/documents/doc-x/pages/0/leak?distortion=none")
    assert leak.headers["cache-control"] == "no-store"
