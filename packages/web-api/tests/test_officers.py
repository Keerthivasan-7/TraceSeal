from __future__ import annotations

from agent.seed_keystores import DEMO_PASSPHRASE, seed_keystores
from fastapi.testclient import TestClient

from helpers import enrol_officer
from web_api.config import Settings

# Full open()/decrypt-session coverage needs live key-release nodes reachable
# over real HTTP (sender.distribute.register_shares and agent.decrypt's
# request_key_grant both make genuine httpx calls to a node URL, with no
# in-process injection point) — that path is verified against the real
# docker-compose cluster (make demo-m8), not simulated here. These tests
# cover every validation branch that runs before a network call is made.


def test_list_officers_shows_not_enrolled_and_locked(client: TestClient) -> None:
    response = client.get("/officers")
    assert response.status_code == 200
    rows = {r["officer_id"]: r for r in response.json()}
    assert rows["officer-a"]["status"] == "not enrolled"
    assert rows["officer-a"]["unlocked"] is False


def test_unlock_unseeded_keystore_404s(client: TestClient) -> None:
    response = client.post("/officers/officer-a/unlock", json={"passphrase": "whatever"})
    assert response.status_code == 404


def test_unlock_wrong_passphrase_401s(client: TestClient, settings: Settings) -> None:
    seed_keystores(settings.pki_dir, settings.keystore_dir, passphrase=DEMO_PASSPHRASE)
    response = client.post("/officers/officer-a/unlock", json={"passphrase": "wrong"})
    assert response.status_code == 401


def test_unlock_and_lock_flow(client: TestClient, settings: Settings) -> None:
    seed_keystores(settings.pki_dir, settings.keystore_dir, passphrase=DEMO_PASSPHRASE)

    unlock = client.post("/officers/officer-a/unlock", json={"passphrase": DEMO_PASSPHRASE})
    assert unlock.status_code == 200
    assert unlock.json() == {"officer_id": "officer-a", "unlocked": True}

    rows = {r["officer_id"]: r for r in client.get("/officers").json()}
    assert rows["officer-a"]["unlocked"] is True

    lock = client.post("/officers/officer-a/lock")
    assert lock.status_code == 200
    rows = {r["officer_id"]: r for r in client.get("/officers").json()}
    assert rows["officer-a"]["unlocked"] is False


def test_open_without_unlocked_session_401s(client: TestClient) -> None:
    response = client.post("/officers/officer-a/documents/doc-x/open", json={})
    assert response.status_code == 401


def test_open_unenrolled_officer_400s(client: TestClient, settings: Settings) -> None:
    seed_keystores(settings.pki_dir, settings.keystore_dir, passphrase=DEMO_PASSPHRASE)
    client.post("/officers/officer-a/unlock", json={"passphrase": DEMO_PASSPHRASE})

    response = client.post("/officers/officer-a/documents/doc-x/open", json={})
    assert response.status_code == 400
    assert "not enrolled" in response.json()["detail"]


def test_open_missing_distributed_copy_404s(client: TestClient, settings: Settings) -> None:
    enrol_officer(client, "officer-a")
    seed_keystores(settings.pki_dir, settings.keystore_dir, passphrase=DEMO_PASSPHRASE)
    client.post("/officers/officer-a/unlock", json={"passphrase": DEMO_PASSPHRASE})

    response = client.post("/officers/officer-a/documents/doc-does-not-exist/open", json={})
    assert response.status_code == 404


def test_list_documents_empty_before_any_distribution(client: TestClient) -> None:
    response = client.get("/officers/officer-a/documents")
    assert response.status_code == 200
    assert response.json() == []


def test_get_page_without_open_session_404s(client: TestClient) -> None:
    response = client.get("/officers/officer-a/documents/doc-x/pages/0")
    assert response.status_code == 404
