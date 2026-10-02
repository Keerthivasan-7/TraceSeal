from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from ledger.client import LedgerClient

from role_helpers import PASSPHRASES, build_role_app, seed_role_keystores
from web_api.config import Settings

LOGIN = "/session/login"


@pytest.fixture
def officer_client(settings: Settings, ledger_client: LedgerClient) -> Iterator[TestClient]:
    seed_role_keystores(settings)
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as c:
        yield c


def test_session_info_when_logged_out(officer_client: TestClient) -> None:
    body = officer_client.get("/session").json()
    assert body["role"] == "officer"
    assert body["identity_id"] == "officer-a"
    assert body["auth_required"] is True
    assert body["authenticated"] is False
    assert body["allowed_screens"] == ["inbox"]


def test_wrong_passphrase_is_401_and_logged(officer_client: TestClient) -> None:
    response = officer_client.post(LOGIN, json={"passphrase": "nope"})
    assert response.status_code == 401
    assert officer_client.get("/session").json()["authenticated"] is False


def test_other_identitys_passphrase_does_not_unlock(officer_client: TestClient) -> None:
    response = officer_client.post(LOGIN, json={"passphrase": PASSPHRASES["officer-b"]})
    assert response.status_code == 401


def test_login_sets_httponly_strict_cookie_and_never_returns_token(
    officer_client: TestClient,
) -> None:
    response = officer_client.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]})
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith("ts_session_officer-a=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie
    token = response.cookies["ts_session_officer-a"]
    assert token not in response.text
    info = officer_client.get("/session").json()
    assert info["authenticated"] is True
    assert 0 < info["idle_expires_in_s"] <= 300
    assert 0 < info["abs_expires_in_s"] <= 1800


def test_logout_drops_identity_and_session(settings: Settings, ledger_client: LedgerClient) -> None:
    seed_role_keystores(settings, ["officer-a"])
    app = build_role_app(settings, ledger_client, "officer", "officer-a")
    with TestClient(app) as client:
        assert client.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]}).status_code == 200
        assert "officer-a" in app.state.app_state.unlocked
        assert client.post("/session/logout").status_code == 200
        assert "officer-a" not in app.state.app_state.unlocked
        assert client.get("/session").json()["authenticated"] is False


def test_missing_keystore_is_503_naming_the_identity(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as client:
        response = client.post(LOGIN, json={"passphrase": "x"})
        assert response.status_code == 503
        assert "officer-a" in response.json()["detail"]


def test_ops_role_has_no_login(settings: Settings, ledger_client: LedgerClient) -> None:
    with TestClient(build_role_app(settings, ledger_client, "ops")) as client:
        assert client.post(LOGIN, json={"passphrase": "x"}).status_code == 404
        info = client.get("/session").json()
        assert info["auth_required"] is False
        assert info["allowed_screens"] == ["command", "monitor", "ledger"]


def test_lockout_blocks_even_the_correct_passphrase(officer_client: TestClient) -> None:
    for _ in range(5):
        assert officer_client.post(LOGIN, json={"passphrase": "wrong"}).status_code == 401
    blocked = officer_client.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]})
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) >= 1
    assert officer_client.get("/session").json()["authenticated"] is False


def test_new_login_replaces_the_previous_session(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    app = build_role_app(settings, ledger_client, "officer", "officer-a")
    seed_role_keystores(settings, ["officer-a"])
    with TestClient(app) as first, TestClient(app) as second:
        first.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]})
        second.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]})
        assert second.get("/session").json()["authenticated"] is True
        assert first.get("/session").json()["authenticated"] is False


def test_polling_session_info_does_not_extend_idle_timeout(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    class Clock:
        now = 0.0

        def __call__(self) -> float:
            return self.now

    clock = Clock()
    seed_role_keystores(settings, ["officer-a"])
    app = build_role_app(settings, ledger_client, "officer", "officer-a", clock=clock)
    with TestClient(app) as client:
        client.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]})
        for _ in range(3):  # UI polls every few seconds; must not keep the session alive
            clock.now += 80
            client.get("/session")
        assert client.get("/session").json()["authenticated"] is True  # 240 s, still inside 300
        clock.now += 80  # 320 s since the last *real* activity (the login)
        assert client.get("/session").json()["authenticated"] is False


def test_security_events_require_a_session_and_record_failures(
    officer_client: TestClient,
) -> None:
    assert officer_client.get("/security/events").status_code == 401
    officer_client.post(LOGIN, json={"passphrase": "wrong"})
    officer_client.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]})
    events = officer_client.get("/security/events").json()
    kinds = [e["kind"] for e in events]
    assert "login_failed" in kinds
    assert "login_ok" in kinds
    assert PASSPHRASES["officer-a"] not in str(events)
    assert "wrong" not in str(events)


def test_command_login_unlocks_sender_and_forensics_with_one_passphrase(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    seed_role_keystores(settings)
    app = build_role_app(settings, ledger_client, "command")
    with TestClient(app) as client:
        response = client.post(LOGIN, json={"passphrase": PASSPHRASES["sender-1"]})
        assert response.status_code == 200
        unlocked = app.state.app_state.unlocked
        assert {"sender-1", "forensics-1"} <= set(unlocked)
        assert "officer-a" not in unlocked
