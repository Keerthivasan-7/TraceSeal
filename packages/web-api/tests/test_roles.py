"""Role-scoped routers + the session guard: who can reach what, and what is
wiped when a session ends."""

from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient
from ledger.client import LedgerClient

from role_helpers import PASSPHRASES, build_role_app, seed_role_keystores
from web_api.config import Settings
from web_api.state import OpenSession

LOGIN = "/session/login"


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _login(client: TestClient, passphrase: str) -> None:
    response = client.post(LOGIN, json={"passphrase": passphrase})
    assert response.status_code == 200, response.text


@pytest.fixture(autouse=True)
def _keystores(settings: Settings) -> None:
    seed_role_keystores(settings)


# ---------------------------------------------------------------- officer role


def test_officer_routes_need_a_session(settings: Settings, ledger_client: LedgerClient) -> None:
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as client:
        assert client.get("/officers/officer-a/documents").status_code == 401
        _login(client, PASSPHRASES["officer-a"])
        assert client.get("/officers/officer-a/documents").status_code == 200


@pytest.mark.parametrize("path_id", ["officer-b", "OFFICER-A", "%6Fficer-b", "officer-a%20", "x"])
def test_officer_cannot_reach_another_officers_routes(
    settings: Settings, ledger_client: LedgerClient, path_id: str
) -> None:
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as client:
        _login(client, PASSPHRASES["officer-a"])
        for suffix in ("/documents", "/documents/doc-x/pages/0"):
            response = client.get(f"/officers/{path_id}{suffix}")
            assert response.status_code in (403, 404), (path_id, suffix, response.status_code)
            assert response.status_code != 200
        response = client.post(f"/officers/{path_id}/documents/doc-x/open", json={})
        assert response.status_code in (403, 404)


def test_officer_console_does_not_mount_other_roles_routes(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as client:
        _login(client, PASSPHRASES["officer-a"])
        # 404, not 401/403: these routes simply do not exist on this console.
        assert client.post("/distribute/analyze").status_code == 404
        assert client.get("/identity/registry").status_code == 404
        assert client.post("/investigate/open").status_code == 404
        assert client.get("/attacklab/results").status_code == 404
        assert client.get("/system/status").status_code == 404
        assert client.get("/officers").status_code == 404
        assert (
            client.post("/officers/officer-a/unlock", json={"passphrase": "x"}).status_code == 404
        )


def test_session_expiry_wipes_identity_and_decrypted_pages(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    clock = FakeClock()
    app = build_role_app(settings, ledger_client, "officer", "officer-a", clock=clock)
    state = app.state.app_state
    with TestClient(app) as client:
        _login(client, PASSPHRASES["officer-a"])
        state.open_sessions["officer-a:doc-x"] = OpenSession(
            "s", "doc-x", "officer-a", "tx", [np.zeros((2, 2, 3), dtype=np.uint8)]
        )
        clock.now += 301
        assert client.get("/officers/officer-a/documents").status_code == 401
        assert "officer-a" not in state.unlocked
        assert state.open_sessions == {}
        assert any(e["kind"] == "session_expired" for e in state.events.recent())


def test_two_officer_backends_do_not_accept_each_others_sessions(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    app_a = build_role_app(settings, ledger_client, "officer", "officer-a")
    app_b = build_role_app(settings, ledger_client, "officer", "officer-b")
    with TestClient(app_a) as a, TestClient(app_b) as b:
        _login(a, PASSPHRASES["officer-a"])
        _login(b, PASSPHRASES["officer-b"])
        token_a = a.cookies["ts_session_officer-a"]
        # A's token presented to B under every cookie name B might read.
        b.cookies.clear()
        b.cookies.set("ts_session_officer-b", token_a)
        assert b.get("/officers/officer-b/documents").status_code == 401
        b.cookies.set("ts_session_officer-a", token_a)  # a cookie name B never reads
        assert b.get("/officers/officer-b/documents").status_code == 401
        assert b.get("/officers/officer-a/documents").status_code == 401  # 401 (no session) first
        # And A's own session is unaffected.
        assert a.get("/officers/officer-a/documents").status_code == 200


def test_security_events_record_scope_violations(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    with TestClient(build_role_app(settings, ledger_client, "officer", "officer-a")) as client:
        _login(client, PASSPHRASES["officer-a"])
        client.get("/officers/officer-b/documents")
        kinds = [e["kind"] for e in client.get("/security/events").json()]
        assert "scope_violation" in kinds


# ---------------------------------------------------------------- command role


def test_command_role_gets_read_views_but_not_enrolment_or_officer_agent(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    with TestClient(build_role_app(settings, ledger_client, "command")) as client:
        assert client.get("/identity/registry").status_code == 401  # needs a session
        _login(client, PASSPHRASES["sender-1"])
        assert client.get("/identity/registry").status_code == 200
        assert client.get("/officers").status_code == 200  # roster only
        assert client.get("/officers/officer-a/documents").status_code == 404
        assert client.post("/identity/officers/officer-a/propose-enrol", json={}).status_code == 404
        assert (
            client.post("/officers/officer-a/unlock", json={"passphrase": "x"}).status_code == 404
        )


# -------------------------------------------------------------------- ops role


def test_ops_role_is_open_read_only(settings: Settings, ledger_client: LedgerClient) -> None:
    with TestClient(build_role_app(settings, ledger_client, "ops")) as client:
        assert client.get("/system/status").status_code == 200
        assert client.get("/identity/proposals").status_code == 200
        assert client.post("/distribute/analyze").status_code == 404
        assert client.post("/identity/officers/officer-a/propose-enrol", json={}).status_code == 404
        assert client.get("/officers/officer-a/documents").status_code == 404
        assert client.post(LOGIN, json={"passphrase": "x"}).status_code == 404


# -------------------------------------------------------------------- authority


def test_authority_role_has_identity_admin_but_no_documents(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    with TestClient(build_role_app(settings, ledger_client, "authority")) as client:
        assert client.get("/identity/registry").status_code == 401
        _login(client, PASSPHRASES["ca-root"])
        assert client.get("/identity/registry").status_code == 200
        assert client.post("/distribute/analyze").status_code == 404
        assert client.get("/officers/officer-a/documents").status_code == 404


# --------------------------------------------------------------- role `all`


def test_role_all_is_unchanged_and_needs_no_login(client: TestClient) -> None:
    info = client.get("/session").json()
    assert info["role"] == "all"
    assert info["auth_required"] is False
    assert client.get("/officers").status_code == 200
    assert client.get("/identity/registry").status_code == 200


def test_unknown_role_is_rejected(settings: Settings) -> None:
    from dataclasses import replace

    with pytest.raises(ValueError, match="unknown ROLE"):
        replace(settings, role="root")
    with pytest.raises(ValueError, match="IDENTITY_ID"):
        replace(settings, role="officer", identity_id=None)


def test_passive_polls_do_not_extend_idle_timeout_but_real_requests_do(
    settings: Settings, ledger_client: LedgerClient
) -> None:
    clock = FakeClock()
    app = build_role_app(settings, ledger_client, "officer", "officer-a", clock=clock)
    passive = {"X-TS-Passive": "1"}
    url = "/officers/officer-a/documents"
    with TestClient(app) as client:
        _login(client, PASSPHRASES["officer-a"])
        clock.now += 200
        assert client.get(url, headers=passive).status_code == 200
        clock.now += 200  # 400 s since the login; the passive poll did not count
        assert client.get(url, headers=passive).status_code == 401

        _login(client, PASSPHRASES["officer-a"])  # t=400
        clock.now += 200
        assert client.get(url).status_code == 200  # a real request: resets the idle clock
        clock.now += 200  # 200 s since that request, 400 s since login
        assert client.get(url).status_code == 200
