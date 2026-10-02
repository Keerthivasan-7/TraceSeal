"""`resolve_identity`: session-unlocked identity in the isolated roles, raw
file only in role `all`."""

from __future__ import annotations

from dataclasses import replace

import pytest
from ca.keys import load_identity
from fastapi import HTTPException
from fastapi.testclient import TestClient
from ledger.client import LedgerClient

from role_helpers import PASSPHRASES, build_role_app, seed_role_keystores
from web_api.config import Settings
from web_api.identities import resolve_identity
from web_api.state import AppState


def test_role_all_reads_the_raw_file(settings: Settings) -> None:
    identity = resolve_identity(settings, AppState(), "sender-1")
    assert identity.identity_id == "sender-1"


def test_role_all_prefers_an_unlocked_identity(settings: Settings) -> None:
    state = AppState()
    unlocked = load_identity(settings.pki_dir / "sender-1.json")
    state.unlocked["sender-1"] = unlocked
    assert resolve_identity(settings, state, "sender-1") is unlocked


def test_isolated_role_without_login_is_401_and_never_reads_a_file(settings: Settings) -> None:
    command = replace(settings, role="command", vault_dir=settings.pki_dir)
    with pytest.raises(HTTPException) as caught:
        resolve_identity(command, AppState(), "sender-1")
    assert caught.value.status_code == 401


def test_command_session_supplies_sender_identity_from_the_keystore(
    settings: Settings, ledger_client: LedgerClient, tmp_path_factory: pytest.TempPathFactory
) -> None:
    seed_role_keystores(settings, ["sender-1", "forensics-1"])
    empty_vault = tmp_path_factory.mktemp("empty-vault")
    app = build_role_app(settings, ledger_client, "command")
    app.state.settings = replace(app.state.settings, vault_dir=empty_vault)
    with TestClient(app) as client:
        client.post("/session/login", json={"passphrase": PASSPHRASES["sender-1"]})
        identity = resolve_identity(app.state.settings, app.state.app_state, "sender-1")
        assert identity.sig_secret_key  # real key material, from the keystore
        assert list(empty_vault.iterdir()) == []  # nothing was read from, or written to, a vault
