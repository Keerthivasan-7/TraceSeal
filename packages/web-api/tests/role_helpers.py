"""Helpers for building role-scoped apps in tests (ROLE=officer/command/...).

Keystores are created with deliberately distinct, test-only passphrases so a
test can prove that one identity's passphrase does not unlock another's.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import replace

from agent.keystore import create_keystore
from ca.keys import load_identity
from fastapi import FastAPI
from ledger.client import LedgerClient

from web_api.config import Settings
from web_api.deps import get_ledger_backend, get_ledger_client
from web_api.main import create_app

PASSPHRASES = {
    "officer-a": "test-pass-officer-a",
    "officer-b": "test-pass-officer-b",
    "sender-1": "test-pass-command",
    "forensics-1": "test-pass-command",
    "ca-root": "test-pass-custodian",
    "admin-1": "test-pass-admin-1",
    "admin-2": "test-pass-admin-2",
    "admin-3": "test-pass-admin-3",
}


def seed_role_keystores(settings: Settings, identity_ids: list[str] | None = None) -> None:
    for identity_id in identity_ids or list(PASSPHRASES):
        identity = load_identity(settings.pki_dir / f"{identity_id}.json")
        create_keystore(
            identity,
            PASSPHRASES[identity_id],
            settings.keystore_dir / f"{identity_id}.keystore.json",
        )


def role_settings(settings: Settings, role: str, identity_id: str | None = None) -> Settings:
    return replace(settings, role=role, identity_id=identity_id, auth_required_override=None)


def build_role_app(
    settings: Settings,
    ledger_client: LedgerClient,
    role: str,
    identity_id: str | None = None,
    *,
    clock: Callable[[], float] | None = None,
) -> FastAPI:
    app = (
        create_app(role_settings(settings, role, identity_id), clock=clock)
        if clock is not None
        else create_app(role_settings(settings, role, identity_id))
    )
    app.dependency_overrides[get_ledger_backend] = lambda: ledger_client
    app.dependency_overrides[get_ledger_client] = lambda: ledger_client
    return app
