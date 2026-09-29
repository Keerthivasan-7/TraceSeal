"""Shared FastAPI dependencies — thin accessors onto `app.state`, so route
modules never reach into `request.app.state` directly.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Request
from ledger.backend import LedgerBackend, build_ledger_client
from ledger.client import LedgerClient

from web_api.config import Settings
from web_api.state import AppState


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_app_state(request: Request) -> AppState:
    state: AppState = request.app.state.app_state
    return state


def get_ledger_backend(request: Request) -> LedgerBackend:
    """The `LedgerBackend`-typed client (LedgerLite or Fabric, per
    `LEDGER_BACKEND`) — for submitting/reading records, used by every
    screen except Ledger's own replica-integrity view (which needs
    LedgerLite's concrete cross-replica recompute; see
    `get_ledger_client`)."""
    settings: Settings = request.app.state.settings
    return build_ledger_client(
        settings.ledger_backend,
        ledger_leader_url=settings.ledger_leader_url,
        fabric_gateway_url=settings.fabric_gateway_url,
    )


def get_ledger_client(request: Request) -> LedgerClient:
    """The concrete LedgerLite client — only `LedgerClient.verify_chain()`
    needs this specific type (spec's "integrity per replica" is a
    LedgerLite-specific concept; Fabric's own BFT consensus provides that
    guarantee differently — see `web_api.routes.ledger`)."""
    settings: Settings = request.app.state.settings
    return LedgerClient(settings.ledger_leader_url, settings.ledger_replica_urls)


# Route-signature aliases (`x: SettingsDep` instead of
# `x: Settings = Depends(get_settings)`) — ruff/bugbear flags a bare
# `Depends()` call in a default argument (B008); wrapping it in
# `Annotated` instead is FastAPI's own recommended modern style and
# genuinely isn't a mutable-default-argument hazard, since FastAPI
# evaluates the dependency per-request rather than once at def time.
SettingsDep = Annotated[Settings, Depends(get_settings)]
AppStateDep = Annotated[AppState, Depends(get_app_state)]
LedgerBackendDep = Annotated[LedgerBackend, Depends(get_ledger_backend)]
LedgerClientDep = Annotated[LedgerClient, Depends(get_ledger_client)]
