"""Which routers each deployment role mounts.

A router that is not mounted does not exist: a request for it is a plain 404,
indistinguishable from a typo. That is deliberate — an officer console must
not even reveal that, say, `/distribute/analyze` exists behind a locked door.
"""

from __future__ import annotations

from fastapi import APIRouter

from web_api.routes import (
    attacklab,
    distribute,
    identity,
    investigate,
    ledger,
    monitor,
    officers,
    system,
)

_READ_ONLY_VIEWS: list[APIRouter] = [system.router, ledger.router, monitor.router]

ROLE_ROUTERS: dict[str, list[APIRouter]] = {
    # Original combined console: everything, no login.
    "all": [
        *_READ_ONLY_VIEWS,
        identity.read_router,
        identity.admin_router,
        officers.roster_router,
        officers.agent_router,
        officers.legacy_router,
        distribute.router,
        investigate.router,
        attacklab.router,
    ],
    # Document owner: releases documents, investigates leaks. Reads the
    # roster/registry (to pick recipients) but cannot enrol or open anything.
    "command": [
        *_READ_ONLY_VIEWS,
        identity.read_router,
        officers.roster_router,
        distribute.router,
        investigate.router,
        attacklab.router,
    ],
    # One officer's workstation agent: only that officer's own documents.
    "officer": [officers.agent_router],
    # Enrolment authority: the quorum ceremony. Never sees documents.
    "authority": [
        system.router,
        ledger.router,
        identity.read_router,
        identity.admin_router,
        officers.roster_router,
    ],
    # Operations view: read-only, holds no private material at all.
    "ops": [*_READ_ONLY_VIEWS, identity.read_router, officers.roster_router],
}


def routers_for(role: str) -> list[APIRouter]:
    return ROLE_ROUTERS[role]
