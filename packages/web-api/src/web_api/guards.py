"""FastAPI dependencies that enforce who may call what.

Separate from `web_api.auth` (pure primitives) because these need
`web_api.deps`, which imports `web_api.state`, which imports `web_api.auth`.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request

from web_api.auth import Session, cookie_name
from web_api.deps import AppStateDep, SettingsDep

PASSIVE_HEADER = "x-ts-passive"


def require_session(
    request: Request, settings: SettingsDep, app_state: AppStateDep
) -> Session | None:
    """401 unless the request carries a live session cookie for *this*
    backend. A no-op (returns None) where auth is disabled (`all`, `ops`)."""
    if not settings.auth_enabled:
        return None
    token = request.cookies.get(cookie_name(settings))
    # The UI polls with `X-TS-Passive: 1`; polling must not be what keeps a
    # session alive, or the idle timeout would never fire in an open tab.
    # Only requests a person triggered (no header) reset the idle clock.
    passive = request.headers.get(PASSIVE_HEADER) == "1"
    session = app_state.sessions.validate(token, touch=not passive)
    if session is None:
        kind = "auth_invalid" if token else "auth_missing"
        app_state.events.add(kind, f"{request.method} {request.url.path}")
        raise HTTPException(status_code=401, detail="login required")
    return session


SessionDep = Annotated[Session | None, Depends(require_session)]


def officer_scope(
    officer_id: str, session: SessionDep, settings: SettingsDep, app_state: AppStateDep
) -> None:
    """Pins an officer-parameterised route to the one officer this backend
    belongs to *and* to the session's own identity. Exact string comparison:
    FastAPI has already percent-decoded the path, so `%6Fficer-b` arrives as
    `officer-b` and is rejected the same as the plain form."""
    if settings.role == "officer" and officer_id != settings.identity_id:
        app_state.events.add("scope_violation", f"path asked for {officer_id!r}")
        raise HTTPException(status_code=403, detail="not this console's officer")
    if session is not None and session.principal_id != officer_id:
        app_state.events.add(
            "scope_violation", f"session {session.principal_id!r} -> {officer_id!r}"
        )
        raise HTTPException(status_code=403, detail="session does not belong to this officer")
