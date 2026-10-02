"""Login, logout and session status for the isolated roles.

The login credential is the keystore passphrase itself: a successful
Argon2id+AES-GCM unlock of this backend's own keystore(s) *is* the
authentication (a wrong passphrase fails AEAD authentication exactly like a
tampered file). There is no separate password table to leak or to disagree
with the keystore.
"""

from __future__ import annotations

import math
import socket
from typing import Any

from agent.keystore import unlock_keystore
from ca.keys import Identity
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel
from tscore.errors import TamperError

from web_api.auth import cookie_name
from web_api.config import Settings
from web_api.deps import AppStateDep, LedgerBackendDep, SettingsDep
from web_api.guards import SessionDep
from web_api.identity_status import current_cert_hash
from web_api.role_defs import FIXED_PRINCIPALS, ROLE_SCREENS

router = APIRouter(tags=["session"])


class LoginRequest(BaseModel):
    passphrase: str


def principal_label(settings: Settings) -> str:
    return settings.identity_id or settings.role


def principal_identity_ids(settings: Settings) -> list[str]:
    if settings.role == "officer":
        assert settings.identity_id is not None  # enforced by Settings.__post_init__
        return [settings.identity_id]
    return FIXED_PRINCIPALS.get(settings.role, [])


@router.get("/session")
def get_session(
    request: Request, settings: SettingsDep, app_state: AppStateDep, ledger: LedgerBackendDep
) -> dict[str, Any]:
    session = None
    if settings.auth_enabled:
        # touch=False: the UI polls this for its countdown; polling must not
        # be what keeps a session alive.
        session = app_state.sessions.validate(
            request.cookies.get(cookie_name(settings)), touch=False
        )
    authenticated = session is not None or not settings.auth_enabled

    idle_left = abs_left = None
    cert_hash: str | None = None
    if session is not None:
        idle_left, abs_left = app_state.sessions.time_left(session)
        if settings.role == "officer" and settings.identity_id:
            try:
                cert_hash = current_cert_hash(ledger, settings.identity_id)
            except Exception:  # noqa: BLE001 - status display only; never fail the poll on it
                cert_hash = None

    return {
        "role": settings.role,
        "identity_id": settings.identity_id,
        "auth_required": settings.auth_enabled,
        "authenticated": authenticated,
        "principal_ids": principal_identity_ids(settings),
        "cert_hash": cert_hash,
        "idle_expires_in_s": idle_left,
        "abs_expires_in_s": abs_left,
        "allowed_screens": ROLE_SCREENS[settings.role],
        "container": socket.gethostname(),
    }


@router.post("/session/login")
def login(
    body: LoginRequest, response: Response, settings: SettingsDep, app_state: AppStateDep
) -> dict[str, Any]:
    principals = principal_identity_ids(settings)
    if not settings.auth_enabled or not principals:
        raise HTTPException(status_code=404, detail="this console has no login")

    retry_after = app_state.lockout.retry_after()
    if retry_after > 0:
        app_state.events.add("login_blocked", f"backoff active, {math.ceil(retry_after)}s left")
        raise HTTPException(
            status_code=429,
            detail=f"too many failed attempts — try again in {math.ceil(retry_after)}s",
            headers={"Retry-After": str(math.ceil(retry_after))},
        )

    paths = {i: settings.keystore_dir / f"{i}.keystore.json" for i in principals}
    for identity_id, path in paths.items():
        if not path.exists():
            raise HTTPException(
                status_code=503, detail=f"no keystore provisioned for {identity_id!r}"
            )

    identities: dict[str, Identity] = {}
    try:
        for identity_id, path in paths.items():
            identities[identity_id] = unlock_keystore(path, body.passphrase)
    except TamperError as exc:
        app_state.lockout.record_failure()
        app_state.events.add(
            "login_failed", f"incorrect passphrase for {principal_label(settings)}"
        )
        raise HTTPException(status_code=401, detail="incorrect passphrase") from exc

    app_state.lockout.record_success()
    for previous in app_state.sessions.revoke_all():
        app_state.end_session(previous)
    token, _ = app_state.sessions.create(principal_label(settings), list(identities))
    app_state.unlocked.update(identities)
    app_state.events.add("login_ok", f"{principal_label(settings)} unlocked")

    response.set_cookie(
        key=cookie_name(settings),
        value=token,
        httponly=True,
        samesite="strict",
        path="/",
    )
    return {"authenticated": True, "principal_ids": list(identities)}


@router.post("/session/logout")
def logout(
    request: Request, response: Response, settings: SettingsDep, app_state: AppStateDep
) -> dict[str, bool]:
    session = app_state.sessions.validate(request.cookies.get(cookie_name(settings)), touch=False)
    if session is not None:
        app_state.sessions.revoke(session)
        app_state.end_session(session)
        app_state.events.add("logout", f"{principal_label(settings)} locked")
    response.delete_cookie(cookie_name(settings), path="/")
    return {"authenticated": False}


@router.get("/security/events")
def security_events(_session: SessionDep, app_state: AppStateDep) -> list[dict[str, object]]:
    return app_state.events.recent()
