"""FastAPI app factory + real-deployment entrypoint for the web UI bridge.

`create_app` is a factory (like `ledger.service.create_app`/
`keyrelease.service.create_app`) so tests can instantiate it in-process
against injected clients instead of a real cluster.

The same image runs every deployment role (`ROLE` env, see `web_api.roles`):
`all` is the original single console; `officer`/`command`/`authority`/`ops`
are the isolated per-workstation backends.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

import uvicorn
from fastapi import Depends, FastAPI, Request, Response

from web_api.auth import Clock, LockoutTracker, SessionManager
from web_api.config import Settings, load_settings
from web_api.guards import require_session
from web_api.roles import routers_for
from web_api.routes import session
from web_api.state import AppState

SWEEP_INTERVAL_S = 5.0


async def _sweep_forever(app_state: AppState) -> None:
    while True:
        await asyncio.sleep(SWEEP_INTERVAL_S)
        app_state.sweep_expired()


def create_app(settings: Settings | None = None, *, clock: Clock = time.monotonic) -> FastAPI:
    settings = settings or load_settings()
    app_state = AppState(
        sessions=SessionManager(settings.idle_timeout_s, settings.abs_timeout_s, clock),
        lockout=LockoutTracker(clock),
        clock=clock,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        # Idle decrypted pages must not linger until someone happens to make
        # another request: expire sessions on a timer as well.
        sweeper = asyncio.create_task(_sweep_forever(app_state))
        try:
            yield
        finally:
            sweeper.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await sweeper

    app = FastAPI(title=f"TraceSeal web-api ({settings.role})", lifespan=lifespan)
    app.state.settings = settings
    app.state.app_state = app_state

    @app.middleware("http")
    async def expire_sessions(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        app_state.sweep_expired()
        return await call_next(request)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(session.router)
    guards = [Depends(require_session)] if settings.auth_enabled else []
    for router in routers_for(settings.role):
        app.include_router(router, dependencies=guards)

    return app


def main() -> None:
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104 - internal-only Docker network


if __name__ == "__main__":
    main()
