"""FastAPI app factory + real-deployment entrypoint for the web UI bridge.

`create_app` is a factory (like `ledger.service.create_app`/
`keyrelease.service.create_app`) so tests can instantiate it in-process
against injected clients instead of a real cluster.
"""

from __future__ import annotations

import uvicorn
from fastapi import FastAPI

from web_api.config import Settings, load_settings
from web_api.routes import distribute, identity, ledger, officers, system
from web_api.state import AppState


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="TraceSeal web-api")
    app.state.settings = settings
    app.state.app_state = AppState()

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(system.router)
    app.include_router(ledger.router)
    app.include_router(identity.router)
    app.include_router(distribute.router)
    app.include_router(officers.router)

    return app


def main() -> None:
    app = create_app()
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104 - internal-only Docker network


if __name__ == "__main__":
    main()
