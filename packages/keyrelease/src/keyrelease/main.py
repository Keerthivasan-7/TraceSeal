"""Real-deployment entrypoint: `python -m keyrelease.main`."""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from keyrelease.service import create_app


def main() -> None:
    node_index = int(os.environ.get("NODE_INDEX", "0"))
    node_count = int(os.environ.get("NODE_COUNT", "5"))
    pki_dir = Path(os.environ.get("PKI_DIR", "/pki"))
    db_path = os.environ.get("DB_PATH", f"/data/keyrelease-{node_index}.db")
    ledger_leader_url = os.environ.get("LEDGER_LEADER_URL", "http://ledger-0:8000")
    peer_url_template = os.environ.get("PEER_URL_TEMPLATE", "http://keyrelease-{i}:8000")

    app = create_app(
        node_index=node_index,
        pki_dir=pki_dir,
        db_path=db_path,
        ledger_leader_url=ledger_leader_url,
        node_count=node_count,
        peer_url_template=peer_url_template,
    )
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104 - internal-only Docker network


if __name__ == "__main__":
    main()
