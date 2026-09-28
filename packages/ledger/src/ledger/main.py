"""Real-deployment entrypoint: `python -m ledger.main`.

Reads this replica's configuration from the environment and serves
`ledger.service.create_app`'s app with uvicorn.
"""

from __future__ import annotations

import os
from pathlib import Path

import uvicorn

from ledger.service import create_app


def main() -> None:
    replica_index = int(os.environ.get("REPLICA_INDEX", "0"))
    replica_count = int(os.environ.get("REPLICA_COUNT", "4"))
    pki_dir = Path(os.environ.get("PKI_DIR", "/pki"))
    db_path = os.environ.get("DB_PATH", f"/data/ledger-{replica_index}.db")
    peer_url_template = os.environ.get("PEER_URL_TEMPLATE", "http://ledger-{i}:8000")

    app = create_app(
        replica_index=replica_index,
        pki_dir=pki_dir,
        db_path=db_path,
        replica_count=replica_count,
        peer_url_template=peer_url_template,
    )
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104 - internal-only Docker network


if __name__ == "__main__":
    main()
