"""Environment-driven settings — mirrors the env-var convention every other
service's `main.py` already uses (e.g. `ledger.main`, `keyrelease.main`),
just collected into one dataclass instead of scattered `os.environ.get`
calls, since this service reads more of them than any single existing one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _replica_urls(env_value: str | None, *, default: list[str]) -> list[str]:
    if not env_value:
        return default
    return [url.strip() for url in env_value.split(",") if url.strip()]


@dataclass(frozen=True)
class Settings:
    pki_dir: Path = field(default_factory=lambda: Path(os.environ.get("PKI_DIR", "/pki")))
    demo_dir: Path = field(default_factory=lambda: Path(os.environ.get("DEMO_DIR", "/app/demo")))
    blob_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("BLOB_DIR", "/app/demo/blob"))
    )
    keystore_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("KEYSTORE_DIR", "/app/demo/keystores"))
    )
    attacklab_out_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("ATTACKLAB_OUT_DIR", "/app/attacklab/out"))
    )
    ledger_backend: str = field(
        default_factory=lambda: os.environ.get("LEDGER_BACKEND", "lite")
    )
    ledger_leader_url: str = field(
        default_factory=lambda: os.environ.get("LEDGER_LEADER_URL", "http://ledger-0:8000")
    )
    ledger_replica_urls: list[str] = field(
        default_factory=lambda: _replica_urls(
            os.environ.get("LEDGER_REPLICA_URLS"),
            default=[f"http://ledger-{i}:8000" for i in range(4)],
        )
    )
    fabric_gateway_url: str = field(
        default_factory=lambda: os.environ.get("FABRIC_GATEWAY_URL", "http://fabric-gateway:8000")
    )
    keyrelease_node_count: int = field(
        default_factory=lambda: int(os.environ.get("KEYRELEASE_NODE_COUNT", "5"))
    )
    keyrelease_url_template: str = field(
        default_factory=lambda: os.environ.get(
            "KEYRELEASE_URL_TEMPLATE", "http://keyrelease-{i}:8000"
        )
    )

    def keyrelease_urls(self) -> list[str]:
        return [
            self.keyrelease_url_template.format(i=i) for i in range(self.keyrelease_node_count)
        ]


def load_settings() -> Settings:
    return Settings()
