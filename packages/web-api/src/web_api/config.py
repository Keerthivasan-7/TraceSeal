"""Environment-driven settings — mirrors the env-var convention every other
service's `main.py` already uses (e.g. `ledger.main`, `keyrelease.main`),
just collected into one dataclass instead of scattered `os.environ.get`
calls, since this service reads more of them than any single existing one.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROLES = frozenset({"all", "officer", "command", "authority", "ops"})


def _env_bool(value: str | None) -> bool | None:
    if value is None or value == "":
        return None
    return value.strip().lower() in {"1", "true", "yes", "on"}


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
    docs_dir: Path = field(default_factory=lambda: Path(os.environ.get("DOCS_DIR", "/app/docs")))
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

    # --- Role isolation (docs/superpowers/specs/2026-10-01-role-isolation-design.md)
    # `all` is the original single-console deployment: every router, no login.
    role: str = field(default_factory=lambda: os.environ.get("ROLE", "all"))
    identity_id: str | None = field(default_factory=lambda: os.environ.get("IDENTITY_ID") or None)
    auth_required_override: bool | None = field(
        default_factory=lambda: _env_bool(os.environ.get("AUTH_REQUIRED"))
    )
    idle_timeout_s: float = field(
        default_factory=lambda: float(os.environ.get("SESSION_IDLE_S", "300"))
    )
    abs_timeout_s: float = field(
        default_factory=lambda: float(os.environ.get("SESSION_ABS_S", "1800"))
    )
    # Where unattended-service / raw private identity files live. Unset means
    # "same directory as the registry" — every pre-existing deployment.
    vault_dir: Path | None = field(
        default_factory=lambda: Path(v) if (v := os.environ.get("VAULT_DIR")) else None
    )
    enrol_inbox_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("ENROL_INBOX_DIR", "/app/demo/enrol-inbox"))
    )

    def __post_init__(self) -> None:
        if self.role not in ROLES:
            raise ValueError(f"unknown ROLE {self.role!r}; expected one of {sorted(ROLES)}")
        if self.role == "officer" and not self.identity_id:
            raise ValueError("ROLE=officer requires IDENTITY_ID (e.g. officer-a)")

    @property
    def auth_enabled(self) -> bool:
        """Whether routes require a logged-in session. `all` (dev/combined)
        and `ops` (read-only, holds no private keys) default to open."""
        if self.auth_required_override is not None:
            return self.auth_required_override
        return self.role not in {"all", "ops"}

    @property
    def identity_dir(self) -> Path:
        return self.vault_dir if self.vault_dir is not None else self.pki_dir

    def keyrelease_urls(self) -> list[str]:
        return [
            self.keyrelease_url_template.format(i=i) for i in range(self.keyrelease_node_count)
        ]


def load_settings() -> Settings:
    return Settings()
