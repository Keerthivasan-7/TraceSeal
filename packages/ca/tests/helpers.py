"""Shared test helpers: wire a 4-replica LedgerLite cluster in-process over
real FastAPI apps (mounted via `starlette.testclient.TestClient`'s sync ASGI
transport — see `docs/DECISIONS.md` ADR-0017 for why not
`httpx.ASGITransport`), plus a small PKI of admins/CA/officers for the
enrolment ceremony. Not a test module itself (no `test_` prefix, so pytest
won't collect it)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def seed_enrolment_pki(pki_dir: Path) -> dict[str, Any]:
    from ca.keys import ROOT_SIG_ALG, generate_identity, save_identity
    from ca.registry import build_registry_entry, save_registry

    registry: dict[str, Any] = {}

    ca_identity = generate_identity("ca-root", sig_alg=ROOT_SIG_ALG, with_kem=False)
    save_identity(ca_identity, pki_dir / "ca-root.json")
    registry["ca-root"] = build_registry_entry(ca_identity)

    for i in range(4):
        identity = generate_identity(f"ledger-{i}", with_kem=False)
        save_identity(identity, pki_dir / f"{identity.identity_id}.json")
        registry[identity.identity_id] = build_registry_entry(identity)

    admins = {}
    for admin_id in ("admin-1", "admin-2", "admin-3"):
        identity = generate_identity(admin_id, with_kem=False)
        save_identity(identity, pki_dir / f"{admin_id}.json")
        registry[admin_id] = build_registry_entry(identity)
        admins[admin_id] = identity

    officer = generate_identity("officer-a", with_kem=True)
    save_identity(officer, pki_dir / "officer-a.json")
    registry["officer-a"] = build_registry_entry(officer)

    save_registry(registry, pki_dir / "registry.json")
    return {"ca": ca_identity, "admins": admins, "officer": officer}


def build_ledger_client(pki_dir: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    import httpx
    from ledger.client import LedgerClient
    from ledger.service import HttpPeerClient, create_app
    from starlette.testclient import TestClient

    urls = [f"http://ledger-{i}" for i in range(4)]
    apps = {
        i: create_app(replica_index=i, pki_dir=pki_dir, db_path=str(tmp_path / f"ledger-{i}.db"))
        for i in range(1, 4)
    }
    mounts = {urls[i]: TestClient(apps[i])._transport for i in range(1, 4)}
    peer_http_client = httpx.Client(mounts=mounts)
    peers = [HttpPeerClient(f"ledger-{i}", urls[i], client=peer_http_client) for i in range(1, 4)]
    apps[0] = create_app(
        replica_index=0, pki_dir=pki_dir, db_path=str(tmp_path / "ledger-0.db"), peers=peers
    )
    all_mounts = {urls[i]: TestClient(apps[i])._transport for i in range(4)}
    http_client = httpx.Client(mounts=all_mounts)
    return LedgerClient(urls[0], urls, client=http_client)
