"""Shared test helpers: a real 4-replica in-process LedgerLite cluster,
wired the same way `packages/forensics/tests/helpers.py`'s
`build_ledger_client` does — duplicated rather than imported across
package boundaries, consistent with how every package's own
`tests/helpers.py` is self-contained in this repo. Not a test module
itself (no `test_` prefix, so pytest won't collect it)."""

from __future__ import annotations

from pathlib import Path

import httpx
from fastapi.testclient import TestClient as FastAPITestClient
from ledger.client import LedgerClient
from ledger.service import HttpPeerClient, create_app
from starlette.testclient import TestClient


def enrol_officer(client: FastAPITestClient, officer_id: str) -> None:
    """Run a full enrolment ceremony via the real HTTP routes — shared by
    every test module that needs an officer with a certificate on file
    (Distribute's recipient check, the Officer Inbox's decrypt session)."""
    propose = client.post(f"/identity/officers/{officer_id}/propose-enrol", json={})
    assert propose.status_code == 200, propose.text
    tx_id = propose.json()["proposal_tx_id"]
    for admin_id in ("admin-1", "admin-2"):
        approve = client.post(f"/identity/proposals/{tx_id}/approve", json={"admin_id": admin_id})
        assert approve.status_code == 200, approve.text
    finalize = client.post(f"/identity/proposals/{tx_id}/finalize")
    assert finalize.status_code == 200, finalize.text


def build_ledger_client(pki_dir: Path, tmp_path: Path) -> LedgerClient:
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
