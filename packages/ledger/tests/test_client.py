"""LedgerClient tests: a single `httpx.Client` with per-URL `mounts` routes
each replica's base URL to its own in-process ASGI app
(`httpx.ASGITransport`) — real HTTP semantics, no real network or Docker."""

import pytest

pytestmark = pytest.mark.requires_liboqs


def _seed_pki(pki_dir):  # type: ignore[no-untyped-def]
    from ca.keys import generate_identity, save_identity
    from ca.registry import build_registry_entry, save_registry

    registry = {}
    for i in range(4):
        identity = generate_identity(f"ledger-{i}", with_kem=False)
        save_identity(identity, pki_dir / f"ledger-{i}.json")
        registry[identity.identity_id] = build_registry_entry(identity)
    sender = generate_identity("sender-1", with_kem=False)
    save_identity(sender, pki_dir / "sender-1.json")
    registry["sender-1"] = build_registry_entry(sender)
    save_registry(registry, pki_dir / "registry.json")
    return sender


def _build_client(tmp_path):  # type: ignore[no-untyped-def]
    import httpx
    from starlette.testclient import TestClient

    from ledger.client import LedgerClient
    from ledger.service import HttpPeerClient, create_app

    # httpx's `ASGITransport` only implements the async request path
    # (`handle_async_request`), so it can't be mounted into a sync
    # `httpx.Client` (confirmed directly: `AttributeError: 'ASGITransport'
    # object has no attribute 'handle_request'`). `starlette.testclient
    # .TestClient`'s own internal transport IS sync-capable (it bridges to
    # the ASGI app via an anyio portal), so we reuse that instead.
    urls = [f"http://ledger-{i}" for i in range(4)]
    apps = {
        i: create_app(replica_index=i, pki_dir=tmp_path, db_path=str(tmp_path / f"ledger-{i}.db"))
        for i in range(1, 4)
    }
    # The leader needs real PeerClient objects, not the default httpx-to-
    # real-DNS ones `create_app` would build on its own — point them at
    # the SAME mounted-ASGI http_client used for everything else below.
    mounts = {urls[i]: TestClient(apps[i])._transport for i in range(1, 4)}
    peer_http_client = httpx.Client(mounts=mounts)
    peers = [
        HttpPeerClient(f"ledger-{i}", urls[i], client=peer_http_client) for i in range(1, 4)
    ]
    apps[0] = create_app(
        replica_index=0, pki_dir=tmp_path, db_path=str(tmp_path / "ledger-0.db"), peers=peers
    )

    all_mounts = {urls[i]: TestClient(apps[i])._transport for i in range(4)}
    http_client = httpx.Client(mounts=all_mounts)
    return LedgerClient(urls[0], urls, client=http_client)


def _submission(sender):  # type: ignore[no-untyped-def]
    from tscore.records import DocRegisterRecord, make_submission

    payload = DocRegisterRecord(
        doc_id="doc-1",
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=10,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
    )
    return make_submission(
        sender.sig_alg,
        sender.sig_secret_key,
        sender.identity_id,
        "traceseal/doc-register/v1",
        payload,
    )


def test_submit_and_wait_final(tmp_path) -> None:
    sender = _seed_pki(tmp_path)
    client = _build_client(tmp_path)

    tx_id = client.submit(_submission(sender))
    record = client.wait_final(tx_id, timeout_s=5.0)
    assert record.tx_id == tx_id
    assert len(record.quorum_signer_ids) >= 3


def test_query_filters_by_domain(tmp_path) -> None:
    sender = _seed_pki(tmp_path)
    client = _build_client(tmp_path)
    client.submit(_submission(sender))

    matches = client.query(domain="traceseal/doc-register/v1")
    assert len(matches) == 1
    no_matches = client.query(domain="traceseal/receipt/v1")
    assert no_matches == []


def test_verify_chain_ok_after_a_real_submission(tmp_path) -> None:
    sender = _seed_pki(tmp_path)
    client = _build_client(tmp_path)
    client.submit(_submission(sender))

    report = client.verify_chain()
    assert report.ok
    assert report.diverged_replica_ids == []
    assert report.consensus_height == 1
