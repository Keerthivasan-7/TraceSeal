"""Shared test helpers: seed a PKI, wire a full 4-replica ledger + 5-node
key-release cluster in-process over real FastAPI apps (mounted via
`starlette.testclient.TestClient`'s sync ASGI transport — see
`build_ledger_client`'s comment for why not `httpx.ASGITransport` — no
Docker, no real network), and build/distribute a small sender package.
Not a test module itself (no `test_` prefix, so pytest won't collect it)."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def seed_pki(pki_dir: Path) -> dict[str, Any]:
    from ca.issue import issue_certificate
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

    for i in range(5):
        identity = generate_identity(f"keyrelease-{i}", with_kem=True)
        save_identity(identity, pki_dir / f"{identity.identity_id}.json")
        registry[identity.identity_id] = build_registry_entry(identity)

    sender = generate_identity("sender-1", with_kem=True)
    save_identity(sender, pki_dir / "sender-1.json")
    registry["sender-1"] = build_registry_entry(sender)

    officer = generate_identity("officer-a", with_kem=True)
    save_identity(officer, pki_dir / "officer-a.json")
    cert, cert_sig = issue_certificate(
        ca_identity, "officer-a", officer.sig_public_key, officer.kem_public_key
    )
    registry["officer-a"] = build_registry_entry(
        officer, certificate_cbor=cert.to_canonical_cbor(), certificate_signature=cert_sig
    )

    officer_b = generate_identity("officer-b", with_kem=True)
    save_identity(officer_b, pki_dir / "officer-b.json")
    cert_b, cert_b_sig = issue_certificate(
        ca_identity, "officer-b", officer_b.sig_public_key, officer_b.kem_public_key
    )
    registry["officer-b"] = build_registry_entry(
        officer_b, certificate_cbor=cert_b.to_canonical_cbor(), certificate_signature=cert_b_sig
    )

    save_registry(registry, pki_dir / "registry.json")
    return {
        "ca": ca_identity,
        "sender": sender,
        "officer": officer,
        "cert": cert,
        "officer_b": officer_b,
        "cert_b": cert_b,
    }


def officer_cert_hash(identities: dict[str, Any]) -> bytes:
    from tscore.hashing import sha3_256

    cert_bytes: bytes = identities["cert"].to_canonical_cbor()
    return sha3_256(cert_bytes)


def submit_enroll_final(ledger_client, ca_identity, officer_id: str, cert) -> None:  # type: ignore[no-untyped-def]
    """Fast test-fixture stand-in for the real quorum ceremony (exercised on
    its own in `packages/ca/tests/test_enrolment.py`) — these tests need a
    ready, already-enrolled PKI, not a test of enrolment itself. Required
    since M4: `keyrelease.node.handle_decrypt_request` independently checks
    a request's `recipient_cert_hash` against the signer's real ENROLL_FINAL
    record on the ledger."""
    from tscore.hashing import sha3_256
    from tscore.records import DOMAIN_ENROLL_FINAL, EnrollFinalRecord, make_submission

    record = EnrollFinalRecord(
        officer_id=officer_id,
        proposal_tx_id="test-fixture-proposal",
        cert_hash=sha3_256(cert.to_canonical_cbor()),
    )
    submission = make_submission(
        ca_identity.sig_alg,
        ca_identity.sig_secret_key,
        ca_identity.identity_id,
        DOMAIN_ENROLL_FINAL,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=10.0)


def build_lookup_public_key(pki_dir: Path):  # type: ignore[no-untyped-def]
    from ca.registry import load_registry, sig_public_key

    def lookup_public_key(signer_id: str) -> tuple[str, bytes]:
        return sig_public_key(load_registry(pki_dir / "registry.json"), signer_id)

    return lookup_public_key


def build_ledger_client(pki_dir: Path, tmp_path: Path):  # type: ignore[no-untyped-def]
    import httpx
    from ledger.client import LedgerClient
    from ledger.service import HttpPeerClient, create_app
    from starlette.testclient import TestClient

    # `httpx.ASGITransport` only implements the async request path, so it
    # can't be mounted into a sync `httpx.Client` (confirmed directly:
    # `AttributeError: 'ASGITransport' object has no attribute
    # 'handle_request'` under httpx 0.28). `TestClient`'s own internal
    # transport IS sync-capable (bridges to the ASGI app via an anyio
    # portal), so mount that instead.
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


def build_keyrelease_cluster(pki_dir: Path, tmp_path: Path, ledger_client):  # type: ignore[no-untyped-def]
    """Wire 5 real `keyrelease.service` FastAPI apps in-process, node 0
    equipped with real peer clients (mounted via `TestClient`'s sync ASGI
    transport) so it can act as coordinator. Returns
    `(http_client, node0_base_url, apps)`
    — `apps` lets the caller reach each node's `KeyReleaseNode` directly
    (`apps[i].state.node`) for out-of-band share registration, the same way
    a sender would confidentially register a share with one specific node
    rather than broadcasting it through HTTP in this test."""
    import httpx
    from keyrelease.service import HttpPeerReleaseClient, create_app
    from starlette.testclient import TestClient

    # See `build_ledger_client`'s comment above: `httpx.ASGITransport` is
    # async-only, so mount `TestClient`'s sync transport instead.
    urls = {i: f"http://keyrelease-{i}" for i in range(5)}
    apps = {
        i: create_app(
            node_index=i,
            pki_dir=pki_dir,
            db_path=str(tmp_path / f"keyrelease-{i}.db"),
            ledger_client=ledger_client,
        )
        for i in range(1, 5)
    }
    peer_mounts = {urls[i]: TestClient(apps[i])._transport for i in range(1, 5)}
    peer_client = httpx.Client(mounts=peer_mounts)
    coordinator_peers = [
        HttpPeerReleaseClient(f"keyrelease-{i}", urls[i], client=peer_client) for i in range(1, 5)
    ]
    apps[0] = create_app(
        node_index=0,
        pki_dir=pki_dir,
        db_path=str(tmp_path / "keyrelease-0.db"),
        ledger_client=ledger_client,
        peers=coordinator_peers,
    )
    all_mounts = {urls[i]: TestClient(apps[i])._transport for i in range(5)}
    http_client = httpx.Client(mounts=all_mounts)
    return http_client, urls[0], apps


def build_sample_package(tmp_path: Path, doc_id: str):  # type: ignore[no-untyped-def]
    """Render a tiny synthetic document, build its variants and encrypted
    package, and write it to a blob-store path — everything `sender` would
    do before a document is distributed."""
    from sender.package import build_package, generate_document_keys, save_package
    from sender.positions import select_positions
    from sender.sample_doc import build_sample_document
    from sender.variants import build_document_variants

    doc = build_sample_document(page_count=1)
    positions = select_positions(doc, max_per_page=6)
    variants = build_document_variants(doc, positions, dpi=150)
    doc.close()

    k_a, k_b, s_v = generate_document_keys()
    package = build_package(variants, doc_id, k_a, k_b, s_v)
    package_path = tmp_path / "blobstore" / doc_id / "package.json"
    save_package(package, package_path)
    return package, package_path, variants, k_a, k_b, s_v


def distribute_document(  # type: ignore[no-untyped-def]
    pki_dir: Path,
    apps: dict,
    ledger_client,
    doc_id: str,
    package_path: Path,
    positions_count: int,
    k_b: bytes,
    s_v: bytes,
    cert_hash: bytes,
) -> None:
    """Shamir-split `K_B||S_v` and the bias vector to all 5 key-release
    nodes' stores directly (bypassing HTTP — the wire format is already
    covered by `test_distribute.py` in `sender`), and submit `DOC_REGISTER`."""
    import numpy as np
    from ca.keys import load_identity
    from ca.registry import kem_public_key, load_registry
    from sender.distribute import register_document
    from sender.package import compute_package_hash
    from tscore.kdf import domain_info
    from tscore.kem import kem_seal
    from tscore.records import DOMAIN_SHARE_REGISTRATION, ShareRegistrationPayload, make_submission
    from tscore.release_secret import bias_vector_to_bytes, combine_release_secret
    from tscore.shamir import split as shamir_split
    from tscore.tardos import sample_bias_vector

    sender_identity = load_identity(pki_dir / "sender-1.json")
    registry = load_registry(pki_dir / "registry.json")

    rng = np.random.default_rng(0)
    bias_vector = sample_bias_vector(positions_count, cutoff=0.1, rng=rng)
    secret = combine_release_secret(k_b, s_v)
    bias_bytes = bias_vector_to_bytes(bias_vector)
    shares = shamir_split(secret, n=5, k=3)

    for i, share in enumerate(shares):
        node_id = f"keyrelease-{i}"
        kem_alg, kem_pub = kem_public_key(registry, node_id)
        header = f"traceseal/share/v1/{doc_id}/{node_id}".encode()
        share_info = domain_info("share-wrap", doc_id.encode(), node_id.encode())
        wrapped_share = kem_seal(
            kem_pub, bytes([share.x]) + share.ys, header=header, info=share_info, alg=kem_alg
        )
        bias_info = domain_info("bias-wrap", doc_id.encode(), node_id.encode())
        wrapped_bias = kem_seal(kem_pub, bias_bytes, header=header, info=bias_info, alg=kem_alg)
        payload = ShareRegistrationPayload(
            doc_id=doc_id,
            node_id=node_id,
            wrapped_share=wrapped_share,
            wrapped_bias_vector=wrapped_bias,
        )
        submission = make_submission(
            sender_identity.sig_alg,
            sender_identity.sig_secret_key,
            sender_identity.identity_id,
            DOMAIN_SHARE_REGISTRATION,
            payload,
        )
        apps[i].state.node.register_share(submission)

    register_document(
        ledger_client,
        doc_id=doc_id,
        package_hash=compute_package_hash(package_path),
        recipient_cert_hashes=[cert_hash],
        policy_hash=b"\x00" * 32,
        positions_count=positions_count,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
        sender_sig_alg=sender_identity.sig_alg,
        sender_secret_key=sender_identity.sig_secret_key,
        sender_id=sender_identity.identity_id,
    )


def wrap_k_a_for_officer(pki_dir: Path, doc_id: str, k_a: bytes, path: Path) -> None:
    from ca.keys import load_identity
    from tscore.kdf import domain_info
    from tscore.kem import kem_seal

    officer = load_identity(pki_dir / "officer-a.json")
    assert officer.kem_alg is not None and officer.kem_public_key is not None
    header = f"traceseal/k-a/v1/{doc_id}/officer-a".encode()
    info = domain_info("k-a-wrap", doc_id.encode(), b"officer-a")
    wrapped = kem_seal(officer.kem_public_key, k_a, header=header, info=info, alg=officer.kem_alg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(wrapped)
