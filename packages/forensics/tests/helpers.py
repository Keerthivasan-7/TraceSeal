"""Shared test helpers: seed a PKI (including the M5 `forensics-1`
identity), wire a full 4-replica ledger + 5-node key-release cluster
in-process (no Docker, no real network — same pattern as
`packages/keyrelease/tests/helpers.py`, duplicated rather than imported
across package boundaries, consistent with how every package's own
`tests/helpers.py` is self-contained in this repo), and run one real
decrypt session end to end. Not a test module itself (no `test_` prefix,
so pytest won't collect it)."""

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

    forensics = generate_identity("forensics-1", with_kem=False)
    save_identity(forensics, pki_dir / "forensics-1.json")
    registry["forensics-1"] = build_registry_entry(forensics)

    officer = generate_identity("officer-a", with_kem=True)
    save_identity(officer, pki_dir / "officer-a.json")
    cert, cert_sig = issue_certificate(
        ca_identity, "officer-a", officer.sig_public_key, officer.kem_public_key
    )
    registry["officer-a"] = build_registry_entry(
        officer, certificate_cbor=cert.to_canonical_cbor(), certificate_signature=cert_sig
    )

    save_registry(registry, pki_dir / "registry.json")
    return {
        "ca": ca_identity,
        "sender": sender,
        "forensics": forensics,
        "officer": officer,
        "cert": cert,
    }


def submit_enroll_final(ledger_client, ca_identity, officer_id: str, cert) -> None:  # type: ignore[no-untyped-def]
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


def build_keyrelease_nodes(pki_dir: Path, tmp_path: Path, ledger_client):  # type: ignore[no-untyped-def]
    from ca.keys import load_identity
    from ca.registry import kem_public_key, load_registry, sig_public_key
    from keyrelease.node import KeyReleaseNode
    from keyrelease.store import KeyReleaseStore

    def lookup_sig(signer_id: str) -> tuple[str, bytes]:
        registry = load_registry(pki_dir / "registry.json")
        return sig_public_key(registry, signer_id)

    def lookup_kem(signer_id: str) -> tuple[str, bytes]:
        registry = load_registry(pki_dir / "registry.json")
        return kem_public_key(registry, signer_id)

    nodes = {}
    for i in range(5):
        node_id = f"keyrelease-{i}"
        identity = load_identity(pki_dir / f"{node_id}.json")
        store = KeyReleaseStore(str(tmp_path / f"{node_id}.db"))
        nodes[node_id] = KeyReleaseNode(
            node_id,
            identity.sig_alg,
            identity.sig_secret_key,
            identity.kem_alg,
            identity.kem_secret_key,
            store,
            lookup_sig,
            lookup_kem,
            ledger_client,
        )
    return nodes


class InProcessReleasePeer:
    def __init__(self, node) -> None:  # type: ignore[no-untyped-def]
        self._node = node

    @property
    def node_id(self) -> str:
        return str(self._node.node_id)

    def release_share(self, session_id: str, doc_id: str) -> tuple[int, bytes, bytes, bytes]:
        result: tuple[int, bytes, bytes, bytes] = self._node.release_share(session_id, doc_id)
        return result


class InProcessKeyReleaseClient:
    """Same public shape as `keyrelease.client.KeyReleaseClient`, but calls
    the in-process `KeyReleaseNode` objects directly instead of doing real
    HTTP — `forensics.investigation` only ever calls `reveal_bias_vector`/
    `reveal_commitment` on whatever it's handed, so this satisfies it by
    duck typing without needing a real network round trip in tests."""

    def __init__(self, nodes: dict) -> None:  # type: ignore[no-untyped-def]
        self._nodes = nodes

    def reveal_bias_vector(self, doc_id: str) -> bytes:
        from keyrelease.node import RevealNotFound

        errors = []
        for node in self._nodes.values():
            try:
                return node.reveal_bias_vector(doc_id)
            except RevealNotFound as exc:
                errors.append(str(exc))
        raise RuntimeError(f"no key-release node has a bias vector for doc {doc_id!r}: {errors}")

    def reveal_commitment(self, coordinator_node_id: str, session_id: str, doc_id: str):  # type: ignore[no-untyped-def]
        commitment = self._nodes[coordinator_node_id].reveal_commitment(session_id, doc_id)
        return commitment.codeword, commitment.salt, commitment.commit_hash


def register_all_shares(
    pki_dir: Path, nodes: dict, doc_id: str, k_b: bytes, s_v: bytes, bias_vector  # type: ignore[no-untyped-def]
) -> None:
    from ca.keys import load_identity
    from ca.registry import kem_public_key, load_registry
    from tscore.kdf import domain_info
    from tscore.kem import kem_seal
    from tscore.records import DOMAIN_SHARE_REGISTRATION, ShareRegistrationPayload, make_submission
    from tscore.release_secret import bias_vector_to_bytes, combine_release_secret
    from tscore.shamir import split as shamir_split

    sender_identity = load_identity(pki_dir / "sender-1.json")
    registry = load_registry(pki_dir / "registry.json")
    secret = combine_release_secret(k_b, s_v)
    bias_bytes = bias_vector_to_bytes(bias_vector)
    shares = shamir_split(secret, n=len(nodes), k=3)

    for share, (node_id, node) in zip(shares, nodes.items(), strict=True):
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
        node.register_share(submission)


def submit_doc_register(
    ledger_client,  # type: ignore[no-untyped-def]
    pki_dir: Path,
    doc_id: str,
    positions_count: int,
    *,
    tardos_n: int = 5,
    tardos_c0: int = 3,
    tardos_eps1: float = 1e-4,
) -> None:
    from ca.keys import load_identity
    from tscore.records import DOMAIN_DOC_REGISTER, DocRegisterRecord, make_submission

    sender_identity = load_identity(pki_dir / "sender-1.json")
    record = DocRegisterRecord(
        doc_id=doc_id,
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=positions_count,
        tardos_n=tardos_n,
        tardos_c0=tardos_c0,
        tardos_eps1=tardos_eps1,
    )
    submission = make_submission(
        sender_identity.sig_alg,
        sender_identity.sig_secret_key,
        sender_identity.identity_id,
        DOMAIN_DOC_REGISTER,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=10.0)


def run_decrypt_session(pki_dir: Path, nodes: dict, doc_id: str, session_id: str, cert_hash: bytes):  # type: ignore[no-untyped-def]
    """Runs one real `handle_decrypt_request` against `keyrelease-0` as
    coordinator, exactly like `keyrelease/tests/test_integration.py` —
    this is what actually populates `DECRYPT_REQUEST_LEDGER`/
    `KEYGRANT_ISSUED` on the ledger and a commitment on the coordinator's
    own store, which `forensics.investigation.gather_candidate_codewords`
    later reads back."""
    from ca.keys import load_identity
    from tscore.records import DOMAIN_DECRYPT_REQUEST, DecryptRequest, make_submission

    officer = load_identity(pki_dir / "officer-a.json")
    request = DecryptRequest(
        doc_id=doc_id,
        package_hash=b"\x00" * 32,
        recipient_cert_hash=cert_hash,
        session_id=session_id,
        agent_time=0.0,
    )
    submission = make_submission(
        officer.sig_alg,
        officer.sig_secret_key,
        officer.identity_id,
        DOMAIN_DECRYPT_REQUEST,
        request,
    )
    coordinator = nodes["keyrelease-0"]
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]
    return coordinator.handle_decrypt_request(submission, peers)
