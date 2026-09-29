"""HTTP-layer tests: 4 `create_app` instances wired together via
`HttpPeerClient` backed by FastAPI `TestClient`s (ASGI transport, no real
network) instead of `httpx.Client` — exercises the actual routes, Pydantic
wire models, and hex encode/decode, not just `LedgerNode` directly."""

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


def _make_submission(sender):  # type: ignore[no-untyped-def]
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


def _build_cluster(tmp_path):  # type: ignore[no-untyped-def]
    from fastapi.testclient import TestClient

    from ledger.service import HttpPeerClient, create_app

    test_clients = {}
    for i in range(1, 4):
        db_path = str(tmp_path / f"ledger-{i}.db")
        app = create_app(replica_index=i, pki_dir=tmp_path, db_path=db_path)
        test_clients[i] = TestClient(app)

    # The leader (index 0) needs real peer objects wired to the OTHER 3
    # apps' TestClients (base_url="" — TestClient routes by path alone).
    peers = [HttpPeerClient(f"ledger-{i}", "", client=test_clients[i]) for i in range(1, 4)]
    leader_app = create_app(
        replica_index=0, pki_dir=tmp_path, db_path=str(tmp_path / "ledger-0.db"), peers=peers
    )
    test_clients[0] = TestClient(leader_app)
    return test_clients


def test_submit_via_http_reaches_quorum_and_replicates(tmp_path) -> None:
    sender = _seed_pki(tmp_path)
    clients = _build_cluster(tmp_path)
    submission = _make_submission(sender)

    from ledger.wire import SubmissionWire

    wire = SubmissionWire.from_submission(submission)
    response = clients[0].post("/submit", json=wire.model_dump())
    assert response.status_code == 200, response.text
    body = response.json()
    tx_id = body["tx_id"]
    assert len(body["quorum_signer_ids"]) >= 3
    assert body["failed_peers"] == {}

    # Every replica actually has it (not just the leader).
    for i in range(4):
        record_response = clients[i].get(f"/records/{tx_id}")
        assert record_response.status_code == 200, f"ledger-{i} missing the record"


def test_record_proof_exposes_a_real_verifiable_submitter_signature(tmp_path) -> None:
    """`/records/{tx_id}` never carries submitter_signature (ADR-0023); the
    new `/records/{tx_id}/proof` route does, for evidence-bundle building
    (ADR-0028) — confirm the exposed signature actually verifies, not just
    that the field is present."""
    from tscore.schemas import verify_envelope_bytes

    sender = _seed_pki(tmp_path)
    clients = _build_cluster(tmp_path)
    submission = _make_submission(sender)

    from ledger.wire import SubmissionWire

    wire = SubmissionWire.from_submission(submission)
    response = clients[0].post("/submit", json=wire.model_dump())
    assert response.status_code == 200, response.text
    tx_id = response.json()["tx_id"]

    plain = clients[0].get(f"/records/{tx_id}").json()
    assert "submitter_signature" not in plain

    proof = clients[0].get(f"/records/{tx_id}/proof").json()
    assert proof["submitter_signature"]
    assert verify_envelope_bytes(
        sender.sig_alg,
        sender.sig_public_key,
        bytes.fromhex(proof["envelope_cbor"]),
        bytes.fromhex(proof["submitter_signature"]),
    )


def test_submit_rejected_by_non_leader(tmp_path) -> None:
    sender = _seed_pki(tmp_path)
    clients = _build_cluster(tmp_path)
    submission = _make_submission(sender)

    from ledger.wire import SubmissionWire

    wire = SubmissionWire.from_submission(submission)
    response = clients[1].post("/submit", json=wire.model_dump())
    assert response.status_code == 400


def test_co_sign_rejects_unknown_signer(tmp_path) -> None:
    from tscore.records import DocRegisterRecord, make_submission
    from tscore.sig import ML_DSA_65, generate_keypair

    _seed_pki(tmp_path)  # registry has no "mystery-signer" entry
    clients = _build_cluster(tmp_path)

    kp = generate_keypair(ML_DSA_65)
    payload = DocRegisterRecord(
        doc_id="doc-1",
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=1,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
    )
    submission = make_submission(
        ML_DSA_65, kp.secret_key, "mystery-signer", "traceseal/doc-register/v1", payload
    )
    from ledger.wire import SubmissionWire

    wire = SubmissionWire.from_submission(submission)
    response = clients[1].post("/co-sign", json=wire.model_dump())
    assert response.status_code == 400
