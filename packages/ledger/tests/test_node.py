"""Consensus logic tests: several LedgerNode instances wired directly
in-process (no HTTP, no Docker) via a tiny adapter implementing the
`PeerClient` protocol as a direct method call."""

import pytest

pytestmark = pytest.mark.requires_liboqs


class _InProcessPeer:
    def __init__(self, node):  # type: ignore[no-untyped-def]
        self._node = node

    @property
    def replica_id(self) -> str:
        return str(self._node.replica_id)

    def co_sign(self, submission):  # type: ignore[no-untyped-def]
        return self._node.co_sign(submission)

    def finalize(self, submission, quorum_signer_ids, quorum_signatures):  # type: ignore[no-untyped-def]
        self._node.finalize(submission, quorum_signer_ids, quorum_signatures)


def _build_cluster(tmp_path, n: int = 4):  # type: ignore[no-untyped-def]
    from tscore.sig import ML_DSA_65, generate_keypair

    from ledger.node import LedgerNode
    from ledger.store import LedgerStore

    registry: dict[str, tuple[str, bytes]] = {}
    nodes = {}
    for i in range(n):
        replica_id = f"ledger-{i}"
        kp = generate_keypair(ML_DSA_65)
        registry[replica_id] = (ML_DSA_65, kp.public_key)
        store = LedgerStore(str(tmp_path / f"{replica_id}.db"))
        nodes[replica_id] = LedgerNode(
            replica_id, ML_DSA_65, kp.secret_key, store, lambda sid: registry[sid]
        )
    return nodes, registry


def _make_submission(registry, tmp_path):  # type: ignore[no-untyped-def]
    from tscore.records import DocRegisterRecord, make_submission
    from tscore.sig import ML_DSA_65, generate_keypair

    kp = generate_keypair(ML_DSA_65)
    registry["sender-1"] = (ML_DSA_65, kp.public_key)
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
        ML_DSA_65, kp.secret_key, "sender-1", "traceseal/doc-register/v1", payload
    )


def test_submit_and_finalize_reaches_quorum_and_replicates(tmp_path) -> None:
    nodes, registry = _build_cluster(tmp_path)
    submission = _make_submission(registry, tmp_path)
    leader = nodes["ledger-0"]
    peers = [_InProcessPeer(nodes[rid]) for rid in ("ledger-1", "ledger-2", "ledger-3")]

    result = leader.submit_and_finalize(submission, peers)

    assert result.failed_peers == {}
    assert len(result.record.quorum_signer_ids) >= 3
    # Every replica (not just the leader) actually holds the record.
    for replica_id, node in nodes.items():
        stored = node.store.get_by_tx_id(result.record.tx_id)
        assert stored is not None, f"{replica_id} did not receive the finalized record"


def test_submit_is_idempotent_on_resubmission(tmp_path) -> None:
    nodes, registry = _build_cluster(tmp_path)
    submission = _make_submission(registry, tmp_path)
    leader = nodes["ledger-0"]
    peers = [_InProcessPeer(nodes[rid]) for rid in ("ledger-1", "ledger-2", "ledger-3")]

    first = leader.submit_and_finalize(submission, peers)
    second = leader.submit_and_finalize(submission, peers)
    assert first.record.tx_id == second.record.tx_id
    assert len(leader.store.all_records()) == 1


def test_submit_fails_without_quorum(tmp_path) -> None:
    from tscore.errors import VerificationError

    nodes, registry = _build_cluster(tmp_path)
    submission = _make_submission(registry, tmp_path)
    leader = nodes["ledger-0"]
    # Only one live peer available: leader (1) + 1 peer = 2 < QUORUM_THRESHOLD (3).
    peers = [_InProcessPeer(nodes["ledger-1"])]

    with pytest.raises(VerificationError):
        leader.submit_and_finalize(submission, peers)
    assert leader.store.last() is None


def test_finalize_rejects_forged_quorum_signature(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.sig import ML_DSA_65, generate_keypair

    nodes, registry = _build_cluster(tmp_path)
    submission = _make_submission(registry, tmp_path)
    victim = nodes["ledger-1"]

    forger = generate_keypair(ML_DSA_65)  # not actually ledger-2's real key
    forged_signature = forger.secret_key  # garbage, not even a real signature over this message
    with pytest.raises(VerificationError):
        victim.finalize(
            submission,
            quorum_signer_ids=["ledger-0", "ledger-2", "ledger-3"],
            quorum_signatures=[b"not-a-real-signature", forged_signature, b"also-fake"],
        )
    assert victim.store.last() is None


def test_finalize_rejects_too_few_distinct_signers(tmp_path) -> None:
    from tscore.errors import VerificationError

    nodes, registry = _build_cluster(tmp_path)
    submission = _make_submission(registry, tmp_path)
    node = nodes["ledger-0"]

    with pytest.raises(VerificationError, match="quorum"):
        node.finalize(
            submission,
            quorum_signer_ids=["ledger-0", "ledger-0"],  # same signer twice, not 3 distinct
            quorum_signatures=[b"a", b"b"],
        )
