import dataclasses

from ledger.store import LedgerStore
from ledger.verify import verify_chain


def _seed_store(tmp_path, name: str, n: int = 3) -> LedgerStore:
    store = LedgerStore(str(tmp_path / f"{name}.db"))
    for i in range(n):
        store.append(
            tx_id=f"tx-{i}",
            envelope_cbor=f"payload-{i}".encode(),
            submitter_id="s",
            submitter_signature=b"sig",
            quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
            quorum_signatures=[b"1", b"2", b"3"],
        )
    return store


def test_verify_chain_ok_when_all_replicas_agree(tmp_path) -> None:
    replicas = {f"ledger-{i}": _seed_store(tmp_path, f"ledger-{i}").all_records() for i in range(4)}
    report = verify_chain(replicas)
    assert report.ok
    assert report.diverged_replica_ids == []
    assert report.consensus_height == 3


def test_verify_chain_flags_single_tampered_replica(tmp_path) -> None:
    # Three honest replicas agree; a fourth's record at height 2 has a
    # different (fabricated) record_hash — constructed directly rather
    # than via SQL surgery on a real store, so this test targets the
    # cross-replica *comparison* specifically (the internal hash-chain
    # recompute path already has its own test in test_store.py).
    replicas = {f"ledger-{i}": _seed_store(tmp_path, f"ledger-{i}").all_records() for i in range(4)}
    tampered_record = dataclasses.replace(
        replicas["ledger-2"][1], record_hash=b"\xff" * 32
    )
    replicas["ledger-2"] = [replicas["ledger-2"][0], tampered_record, replicas["ledger-2"][2]]

    report = verify_chain(replicas)
    assert not report.ok
    assert report.diverged_replica_ids == ["ledger-2"]
    # The other 3 replicas still agree with each other and are internally valid.
    for status in report.replicas:
        if status.replica_id != "ledger-2":
            assert status.internally_valid


def test_verify_chain_handles_empty_replicas() -> None:
    report = verify_chain({})
    assert report.ok
    assert report.consensus_height == 0
