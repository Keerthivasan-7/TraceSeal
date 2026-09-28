from ledger.store import GENESIS_HASH, LedgerStore


def _store(tmp_path) -> LedgerStore:
    return LedgerStore(str(tmp_path / "replica.db"))


def test_empty_store_has_no_last_record(tmp_path) -> None:
    store = _store(tmp_path)
    assert store.last() is None
    assert store.all_records() == []


def test_append_and_get_by_tx_id(tmp_path) -> None:
    store = _store(tmp_path)
    record = store.append(
        tx_id="tx-1",
        envelope_cbor=b"envelope-bytes",
        submitter_id="sender-1",
        submitter_signature=b"sig-1",
        quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
        quorum_signatures=[b"q0", b"q1", b"q2"],
    )
    assert record.height == 1
    assert record.prev_hash == GENESIS_HASH
    fetched = store.get_by_tx_id("tx-1")
    assert fetched == record


def test_chain_links_prev_hash_to_previous_record_hash(tmp_path) -> None:
    store = _store(tmp_path)
    first = store.append(
        tx_id="tx-1",
        envelope_cbor=b"a",
        submitter_id="s",
        submitter_signature=b"sig",
        quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
        quorum_signatures=[b"1", b"2", b"3"],
    )
    second = store.append(
        tx_id="tx-2",
        envelope_cbor=b"b",
        submitter_id="s",
        submitter_signature=b"sig",
        quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
        quorum_signatures=[b"1", b"2", b"3"],
    )
    assert second.prev_hash == first.record_hash
    assert second.height == 2


def test_recompute_chain_valid_on_untampered_store(tmp_path) -> None:
    store = _store(tmp_path)
    for i in range(3):
        store.append(
            tx_id=f"tx-{i}",
            envelope_cbor=f"payload-{i}".encode(),
            submitter_id="s",
            submitter_signature=b"sig",
            quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
            quorum_signatures=[b"1", b"2", b"3"],
        )
    valid, bad_height = store.recompute_chain_valid()
    assert valid
    assert bad_height is None


def test_recompute_chain_valid_detects_direct_tampering(tmp_path) -> None:
    db_path = tmp_path / "replica.db"
    store = LedgerStore(str(db_path))
    store.append(
        tx_id="tx-0",
        envelope_cbor=b"payload-0",
        submitter_id="s",
        submitter_signature=b"sig",
        quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
        quorum_signatures=[b"1", b"2", b"3"],
    )
    store.append(
        tx_id="tx-1",
        envelope_cbor=b"payload-1",
        submitter_id="s",
        submitter_signature=b"sig",
        quorum_signer_ids=["ledger-0", "ledger-1", "ledger-2"],
        quorum_signatures=[b"1", b"2", b"3"],
    )
    store.close()

    # Simulate an insider directly editing one replica's database file.
    import sqlite3

    conn = sqlite3.connect(str(db_path))
    conn.execute("UPDATE records SET envelope_cbor = ? WHERE tx_id = ?", (b"tampered!", "tx-0"))
    conn.commit()
    conn.close()

    reopened = LedgerStore(str(db_path))
    valid, bad_height = reopened.recompute_chain_valid()
    assert not valid
    assert bad_height == 1
