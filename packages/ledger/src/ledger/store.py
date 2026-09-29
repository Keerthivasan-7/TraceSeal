"""Per-replica SQLite-backed append-only log (spec Section 12: "4 replica
processes with separate volumes").

Deliberately stdlib `sqlite3`, not Postgres/SQLAlchemy: LedgerLite's own
job is a small per-replica hash-chained log with cross-replica signature
checking, not general relational metadata — see docs/DECISIONS.md's M3
scoping decisions for why Postgres is deferred to whenever something
actually needs it.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass

from tscore.chain import compute_record_hash

GENESIS_HASH = b"\x00" * 32


@dataclass(frozen=True)
class StoredRecord:
    height: int
    tx_id: str
    envelope_cbor: bytes
    submitter_id: str
    submitter_signature: bytes
    quorum_signer_ids: list[str]
    quorum_signatures: list[bytes]
    prev_hash: bytes
    record_hash: bytes
    created_at: float


class LedgerStore:
    """One replica's local log. Not thread-safe across processes (SQLite's
    own file locking handles concurrent access from a single process
    fine, which is all a single-replica FastAPI worker needs)."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS records (
                height INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id TEXT UNIQUE NOT NULL,
                envelope_cbor BLOB NOT NULL,
                submitter_id TEXT NOT NULL,
                submitter_signature BLOB NOT NULL,
                quorum_signer_ids TEXT NOT NULL,
                quorum_signatures TEXT NOT NULL,
                prev_hash BLOB NOT NULL,
                record_hash BLOB NOT NULL,
                created_at REAL NOT NULL
            )
            """
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def get_by_tx_id(self, tx_id: str) -> StoredRecord | None:
        row = self._conn.execute(
            "SELECT height, tx_id, envelope_cbor, submitter_id, submitter_signature, "
            "quorum_signer_ids, quorum_signatures, prev_hash, record_hash, created_at "
            "FROM records WHERE tx_id = ?",
            (tx_id,),
        ).fetchone()
        return self._row_to_record(row) if row else None

    def last(self) -> StoredRecord | None:
        row = self._conn.execute(
            "SELECT height, tx_id, envelope_cbor, submitter_id, submitter_signature, "
            "quorum_signer_ids, quorum_signatures, prev_hash, record_hash, created_at "
            "FROM records ORDER BY height DESC LIMIT 1"
        ).fetchone()
        return self._row_to_record(row) if row else None

    def all_records(self) -> list[StoredRecord]:
        rows = self._conn.execute(
            "SELECT height, tx_id, envelope_cbor, submitter_id, submitter_signature, "
            "quorum_signer_ids, quorum_signatures, prev_hash, record_hash, created_at "
            "FROM records ORDER BY height ASC"
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def append(
        self,
        *,
        tx_id: str,
        envelope_cbor: bytes,
        submitter_id: str,
        submitter_signature: bytes,
        quorum_signer_ids: list[str],
        quorum_signatures: list[bytes],
    ) -> StoredRecord:
        prev = self.last()
        prev_hash = prev.record_hash if prev else GENESIS_HASH
        record_hash = compute_record_hash(prev_hash, tx_id, envelope_cbor, quorum_signer_ids)
        created_at = time.time()
        self._conn.execute(
            "INSERT INTO records (tx_id, envelope_cbor, submitter_id, submitter_signature, "
            "quorum_signer_ids, quorum_signatures, prev_hash, record_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                tx_id,
                envelope_cbor,
                submitter_id,
                submitter_signature,
                ",".join(quorum_signer_ids),
                "|".join(sig.hex() for sig in quorum_signatures),
                prev_hash,
                record_hash,
                created_at,
            ),
        )
        self._conn.commit()
        result = self.get_by_tx_id(tx_id)
        assert result is not None
        return result

    @staticmethod
    def _row_to_record(row: tuple[object, ...]) -> StoredRecord:
        (
            height,
            tx_id,
            envelope_cbor,
            submitter_id,
            submitter_signature,
            quorum_signer_ids_csv,
            quorum_signatures_csv,
            prev_hash,
            record_hash,
            created_at,
        ) = row
        assert isinstance(quorum_signer_ids_csv, str)
        assert isinstance(quorum_signatures_csv, str)
        signer_ids = quorum_signer_ids_csv.split(",") if quorum_signer_ids_csv else []
        signatures = (
            [bytes.fromhex(s) for s in quorum_signatures_csv.split("|")]
            if quorum_signatures_csv
            else []
        )
        return StoredRecord(
            height=height,  # type: ignore[arg-type]
            tx_id=tx_id,  # type: ignore[arg-type]
            envelope_cbor=envelope_cbor,  # type: ignore[arg-type]
            submitter_id=submitter_id,  # type: ignore[arg-type]
            submitter_signature=submitter_signature,  # type: ignore[arg-type]
            quorum_signer_ids=signer_ids,
            quorum_signatures=signatures,
            prev_hash=prev_hash,  # type: ignore[arg-type]
            record_hash=record_hash,  # type: ignore[arg-type]
            created_at=created_at,  # type: ignore[arg-type]
        )

    def recompute_chain_valid(self) -> tuple[bool, int | None]:
        """Recompute the hash chain from genesis and compare against what's
        stored; returns ``(valid, first_bad_height)``."""
        prev_hash = GENESIS_HASH
        for record in self.all_records():
            expected = compute_record_hash(
                prev_hash, record.tx_id, record.envelope_cbor, record.quorum_signer_ids
            )
            if expected != record.record_hash or record.prev_hash != prev_hash:
                return False, record.height
            prev_hash = record.record_hash
        return True, None
