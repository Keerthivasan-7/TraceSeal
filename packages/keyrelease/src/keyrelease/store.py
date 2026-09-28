"""One key-release node's local persistent state (spec Section 7.3):
its own Shamir share + the Tardos bias vector per document it's been
registered for, and the per-session codeword commitment `(X, salt)` —
this node's stand-in for the forensic vault (M3 scoping decision; see
docs/DECISIONS.md — the real, separately-trusted vault is M5).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass


@dataclass(frozen=True)
class DocumentShare:
    doc_id: str
    share_x: int
    share_ys: bytes
    bias_vector: bytes  # float32 array bytes, see tscore.release_secret


@dataclass(frozen=True)
class SessionCommitment:
    session_id: str
    doc_id: str
    codeword: bytes  # int8 array bytes, one byte per position
    salt: bytes
    commit_hash: bytes


class KeyReleaseStore:
    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS shares ("
            "doc_id TEXT PRIMARY KEY, share_x INTEGER NOT NULL, "
            "share_ys BLOB NOT NULL, bias_vector BLOB NOT NULL)"
        )
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS commitments ("
            "session_id TEXT PRIMARY KEY, doc_id TEXT NOT NULL, "
            "codeword BLOB NOT NULL, salt BLOB NOT NULL, commit_hash BLOB NOT NULL)"
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def save_share(self, doc_id: str, share_x: int, share_ys: bytes, bias_vector: bytes) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO shares (doc_id, share_x, share_ys, bias_vector) "
            "VALUES (?, ?, ?, ?)",
            (doc_id, share_x, share_ys, bias_vector),
        )
        self._conn.commit()

    def get_share(self, doc_id: str) -> DocumentShare | None:
        row = self._conn.execute(
            "SELECT doc_id, share_x, share_ys, bias_vector FROM shares WHERE doc_id = ?", (doc_id,)
        ).fetchone()
        if row is None:
            return None
        return DocumentShare(doc_id=row[0], share_x=row[1], share_ys=row[2], bias_vector=row[3])

    def save_commitment(
        self, session_id: str, doc_id: str, codeword: bytes, salt: bytes, commit_hash: bytes
    ) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO commitments "
            "(session_id, doc_id, codeword, salt, commit_hash) VALUES (?, ?, ?, ?, ?)",
            (session_id, doc_id, codeword, salt, commit_hash),
        )
        self._conn.commit()

    def get_commitment(self, session_id: str) -> SessionCommitment | None:
        row = self._conn.execute(
            "SELECT session_id, doc_id, codeword, salt, commit_hash FROM commitments "
            "WHERE session_id = ?",
            (session_id,),
        ).fetchone()
        if row is None:
            return None
        return SessionCommitment(
            session_id=row[0], doc_id=row[1], codeword=row[2], salt=row[3], commit_hash=row[4]
        )
