"""Durable local queue for signed ledger events the agent could not submit
live (spec Section 7.4: "if the ledger is unreachable, the agent queues
signed events and flushes them later. It never opens a document without,
at minimum, the queued signed event."). Deliberately narrow scope
(docs/DECISIONS.md): only `OPEN_EVENT`/`OPEN_DENIED` ever go through this
path — `ReceiptRecord` submission stays a hard synchronous `submit`+
`wait_final`, exactly as before M4.

One line of hex-encoded `SignedSubmission` JSON per queued event, so a
crash mid-append can corrupt at most the last (incomplete) line, never the
ones before it.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from ledger.client import LedgerClient
from tscore.records import SignedSubmission


def _line_for(submission: SignedSubmission) -> str:
    return json.dumps(
        {
            "envelope_cbor": submission.envelope_cbor.hex(),
            "signer_id": submission.signer_id,
            "signature": submission.signature.hex(),
        }
    )


def _submission_from_line(line: str) -> SignedSubmission:
    data = json.loads(line)
    return SignedSubmission(
        envelope_cbor=bytes.fromhex(data["envelope_cbor"]),
        signer_id=data["signer_id"],
        signature=bytes.fromhex(data["signature"]),
    )


def append(path: Path, submission: SignedSubmission) -> None:
    """Durably append one queued submission (fsync before return) — a crash
    right after this call can't silently lose it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(_line_for(submission) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_all(path: Path) -> list[SignedSubmission]:
    if not path.exists():
        return []
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return [_submission_from_line(line) for line in lines]


def flush(path: Path, ledger_client: LedgerClient) -> list[str]:
    """Best-effort: try to submit+wait_final every queued submission, in
    order. Only the ones that actually finalize are removed from the queue
    (rewritten atomically); the rest stay queued for the next flush. Returns
    the tx_ids that finalized."""
    submissions = read_all(path)
    if not submissions:
        return []

    finalized_tx_ids: list[str] = []
    remaining: list[SignedSubmission] = []
    for submission in submissions:
        try:
            tx_id = ledger_client.submit(submission)
            ledger_client.wait_final(tx_id)
        except Exception:  # noqa: BLE001 - still unreachable/failing; keep queued, try next flush
            remaining.append(submission)
            continue
        finalized_tx_ids.append(tx_id)

    tmp_path = path.with_suffix(path.suffix + ".tmp")
    tmp_path.write_text(
        "".join(_line_for(submission) + "\n" for submission in remaining), encoding="utf-8"
    )
    tmp_path.replace(path)
    return finalized_tx_ids
