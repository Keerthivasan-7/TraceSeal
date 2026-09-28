"""External client library for the ledger (spec Section 12's
`LedgerBackend` interface), used by `sender`, `keyrelease`, and `agent`.

Submission is synchronous end-to-end at M3: the leader's `/submit`
performs the whole co-sign/finalize quorum round-trip before responding
(see `ledger.node.LedgerNode.submit_and_finalize`), so by the time
`submit()` returns, the record is normally already final. `wait_final`
still exists as its own call (spec's `LedgerBackend` shape keeps `submit`
and `wait_final` separate) and polls `/records/{tx_id}`, which matters if
it's ever called from a different process than the one that submitted.
"""

from __future__ import annotations

import time

import httpx
from tscore.records import SignedSubmission
from tscore.schemas import SignedEnvelope

from ledger.store import StoredRecord
from ledger.verify import ChainReport, verify_chain
from ledger.wire import RecordWire, SubmissionWire


class LedgerTimeoutError(Exception):
    pass


class LedgerClient:
    def __init__(
        self,
        leader_url: str,
        replica_urls: list[str] | None = None,
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        """``client`` is injectable so tests can pass an `httpx.Client`
        wired to an in-process ASGI app (`httpx.ASGITransport`) instead of
        a real one — same interface either way."""
        self._leader_url = leader_url
        self._replica_urls = replica_urls or [leader_url]
        self._client = client or httpx.Client(timeout=timeout)

    def submit(self, submission: SignedSubmission) -> str:
        response = self._client.post(
            f"{self._leader_url}/submit",
            json=SubmissionWire.from_submission(submission).model_dump(),
        )
        response.raise_for_status()
        tx_id: str = response.json()["tx_id"]
        return tx_id

    def wait_final(self, tx_id: str, timeout_s: float = 10.0) -> RecordWire:
        deadline = time.monotonic() + timeout_s
        while True:
            response = self._client.get(f"{self._leader_url}/records/{tx_id}")
            if response.status_code == 200:
                return RecordWire.model_validate(response.json())
            if time.monotonic() >= deadline:
                raise LedgerTimeoutError(f"tx {tx_id!r} not final within {timeout_s}s")
            time.sleep(0.2)

    def get(self, tx_id: str) -> RecordWire:
        response = self._client.get(f"{self._leader_url}/records/{tx_id}")
        response.raise_for_status()
        return RecordWire.model_validate(response.json())

    def query(self, domain: str | None = None) -> list[RecordWire]:
        """Fetch the whole chain, optionally filtered to one signing domain
        (e.g. ``"traceseal/decrypt-request/v1"``) — fine at LedgerLite's
        scale; a real production ledger would index this server-side."""
        response = self._client.get(f"{self._leader_url}/chain")
        response.raise_for_status()
        records = [RecordWire.model_validate(r) for r in response.json()]
        if domain is None:
            return records
        return [r for r in records if _envelope_domain(r) == domain]

    def verify_chain(self) -> ChainReport:
        replica_records: dict[str, list[StoredRecord]] = {}
        for url in self._replica_urls:
            response = self._client.get(f"{url}/chain")
            response.raise_for_status()
            replica_records[url] = [_wire_to_stored_record(r) for r in response.json()]
        return verify_chain(replica_records)


def _envelope_domain(record: RecordWire) -> str:
    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(record.envelope_cbor))
    return envelope.domain


def _wire_to_stored_record(raw: dict[str, object]) -> StoredRecord:
    wire = RecordWire.model_validate(raw)
    return StoredRecord(
        height=wire.height,
        tx_id=wire.tx_id,
        envelope_cbor=bytes.fromhex(wire.envelope_cbor),
        submitter_id=wire.submitter_id,
        submitter_signature=b"",  # not exposed over /chain; unused by hash-chain verification
        quorum_signer_ids=wire.quorum_signer_ids,
        quorum_signatures=[bytes.fromhex(s) for s in wire.quorum_signatures],
        prev_hash=bytes.fromhex(wire.prev_hash),
        record_hash=bytes.fromhex(wire.record_hash),
        created_at=wire.created_at,
    )
