"""FastAPI HTTP layer for one LedgerLite replica (spec Section 12).

Thin wrapper around `ledger.node.LedgerNode` — all the actual consensus
rules live there and are unit-tested without any of this. This module
only: exposes `/co-sign`, `/finalize`, `/submit` (leader only), `/chain`,
`/records` over HTTP, and implements `HttpPeerClient` so the leader can
call its peers for real.

`create_app` is a factory (not module-level globals) specifically so it
can be instantiated multiple times with different config in-process for
tests (e.g. wiring 4 FastAPI `TestClient`s together to test the real HTTP
layer, not just `LedgerNode` directly) without needing 4 real containers.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from ca.keys import load_identity
from ca.registry import load_registry, sig_public_key
from fastapi import FastAPI, HTTPException
from tscore.errors import VerificationError
from tscore.records import SignedSubmission

from ledger.node import LedgerNode, PeerClient
from ledger.store import LedgerStore
from ledger.wire import CoSignResponse, FinalizeRequest, RecordProofWire, RecordWire, SubmissionWire

DEFAULT_PEER_TIMEOUT_S = 10.0


class HttpPeerClient:
    """`PeerClient` implementation used by the leader to call real peer
    replicas over the internal network.

    ``client`` is injectable so tests can pass a FastAPI `TestClient`
    (ASGI-transport, no real network) wired to another in-process
    `create_app` instance instead of a real `httpx.Client` — both satisfy
    the same `.post(url, json=...)` / `.raise_for_status()` / `.json()`
    interface, so the exact same peer-calling code path is exercised
    either way.
    """

    def __init__(
        self,
        replica_id: str,
        base_url: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = DEFAULT_PEER_TIMEOUT_S,
    ) -> None:
        self.replica_id = replica_id
        self._base_url = base_url
        self._client = client or httpx.Client(timeout=timeout)

    def co_sign(self, submission: SignedSubmission) -> bytes:
        wire = SubmissionWire.from_submission(submission)
        response = self._client.post(f"{self._base_url}/co-sign", json=wire.model_dump())
        response.raise_for_status()
        return bytes.fromhex(CoSignResponse.model_validate(response.json()).signature)

    def finalize(
        self,
        submission: SignedSubmission,
        quorum_signer_ids: list[str],
        quorum_signatures: list[bytes],
    ) -> None:
        body = FinalizeRequest(
            submission=SubmissionWire.from_submission(submission),
            quorum_signer_ids=quorum_signer_ids,
            quorum_signatures=[sig.hex() for sig in quorum_signatures],
        )
        response = self._client.post(f"{self._base_url}/finalize", json=body.model_dump())
        response.raise_for_status()


def _record_to_wire(record: object) -> RecordWire:
    from ledger.store import StoredRecord

    assert isinstance(record, StoredRecord)
    return RecordWire(
        height=record.height,
        tx_id=record.tx_id,
        envelope_cbor=record.envelope_cbor.hex(),
        submitter_id=record.submitter_id,
        quorum_signer_ids=record.quorum_signer_ids,
        quorum_signatures=[sig.hex() for sig in record.quorum_signatures],
        prev_hash=record.prev_hash.hex(),
        record_hash=record.record_hash.hex(),
        created_at=record.created_at,
    )


def _record_to_proof_wire(record: object) -> RecordProofWire:
    """Unlike `_record_to_wire`, does NOT redact `submitter_signature` —
    served only from `/records/{tx_id}/proof`, for the distinct use case
    of building/verifying an evidence bundle (ADR-0028)."""
    from ledger.store import StoredRecord

    assert isinstance(record, StoredRecord)
    return RecordProofWire(
        height=record.height,
        tx_id=record.tx_id,
        envelope_cbor=record.envelope_cbor.hex(),
        submitter_id=record.submitter_id,
        submitter_signature=record.submitter_signature.hex(),
        quorum_signer_ids=record.quorum_signer_ids,
        quorum_signatures=[sig.hex() for sig in record.quorum_signatures],
        prev_hash=record.prev_hash.hex(),
        record_hash=record.record_hash.hex(),
        created_at=record.created_at,
    )


def create_app(
    *,
    replica_index: int,
    pki_dir: Path,
    db_path: str,
    vault_dir: Path | None = None,
    replica_count: int = 4,
    peer_url_template: str = "http://ledger-{i}:8000",
    peers: list[PeerClient] | None = None,
) -> FastAPI:
    """Build one replica's FastAPI app.

    ``peers`` lets tests inject non-HTTP peer clients (e.g. wrapping other
    in-process `create_app` instances' `LedgerNode`s directly); real
    deployment omits it and gets real `HttpPeerClient`s.
    """
    replica_id = f"ledger-{replica_index}"
    is_leader = replica_index == 0
    # `vault_dir` holds this replica's own private identity; `pki_dir` stays the
    # shared public registry. Unset = the original single-directory layout.
    identity = load_identity((vault_dir or pki_dir) / f"{replica_id}.json")

    def lookup_public_key(signer_id: str) -> tuple[str, bytes]:
        registry = load_registry(pki_dir / "registry.json")
        return sig_public_key(registry, signer_id)

    store = LedgerStore(db_path)
    node = LedgerNode(
        replica_id, identity.sig_alg, identity.sig_secret_key, store, lookup_public_key
    )

    def default_peers() -> list[PeerClient]:
        return [
            HttpPeerClient(f"ledger-{i}", peer_url_template.format(i=i))
            for i in range(replica_count)
            if i != replica_index
        ]

    app = FastAPI(title=f"TraceSeal LedgerLite — {replica_id}")
    app.state.node = node  # exposed for tests; route handlers use the closure above directly

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"replica_id": replica_id, "role": "leader" if is_leader else "follower"}

    @app.post("/co-sign", response_model=CoSignResponse)
    def co_sign(body: SubmissionWire) -> CoSignResponse:
        try:
            signature = node.co_sign(body.to_submission())
        except VerificationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return CoSignResponse(replica_id=replica_id, signature=signature.hex())

    @app.post("/finalize")
    def finalize(body: FinalizeRequest) -> dict[str, object]:
        try:
            record = node.finalize(
                body.submission.to_submission(),
                body.quorum_signer_ids,
                [bytes.fromhex(s) for s in body.quorum_signatures],
            )
        except VerificationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"tx_id": record.tx_id, "height": record.height}

    @app.post("/submit")
    def submit(body: SubmissionWire) -> dict[str, object]:
        if not is_leader:
            raise HTTPException(status_code=400, detail="not the leader; submit to ledger-0")
        try:
            result = node.submit_and_finalize(body.to_submission(), peers or default_peers())
        except VerificationError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "tx_id": result.record.tx_id,
            "height": result.record.height,
            "quorum_signer_ids": result.record.quorum_signer_ids,
            "failed_peers": result.failed_peers,
        }

    @app.get("/records/{tx_id}")
    def get_record(tx_id: str) -> RecordWire:
        record = store.get_by_tx_id(tx_id)
        if record is None:
            raise HTTPException(status_code=404, detail="unknown tx_id")
        return _record_to_wire(record)

    @app.get("/records/{tx_id}/proof")
    def get_record_proof(tx_id: str) -> RecordProofWire:
        record = store.get_by_tx_id(tx_id)
        if record is None:
            raise HTTPException(status_code=404, detail="unknown tx_id")
        return _record_to_proof_wire(record)

    @app.get("/chain")
    def get_chain() -> list[RecordWire]:
        return [_record_to_wire(r) for r in store.all_records()]

    return app
