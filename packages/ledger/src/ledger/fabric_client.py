"""Client for the M6 Fabric backend (spec Section 12) — talks to
`packages/fabric-gateway` (a thin REST facade over the real
`hyperledger/fabric-gateway` Go SDK; there is no official Python SDK) over
plain HTTP, returning the EXACT same `ledger.wire.RecordWire`/
`RecordProofWire` types `ledger.client.LedgerClient` already returns, so
this is a genuine drop-in alternative — every consumer that already works
against `LedgerClient` works against this unchanged (see `ledger.backend`).

Unlike LedgerLite, Fabric's own multi-org endorsement policy (spec's
`OutOf(3, ...)` across the 4 peer orgs, docs/DECISIONS.md ADR-0031) already
provides the "quorum" guarantee for the record's initial write — the
`quorum_signer_ids`/`quorum_signatures` fields this client returns come
from the SEPARATE, post-hoc ML-DSA co-signing round (`ledger.cosigner`),
not from anything this client does itself.
"""

from __future__ import annotations

import time

import httpx
from tscore.records import SignedSubmission

from ledger.wire import RecordProofWire, RecordWire


class FabricLedgerTimeoutError(Exception):
    pass


class FabricLedgerClient:
    def __init__(
        self,
        gateway_url: str,
        *,
        timeout: float = 30.0,
        client: httpx.Client | None = None,
    ) -> None:
        self._gateway_url = gateway_url
        self._client = client or httpx.Client(timeout=timeout)

    def submit(self, submission: SignedSubmission) -> str:
        from tscore.schemas import SignedEnvelope

        envelope = SignedEnvelope.from_canonical_cbor(submission.envelope_cbor)
        response = self._client.post(
            f"{self._gateway_url}/submit",
            json={
                "domain": envelope.domain,
                "envelope_cbor": submission.envelope_cbor.hex(),
                "signer_id": submission.signer_id,
                "signature": submission.signature.hex(),
            },
        )
        response.raise_for_status()
        tx_id: str = response.json()["tx_id"]
        return tx_id

    def wait_final(self, tx_id: str, timeout_s: float = 10.0) -> RecordWire:
        # The Go gateway's `/submit` already blocks until the Fabric
        # Gateway SDK reports the transaction committed (its own
        # `SubmitTransaction` is synchronous), so by the time `submit()`
        # returns the record already exists — this polls anyway, for the
        # exact same "commit-before-release" contract
        # `ledger.client.LedgerClient.wait_final` gives every caller,
        # regardless of which backend is behind it.
        deadline = time.monotonic() + timeout_s
        while True:
            response = self._client.get(f"{self._gateway_url}/records/{tx_id}")
            if response.status_code == 200:
                return RecordWire.model_validate(response.json())
            if time.monotonic() >= deadline:
                raise FabricLedgerTimeoutError(f"tx {tx_id!r} not final within {timeout_s}s")
            time.sleep(0.2)

    def get(self, tx_id: str) -> RecordWire:
        response = self._client.get(f"{self._gateway_url}/records/{tx_id}")
        response.raise_for_status()
        return RecordWire.model_validate(response.json())

    def get_proof(self, tx_id: str) -> RecordProofWire:
        response = self._client.get(f"{self._gateway_url}/records/{tx_id}/proof")
        response.raise_for_status()
        return RecordProofWire.model_validate(response.json())

    def query(self, domain: str | None = None) -> list[RecordWire]:
        if domain is None:
            raise ValueError(
                "FabricLedgerClient.query requires a domain filter — "
                "QueryRecordsByDomain is the only chaincode query function "
                "(no unfiltered 'whole chain' query exists under this backend)"
            )
        response = self._client.get(f"{self._gateway_url}/chain", params={"domain": domain})
        response.raise_for_status()
        return [RecordWire.model_validate(r) for r in response.json()]

    def register_identity(self, identity_id: str, sig_alg: str, sig_public_key: bytes) -> None:
        """M6-only (no LedgerLite equivalent): seeds one identity's public
        key into the chaincode's on-chain registry — must be called once
        per identity before that identity can ever submit or co-sign a
        record (`chaincode/traceseal/contract.go`'s `RegisterIdentity`)."""
        response = self._client.post(
            f"{self._gateway_url}/register-identity",
            json={
                "identity_id": identity_id,
                "sig_alg": sig_alg,
                "sig_public_key": sig_public_key.hex(),
            },
        )
        response.raise_for_status()

    def add_cosignature(self, tx_id: str, org_validator_id: str, signature: bytes) -> None:
        """M6-only: appends one validator org's ML-DSA co-signature to an
        already-committed record (`ledger.cosigner`'s job, not called by
        any of the M0-M5 protocol code)."""
        response = self._client.post(
            f"{self._gateway_url}/add-cosignature",
            json={
                "tx_id": tx_id,
                "org_validator_id": org_validator_id,
                "signature": signature.hex(),
            },
        )
        response.raise_for_status()
