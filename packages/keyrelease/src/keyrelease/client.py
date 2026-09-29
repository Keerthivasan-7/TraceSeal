"""External client for forensics to reach the key-release vault-reveal
endpoints (spec 7.5 step 3, docs/DECISIONS.md ADR-0026) — mirrors
`ledger.client.LedgerClient`'s shape. Not used by keyrelease's own
peer-to-peer protocol (that's `HttpPeerReleaseClient` in
`keyrelease.service`); this is purely the forensics-facing reveal surface.
"""

from __future__ import annotations

import httpx

from keyrelease.wire import (
    RevealBiasVectorRequest,
    RevealBiasVectorResponse,
    RevealCommitmentRequest,
    RevealCommitmentResponse,
)


class KeyReleaseClient:
    def __init__(
        self,
        node_urls: dict[str, str],
        *,
        timeout: float = 10.0,
        client: httpx.Client | None = None,
    ) -> None:
        """``node_urls`` maps node_id -> base_url for every known
        key-release node. ``client`` is injectable so tests can pass an
        `httpx.Client` wired to in-process ASGI apps instead of a real
        one."""
        self._node_urls = node_urls
        self._client = client or httpx.Client(timeout=timeout)

    def reveal_bias_vector(self, doc_id: str) -> bytes:
        """Tries every known node in turn — any one that registered this
        doc has an identical broadcast copy of the bias vector (it isn't
        secret-shared, see `tscore.release_secret`)."""
        errors: dict[str, str] = {}
        for node_id, base_url in self._node_urls.items():
            response = self._client.post(
                f"{base_url}/reveal-bias-vector",
                json=RevealBiasVectorRequest(doc_id=doc_id).model_dump(),
            )
            if response.status_code == 404:
                errors[node_id] = response.json().get("detail", "not found")
                continue
            response.raise_for_status()
            body = RevealBiasVectorResponse.model_validate(response.json())
            return bytes.fromhex(body.bias_vector)
        raise RuntimeError(f"no key-release node has a bias vector for doc {doc_id!r}: {errors}")

    def reveal_commitment(
        self, coordinator_node_id: str, session_id: str, doc_id: str
    ) -> tuple[bytes, bytes, bytes]:
        """MUST target the specific coordinating node — callers resolve
        that from the ledger's `DECRYPT_REQUEST_LEDGER` record's own
        `submitter_id` (see `forensics.investigation`). Returns
        `(codeword_bytes, salt, commit_hash)`."""
        base_url = self._node_urls[coordinator_node_id]
        response = self._client.post(
            f"{base_url}/reveal-commitment",
            json=RevealCommitmentRequest(session_id=session_id, doc_id=doc_id).model_dump(),
        )
        response.raise_for_status()
        body = RevealCommitmentResponse.model_validate(response.json())
        return (
            bytes.fromhex(body.codeword),
            bytes.fromhex(body.salt),
            bytes.fromhex(body.commit_hash),
        )
