"""FastAPI HTTP layer for one key-release node (spec Section 7.3).

Thin wrapper around `keyrelease.node.KeyReleaseNode` — all the actual
protocol logic lives there and is unit-tested without any of this.
`create_app` is a factory (like `ledger.service.create_app`) so tests can
instantiate several nodes in-process, wired together via
`HttpPeerReleaseClient`s backed by FastAPI `TestClient`s instead of real
HTTP.
"""

from __future__ import annotations

from pathlib import Path

import httpx
from ca.keys import load_identity
from ca.registry import kem_public_key, load_registry, sig_public_key
from fastapi import FastAPI, HTTPException
from ledger.client import LedgerClient
from ledger.wire import SubmissionWire
from tscore.errors import VerificationError

from keyrelease.node import KeyReleaseNode, PeerReleaseClient, PolicyConfig, ShareReleaseDenied
from keyrelease.store import KeyReleaseStore
from keyrelease.wire import DecryptResponse, ReleaseShareRequest, ReleaseShareResponse

DEFAULT_PEER_TIMEOUT_S = 10.0


class HttpPeerReleaseClient:
    """`PeerReleaseClient` implementation used by a coordinator to call
    its peer nodes over the internal network (or, in tests, an injected
    `httpx.Client`/`TestClient` — see `ledger.service.HttpPeerClient`'s
    docstring for why both satisfy the same interface)."""

    def __init__(
        self,
        node_id: str,
        base_url: str,
        *,
        client: httpx.Client | None = None,
        timeout: float = DEFAULT_PEER_TIMEOUT_S,
    ) -> None:
        self.node_id = node_id
        self._base_url = base_url
        self._client = client or httpx.Client(timeout=timeout)

    def release_share(self, session_id: str, doc_id: str) -> tuple[int, bytes, bytes, bytes]:
        request = ReleaseShareRequest(session_id=session_id, doc_id=doc_id)
        response = self._client.post(f"{self._base_url}/release-share", json=request.model_dump())
        response.raise_for_status()
        body = ReleaseShareResponse.model_validate(response.json())
        return (
            body.share_x,
            bytes.fromhex(body.share_ys),
            bytes.fromhex(body.signature),
            bytes.fromhex(body.header_signature),
        )


def create_app(
    *,
    node_index: int,
    pki_dir: Path,
    db_path: str,
    ledger_leader_url: str = "http://ledger-0:8000",
    node_count: int = 5,
    peer_url_template: str = "http://keyrelease-{i}:8000",
    peers: list[PeerReleaseClient] | None = None,
    ledger_client: LedgerClient | None = None,
    policy: PolicyConfig | None = None,
) -> FastAPI:
    node_id = f"keyrelease-{node_index}"
    identity = load_identity(pki_dir / f"{node_id}.json")
    assert identity.kem_alg is not None and identity.kem_secret_key is not None

    def lookup_sig(signer_id: str) -> tuple[str, bytes]:
        registry = load_registry(pki_dir / "registry.json")
        return sig_public_key(registry, signer_id)

    def lookup_kem(signer_id: str) -> tuple[str, bytes]:
        registry = load_registry(pki_dir / "registry.json")
        return kem_public_key(registry, signer_id)

    store = KeyReleaseStore(db_path)
    ledger = ledger_client or LedgerClient(ledger_leader_url)
    node = KeyReleaseNode(
        node_id,
        identity.sig_alg,
        identity.sig_secret_key,
        identity.kem_alg,
        identity.kem_secret_key,
        store,
        lookup_sig,
        lookup_kem,
        ledger,
        policy,
    )

    def default_peers() -> list[PeerReleaseClient]:
        return [
            HttpPeerReleaseClient(f"keyrelease-{i}", peer_url_template.format(i=i))
            for i in range(node_count)
            if i != node_index
        ]

    app = FastAPI(title=f"TraceSeal key-release — {node_id}")
    app.state.node = node

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"node_id": node_id}

    @app.post("/register-share")
    def register_share(body: SubmissionWire) -> dict[str, str]:
        try:
            node.register_share(body.to_submission())
        except VerificationError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "ok"}

    @app.post("/release-share", response_model=ReleaseShareResponse)
    def release_share(body: ReleaseShareRequest) -> ReleaseShareResponse:
        try:
            share_x, share_ys, signature, header_signature = node.release_share(
                body.session_id, body.doc_id
            )
        except ShareReleaseDenied as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc
        return ReleaseShareResponse(
            node_id=node_id,
            share_x=share_x,
            share_ys=share_ys.hex(),
            signature=signature.hex(),
            header_signature=header_signature.hex(),
        )

    @app.post("/decrypt-request", response_model=DecryptResponse)
    def decrypt_request(body: SubmissionWire) -> DecryptResponse:
        try:
            active_peers = peers or default_peers()
            result = node.handle_decrypt_request(body.to_submission(), active_peers)
        except (VerificationError, ShareReleaseDenied) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return DecryptResponse(
            wrapped_grant=result.wrapped_grant.hex(),
            sealed_header=result.sealed_header_cbor.hex(),
            header_signer_ids=result.header_signer_ids,
            header_signatures=[sig.hex() for sig in result.header_signatures],
        )

    return app
