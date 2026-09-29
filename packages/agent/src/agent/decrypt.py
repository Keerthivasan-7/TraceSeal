"""One officer's decrypt session (spec Section 7.3): build and sign a
`DecryptRequest`, submit it to one key-release node, unwrap the returned
`KeyGrant`, verify the co-signed `SealedHeader` (spec Section 7.4 — copy
binding / forwarding detection), decrypt and assemble the document **in
memory only**, then sign and submit a `Receipt`.

The agent never learns its own Tardos codeword bits directly — it just
receives, per position, whichever single variant key the key-release
quorum decided to hand it. Since the package holds *both* bit-0 and
bit-1 ciphertexts per position under independent keys, and the agent only
has one of the two keys, the honest way to find the right one is to try
both stored ciphertexts and keep whichever one actually decrypts (a wrong
key fails AES-GCM's tag check, `tscore.aead` raises `TamperError`) — this
is not an oracle, it only ever succeeds on the one ciphertext the key was
actually derived for.

Assembled pages exist only as in-memory `numpy` arrays for the lifetime of
this call — nothing here writes plaintext to disk.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx
import numpy as np
from ca.keys import Identity
from ledger.backend import LedgerBackend
from ledger.wire import SubmissionWire
from sender.manifest import position_pixel_bbox
from sender.package import (
    EncryptedPackage,
    compute_package_hash,
    derive_k_base,
    load_package,
    open_base_page,
    open_variant_patch,
)
from tscore.errors import TamperError, VerificationError
from tscore.hashing import sha3_256
from tscore.kdf import domain_info
from tscore.kem import kem_open
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST,
    DOMAIN_OPEN_DENIED,
    DOMAIN_OPEN_EVENT,
    DOMAIN_RECEIPT,
    KEY_RELEASE_QUORUM_THRESHOLD,
    DecryptRequest,
    KeyGrant,
    OpenDeniedRecord,
    OpenEventRecord,
    ReceiptRecord,
    SealedHeader,
    SignedSubmission,
    make_submission,
)
from tscore.schemas import random_session_id
from tscore.sig import verify as sig_verify

from agent import outbox

PublicKeyLookup = Callable[[str], tuple[str, bytes]]
DEFAULT_TIMEOUT_S = 30.0


class DecryptRequestDeniedError(Exception):
    """The key-release node rejected the `DecryptRequest` (policy, unknown
    document, revoked certificate, or a session_id mismatch on the returned
    grant)."""


class ForwardedCopyError(Exception):
    """Raised when the `SealedHeader`'s `recipient_cert_hash` names a
    different identity than this agent's own — spec 7.4's forwarding-
    detection path. An `OpenDeniedRecord` has already been submitted (or
    durably queued) by the time this is raised."""


@dataclass(frozen=True)
class DecryptResult:
    session_id: str
    pages: list[np.ndarray]
    receipt_tx_id: str


@dataclass(frozen=True)
class KeyGrantResponse:
    """The network round-trip's result — factored out of `open_document` so
    `agent.demo_m4`'s forwarding demo and unit tests can drive it directly
    with a deliberately-wrong `recipient_cert_hash`, exercising the same
    production code path either way."""

    session_id: str
    wrapped_grant: bytes
    sealed_header_cbor: bytes
    header_signer_ids: list[str]
    header_signatures: list[bytes]


def _open_either_bit(
    package: EncryptedPackage, position_index: int, variant_key: bytes
) -> np.ndarray:
    """Try both stored ciphertexts for this position; return whichever one
    `variant_key` actually opens. Raises `TamperError` if neither does,
    which would mean the grant's key doesn't match this package at all."""
    try:
        return open_variant_patch(package, position_index, 0, variant_key)
    except TamperError:
        return open_variant_patch(package, position_index, 1, variant_key)


def build_decrypt_request(
    identity: Identity, doc_id: str, package_hash: bytes, recipient_cert_hash: bytes
) -> tuple[str, SignedSubmission]:
    session_id = random_session_id()
    request = DecryptRequest(
        doc_id=doc_id,
        package_hash=package_hash,
        recipient_cert_hash=recipient_cert_hash,
        session_id=session_id,
        agent_time=time.time(),
    )
    submission = make_submission(
        identity.sig_alg,
        identity.sig_secret_key,
        identity.identity_id,
        DOMAIN_DECRYPT_REQUEST,
        request,
    )
    return session_id, submission


def request_key_grant(
    identity: Identity,
    doc_id: str,
    package_hash: bytes,
    recipient_cert_hash: bytes,
    keyrelease_url: str,
    *,
    http_client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> KeyGrantResponse:
    """The network round-trip half of `open_document`. `recipient_cert_hash`
    is self-declared by the caller (this is exactly the value a malicious
    or careless caller could set wrong — see `agent.demo_m4`'s
    `--claim-cert-of` forwarding demo, which calls this directly)."""
    session_id, submission = build_decrypt_request(
        identity, doc_id, package_hash, recipient_cert_hash
    )
    client = http_client or httpx.Client(timeout=timeout)
    response = client.post(
        f"{keyrelease_url}/decrypt-request",
        json=SubmissionWire.from_submission(submission).model_dump(),
    )
    if response.status_code >= 400:
        raise DecryptRequestDeniedError(
            f"key-release node refused DecryptRequest ({response.status_code}): "
            f"{response.text}"
        )
    body = response.json()
    return KeyGrantResponse(
        session_id=session_id,
        wrapped_grant=bytes.fromhex(body["wrapped_grant"]),
        sealed_header_cbor=bytes.fromhex(body["sealed_header"]),
        header_signer_ids=list(body["header_signer_ids"]),
        header_signatures=[bytes.fromhex(sig) for sig in body["header_signatures"]],
    )


def _submit_or_queue(
    ledger_client: LedgerBackend, submission: SignedSubmission, outbox_path: Path
) -> str | None:
    """Try live submit+wait_final; on any connectivity failure, durably
    queue instead and return None. Only a failure to even durably queue
    (e.g. disk full) is allowed to propagate — spec requires at minimum the
    queued signed event before ever proceeding."""
    try:
        tx_id = ledger_client.submit(submission)
        ledger_client.wait_final(tx_id)
        return tx_id
    except Exception:  # noqa: BLE001 - ledger unreachable/failing; fall back to the outbox
        outbox.append(outbox_path, submission)
        return None


def verify_copy_binding(
    identity: Identity,
    doc_id: str,
    session_id: str,
    sealed_header_cbor: bytes,
    header_signer_ids: list[str],
    header_signatures: list[bytes],
    recipient_cert_hash: bytes,
    lookup_public_key: PublicKeyLookup,
    ledger_client: LedgerBackend,
    outbox_path: Path,
    *,
    threshold: int = KEY_RELEASE_QUORUM_THRESHOLD,
) -> SealedHeader:
    """Independently re-verify the `SealedHeader`'s quorum exactly the way
    `ledger.node.LedgerNode.finalize` re-verifies a quorum — never trust the
    claimed signer list. Only once the quorum itself checks out do we
    compare the header's claimed `recipient_cert_hash` against this agent's
    own. A header that fails the QUORUM check raises `VerificationError`
    (a malformed/under-quorum response — not evidence of forwarding). A
    header that passes quorum but names a different recipient raises
    `ForwardedCopyError` (this IS forwarding — spec Section 7.4)."""
    if len(set(header_signer_ids)) < threshold or len(header_signer_ids) != len(header_signatures):
        raise VerificationError(
            f"SealedHeader quorum has only {len(set(header_signer_ids))} distinct signers, "
            f"need >= {threshold}"
        )
    for signer_id, signature in zip(header_signer_ids, header_signatures, strict=True):
        alg, public_key = lookup_public_key(signer_id)
        if not sig_verify(alg, public_key, sealed_header_cbor, signature):
            raise VerificationError(f"SealedHeader signature from {signer_id!r} does not verify")

    header = SealedHeader.from_canonical_cbor(sealed_header_cbor)
    if header.doc_id != doc_id or header.session_id != session_id:
        raise VerificationError("SealedHeader does not match this session's doc_id/session_id")

    if header.recipient_cert_hash != recipient_cert_hash:
        denied = OpenDeniedRecord(
            doc_id=doc_id, presented_by=recipient_cert_hash, owner=header.recipient_cert_hash
        )
        submission = make_submission(
            identity.sig_alg,
            identity.sig_secret_key,
            identity.identity_id,
            DOMAIN_OPEN_DENIED,
            denied,
        )
        _submit_or_queue(ledger_client, submission, outbox_path)
        raise ForwardedCopyError(
            f"SealedHeader names recipient {header.recipient_cert_hash.hex()}, "
            f"not this identity's own certificate ({recipient_cert_hash.hex()})"
        )

    return header


def open_document(
    identity: Identity,
    doc_id: str,
    package_path: Path,
    wrapped_k_a_path: Path,
    recipient_cert_hash: bytes,
    keyrelease_url: str,
    ledger_client: LedgerBackend,
    lookup_public_key: PublicKeyLookup,
    outbox_path: Path,
    *,
    http_client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> DecryptResult:
    """Run one full decrypt session against `keyrelease_url` and return the
    assembled pages plus the tx_id of this session's finalized Receipt."""
    assert identity.kem_alg is not None and identity.kem_secret_key is not None

    package = load_package(package_path)
    package_hash = compute_package_hash(package_path)

    grant_response = request_key_grant(
        identity,
        doc_id,
        package_hash,
        recipient_cert_hash,
        keyrelease_url,
        http_client=http_client,
        timeout=timeout,
    )

    grant_header = f"traceseal/keygrant/v1/{grant_response.session_id}".encode()
    grant_info = domain_info("keygrant", doc_id.encode(), grant_response.session_id.encode())
    grant_bytes = kem_open(
        identity.kem_secret_key,
        grant_response.wrapped_grant,
        header=grant_header,
        info=grant_info,
        alg=identity.kem_alg,
    )
    grant = KeyGrant.from_canonical_cbor(grant_bytes)
    if grant.session_id != grant_response.session_id:
        raise DecryptRequestDeniedError(
            f"KeyGrant session_id {grant.session_id!r} != requested {grant_response.session_id!r}"
        )

    verify_copy_binding(
        identity,
        doc_id,
        grant_response.session_id,
        grant_response.sealed_header_cbor,
        grant_response.header_signer_ids,
        grant_response.header_signatures,
        recipient_cert_hash,
        lookup_public_key,
        ledger_client,
        outbox_path,
    )
    # Raises ForwardedCopyError above on mismatch, before any decrypt happens.

    open_event = OpenEventRecord(session_id=grant_response.session_id, doc_id=doc_id)
    open_event_submission = make_submission(
        identity.sig_alg,
        identity.sig_secret_key,
        identity.identity_id,
        DOMAIN_OPEN_EVENT,
        open_event,
    )
    _submit_or_queue(ledger_client, open_event_submission, outbox_path)

    k_a_header = f"traceseal/k-a/v1/{doc_id}/{identity.identity_id}".encode()
    k_a_info = domain_info("k-a-wrap", doc_id.encode(), identity.identity_id.encode())
    k_a = kem_open(
        identity.kem_secret_key,
        wrapped_k_a_path.read_bytes(),
        header=k_a_header,
        info=k_a_info,
        alg=identity.kem_alg,
    )

    k_base = derive_k_base(k_a, grant.k_b, doc_id)
    page_arrays = [
        open_base_page(package, page_index, k_base)
        for page_index in range(len(package.base_pages_ciphertext))
    ]

    for idx, position in enumerate(package.manifest.positions):
        variant_key = grant.variant_keys[idx]
        patch = _open_either_bit(package, idx, variant_key)
        x0, y0, x1, y1 = position_pixel_bbox(position, package.manifest.dpi)
        page = page_arrays[position.page_index]
        h, w = page.shape[:2]
        x1c, y1c = min(x1, w), min(y1, h)
        if x0 >= x1c or y0 >= y1c:
            continue
        page[y0:y1c, x0:x1c] = patch[: y1c - y0, : x1c - x0]

    pages_hash = sha3_256(b"".join(page.tobytes() for page in page_arrays))
    receipt = ReceiptRecord(session_id=grant_response.session_id, assembled_pages_hash=pages_hash)
    receipt_submission = make_submission(
        identity.sig_alg, identity.sig_secret_key, identity.identity_id, DOMAIN_RECEIPT, receipt
    )
    receipt_tx_id = ledger_client.submit(receipt_submission)
    ledger_client.wait_final(receipt_tx_id, timeout_s=timeout)

    return DecryptResult(
        session_id=grant_response.session_id, pages=page_arrays, receipt_tx_id=receipt_tx_id
    )
