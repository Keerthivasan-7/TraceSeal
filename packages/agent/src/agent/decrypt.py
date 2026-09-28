"""One officer's decrypt session (spec Section 7.3): build and sign a
`DecryptRequest`, submit it to one key-release node, unwrap the returned
`KeyGrant`, decrypt and assemble the document **in memory only**, then sign
and submit a `Receipt`.

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
from dataclasses import dataclass
from pathlib import Path

import httpx
import numpy as np
from ca.keys import Identity
from ledger.client import LedgerClient
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
from tscore.errors import TamperError
from tscore.hashing import sha3_256
from tscore.kdf import domain_info
from tscore.kem import kem_open
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST,
    DOMAIN_RECEIPT,
    DecryptRequest,
    KeyGrant,
    ReceiptRecord,
    SignedSubmission,
    make_submission,
)
from tscore.schemas import random_session_id

DEFAULT_TIMEOUT_S = 30.0


class DecryptRequestDeniedError(Exception):
    """The key-release node rejected the `DecryptRequest` (policy, unknown
    document, or a session_id mismatch on the returned grant)."""


@dataclass(frozen=True)
class DecryptResult:
    session_id: str
    pages: list[np.ndarray]
    receipt_tx_id: str


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


def open_document(
    identity: Identity,
    doc_id: str,
    package_path: Path,
    wrapped_k_a_path: Path,
    recipient_cert_hash: bytes,
    keyrelease_url: str,
    ledger_client: LedgerClient,
    *,
    http_client: httpx.Client | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> DecryptResult:
    """Run one full decrypt session against `keyrelease_url` and return the
    assembled pages plus the tx_id of this session's finalized Receipt."""
    assert identity.kem_alg is not None and identity.kem_secret_key is not None

    package = load_package(package_path)
    package_hash = compute_package_hash(package_path)
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
    wrapped_grant = bytes.fromhex(response.json()["wrapped_grant"])

    grant_header = f"traceseal/keygrant/v1/{session_id}".encode()
    grant_info = domain_info("keygrant", doc_id.encode(), session_id.encode())
    grant_bytes = kem_open(
        identity.kem_secret_key,
        wrapped_grant,
        header=grant_header,
        info=grant_info,
        alg=identity.kem_alg,
    )
    grant = KeyGrant.from_canonical_cbor(grant_bytes)
    if grant.session_id != session_id:
        raise DecryptRequestDeniedError(
            f"KeyGrant session_id {grant.session_id!r} != requested {session_id!r}"
        )

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
    receipt = ReceiptRecord(session_id=session_id, assembled_pages_hash=pages_hash)
    receipt_submission = make_submission(
        identity.sig_alg, identity.sig_secret_key, identity.identity_id, DOMAIN_RECEIPT, receipt
    )
    receipt_tx_id = ledger_client.submit(receipt_submission)
    ledger_client.wait_final(receipt_tx_id, timeout_s=timeout)

    return DecryptResult(session_id=session_id, pages=page_arrays, receipt_tx_id=receipt_tx_id)
