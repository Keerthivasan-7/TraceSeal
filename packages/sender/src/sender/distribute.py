"""Document registration and distribution (spec Section 7.2).

Three separable steps, each its own function so tests can exercise them
independently: Shamir-splitting `K_B || S_v` across the 5 key-release
nodes and giving every node the (unsplit) Tardos bias vector too
(`register_shares` — see `sender.release_secret` for why the bias vector
isn't part of the split secret), wrapping `K_A` to each recipient, and
submitting `DOC_REGISTER` to the ledger. Keys are the caller's to zeroise
afterward (best-effort — Python can't guarantee memory zeroing; see
`zeroize`).
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx
from ledger.backend import LedgerBackend
from ledger.wire import SubmissionWire
from tscore.kdf import domain_info
from tscore.kem import kem_seal
from tscore.records import (
    DOMAIN_DOC_REGISTER,
    DOMAIN_SHARE_REGISTRATION,
    DocRegisterRecord,
    ShareRegistrationPayload,
    make_submission,
)
from tscore.shamir import split as shamir_split

DEFAULT_SHAMIR_THRESHOLD = 3
DEFAULT_TIMEOUT_S = 10.0


@dataclass(frozen=True)
class KeyReleaseNodeInfo:
    identity_id: str
    url: str
    kem_alg: str
    kem_public_key: bytes


@dataclass(frozen=True)
class RecipientInfo:
    identity_id: str
    cert_hash: bytes
    kem_alg: str
    kem_public_key: bytes


def zeroize(data: bytearray) -> None:
    """Best-effort zeroing. Python strings/bytes are immutable and may
    already have been copied by the interpreter; this cannot *guarantee*
    the key material is gone from memory the way a language with explicit
    memory control could. Callers should hold key material in
    `bytearray`, not `bytes`, if they want this to do anything at all."""
    for i in range(len(data)):
        data[i] = 0


def register_shares(
    doc_id: str,
    secret: bytes,
    bias_vector_bytes: bytes,
    nodes: list[KeyReleaseNodeInfo],
    sender_sig_alg: str,
    sender_secret_key: bytes,
    sender_id: str,
    *,
    threshold: int = DEFAULT_SHAMIR_THRESHOLD,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> None:
    """Shamir-split `secret` (see `sender.release_secret.combine_release_secret`)
    across `nodes`; every node also gets the same plaintext bias vector
    (not secret-shared). Both are registered directly with each node
    (confidential — not a ledger record)."""
    shares = shamir_split(secret, n=len(nodes), k=threshold)
    client = httpx.Client(timeout=timeout)
    for share, node in zip(shares, nodes, strict=True):
        header = f"traceseal/share/v1/{doc_id}/{node.identity_id}".encode()
        share_info = domain_info("share-wrap", doc_id.encode(), node.identity_id.encode())
        wrapped_share = kem_seal(
            node.kem_public_key,
            bytes([share.x]) + share.ys,
            header=header,
            info=share_info,
            alg=node.kem_alg,
        )
        bias_info = domain_info("bias-wrap", doc_id.encode(), node.identity_id.encode())
        wrapped_bias = kem_seal(
            node.kem_public_key,
            bias_vector_bytes,
            header=header,
            info=bias_info,
            alg=node.kem_alg,
        )
        payload = ShareRegistrationPayload(
            doc_id=doc_id,
            node_id=node.identity_id,
            wrapped_share=wrapped_share,
            wrapped_bias_vector=wrapped_bias,
        )
        submission = make_submission(
            sender_sig_alg, sender_secret_key, sender_id, DOMAIN_SHARE_REGISTRATION, payload
        )
        response = client.post(
            f"{node.url}/register-share",
            json=SubmissionWire.from_submission(submission).model_dump(),
        )
        response.raise_for_status()


def wrap_k_a_for_recipients(
    k_a: bytes, doc_id: str, recipients: list[RecipientInfo]
) -> dict[str, bytes]:
    """KEM-wrap `K_A` to every recipient's own ML-KEM public key."""
    wrapped: dict[str, bytes] = {}
    for recipient in recipients:
        header = f"traceseal/k-a/v1/{doc_id}/{recipient.identity_id}".encode()
        info = domain_info("k-a-wrap", doc_id.encode(), recipient.identity_id.encode())
        wrapped[recipient.identity_id] = kem_seal(
            recipient.kem_public_key, k_a, header=header, info=info, alg=recipient.kem_alg
        )
    return wrapped


def register_document(
    ledger_client: LedgerBackend,
    *,
    doc_id: str,
    package_hash: bytes,
    recipient_cert_hashes: list[bytes],
    policy_hash: bytes,
    positions_count: int,
    tardos_n: int,
    tardos_c0: int,
    tardos_eps1: float,
    sender_sig_alg: str,
    sender_secret_key: bytes,
    sender_id: str,
    wait_timeout_s: float = 30.0,
) -> str:
    """Submit `DOC_REGISTER` and wait for ledger finality; returns tx_id."""
    record = DocRegisterRecord(
        doc_id=doc_id,
        package_hash=package_hash,
        recipient_cert_hashes=recipient_cert_hashes,
        policy_hash=policy_hash,
        positions_count=positions_count,
        tardos_n=tardos_n,
        tardos_c0=tardos_c0,
        tardos_eps1=tardos_eps1,
    )
    submission = make_submission(
        sender_sig_alg, sender_secret_key, sender_id, DOMAIN_DOC_REGISTER, record
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=wait_timeout_s)
    return tx_id
