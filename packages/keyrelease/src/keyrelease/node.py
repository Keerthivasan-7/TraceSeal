"""Key-release node consensus logic (spec Section 7.3), transport-agnostic
— kept separate from the FastAPI HTTP layer (`keyrelease/service.py`) the
same way `ledger.node` is, so it's unit-testable by wiring several
`KeyReleaseNode` instances directly together in-process.

Every node is symmetric: whichever one a recipient happens to submit a
`DecryptRequest` to acts as **coordinator** for that session
(`handle_decrypt_request`); every node (including the coordinator, for its
own share) can also act as a **peer** being asked to release its share
(`release_share`) — and that's the one method that independently re-checks
ledger finality before ever handing anything back, regardless of who's
asking (spec's "grant-before-finality is impossible").
"""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

import numpy as np
from ledger.client import LedgerClient
from ledger.wire import RecordWire
from tscore.errors import VerificationError
from tscore.hashing import sha3_256
from tscore.kdf import domain_info
from tscore.kem import kem_open, kem_seal
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_KEYGRANT_ISSUED,
    DecryptRequest,
    DecryptRequestLedgerRecord,
    DocRegisterRecord,
    KeyGrant,
    KeyGrantIssuedRecord,
    ShareRegistrationPayload,
    SignedSubmission,
    make_submission,
    open_submission,
)
from tscore.release_secret import bias_vector_from_bytes, derive_variant_key, split_release_secret
from tscore.schemas import SignedEnvelope
from tscore.shamir import Share
from tscore.shamir import reconstruct as shamir_reconstruct
from tscore.sig import sign as sig_sign
from tscore.tardos import assign_codeword

from keyrelease.store import KeyReleaseStore

PublicKeyLookup = Callable[[str], tuple[str, bytes]]  # identity_id -> (alg, public_key)
QUORUM_THRESHOLD = 3

# Wire framing for a share transferred between nodes: 1 leading byte for
# the Shamir x-coordinate (1..255), the rest is the share's y bytes.
_SHARE_X_LEN = 1


class ShareReleaseDenied(Exception):
    """Raised by `release_share` when finality can't be confirmed, or this
    node simply has no share for the document — never returns partial or
    "trust me" information."""


class PeerReleaseClient(Protocol):
    node_id: str

    def release_share(self, session_id: str, doc_id: str) -> tuple[int, bytes, bytes]: ...


@dataclass(frozen=True)
class PolicyConfig:
    max_sessions_per_recipient: int = 1000  # generous default; see M3 scoping decisions


def _decode_payload[T](record: RecordWire, model: type[T]) -> T:
    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(record.envelope_cbor))
    result: T = model.from_canonical_cbor(envelope.payload)  # type: ignore[attr-defined]
    return result


class KeyReleaseNode:
    def __init__(
        self,
        node_id: str,
        sig_alg: str,
        sig_secret_key: bytes,
        kem_alg: str,
        kem_secret_key: bytes,
        store: KeyReleaseStore,
        lookup_public_key: PublicKeyLookup,
        lookup_kem_public_key: PublicKeyLookup,
        ledger_client: LedgerClient,
        policy: PolicyConfig | None = None,
    ) -> None:
        self.node_id = node_id
        self.sig_alg = sig_alg
        self.sig_secret_key = sig_secret_key
        self.kem_alg = kem_alg
        self.kem_secret_key = kem_secret_key
        self.store = store
        self.lookup_public_key = lookup_public_key
        self.lookup_kem_public_key = lookup_kem_public_key
        self.ledger_client = ledger_client
        self.policy = policy or PolicyConfig()

    # -- registration ------------------------------------------------

    def register_share(self, submission: SignedSubmission) -> None:
        alg, public_key = self.lookup_public_key(submission.signer_id)
        envelope = open_submission(alg, public_key, submission)
        payload = ShareRegistrationPayload.from_canonical_cbor(envelope.payload)
        if payload.node_id != self.node_id:
            raise VerificationError(
                f"share registered for {payload.node_id!r}, not this node ({self.node_id!r})"
            )
        header = f"traceseal/share/v1/{payload.doc_id}/{self.node_id}".encode()

        share_info = domain_info("share-wrap", payload.doc_id.encode(), self.node_id.encode())
        raw_share = kem_open(
            self.kem_secret_key,
            payload.wrapped_share,
            header=header,
            info=share_info,
            alg=self.kem_alg,
        )
        share_x, share_ys = raw_share[0], raw_share[_SHARE_X_LEN:]

        bias_info = domain_info("bias-wrap", payload.doc_id.encode(), self.node_id.encode())
        bias_bytes = kem_open(
            self.kem_secret_key,
            payload.wrapped_bias_vector,
            header=header,
            info=bias_info,
            alg=self.kem_alg,
        )
        self.store.save_share(payload.doc_id, share_x, share_ys, bias_bytes)

    # -- peer role: the security-critical one -------------------------

    def release_share(self, session_id: str, doc_id: str) -> tuple[int, bytes, bytes]:
        """Release this node's share ONLY if `session_id`'s
        DECRYPT_REQUEST is genuinely final on the ledger. `/chain` and
        `/records` only ever expose records that finished the ledger's own
        quorum process (`ledger.node.LedgerNode.finalize`) — so finding
        the record here *is* the finality proof; there is no "pending"
        state a caller could point at to short-circuit this."""
        records = self.ledger_client.query(domain=DOMAIN_DECRYPT_REQUEST_LEDGER)
        found = False
        for record in records:
            decoded = _decode_payload(record, DecryptRequestLedgerRecord)
            if decoded.session_id == session_id and decoded.doc_id == doc_id:
                found = True
                break
        if not found:
            raise ShareReleaseDenied(
                f"no finalized DECRYPT_REQUEST_LEDGER record for session {session_id!r}"
            )

        share = self.store.get_share(doc_id)
        if share is None:
            raise ShareReleaseDenied(f"this node has no share for doc {doc_id!r}")

        attestation = sha3_256(f"{doc_id}|{session_id}|{self.node_id}".encode())
        signature = sig_sign(self.sig_alg, self.sig_secret_key, attestation)
        return share.share_x, share.share_ys, signature

    # -- coordinator role ----------------------------------------------

    def handle_decrypt_request(
        self, submission: SignedSubmission, peers: list[PeerReleaseClient]
    ) -> bytes:
        """Returns the KEM-wrapped `KeyGrant` bytes, ready to send back to
        the recipient."""
        recipient_alg, recipient_pub = self.lookup_public_key(submission.signer_id)
        recipient_envelope = open_submission(recipient_alg, recipient_pub, submission)
        request = DecryptRequest.from_canonical_cbor(recipient_envelope.payload)

        doc_share = self.store.get_share(request.doc_id)
        if doc_share is None:
            raise VerificationError(f"no share registered here for doc {request.doc_id!r}")

        doc_register = self._find_doc_register(request.doc_id)
        if doc_register is None:
            raise VerificationError(f"no DOC_REGISTER found for doc {request.doc_id!r}")

        self._enforce_policy(request)

        bias_vector = bias_vector_from_bytes(doc_share.bias_vector, doc_register.positions_count)
        rng = np.random.default_rng()
        codeword = assign_codeword(bias_vector, rng)
        codeword_bytes = codeword.astype(np.int8).tobytes()
        salt = secrets.token_bytes(16)
        commit_hash = sha3_256(
            request.doc_id.encode() + request.session_id.encode() + codeword_bytes + salt
        )
        self.store.save_commitment(
            request.session_id, request.doc_id, codeword_bytes, salt, commit_hash
        )

        ledger_record = DecryptRequestLedgerRecord(
            doc_id=request.doc_id,
            session_id=request.session_id,
            recipient_envelope_cbor=submission.envelope_cbor,
            recipient_signer_id=submission.signer_id,
            recipient_signature=submission.signature,
            codeword_commitment=commit_hash,
        )
        ledger_submission = make_submission(
            self.sig_alg,
            self.sig_secret_key,
            self.node_id,
            DOMAIN_DECRYPT_REQUEST_LEDGER,
            ledger_record,
        )
        tx_id = self.ledger_client.submit(ledger_submission)
        self.ledger_client.wait_final(tx_id, timeout_s=30.0)  # commit-before-release

        contributing_ids = [self.node_id]
        contributing_sigs = [
            sig_sign(
                self.sig_alg,
                self.sig_secret_key,
                sha3_256(f"{request.doc_id}|{request.session_id}|{self.node_id}".encode()),
            )
        ]
        shares: list[Share] = [Share(x=doc_share.share_x, ys=doc_share.share_ys)]
        skipped_peers: list[tuple[str, str]] = []
        for peer in peers:
            if len(shares) >= QUORUM_THRESHOLD:
                break
            try:
                x, ys, signature = peer.release_share(request.session_id, request.doc_id)
            except Exception as exc:  # noqa: BLE001 - a refusing/unreachable peer just doesn't count
                skipped_peers.append((peer.node_id, str(exc)))
                continue
            shares.append(Share(x=x, ys=ys))
            contributing_ids.append(peer.node_id)
            contributing_sigs.append(signature)

        if len(shares) < QUORUM_THRESHOLD:
            raise VerificationError(
                f"only {len(shares)} shares obtained, need >= {QUORUM_THRESHOLD} "
                f"(skipped peers: {skipped_peers})"
            )

        combined_secret = shamir_reconstruct(shares)
        k_b, s_v = split_release_secret(combined_secret)
        variant_keys = [
            derive_variant_key(s_v, request.doc_id, i, int(codeword[i]))
            for i in range(doc_register.positions_count)
        ]

        grant = KeyGrant(session_id=request.session_id, k_b=k_b, variant_keys=variant_keys)
        recipient_kem_alg, recipient_kem_pub = self.lookup_kem_public_key(submission.signer_id)
        header = f"traceseal/keygrant/v1/{request.session_id}".encode()
        info = domain_info("keygrant", request.doc_id.encode(), request.session_id.encode())
        wrapped_grant = kem_seal(
            recipient_kem_pub,
            grant.to_canonical_cbor(),
            header=header,
            info=info,
            alg=recipient_kem_alg,
        )

        issued_record = KeyGrantIssuedRecord(
            session_id=request.session_id,
            grant_ciphertext_hash=sha3_256(wrapped_grant),
            contributing_node_ids=contributing_ids,
            contributing_signatures=contributing_sigs,
        )
        issued_submission = make_submission(
            self.sig_alg, self.sig_secret_key, self.node_id, DOMAIN_KEYGRANT_ISSUED, issued_record
        )
        issued_tx = self.ledger_client.submit(issued_submission)
        self.ledger_client.wait_final(issued_tx, timeout_s=30.0)

        # Best-effort zeroisation — see sender.distribute.zeroize's docstring
        # for why this can't be a guarantee in Python.
        del combined_secret, k_b, s_v, variant_keys

        return wrapped_grant

    def _find_doc_register(self, doc_id: str) -> DocRegisterRecord | None:
        for record in self.ledger_client.query(domain=DOMAIN_DOC_REGISTER):
            decoded = _decode_payload(record, DocRegisterRecord)
            if decoded.doc_id == doc_id:
                return decoded
        return None

    def _enforce_policy(self, request: DecryptRequest) -> None:
        count = 0
        for record in self.ledger_client.query(domain=DOMAIN_DECRYPT_REQUEST_LEDGER):
            decoded = _decode_payload(record, DecryptRequestLedgerRecord)
            if decoded.doc_id != request.doc_id:
                continue
            # The recipient's own original request is embedded verbatim;
            # decode it to compare cert hashes without trusting anything
            # the coordinator itself added.
            original = DecryptRequest.from_canonical_cbor(
                SignedEnvelope.from_canonical_cbor(decoded.recipient_envelope_cbor).payload
            )
            if original.recipient_cert_hash == request.recipient_cert_hash:
                count += 1
        if count >= self.policy.max_sessions_per_recipient:
            raise VerificationError(
                f"policy: recipient already has {count} sessions for this document "
                f"(max {self.policy.max_sessions_per_recipient})"
            )
