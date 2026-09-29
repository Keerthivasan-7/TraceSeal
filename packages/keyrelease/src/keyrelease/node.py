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
from ledger.backend import LedgerBackend
from ledger.wire import RecordWire
from tscore.errors import VerificationError
from tscore.hashing import sha3_256
from tscore.kdf import domain_info
from tscore.kem import kem_open, kem_seal
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_REVOKE_FINAL,
    KEY_RELEASE_QUORUM_THRESHOLD,
    DecryptRequest,
    DecryptRequestLedgerRecord,
    DocRegisterRecord,
    EnrollFinalRecord,
    KeyGrant,
    KeyGrantIssuedRecord,
    RevokeFinalRecord,
    SealedHeader,
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

from keyrelease.store import KeyReleaseStore, SessionCommitment

PublicKeyLookup = Callable[[str], tuple[str, bytes]]  # identity_id -> (alg, public_key)
QUORUM_THRESHOLD = KEY_RELEASE_QUORUM_THRESHOLD

# Wire framing for a share transferred between nodes: 1 leading byte for
# the Shamir x-coordinate (1..255), the rest is the share's y bytes.
_SHARE_X_LEN = 1


class ShareReleaseDenied(Exception):
    """Raised by `release_share` when finality can't be confirmed, or this
    node simply has no share for the document — never returns partial or
    "trust me" information."""


class RevealNotFound(Exception):
    """Raised by `reveal_bias_vector`/`reveal_commitment` (spec Section
    7.5 step 3's vault reveal, docs/DECISIONS.md ADR-0026) when this node
    simply doesn't have the requested data — never returns partial
    information."""


class PeerReleaseClient(Protocol):
    node_id: str

    def release_share(self, session_id: str, doc_id: str) -> tuple[int, bytes, bytes, bytes]: ...


@dataclass(frozen=True)
class PolicyConfig:
    max_sessions_per_recipient: int = 1000  # generous default; see M3 scoping decisions


@dataclass(frozen=True)
class DecryptGrantResult:
    """Everything `handle_decrypt_request` sends back: the KEM-wrapped
    `KeyGrant`, plus the co-signed `SealedHeader` (spec Section 7.4) the
    recipient-agent independently re-verifies before ever decrypting
    anything (docs/DECISIONS.md ADR-0022)."""

    wrapped_grant: bytes
    sealed_header_cbor: bytes
    header_signer_ids: list[str]
    header_signatures: list[bytes]


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
        ledger_client: LedgerBackend,
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

    # -- forensic vault reveal (M5, spec 7.5 step 3) -------------------

    def reveal_bias_vector(self, doc_id: str) -> bytes:
        """Returns ONLY the plaintext Tardos bias vector for `doc_id` —
        NEVER this node's Shamir `share_x`/`share_ys`, which lives in the
        same store row but must never cross this boundary. Any node that
        registered the doc has an identical broadcast copy (the bias
        vector isn't secret-shared — see `tscore.release_secret`), so
        callers may ask any node, not just the coordinator."""
        share = self.store.get_share(doc_id)
        if share is None:
            raise RevealNotFound(f"no share/bias-vector registered here for doc {doc_id!r}")
        return share.bias_vector

    def reveal_commitment(self, session_id: str, doc_id: str) -> SessionCommitment:
        """Returns this node's own locally stored (codeword, salt,
        commit_hash) for `session_id` — only ever populated on the node
        that coordinated that session's DecryptRequest (see
        `handle_decrypt_request`'s `store.save_commitment` call below).
        Callers resolve which node that was from the ledger's
        DECRYPT_REQUEST_LEDGER record's own `submitter_id` — this node
        makes no claim about being the right one to ask."""
        commitment = self.store.get_commitment(session_id)
        if commitment is None or commitment.doc_id != doc_id:
            raise RevealNotFound(
                f"no commitment for session {session_id!r}/doc {doc_id!r} on this node"
            )
        return commitment

    # -- peer role: the security-critical one -------------------------

    def release_share(self, session_id: str, doc_id: str) -> tuple[int, bytes, bytes, bytes]:
        """Release this node's share ONLY if `session_id`'s
        DECRYPT_REQUEST is genuinely final on the ledger. `/chain` and
        `/records` only ever expose records that finished the ledger's own
        quorum process (`ledger.node.LedgerNode.finalize`) — so finding
        the record here *is* the finality proof; there is no "pending"
        state a caller could point at to short-circuit this.

        Also independently reconstructs and co-signs this session's
        `SealedHeader` from the SAME ledger-verified data just looked up
        for the finality check — not from bytes handed to it by the
        coordinator — mirroring the "every node re-verifies, not just the
        coordinator" discipline (ADR-0014)."""
        found: DecryptRequestLedgerRecord | None = None
        for record in self.ledger_client.query(domain=DOMAIN_DECRYPT_REQUEST_LEDGER):
            decoded = _decode_payload(record, DecryptRequestLedgerRecord)
            if decoded.session_id == session_id and decoded.doc_id == doc_id:
                found = decoded
                break
        if found is None:
            raise ShareReleaseDenied(
                f"no finalized DECRYPT_REQUEST_LEDGER record for session {session_id!r}"
            )

        share = self.store.get_share(doc_id)
        if share is None:
            raise ShareReleaseDenied(f"this node has no share for doc {doc_id!r}")

        doc_register = self._find_doc_register(doc_id)
        if doc_register is None:
            raise ShareReleaseDenied(f"no DOC_REGISTER found for doc {doc_id!r}")

        original = DecryptRequest.from_canonical_cbor(
            SignedEnvelope.from_canonical_cbor(found.recipient_envelope_cbor).payload
        )
        sealed_header = SealedHeader(
            doc_id=doc_id,
            recipient_cert_hash=original.recipient_cert_hash,
            session_id=session_id,
            policy_id=doc_register.policy_hash,
        )
        header_signature = sig_sign(
            self.sig_alg, self.sig_secret_key, sealed_header.to_canonical_cbor()
        )

        attestation = sha3_256(f"{doc_id}|{session_id}|{self.node_id}".encode())
        signature = sig_sign(self.sig_alg, self.sig_secret_key, attestation)
        return share.share_x, share.share_ys, signature, header_signature

    # -- coordinator role ----------------------------------------------

    def handle_decrypt_request(
        self, submission: SignedSubmission, peers: list[PeerReleaseClient]
    ) -> DecryptGrantResult:
        """Returns the KEM-wrapped `KeyGrant` plus a co-signed `SealedHeader`,
        ready to send back to the recipient."""
        recipient_alg, recipient_pub = self.lookup_public_key(submission.signer_id)
        recipient_envelope = open_submission(recipient_alg, recipient_pub, submission)
        request = DecryptRequest.from_canonical_cbor(recipient_envelope.payload)

        current_cert_hash = self._current_cert_hash(submission.signer_id)
        if current_cert_hash is None or current_cert_hash != request.recipient_cert_hash:
            raise VerificationError(
                f"recipient_cert_hash does not match {submission.signer_id!r}'s "
                "current enrolled certificate"
            )

        doc_share = self.store.get_share(request.doc_id)
        if doc_share is None:
            raise VerificationError(f"no share registered here for doc {request.doc_id!r}")

        doc_register = self._find_doc_register(request.doc_id)
        if doc_register is None:
            raise VerificationError(f"no DOC_REGISTER found for doc {request.doc_id!r}")

        self._check_not_revoked(request.recipient_cert_hash)
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

        sealed_header = SealedHeader(
            doc_id=request.doc_id,
            recipient_cert_hash=request.recipient_cert_hash,
            session_id=request.session_id,
            policy_id=doc_register.policy_hash,
        )
        header_sigs = [
            sig_sign(self.sig_alg, self.sig_secret_key, sealed_header.to_canonical_cbor())
        ]

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
                x, ys, signature, header_signature = peer.release_share(
                    request.session_id, request.doc_id
                )
            except Exception as exc:  # noqa: BLE001 - a refusing/unreachable peer just doesn't count
                skipped_peers.append((peer.node_id, str(exc)))
                continue
            shares.append(Share(x=x, ys=ys))
            contributing_ids.append(peer.node_id)
            contributing_sigs.append(signature)
            header_sigs.append(header_signature)

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

        return DecryptGrantResult(
            wrapped_grant=wrapped_grant,
            sealed_header_cbor=sealed_header.to_canonical_cbor(),
            header_signer_ids=contributing_ids,
            header_signatures=header_sigs,
        )

    def _current_cert_hash(self, officer_id: str) -> bytes | None:
        """Most recent ENROLL_FINAL cert_hash for `officer_id`, or None if
        never enrolled. Used to independently verify a DecryptRequest's
        self-declared `recipient_cert_hash` against the signer's REAL
        certificate — closing a single-actor framing gap a purely
        client-side SealedHeader check would leave open: without this,
        any officer could sign a valid request while self-declaring a
        DIFFERENT officer's cert_hash, and this node would service it. Spec
        Section 2's residual-trust assumption requires the sender AND a
        threshold of key-release nodes to collude to frame someone — not
        one signer acting alone (docs/DECISIONS.md)."""
        latest_height = -1
        latest_cert_hash: bytes | None = None
        for record in self.ledger_client.query(domain=DOMAIN_ENROLL_FINAL):
            decoded = _decode_payload(record, EnrollFinalRecord)
            if decoded.officer_id != officer_id:
                continue
            if record.height > latest_height:
                latest_height = record.height
                latest_cert_hash = decoded.cert_hash
        return latest_cert_hash

    def _check_not_revoked(self, recipient_cert_hash: bytes) -> None:
        """Spec Section 7.1: "every service checks certificate status
        against the ledger state" — a direct query, not a local cache
        (docs/DECISIONS.md ADR-0021)."""
        for record in self.ledger_client.query(domain=DOMAIN_REVOKE_FINAL):
            decoded = _decode_payload(record, RevokeFinalRecord)
            if decoded.cert_hash == recipient_cert_hash:
                raise VerificationError(
                    f"recipient certificate revoked: {recipient_cert_hash.hex()}"
                )

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
