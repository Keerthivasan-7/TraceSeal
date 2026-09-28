"""LedgerLite consensus logic (spec Section 12), transport-agnostic.

Kept separate from the FastAPI HTTP layer (``ledger/service.py``) so the
quorum/co-signing/finalize logic is fully unit-testable by wiring several
``LedgerNode`` instances directly together in-process (see
``ledger/tests/test_node.py``) — no Docker, no real HTTP, no FastAPI
``TestClient`` even, needed to prove the consensus rules themselves are
correct.

"No view change" per spec's own hedge: one fixed replica (index 0) always
acts as leader for ``submit_and_finalize``; the others only ever co-sign
and finalize what the leader proposes. This is explicitly labelled
"tamper-evident replicated log, not full BFT" — it does not tolerate a
leader failure the way a real BFT protocol would.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from tscore.errors import VerificationError
from tscore.hashing import sha3_256
from tscore.records import SignedSubmission, open_submission
from tscore.sig import sign as sig_sign
from tscore.sig import verify as sig_verify

from ledger.store import LedgerStore, StoredRecord

QUORUM_THRESHOLD = 3

PublicKeyLookup = Callable[[str], tuple[str, bytes]]  # signer_id -> (alg, public_key)


class PeerClient(Protocol):
    replica_id: str

    def co_sign(self, submission: SignedSubmission) -> bytes: ...

    def finalize(
        self,
        submission: SignedSubmission,
        quorum_signer_ids: list[str],
        quorum_signatures: list[bytes],
    ) -> None: ...


@dataclass(frozen=True)
class SubmitResult:
    record: StoredRecord
    failed_peers: dict[str, str]  # replica_id -> error message, for co-sign or finalize failures


def tx_id_for(envelope_cbor: bytes) -> str:
    return sha3_256(envelope_cbor).hex()


class LedgerNode:
    def __init__(
        self,
        replica_id: str,
        sig_alg: str,
        secret_key: bytes,
        store: LedgerStore,
        lookup_public_key: PublicKeyLookup,
    ) -> None:
        self.replica_id = replica_id
        self.sig_alg = sig_alg
        self.secret_key = secret_key
        self.store = store
        self.lookup_public_key = lookup_public_key

    def _verify_submission(self, submission: SignedSubmission) -> None:
        alg, public_key = self.lookup_public_key(submission.signer_id)
        open_submission(alg, public_key, submission)  # raises VerificationError

    def co_sign(self, submission: SignedSubmission) -> bytes:
        """Verify the submission and return this replica's own signature
        over the envelope bytes — this replica's "vote" that the submitter
        is who they claim and the bytes are well-formed."""
        self._verify_submission(submission)
        return sig_sign(self.sig_alg, self.secret_key, submission.envelope_cbor)

    def finalize(
        self,
        submission: SignedSubmission,
        quorum_signer_ids: list[str],
        quorum_signatures: list[bytes],
    ) -> StoredRecord:
        """Independently re-verify the submitter AND every quorum
        signature (never just trust the leader's word) and, if valid,
        append to this replica's own local log."""
        self._verify_submission(submission)
        if len(quorum_signer_ids) != len(quorum_signatures):
            raise VerificationError("quorum signer_ids/signatures length mismatch")
        if len(set(quorum_signer_ids)) < QUORUM_THRESHOLD:
            raise VerificationError(
                f"quorum has only {len(set(quorum_signer_ids))} distinct signers, "
                f"need >= {QUORUM_THRESHOLD}"
            )
        for signer_id, signature in zip(quorum_signer_ids, quorum_signatures, strict=True):
            alg, public_key = self.lookup_public_key(signer_id)
            if not sig_verify(alg, public_key, submission.envelope_cbor, signature):
                raise VerificationError(f"quorum signature from {signer_id!r} does not verify")

        tx_id = tx_id_for(submission.envelope_cbor)
        existing = self.store.get_by_tx_id(tx_id)
        if existing is not None:
            return existing  # idempotent: already finalized, nothing to do
        return self.store.append(
            tx_id=tx_id,
            envelope_cbor=submission.envelope_cbor,
            submitter_id=submission.signer_id,
            submitter_signature=submission.signature,
            quorum_signer_ids=quorum_signer_ids,
            quorum_signatures=quorum_signatures,
        )

    def submit_and_finalize(
        self, submission: SignedSubmission, peers: list[PeerClient]
    ) -> SubmitResult:
        """LEADER role only: gather co-signatures (this replica's own plus
        peers', stopping once quorum is reached), finalize locally, then
        push the finalized quorum to every peer so all replicas actually
        hold the same log (not just the leader) — this is what makes
        `verify_chain` a real cross-replica check later."""
        self._verify_submission(submission)  # fail fast before bothering any peer

        tx_id = tx_id_for(submission.envelope_cbor)
        existing = self.store.get_by_tx_id(tx_id)
        if existing is not None:
            return SubmitResult(record=existing, failed_peers={})

        signer_ids = [self.replica_id]
        signatures = [sig_sign(self.sig_alg, self.secret_key, submission.envelope_cbor)]
        failed: dict[str, str] = {}
        for peer in peers:
            if len(signer_ids) >= QUORUM_THRESHOLD:
                break
            try:
                signature = peer.co_sign(submission)
            except Exception as exc:  # noqa: BLE001 - a peer may fail for any reason; recorded, not fatal
                failed[peer.replica_id] = str(exc)
                continue
            signer_ids.append(peer.replica_id)
            signatures.append(signature)

        if len(signer_ids) < QUORUM_THRESHOLD:
            raise VerificationError(
                f"only {len(signer_ids)} co-signatures obtained, need >= {QUORUM_THRESHOLD} "
                f"(failed peers: {failed})"
            )

        record = self.finalize(submission, signer_ids, signatures)
        for peer in peers:
            try:
                peer.finalize(submission, signer_ids, signatures)
            except Exception as exc:  # noqa: BLE001 - best-effort replication, recorded not fatal
                failed[peer.replica_id] = str(exc)
        return SubmitResult(record=record, failed_peers=failed)
