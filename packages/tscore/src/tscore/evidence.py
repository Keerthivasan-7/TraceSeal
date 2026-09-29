"""Evidence-bundle schema and independent re-verification (spec Section
7.5 step 5, G4): the single source of truth `packages/forensics` (which
builds a bundle) and `packages/verifier` (which independently re-checks
one, depending on nothing but this package) both call — so the two can
never drift apart on what "VALID" means.

Every check here is genuinely re-derived from the bundle's own embedded
data plus its own embedded `trust_roots` — no network call, no live
registry, no trust in whatever produced the bundle beyond its outer
signature (docs/DECISIONS.md ADR-0026 through ADR-0030).

Honesty note (ADR-0027): `verify_record_proof` proves one ledger record's
own internal consistency (its `record_hash` recomputes correctly) and
genuine quorum sign-off (every quorum signature independently verifies,
at threshold) — LedgerLite (ADR-0012) has no Merkle/checkpoint structure,
so this does NOT prove the record wasn't omitted from some longer chain
never independently walked end-to-end. That limitation must always be
surfaced to a human reader (see `forensics.report_pdf`'s mandatory
limitations section), never hidden.
"""

from __future__ import annotations

import math

import numpy as np
from pydantic import BaseModel

from tscore.cbor import CanonicalCBORModel
from tscore.chain import compute_record_hash
from tscore.errors import VerificationError
from tscore.hashing import sha3_256
from tscore.records import (
    KEY_RELEASE_QUORUM_THRESHOLD,
    LEDGER_QUORUM_THRESHOLD,
    DecryptRequest,
    DecryptRequestLedgerRecord,
    DocRegisterRecord,
    EnrollFinalRecord,
    InvestigationOpenedRecord,
    KeyGrantIssuedRecord,
    ReceiptRecord,
    SignedSubmission,
    open_submission,
)
from tscore.schemas import SignedEnvelope
from tscore.sig import verify as sig_verify
from tscore.tardos import accuse
from tscore.tardos import threshold as tardos_threshold


class LedgerRecordProof(BaseModel):
    """The tscore-native, `ledger`-package-independent equivalent of
    `ledger.wire.RecordProofWire` — everything needed to independently
    re-derive `record_hash`, re-verify the submitter's own signature, and
    re-verify every quorum co-signature without ever importing anything
    from `packages/ledger` (that import would break `packages/verifier`'s
    "depends only on tscore" constraint, G4)."""

    tx_id: str
    height: int
    envelope_cbor: bytes
    submitter_id: str
    submitter_signature: bytes
    quorum_signer_ids: list[str]
    quorum_signatures: list[bytes]
    prev_hash: bytes
    record_hash: bytes


class PublicKeyEntry(BaseModel):
    """One identity's public key material, as embedded in an
    `EvidenceBundle` (a converted subset of `demo/pki/registry.json`).
    This IS the verifier's entire trust anchor — `traceseal-verify` never
    fetches a registry itself; see the mandatory limitations section this
    fact requires in the human-readable report."""

    identity_id: str
    # informational only ("forensics" | "officer" | "keyrelease" | "ledger" |
    # "ca"); never used for a security decision
    role: str
    sig_alg: str
    sig_public_key: bytes
    kem_alg: str | None = None
    kem_public_key: bytes | None = None


class SuspectSessionEvidence(BaseModel):
    """One candidate session's full evidence, whether or not it was
    accused — `tscore.tardos.accuse` needs every candidate's codeword
    simultaneously to score any one of them, so a bundle always carries
    every session ever issued for the document, not a pre-filtered list
    (this also gives a full score histogram, not a biased one)."""

    session_id: str
    officer_id: str
    coordinator_node_id: str
    accusation_score: float
    accused: bool
    revealed_codeword: bytes  # int8 array bytes, len == EvidenceBundle.n_total_positions
    revealed_salt: bytes
    decrypt_request_ledger_proof: LedgerRecordProof
    keygrant_issued_proof: LedgerRecordProof
    receipt_proof: LedgerRecordProof | None = None
    enroll_final_proof: LedgerRecordProof | None = None


class EvidenceBundle(CanonicalCBORModel):
    case_id: str
    doc_id: str
    artifact_hash: bytes
    tardos_n: int
    tardos_c0: int
    tardos_eps1: float
    n_observed: int
    n_total_positions: int
    n_erasures: int
    threshold: float
    observed_bits: list[float]  # nan sentinel for erasures
    # float32 array bytes — must match tscore.release_secret.bias_vector_to_bytes's
    # format exactly, since this is that same document-level bias vector,
    # revealed by keyrelease rather than freshly generated here.
    revealed_bias_vector: bytes
    suspects: list[SuspectSessionEvidence]
    investigation_opened_proof: LedgerRecordProof
    doc_register_proof: LedgerRecordProof
    report_pdf_hash: bytes
    trust_roots: list[PublicKeyEntry]
    built_at: float


def _find_key(trust_roots: list[PublicKeyEntry], identity_id: str) -> PublicKeyEntry:
    for entry in trust_roots:
        if entry.identity_id == identity_id:
            return entry
    raise VerificationError(
        f"no public key for {identity_id!r} in the bundle's embedded trust roots"
    )


def decode_record_payload[T: CanonicalCBORModel](proof: LedgerRecordProof, model: type[T]) -> T:
    """Same idiom as `keyrelease.node._decode_payload`/
    `ca.enrolment._decode_payload`, operating on tscore's own
    `LedgerRecordProof` instead of `ledger.wire.RecordWire` — tscore must
    never import from `ledger`. Raises `VerificationError` (not a raw
    decode exception) if the payload is malformed."""
    try:
        envelope = SignedEnvelope.from_canonical_cbor(proof.envelope_cbor)
        return model.from_canonical_cbor(envelope.payload)
    except Exception as exc:  # noqa: BLE001 - any decode failure on untrusted bytes is "invalid", not a crash
        raise VerificationError(
            f"record {proof.tx_id!r}: payload is malformed and could not be decoded: {exc}"
        ) from exc


def verify_record_proof(
    proof: LedgerRecordProof,
    trust_roots: list[PublicKeyEntry],
    *,
    quorum_threshold: int = LEDGER_QUORUM_THRESHOLD,
) -> SignedEnvelope:
    """Independently re-verifies ONE ledger record's own internal
    consistency and genuine quorum sign-off (spec 7.5 step 3's "ledger
    inclusion proof, quorum certificates") — see this module's docstring
    for what this does and does NOT prove."""
    expected_hash = compute_record_hash(
        proof.prev_hash, proof.tx_id, proof.envelope_cbor, proof.quorum_signer_ids
    )
    if expected_hash != proof.record_hash:
        raise VerificationError(
            f"record {proof.tx_id!r}: record_hash does not match its own "
            f"(prev_hash, tx_id, envelope_cbor, quorum_signer_ids) — hash-chain "
            f"self-consistency check failed"
        )
    submitter_key = _find_key(trust_roots, proof.submitter_id)
    if not sig_verify(
        submitter_key.sig_alg,
        submitter_key.sig_public_key,
        proof.envelope_cbor,
        proof.submitter_signature,
    ):
        raise VerificationError(
            f"record {proof.tx_id!r}: submitter signature from "
            f"{proof.submitter_id!r} does not verify"
        )
    if len(proof.quorum_signer_ids) != len(proof.quorum_signatures):
        raise VerificationError(
            f"record {proof.tx_id!r}: quorum signer_ids/signatures length mismatch"
        )
    n_distinct = len(set(proof.quorum_signer_ids))
    if n_distinct < quorum_threshold:
        raise VerificationError(
            f"record {proof.tx_id!r}: only {n_distinct} distinct quorum signers, "
            f"need >= {quorum_threshold}"
        )
    for signer_id, signature in zip(proof.quorum_signer_ids, proof.quorum_signatures, strict=True):
        key = _find_key(trust_roots, signer_id)
        if not sig_verify(key.sig_alg, key.sig_public_key, proof.envelope_cbor, signature):
            raise VerificationError(
                f"record {proof.tx_id!r}: quorum signature from {signer_id!r} does not verify"
            )
    return SignedEnvelope.from_canonical_cbor(proof.envelope_cbor)


def verify_evidence_bundle(
    signed: SignedSubmission,
    *,
    report_pdf_bytes: bytes | None = None,
) -> EvidenceBundle:
    """Full independent re-check (spec 7.5 step 5), in the correct
    parse-then-verify-then-trust order: the bundle's own embedded
    `trust_roots` are read out BEFORE they're trusted, used only to verify
    the bundle's OWN outer signature, and only once that passes is
    anything else in the bundle treated as authentic.

    Raises `tscore.errors.VerificationError` with a message identifying
    exactly what failed, on the first failure — including malformed/
    corrupted input that fails to even decode (a flipped byte can land
    anywhere in the CBOR structure, not just somewhere that happens to
    produce a clean signature-mismatch; any exception while parsing
    untrusted bytes is still just "this bundle is invalid", not a crash).
    Returns the verified `EvidenceBundle` only once every check has
    passed."""
    try:
        envelope = SignedEnvelope.from_canonical_cbor(signed.envelope_cbor)
        bundle = EvidenceBundle.from_canonical_cbor(envelope.payload)
    except Exception as exc:  # noqa: BLE001 - any decode failure on untrusted bytes is "invalid", not a crash
        raise VerificationError(
            f"evidence bundle is malformed and could not be decoded: {exc}"
        ) from exc

    signer_key = _find_key(bundle.trust_roots, signed.signer_id)
    open_submission(signer_key.sig_alg, signer_key.sig_public_key, signed)

    if report_pdf_bytes is not None and sha3_256(report_pdf_bytes) != bundle.report_pdf_hash:
        raise VerificationError(
            "report.pdf hash does not match EvidenceBundle.report_pdf_hash — "
            "the PDF report may have been swapped"
        )

    verify_record_proof(bundle.investigation_opened_proof, bundle.trust_roots)
    opened = decode_record_payload(bundle.investigation_opened_proof, InvestigationOpenedRecord)
    if opened.case_id != bundle.case_id or opened.artifact_hash != bundle.artifact_hash:
        raise VerificationError(
            "INVESTIGATION_OPENED ledger record does not match this bundle's case_id/artifact_hash"
        )

    verify_record_proof(bundle.doc_register_proof, bundle.trust_roots)
    doc_register = decode_record_payload(bundle.doc_register_proof, DocRegisterRecord)
    if (
        doc_register.doc_id != bundle.doc_id
        or doc_register.tardos_n != bundle.tardos_n
        or doc_register.tardos_c0 != bundle.tardos_c0
        or doc_register.tardos_eps1 != bundle.tardos_eps1
        or doc_register.positions_count != bundle.n_total_positions
    ):
        raise VerificationError(
            "bundle's Tardos parameters do not match the on-ledger DOC_REGISTER record"
        )

    codewords: dict[str, np.ndarray] = {}
    for suspect in bundle.suspects:
        verify_record_proof(suspect.decrypt_request_ledger_proof, bundle.trust_roots)
        drl = decode_record_payload(
            suspect.decrypt_request_ledger_proof, DecryptRequestLedgerRecord
        )
        if drl.session_id != suspect.session_id or drl.doc_id != bundle.doc_id:
            raise VerificationError(
                f"suspect {suspect.session_id!r}: DECRYPT_REQUEST_LEDGER record mismatch"
            )

        recomputed_commit = sha3_256(
            bundle.doc_id.encode()
            + suspect.session_id.encode()
            + suspect.revealed_codeword
            + suspect.revealed_salt
        )
        if recomputed_commit != drl.codeword_commitment:
            raise VerificationError(
                f"suspect {suspect.session_id!r}: revealed (codeword, salt) does not "
                f"match the on-ledger codeword_commitment"
            )

        recipient_key = _find_key(bundle.trust_roots, drl.recipient_signer_id)
        if not sig_verify(
            recipient_key.sig_alg,
            recipient_key.sig_public_key,
            drl.recipient_envelope_cbor,
            drl.recipient_signature,
        ):
            raise VerificationError(
                f"suspect {suspect.session_id!r}: recipient's original DecryptRequest "
                f"signature from {drl.recipient_signer_id!r} does not verify"
            )
        original = DecryptRequest.from_canonical_cbor(
            SignedEnvelope.from_canonical_cbor(drl.recipient_envelope_cbor).payload
        )
        if (
            original.session_id != suspect.session_id
            or drl.recipient_signer_id != suspect.officer_id
        ):
            raise VerificationError(f"suspect {suspect.session_id!r}: officer_id mismatch")

        verify_record_proof(suspect.keygrant_issued_proof, bundle.trust_roots)
        kgi = decode_record_payload(suspect.keygrant_issued_proof, KeyGrantIssuedRecord)
        if kgi.session_id != suspect.session_id:
            raise VerificationError(
                f"suspect {suspect.session_id!r}: KEYGRANT_ISSUED record mismatch"
            )
        n_contrib = len(set(kgi.contributing_node_ids))
        if n_contrib < KEY_RELEASE_QUORUM_THRESHOLD:
            raise VerificationError(
                f"suspect {suspect.session_id!r}: only {n_contrib} distinct KeyGrant "
                f"co-signers, need >= {KEY_RELEASE_QUORUM_THRESHOLD}"
            )
        for node_id, sig in zip(
            kgi.contributing_node_ids, kgi.contributing_signatures, strict=True
        ):
            attestation = sha3_256(f"{bundle.doc_id}|{suspect.session_id}|{node_id}".encode())
            node_key = _find_key(bundle.trust_roots, node_id)
            if not sig_verify(node_key.sig_alg, node_key.sig_public_key, attestation, sig):
                raise VerificationError(
                    f"suspect {suspect.session_id!r}: KeyGrant co-signature from "
                    f"{node_id!r} does not verify"
                )

        if suspect.receipt_proof is not None:
            verify_record_proof(suspect.receipt_proof, bundle.trust_roots)
            receipt = decode_record_payload(suspect.receipt_proof, ReceiptRecord)
            if receipt.session_id != suspect.session_id:
                raise VerificationError(f"suspect {suspect.session_id!r}: RECEIPT record mismatch")

        if suspect.enroll_final_proof is not None:
            verify_record_proof(suspect.enroll_final_proof, bundle.trust_roots)
            enroll = decode_record_payload(suspect.enroll_final_proof, EnrollFinalRecord)
            if enroll.officer_id != suspect.officer_id:
                raise VerificationError(
                    f"suspect {suspect.session_id!r}: ENROLL_FINAL officer_id mismatch"
                )

        codewords[suspect.session_id] = np.frombuffer(suspect.revealed_codeword, dtype=np.int8)

    bias_vector = np.frombuffer(bundle.revealed_bias_vector, dtype=np.float32).astype(np.float64)
    observed = np.array(bundle.observed_bits, dtype=np.float64)
    scores = accuse(codewords, observed, bias_vector, bundle.tardos_eps1)
    z = tardos_threshold(bundle.n_observed, bundle.tardos_eps1)
    if not math.isclose(z, bundle.threshold, rel_tol=1e-9, abs_tol=1e-9):
        raise VerificationError(
            f"recomputed accusation threshold {z:.6f} does not match bundle's "
            f"recorded threshold {bundle.threshold:.6f}"
        )
    for suspect in bundle.suspects:
        recomputed = scores[suspect.session_id]
        if not math.isclose(recomputed, suspect.accusation_score, rel_tol=1e-9, abs_tol=1e-6):
            raise VerificationError(
                f"suspect {suspect.session_id!r}: recomputed Tardos score {recomputed:.4f} "
                f"does not match bundle's recorded score {suspect.accusation_score:.4f}"
            )
        if (recomputed > z) != suspect.accused:
            raise VerificationError(
                f"suspect {suspect.session_id!r}: bundle's 'accused' flag is inconsistent "
                f"with the recomputed score vs. threshold"
            )

    return bundle
