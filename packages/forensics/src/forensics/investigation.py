"""Forensic investigation pipeline building a signed `EvidenceBundle` (spec
Section 7.5 steps 1-4): open an investigation on the ledger, reveal every
candidate session's codeword from the key-release vault (ADR-0026),
re-derive the Tardos scores, assemble + self-check + sign the bundle
(decision 9's non-circular ordering — see `docs/DECISIONS.md` ADR-0030),
issue a downstream `ReportIssuedRecord`, and write the `.tsev` archive.

Every cryptographic check here is delegated to `tscore.evidence` — this
module's job is gathering the real, live inputs (from a real ledger and a
real key-release cluster) that module needs, never re-implementing any of
its verification logic (single source of truth, see that module's
docstring).
"""

from __future__ import annotations

import json
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path

from ca.keys import Identity
from ca.registry import Registry
from keyrelease.client import KeyReleaseClient
from ledger.backend import LedgerBackend
from ledger.wire import RecordProofWire, RecordWire
from tscore.errors import VerificationError
from tscore.evidence import (
    EvidenceBundle,
    LedgerRecordProof,
    PublicKeyEntry,
    SuspectSessionEvidence,
    verify_evidence_bundle,
)
from tscore.hashing import sha3_256
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_EVIDENCE_BUNDLE,
    DOMAIN_INVESTIGATION_OPENED,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_RECEIPT,
    DOMAIN_REPORT_ISSUED,
    DecryptRequestLedgerRecord,
    DocRegisterRecord,
    EnrollFinalRecord,
    InvestigationOpenedRecord,
    KeyGrantIssuedRecord,
    ReceiptRecord,
    ReportIssuedRecord,
    SignedSubmission,
    make_submission,
)
from tscore.schemas import SignedEnvelope

from forensics.report_pdf import build_report_pdf

_ROLE_PREFIXES = (
    ("ca-root", "ca"),
    ("ledger-", "ledger"),
    ("keyrelease-", "keyrelease"),
    ("sender-", "sender"),
    ("forensics-", "forensics"),
    ("admin-", "admin"),
    ("officer-", "officer"),
)


def _infer_role(identity_id: str) -> str:
    for prefix, role in _ROLE_PREFIXES:
        if identity_id == prefix or identity_id.startswith(prefix):
            return role
    return "unknown"  # informational only; never used for a security decision


def build_trust_roots(registry: Registry) -> list[PublicKeyEntry]:
    """Converts the PKI registry into the bundle's embedded, self-contained
    trust anchor — this IS the verifier's entire trust root set, see
    `tscore.evidence.PublicKeyEntry`'s docstring."""
    roots = []
    for identity_id, entry in registry.items():
        kem_alg = entry.get("kem_alg")
        roots.append(
            PublicKeyEntry(
                identity_id=identity_id,
                role=_infer_role(identity_id),
                sig_alg=entry["sig_alg"],
                sig_public_key=bytes.fromhex(entry["sig_public_key"]),
                kem_alg=kem_alg,
                kem_public_key=bytes.fromhex(entry["kem_public_key"]) if kem_alg else None,
            )
        )
    return roots


def _to_ledger_record_proof(wire: RecordProofWire) -> LedgerRecordProof:
    """The one place `ledger.wire.RecordProofWire` gets converted into
    tscore's own, `ledger`-independent `LedgerRecordProof` — everywhere
    else in this module works with the tscore type, so the eventual
    standalone verifier (which never imports `ledger`) sees exactly the
    same shape forensics built."""
    return LedgerRecordProof(
        tx_id=wire.tx_id,
        height=wire.height,
        envelope_cbor=bytes.fromhex(wire.envelope_cbor),
        submitter_id=wire.submitter_id,
        submitter_signature=bytes.fromhex(wire.submitter_signature),
        quorum_signer_ids=wire.quorum_signer_ids,
        quorum_signatures=[bytes.fromhex(s) for s in wire.quorum_signatures],
        prev_hash=bytes.fromhex(wire.prev_hash),
        record_hash=bytes.fromhex(wire.record_hash),
    )


def _decode[T](record: RecordWire, model: type[T]) -> T:
    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(record.envelope_cbor))
    result: T = model.from_canonical_cbor(envelope.payload)  # type: ignore[attr-defined]
    return result


def open_investigation(
    case_id: str,
    artifact_hash: bytes,
    forensics_identity: Identity,
    ledger_client: LedgerBackend,
) -> LedgerRecordProof:
    """Spec 7.5 step 1: submitted BEFORE any vault reveal or scoring, so an
    investigation into this exact artifact is always independently
    discoverable even if it's never concluded."""
    record = InvestigationOpenedRecord(case_id=case_id, artifact_hash=artifact_hash)
    submission = make_submission(
        forensics_identity.sig_alg,
        forensics_identity.sig_secret_key,
        forensics_identity.identity_id,
        DOMAIN_INVESTIGATION_OPENED,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=30.0)
    return _to_ledger_record_proof(ledger_client.get_proof(tx_id))


def find_doc_register_proof(ledger_client: LedgerBackend, doc_id: str) -> LedgerRecordProof:
    """Public (unlike the `_find_*` helpers below it): `forensics.demo_m5`
    needs this directly, to assemble the bundle's `doc_register_proof`."""
    for record in ledger_client.query(domain=DOMAIN_DOC_REGISTER):
        if _decode(record, DocRegisterRecord).doc_id == doc_id:
            return _to_ledger_record_proof(ledger_client.get_proof(record.tx_id))
    raise VerificationError(f"no DOC_REGISTER record found on the ledger for doc {doc_id!r}")


def _find_keygrant_issued_proof(ledger_client: LedgerBackend, session_id: str) -> LedgerRecordProof:
    for record in ledger_client.query(domain=DOMAIN_KEYGRANT_ISSUED):
        if _decode(record, KeyGrantIssuedRecord).session_id == session_id:
            return _to_ledger_record_proof(ledger_client.get_proof(record.tx_id))
    raise VerificationError(f"no KEYGRANT_ISSUED record found for session {session_id!r}")


def _find_receipt_proof(ledger_client: LedgerBackend, session_id: str) -> LedgerRecordProof | None:
    for record in ledger_client.query(domain=DOMAIN_RECEIPT):
        if _decode(record, ReceiptRecord).session_id == session_id:
            return _to_ledger_record_proof(ledger_client.get_proof(record.tx_id))
    return None  # a session that hasn't (yet) submitted a Receipt is not itself suspicious


def _find_latest_enroll_final_proof(
    ledger_client: LedgerBackend, officer_id: str
) -> LedgerRecordProof | None:
    """Mirrors `keyrelease.node.KeyReleaseNode._current_cert_hash`'s
    "most recent ENROLL_FINAL for this officer" query, but keeps the proof
    rather than just the decoded cert_hash."""
    latest_height = -1
    latest_proof: LedgerRecordProof | None = None
    for record in ledger_client.query(domain=DOMAIN_ENROLL_FINAL):
        if _decode(record, EnrollFinalRecord).officer_id != officer_id:
            continue
        if record.height > latest_height:
            latest_height = record.height
            latest_proof = _to_ledger_record_proof(ledger_client.get_proof(record.tx_id))
    return latest_proof


@dataclass(frozen=True)
class CandidateSession:
    """One session ever issued for the document, with its vault-revealed
    codeword/salt cross-checked against the ledger's own commitment BEFORE
    ever being trusted (defense in depth — `tscore.evidence` re-checks this
    independently again at verify time, but a builder that already caught a
    forged reveal here should refuse to build a bundle around it)."""

    session_id: str
    officer_id: str
    coordinator_node_id: str
    revealed_codeword: bytes
    revealed_salt: bytes
    decrypt_request_ledger_proof: LedgerRecordProof
    keygrant_issued_proof: LedgerRecordProof
    receipt_proof: LedgerRecordProof | None
    enroll_final_proof: LedgerRecordProof | None


def gather_candidate_codewords(
    doc_id: str,
    ledger_client: LedgerBackend,
    keyrelease_client: KeyReleaseClient,
) -> list[CandidateSession]:
    """Spec 7.5 step 3: every session ever issued for `doc_id` — needed
    ALL at once, not just the ones later found over threshold, since
    `tscore.tardos.accuse` scores every candidate simultaneously (see this
    package's plan for why `EvidenceBundle.suspects` is never pre-filtered).
    The coordinating node for each session is resolved from the ledger's
    own `DECRYPT_REQUEST_LEDGER` record `submitter_id` — that IS the
    coordinator, by construction (`keyrelease.node.handle_decrypt_request`
    submits it under its own identity)."""
    candidates: list[CandidateSession] = []
    for record in ledger_client.query(domain=DOMAIN_DECRYPT_REQUEST_LEDGER):
        drl = _decode(record, DecryptRequestLedgerRecord)
        if drl.doc_id != doc_id:
            continue
        coordinator_node_id = record.submitter_id

        codeword, salt, commit_hash = keyrelease_client.reveal_commitment(
            coordinator_node_id, drl.session_id, doc_id
        )
        if commit_hash != drl.codeword_commitment:
            raise VerificationError(
                f"session {drl.session_id!r}: key-release node "
                f"{coordinator_node_id!r} revealed a commit_hash that does not "
                f"match the on-ledger codeword_commitment — refusing to trust it"
            )
        recomputed = sha3_256(doc_id.encode() + drl.session_id.encode() + codeword + salt)
        if recomputed != drl.codeword_commitment:
            raise VerificationError(
                f"session {drl.session_id!r}: revealed (codeword, salt) does not "
                f"reproduce the on-ledger codeword_commitment — refusing to trust it"
            )

        candidates.append(
            CandidateSession(
                session_id=drl.session_id,
                officer_id=drl.recipient_signer_id,
                coordinator_node_id=coordinator_node_id,
                revealed_codeword=codeword,
                revealed_salt=salt,
                decrypt_request_ledger_proof=_to_ledger_record_proof(
                    ledger_client.get_proof(record.tx_id)
                ),
                keygrant_issued_proof=_find_keygrant_issued_proof(ledger_client, drl.session_id),
                receipt_proof=_find_receipt_proof(ledger_client, drl.session_id),
                enroll_final_proof=_find_latest_enroll_final_proof(
                    ledger_client, drl.recipient_signer_id
                ),
            )
        )
    return candidates


def build_evidence_bundle(
    *,
    case_id: str,
    doc_id: str,
    artifact_hash: bytes,
    tardos_n: int,
    tardos_c0: int,
    tardos_eps1: float,
    n_observed: int,
    n_total_positions: int,
    n_erasures: int,
    threshold: float,
    observed_bits: list[float],
    revealed_bias_vector: bytes,
    candidates: list[CandidateSession],
    scores: dict[str, float],
    accused_sessions: set[str],
    investigation_opened_proof: LedgerRecordProof,
    doc_register_proof: LedgerRecordProof,
    trust_roots: list[PublicKeyEntry],
    forensics_identity: Identity,
) -> tuple[SignedSubmission, EvidenceBundle, bytes]:
    """Assembles, self-checks, renders the PDF, signs, and does a final
    paranoia re-check — in exactly that order (decision 9,
    `docs/DECISIONS.md` ADR-0030), so the report's own "cryptographic
    checks" section is never printed without having actually, freshly
    passed. Returns `(signed_bundle, bundle, report_pdf_bytes)`.

    The draft/final split exists only to break the circular dependency
    between "sign the bundle" and "the bundle names the PDF's hash, but the
    PDF's content depends on the (already-verified) bundle fields" — the
    draft is signed and independently re-verified via the exact same
    `tscore.evidence.verify_evidence_bundle` the standalone verifier calls
    (no bespoke pre-check logic to drift out of sync), then discarded once
    its checks pass; only the final, PDF-hash-complete bundle is the one
    actually issued.
    """
    suspects = [
        SuspectSessionEvidence(
            session_id=c.session_id,
            officer_id=c.officer_id,
            coordinator_node_id=c.coordinator_node_id,
            accusation_score=scores[c.session_id],
            accused=c.session_id in accused_sessions,
            revealed_codeword=c.revealed_codeword,
            revealed_salt=c.revealed_salt,
            decrypt_request_ledger_proof=c.decrypt_request_ledger_proof,
            keygrant_issued_proof=c.keygrant_issued_proof,
            receipt_proof=c.receipt_proof,
            enroll_final_proof=c.enroll_final_proof,
        )
        for c in candidates
    ]

    draft = EvidenceBundle(
        case_id=case_id,
        doc_id=doc_id,
        artifact_hash=artifact_hash,
        tardos_n=tardos_n,
        tardos_c0=tardos_c0,
        tardos_eps1=tardos_eps1,
        n_observed=n_observed,
        n_total_positions=n_total_positions,
        n_erasures=n_erasures,
        threshold=threshold,
        observed_bits=observed_bits,
        revealed_bias_vector=revealed_bias_vector,
        suspects=suspects,
        investigation_opened_proof=investigation_opened_proof,
        doc_register_proof=doc_register_proof,
        report_pdf_hash=b"\x00" * 32,  # the PDF doesn't exist yet — set for real below
        trust_roots=trust_roots,
        built_at=time.time(),
    )

    def _sign(bundle: EvidenceBundle) -> SignedSubmission:
        return make_submission(
            forensics_identity.sig_alg,
            forensics_identity.sig_secret_key,
            forensics_identity.identity_id,
            DOMAIN_EVIDENCE_BUNDLE,
            bundle,
        )

    # Self-check BEFORE ever rendering a PDF that could claim VALID — abort
    # rather than print a false conclusion. report_pdf_bytes is omitted:
    # the real PDF doesn't exist yet, so its hash can't be cross-checked
    # here (that happens below, against the FINAL signed bundle).
    verify_evidence_bundle(_sign(draft))

    report_pdf_bytes = build_report_pdf(draft)

    final = draft.model_copy(update={"report_pdf_hash": sha3_256(report_pdf_bytes)})
    signed = _sign(final)
    # Final paranoia gate: re-verify the actual signed/serialized bytes
    # (not just the draft's in-memory fields) before ever writing case.tsev.
    verify_evidence_bundle(signed, report_pdf_bytes=report_pdf_bytes)

    return signed, final, report_pdf_bytes


def issue_report(
    case_id: str,
    doc_id: str,
    signed_bundle: SignedSubmission,
    report_pdf_bytes: bytes,
    forensics_identity: Identity,
    ledger_client: LedgerBackend,
) -> str:
    """Spec 7.5 step 4: a downstream, post-signing audit-trail entry only —
    it cannot be embedded in the bundle it describes (circular hash
    dependency) and `traceseal-verify` never queries the ledger, so it
    never checks this record (`docs/DECISIONS.md` ADR-0030). Returns the
    finalized tx_id."""
    record = ReportIssuedRecord(
        case_id=case_id,
        doc_id=doc_id,
        bundle_hash=sha3_256(signed_bundle.envelope_cbor),
        report_pdf_hash=sha3_256(report_pdf_bytes),
    )
    submission = make_submission(
        forensics_identity.sig_alg,
        forensics_identity.sig_secret_key,
        forensics_identity.identity_id,
        DOMAIN_REPORT_ISSUED,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=30.0)
    return tx_id


def _json_default(obj: object) -> str:
    if isinstance(obj, bytes):
        return obj.hex()
    raise TypeError(f"not JSON serializable: {type(obj)!r}")


def write_tsev(
    path: Path,
    signed_bundle: SignedSubmission,
    bundle: EvidenceBundle,
    report_pdf_bytes: bytes,
) -> None:
    """Writes the `.tsev` archive: `bundle.cbor` is the EXACT signed
    envelope bytes (`traceseal-verify` reconstructs a `SignedSubmission`
    from this plus `signature.json` — nothing else); `bundle.json` is a
    human-readable decode, informational only, never read by the verifier
    (bytes fields aren't valid UTF-8 in general, so it's hand-encoded to
    hex here rather than via `model_dump_json`, which assumes UTF-8 bytes
    and would raise — see `ledger.wire`'s docstring for the same issue)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bundle.cbor", signed_bundle.envelope_cbor)
        zf.writestr(
            "bundle.json",
            json.dumps(bundle.model_dump(mode="python"), indent=2, default=_json_default),
        )
        zf.writestr(
            "signature.json",
            json.dumps(
                {
                    "signer_id": signed_bundle.signer_id,
                    "signature": signed_bundle.signature.hex(),
                },
                indent=2,
            ),
        )
        zf.writestr("report.pdf", report_pdf_bytes)
