"""In-memory application state — everything here is intentionally
ephemeral (lost on restart) and never persisted to disk beyond what the
underlying `ca`/`sender`/`agent`/`forensics` calls already write to the
ledger/blob store themselves. Officer identities and decrypted pages in
particular must never touch disk here (spec: in-memory-only assembly) —
see `web_api.routes.officers`.

Grows incrementally as each phase's routes need it; this is deliberately
minimal for the Phase 1 skeleton.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import TypeVar

import numpy as np
from ca.keys import Identity
from forensics.detect import PositionObservation
from forensics.investigation import CandidateSession
from forensics.report import InvestigationReport
from sender.quality_gate import QualityGateReport
from sender.variants import DocumentVariants
from tscore.evidence import EvidenceBundle, LedgerRecordProof, PublicKeyEntry
from tscore.records import SignedSubmission

from web_api.auth import Clock, EventLog, LockoutTracker, Session, SessionManager

_V = TypeVar("_V")

# Every dict below holds full-resolution rendered page arrays or assembled
# plaintext pages — genuinely large (order 100-400MB each for a real
# multi-page document) — and nothing ever expired them before this: a
# `DistributeDraft` a caller never released, or a leaked-artifact
# investigation nobody issued a report for, stayed in memory for the rest
# of the process's life. Measured live: repeated /distribute/analyze calls
# during one long testing session pushed web-api to several GB of retained
# arrays and made every subsequent call progressively slower (more heap for
# Python's GC to walk under CPU-bound numpy/PIL work), eventually timing
# out. This is a plain FIFO cap, not a real LRU — good enough for a
# single-operator demo session, not a claim of production-grade cache
# eviction.
MAX_CACHED_ENTRIES = 6


def bounded_insert(
    store: dict[str, _V], key: str, value: _V, *, max_size: int = MAX_CACHED_ENTRIES
) -> None:
    while len(store) >= max_size:
        store.pop(next(iter(store)))
    store[key] = value


@dataclass(frozen=True)
class DistributeDraft:
    """An analyzed-but-not-yet-released document (Distribute screen, Phase
    3): the expensive rendering/quality-gate work is done once in
    `/distribute/analyze` and cached here so `/distribute/{draft_id}/release`
    doesn't have to redo it, and so the officer can review the report before
    committing to a release."""

    draft_id: str
    doc_id: str
    variants: DocumentVariants
    quality_report: QualityGateReport


@dataclass(frozen=True)
class OpenSession:
    """One officer's already-opened document (Officer Inbox/Viewer, Phase
    3) — `pages` are the in-memory-only assembled page arrays `agent.decrypt.
    open_document` returned; never serialized to disk, only PNG-encoded on
    the fly per page for the viewer."""

    session_id: str
    doc_id: str
    officer_id: str
    receipt_tx_id: str
    pages: list[np.ndarray]


@dataclass
class InvestigationRun:
    """One in-progress or completed investigation (Investigate screen,
    Phase 4) — the pipeline's intermediate stages (`aligned`, `observations`)
    exist only so the live visualization can show them; the actual
    accusation result lives in `report`, computed identically to
    `forensics.pipeline.investigate()`. `signed_bundle`/`bundle`/
    `report_pdf_bytes`/`tsev_bytes` are filled in only after `/issue-report`
    runs — `None` until then."""

    case_id: str
    doc_id: str
    page_index: int
    artifact: np.ndarray
    aligned: np.ndarray
    observations: list[PositionObservation]
    page_to_global: dict[int, int]
    report: InvestigationReport
    candidates: list[CandidateSession]
    bias_vector_bytes: bytes
    artifact_hash: bytes
    investigation_opened_proof: LedgerRecordProof
    doc_register_proof: LedgerRecordProof
    trust_roots: list[PublicKeyEntry]
    tardos_n: int
    tardos_c0: int
    tardos_eps1: float
    signed_bundle: SignedSubmission | None = None
    bundle: EvidenceBundle | None = None
    report_pdf_bytes: bytes | None = None
    tsev_bytes: bytes | None = None


@dataclass
class AppState:
    # identity_id -> unlocked Identity. In role `all` this is the original
    # officer Inbox's per-officer unlock table; in the isolated roles it holds
    # exactly the identities of the one logged-in session, and is wiped when
    # that session ends (logout, idle/absolute expiry, replacement login).
    unlocked: dict[str, Identity] = field(default_factory=dict)

    # Session machinery for roles with `auth_enabled` (web_api.auth).
    sessions: SessionManager = field(default_factory=SessionManager)
    lockout: LockoutTracker = field(default_factory=LockoutTracker)
    events: EventLog = field(default_factory=EventLog)
    clock: Clock = time.monotonic
    _admin_lockouts: dict[str, LockoutTracker] = field(default_factory=dict, init=False, repr=False)

    # enrolment proposal tx_id -> the officer's self-signed CSR submission
    # (Identity screen, Phase 2). `ca.enrolment.finalize_enrolment` needs
    # the EXACT SAME CSR submission `propose_enrolment` used — re-building
    # one would produce different (randomly-nonced) envelope bytes and trip
    # the swapped-CSR check — so the propose step's own CSR is cached here
    # for the later finalize call to reuse.
    pending_csrs: dict[str, SignedSubmission] = field(default_factory=dict)

    # draft_id -> analyzed-but-unreleased document (Distribute screen, Phase 3).
    distribute_drafts: dict[str, DistributeDraft] = field(default_factory=dict)

    # "{officer_id}:{doc_id}" -> that officer's currently-open session
    # (Officer Inbox/Viewer, Phase 3).
    open_sessions: dict[str, OpenSession] = field(default_factory=dict)

    # doc_id -> the draft that was released (Distribute screen moves it here
    # instead of deleting it on release). Nothing else in the system keeps
    # the original DocumentVariants after release (the blob store only ever
    # holds ciphertext) and Investigate's pipeline needs the exact same
    # patches the document was built from to align/score a leaked artifact
    # against — so this is the one place that reuse comes from, for the
    # lifetime of this process only (Investigate screen, Phase 4).
    released_documents: dict[str, DistributeDraft] = field(default_factory=dict)

    # case_id -> in-progress or completed investigation (Investigate screen,
    # Phase 4).
    investigations: dict[str, InvestigationRun] = field(default_factory=dict)

    @property
    def officer_sessions(self) -> dict[str, Identity]:
        """Name kept for the original Officer Inbox routes."""
        return self.unlocked

    def admin_lockout(self, admin_id: str) -> LockoutTracker:
        """Per-admin brute-force backoff: guessing one admin's passphrase through
        the approval endpoint is throttled independently of the console login."""
        if admin_id not in self._admin_lockouts:
            self._admin_lockouts[admin_id] = LockoutTracker(self.clock)
        return self._admin_lockouts[admin_id]

    def end_session(self, session: Session) -> None:
        """Wipe everything a session unlocked: its identities and every
        decrypted-page session opened under them. Called on logout, on
        expiry and when a new login replaces the old session — decrypted
        pages must not outlive the login that produced them."""
        for identity_id in session.identity_ids:
            self.unlocked.pop(identity_id, None)
            for key in [k for k in self.open_sessions if k.startswith(f"{identity_id}:")]:
                del self.open_sessions[key]

    def sweep_expired(self) -> None:
        for session in self.sessions.sweep():
            self.end_session(session)
            self.events.add("session_expired", session.principal_id)
