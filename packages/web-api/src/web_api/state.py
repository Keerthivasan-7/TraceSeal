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

from dataclasses import dataclass, field

import numpy as np
from ca.keys import Identity
from sender.quality_gate import QualityGateReport
from sender.variants import DocumentVariants
from tscore.records import SignedSubmission


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
class AppState:
    # officer_id -> unlocked Identity (Officer Inbox/Viewer, Phase 3).
    officer_sessions: dict[str, Identity] = field(default_factory=dict)

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
