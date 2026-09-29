"""Signed PDF investigation report (spec Section 7.5 step 4, Section 11
step 8, Section 20's honesty rules). Built with PyMuPDF — already pinned
(via `sender`) and already proven in this repo to build a PDF from scratch
(`sender.sample_doc`) — declared directly in `forensics`' own
`pyproject.toml` since report generation lives here.

Every fact printed here comes straight off an already-self-checked
`EvidenceBundle` (`forensics.investigation.build_evidence_bundle` only
calls `build_report_pdf` after `tscore.evidence.verify_evidence_bundle`
has already passed on the draft) — this module never re-derives or
re-checks anything, it only renders. The limitations section is mandatory
and always printed, never conditional on how the investigation turned out.
"""

from __future__ import annotations

import time

import pymupdf
from tscore.evidence import EvidenceBundle

# PyMuPDF's base14 Helvetica falls back to a tofu glyph for U+2014 (em
# dash) in insert_text/insert_textbox — every user-visible string in this
# module uses a plain ASCII hyphen instead, even though the rest of this
# codebase's prose otherwise uses em dashes freely.
TITLE = "TRACESEAL FORENSIC INVESTIGATION REPORT (SYNTHETIC - DEMO CONTENT ONLY)"

PAGE_WIDTH = 612.0
PAGE_HEIGHT = 792.0
_MARGIN_LEFT = 56.0
_MARGIN_RIGHT = 56.0
_MARGIN_TOP = 56.0
_MARGIN_BOTTOM = 56.0
_BODY_WIDTH = PAGE_WIDTH - _MARGIN_LEFT - _MARGIN_RIGHT

# Verbatim from CLAUDE.md / docs/SPEC.md Section 20's honesty rules — never
# paraphrase these away, and never omit them regardless of outcome.
_LIMITATIONS = [
    "This report presents a statistical conclusion from per-position pixel "
    "correlation and independently re-verified cryptographic evidence-chain "
    "checks. It is suitable for investigative and evidentiary review. It is "
    "NOT a legal determination of guilt or intent, and does not constitute a "
    "claim of legal admissibility in any jurisdiction.",
    "This system provides no protection against a recipient retyping, "
    "photographing and manually transcribing, or reading the document aloud "
    "to another party - such disclosure leaves no forensic fingerprint and "
    "is out of scope for this investigation.",
    "The ledger inclusion proofs in this bundle (LedgerLite, an internal "
    "development backend - see docs/DECISIONS.md ADR-0012) demonstrate each "
    "cited record's own internal hash-chain consistency and genuine quorum "
    "sign-off. LedgerLite has no Merkle tree or checkpoint structure, so "
    "these proofs do NOT demonstrate that no record was omitted from a "
    "longer chain never independently walked end-to-end.",
    "The public-key trust anchors used to verify every signature in this "
    "bundle are embedded in the bundle itself, taken from the PKI registry "
    "at the time this report was built. They are not independently pinned "
    "by a separate, out-of-band root of trust known to the reader in "
    "advance of receiving this bundle.",
    "The document's Tardos bias vector was revealed directly from key-"
    "release nodes' local storage at investigation time; it is not itself "
    "committed to the ledger, so its provenance rests on the same trust "
    "anchors as the rest of this bundle, not on an independent ledger "
    "record.",
    "All document, officer, and operational content referenced anywhere in "
    "this report is synthetic demonstration data generated for TraceSeal "
    "testing and milestone acceptance. It does not describe any real "
    "document, unit, location, or individual.",
]


class _PDFWriter:
    """Minimal paginated text writer: tracks a cursor down one page and
    opens a fresh page automatically when content would run past the
    bottom margin — everything this report needs, nothing `sample_doc.py`
    didn't already prove works (`insert_text`/`insert_textbox` on a fresh
    `pymupdf.Document`)."""

    def __init__(self, doc: pymupdf.Document) -> None:
        self._doc = doc
        self._page: pymupdf.Page = doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
        self._y = _MARGIN_TOP

    def _ensure_room(self, needed: float) -> None:
        if self._y + needed > PAGE_HEIGHT - _MARGIN_BOTTOM:
            self._page = self._doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
            self._y = _MARGIN_TOP

    def heading(self, text: str, *, fontsize: float = 13.0) -> None:
        self._ensure_room(fontsize + 10.0)
        self._y += 6.0
        self._page.insert_text(
            (_MARGIN_LEFT, self._y + fontsize), text, fontsize=fontsize, fontname="Helvetica-Bold"
        )
        self._y += fontsize + 8.0

    def line(self, text: str, *, fontsize: float = 10.0, fontname: str = "Helvetica") -> None:
        self._ensure_room(fontsize + 4.0)
        self._page.insert_text(
            (_MARGIN_LEFT, self._y + fontsize), text, fontsize=fontsize, fontname=fontname
        )
        self._y += fontsize + 4.0

    def paragraph(self, text: str, *, fontsize: float = 10.0, line_height: float = 1.35) -> None:
        # Reserve a generous block up front; insert_textbox itself will
        # report how much it actually used, but this writer only needs a
        # conservative page-break decision before starting the block.
        n_lines_estimate = max(1, len(text) // 90 + 1)
        block_height = n_lines_estimate * fontsize * line_height + 8.0
        self._ensure_room(block_height)
        rect = pymupdf.Rect(
            _MARGIN_LEFT, self._y, PAGE_WIDTH - _MARGIN_RIGHT, self._y + block_height
        )
        self._page.insert_textbox(rect, text, fontsize=fontsize, lineheight=line_height)
        self._y += block_height

    def bullet(self, text: str, *, fontsize: float = 9.5) -> None:
        # "-" not "•": the bullet-point glyph is another one PyMuPDF's
        # base14 Helvetica doesn't render (same WinAnsi gap as the em dash).
        self.paragraph(f"- {text}", fontsize=fontsize)

    def spacer(self, height: float = 8.0) -> None:
        self._y += height


def _format_suspects_table(writer: _PDFWriter, bundle: EvidenceBundle) -> None:
    header = f"{'session_id':<24}{'officer_id':<16}{'coordinator':<16}{'score':>10}{'accused':>10}"
    writer.line(header, fontname="Helvetica-Bold", fontsize=9.0)
    for suspect in sorted(bundle.suspects, key=lambda s: -s.accusation_score):
        row = (
            f"{suspect.session_id:<24}{suspect.officer_id:<16}{suspect.coordinator_node_id:<16}"
            f"{suspect.accusation_score:>10.3f}{('YES' if suspect.accused else 'no'):>10}"
        )
        writer.line(row, fontsize=9.0)


def _statistical_conclusion(bundle: EvidenceBundle) -> str:
    accused = sorted(
        (s for s in bundle.suspects if s.accused), key=lambda s: -s.accusation_score
    )
    if accused:
        top = accused[0]
        others = ", ".join(s.session_id for s in accused[1:]) or "none"
        return (
            f"Consistent with session {top.session_id} (officer {top.officer_id}): score "
            f"{top.accusation_score:.3f} against threshold {bundle.threshold:.3f} "
            f"(eps1={bundle.tardos_eps1:g}); {bundle.n_observed} of "
            f"{bundle.n_total_positions} mark positions observed ({bundle.n_erasures} erased). "
            f"Additional session(s) also exceeded the threshold: {others}. "
            "This is a statistical conclusion from per-position pixel correlation, suitable "
            "for investigative and evidentiary review - it is not a legal determination of "
            "guilt or intent."
        )
    return (
        f"No candidate session's score exceeded the threshold {bundle.threshold:.3f} "
        f"(eps1={bundle.tardos_eps1:g}) against {bundle.n_observed} of "
        f"{bundle.n_total_positions} observed positions ({bundle.n_erasures} erased). "
        "Insufficient evidence for attribution."
    )


def build_report_pdf(bundle: EvidenceBundle) -> bytes:
    """Renders the full report for `bundle` and returns the PDF bytes.
    Never called before `bundle`'s draft form has already passed
    `tscore.evidence.verify_evidence_bundle` — see
    `forensics.investigation.build_evidence_bundle`'s docstring."""
    doc = pymupdf.open()
    try:
        writer = _PDFWriter(doc)

        writer.heading(TITLE, fontsize=13.0)
        writer.line(f"Case ID:        {bundle.case_id}")
        writer.line(f"Document ID:    {bundle.doc_id}")
        writer.line(f"Artifact hash:  {bundle.artifact_hash.hex()}")
        built_at_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(bundle.built_at))
        writer.line(f"Report built:   {built_at_str}")
        writer.spacer(10.0)

        writer.heading("Statistical Conclusion", fontsize=12.0)
        writer.paragraph(_statistical_conclusion(bundle))
        writer.spacer(6.0)

        writer.heading("Tardos Parameters", fontsize=12.0)
        writer.line(f"n (recipients):            {bundle.tardos_n}")
        writer.line(f"c0 (collusion resistance): {bundle.tardos_c0}")
        writer.line(f"eps1 (false-accusation):   {bundle.tardos_eps1:g}")
        writer.line(f"Mark positions (total):    {bundle.n_total_positions}")
        writer.line(f"Mark positions (observed): {bundle.n_observed}")
        writer.line(f"Erasures:                  {bundle.n_erasures}")
        writer.line(f"Accusation threshold:      {bundle.threshold:.4f}")
        writer.spacer(6.0)

        writer.heading("Cryptographic Evidence-Chain Checks", fontsize=12.0)
        writer.line("[PASSED] Outer bundle signature (ML-DSA) verified against trust roots.")
        writer.line("[PASSED] INVESTIGATION_OPENED ledger record hash-chain + quorum re-verified.")
        writer.line("[PASSED] DOC_REGISTER ledger record hash-chain + quorum re-verified.")
        for suspect in bundle.suspects:
            writer.line(
                f"[PASSED] session {suspect.session_id}: DECRYPT_REQUEST_LEDGER + "
                f"KEYGRANT_ISSUED records re-verified; revealed codeword matches "
                f"on-ledger commitment."
            )
        writer.line("[PASSED] Tardos accusation scores independently recomputed and matched.")
        writer.spacer(6.0)

        writer.heading("Candidate Sessions", fontsize=12.0)
        _format_suspects_table(writer, bundle)
        writer.spacer(10.0)

        writer.heading("Limitations (mandatory - read before relying on this)", fontsize=12.0)
        for item in _LIMITATIONS:
            writer.bullet(item)

        result: bytes = doc.tobytes()
        return result
    finally:
        doc.close()
