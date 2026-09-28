"""Synthetic sample document for the M1 demo/acceptance script and for
`demo/generate_sample_pdf.py`.

All content is placeholder text, clearly labelled as synthetic — spec
Section 20: demo content must never be a real document.
"""

from __future__ import annotations

import pymupdf

TITLE = "OPERATION PLAN (SYNTHETIC — TRACESEAL DEMO CONTENT ONLY)"

_BODY_PARAGRAPHS = [
    "This document is a synthetic placeholder generated for TraceSeal "
    "demonstration and testing purposes only. It does not describe any "
    "real operation, unit, location, or individual, and contains no "
    "classified or sensitive information of any kind.",
    "The purpose of this generated text is to provide a realistic quantity "
    "and distribution of distinct words across several pages, so the mark "
    "position selector has enough eligible candidates to choose from when "
    "building per-recipient forensic variants of this document.",
    "Every recipient of a genuine TraceSeal-protected document receives a "
    "copy that looks completely identical to every other recipient's copy. "
    "The forensic fingerprint is invisible, encoded only in which of two "
    "otherwise indistinguishable renderings of certain words each copy "
    "happens to contain.",
    "Additional paragraphs of similar generated placeholder text follow, "
    "repeating common vocabulary so that the position selector's spacing "
    "and per-page limits are exercised the same way they would be against "
    "a real multi-page briefing document of comparable length and density.",
    "Personnel referenced in this synthetic scenario are fictional and any "
    "resemblance to real callsigns, unit designations, or place names is "
    "purely coincidental, since none were used in generating this text.",
    "This concludes the synthetic body content for this page of the "
    "generated TraceSeal demonstration document used only for automated "
    "testing and milestone acceptance checks, never for an actual release.",
]

PAGE_WIDTH = 612.0
PAGE_HEIGHT = 792.0
_MARGIN_LEFT = 72.0
_MARGIN_RIGHT = 72.0
_BODY_TOP = 140.0
_BODY_BOTTOM = 700.0


def build_sample_document(*, page_count: int = 3) -> pymupdf.Document:
    """Build an in-memory synthetic multi-page PDF with enough body text
    for the mark-position selector to have a reasonable candidate pool."""
    doc = pymupdf.open()
    body_rect = pymupdf.Rect(_MARGIN_LEFT, _BODY_TOP, PAGE_WIDTH - _MARGIN_RIGHT, _BODY_BOTTOM)
    for page_index in range(page_count):
        page = doc.new_page(width=PAGE_WIDTH, height=PAGE_HEIGHT)
        page.insert_text((_MARGIN_LEFT, 100.0), TITLE, fontsize=14, fontname="Helvetica-Bold")
        page.insert_text(
            (_MARGIN_LEFT, 118.0), f"Page {page_index + 1} of {page_count}", fontsize=9
        )
        body_text = " ".join(_BODY_PARAGRAPHS)
        page.insert_textbox(body_rect, body_text, fontsize=11, lineheight=1.4)
    return doc
