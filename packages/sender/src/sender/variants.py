"""Variant A (micro-shift) rendering and base-page extraction (spec Section 9).

For each mark position: the base page has the word's region redacted
(blanked), and two patch crops are produced — one with the word shifted
``-delta_px`` horizontally, one ``+delta_px`` — each re-rendered fresh from
vector text (not by shifting an already-rasterised crop, which would need
to fabricate the vacated/newly-exposed pixels and could show up as a
resampling artefact).

Implementation notes (see docs/DECISIONS.md ADR-0006) — two approaches were
tried and measured before landing on this one:

1. A translated ``pymupdf.Matrix`` over a fixed ``clip`` on the original
   page does **not** produce a shift at all: PyMuPDF sizes/positions the
   output raster from the *transformed* page rectangle, so translating the
   page's matrix cancels out relative to the clip (measured: 0 pixel
   difference).
2. Rendering the word alone on an isolated single-word page (then
   compositing it back) does produce a real shift, but even at zero shift
   it doesn't reconstruct the original exactly (measured: SSIM 0.948, not
   1.0) — an isolated page anti-aliases text slightly differently than the
   same glyph rendered as part of the full page, and naively pasting a
   padded rectangular patch also silently erases whatever legitimate
   neighbouring content (e.g. the start of the next word) falls inside the
   padding margin.

The approach actually used here — clone the whole page, redact just the
one target word, reinsert it at the shifted position on that *same, full*
page, then crop the padded region back out — measured SSIM 1.0 (pixel-
identical) at zero shift, confirming it reproduces the original rendering
context exactly and only genuinely changes what the shift itself changes.
It costs two extra full-page renders per position (one per variant bit),
which is fine at M1's scale; revisit if a much larger real document makes
this too slow.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pymupdf

from sender.positions import WordBox
from sender.rasterize import DEFAULT_DPI, points_to_pixel_scale, render_document, render_page

# Spec Section 9 suggests 2px at 300 DPI as a starting point; measured
# against the real ~150-position sample document (demo/M1 acceptance) that
# came in at whole-page SSIM 0.9799, just under the 0.98 gate. 1.5px clears
# it with margin (measured 0.985) while still being a real, detectable
# shift — see docs/DECISIONS.md ADR-0008.
DEFAULT_DELTA_PX = 1.5
DEFAULT_PATCH_PAD_PTS = 6.0


@dataclass(frozen=True)
class _SpanFont:
    name: str
    size: float
    color: tuple[float, float, float]
    baseline_y: float


def _unpack_color(value: int) -> tuple[float, float, float]:
    return ((value >> 16) & 0xFF) / 255.0, ((value >> 8) & 0xFF) / 255.0, (value & 0xFF) / 255.0


def _find_span_font(page: pymupdf.Page, bbox: tuple[float, float, float, float]) -> _SpanFont:
    cx, cy = (bbox[0] + bbox[2]) / 2.0, (bbox[1] + bbox[3]) / 2.0
    for block in page.get_text("dict")["blocks"]:
        for line in block.get("lines", []):
            for span in line["spans"]:
                sx0, sy0, sx1, sy1 = span["bbox"]
                if sx0 - 1 <= cx <= sx1 + 1 and sy0 - 1 <= cy <= sy1 + 1:
                    return _SpanFont(
                        name=span["font"],
                        size=span["size"],
                        color=_unpack_color(span["color"]),
                        baseline_y=span["origin"][1],
                    )
    raise ValueError(f"no text span found covering bbox {bbox}")


def _resolve_fontname(name: str) -> str:
    # insert_text accepts the full Base14 names directly; anything else
    # (an embedded/subset font from a real-world PDF) falls back to
    # Helvetica. Fine for our own synthetic demo document (which only ever
    # uses Base14 fonts); real-world-PDF font-matching is out of scope for
    # M1 — see docs/DECISIONS.md ADR-0006.
    return name if name in pymupdf.Base14_fontnames else "Helvetica"


def _pixel_bbox(
    bbox: tuple[float, float, float, float], pad_pts: float, dpi: int
) -> tuple[int, int, int, int]:
    scale = points_to_pixel_scale(dpi)
    x0, y0, x1, y1 = bbox
    return (
        round((x0 - pad_pts) * scale),
        round((y0 - pad_pts) * scale),
        round((x1 + pad_pts) * scale),
        round((y1 + pad_pts) * scale),
    )


def _render_page_with_word_shifted(
    doc: pymupdf.Document, word: WordBox, font: _SpanFont, dx_pts: float, dpi: int
) -> np.ndarray:
    """Clone ``doc``, redact ``word`` on its page, reinsert it shifted by
    ``dx_pts``, and render that page — full page, full original context."""
    clone = pymupdf.open("pdf", doc.write())
    try:
        page = clone[word.page_index]
        x0, y0, x1, y1 = word.bbox
        page.add_redact_annot(pymupdf.Rect(x0, y0, x1, y1), fill=(1, 1, 1))
        page.apply_redactions()
        fontname = _resolve_fontname(font.name)
        page.insert_text(
            (x0 + dx_pts, font.baseline_y),
            word.text,
            fontsize=font.size,
            fontname=fontname,
            color=font.color,
        )
        return render_page(page, dpi)
    finally:
        clone.close()


def render_variant_patches(
    doc: pymupdf.Document,
    word: WordBox,
    *,
    dpi: int = DEFAULT_DPI,
    delta_px: float = DEFAULT_DELTA_PX,
    pad_pts: float = DEFAULT_PATCH_PAD_PTS,
) -> tuple[np.ndarray, np.ndarray]:
    """Render the bit-0 (shifted left) and bit-1 (shifted right) patches
    for ``word``, cropped from a full re-render of its page."""
    font = _find_span_font(doc[word.page_index], word.bbox)
    scale = points_to_pixel_scale(dpi)
    delta_pts = delta_px / scale
    px0, py0, px1, py1 = _pixel_bbox(word.bbox, pad_pts, dpi)

    page_bit0 = _render_page_with_word_shifted(doc, word, font, -delta_pts, dpi)
    page_bit1 = _render_page_with_word_shifted(doc, word, font, delta_pts, dpi)
    return page_bit0[py0:py1, px0:px1].copy(), page_bit1[py0:py1, px0:px1].copy()


@dataclass(frozen=True)
class RenderedPosition:
    position: WordBox
    patch_bit0: np.ndarray
    patch_bit1: np.ndarray
    pixel_bbox: tuple[int, int, int, int]  # (x0, y0, x1, y1) on the full page raster


@dataclass(frozen=True)
class DocumentVariants:
    dpi: int
    original_pages: list[np.ndarray]  # rendered before any redaction (quality-gate reference)
    base_pages: list[np.ndarray]  # rendered after redacting every mark position
    rendered_positions: list[RenderedPosition]


def build_document_variants(
    doc: pymupdf.Document,
    positions: list[WordBox],
    *,
    dpi: int = DEFAULT_DPI,
    delta_px: float = DEFAULT_DELTA_PX,
    pad_pts: float = DEFAULT_PATCH_PAD_PTS,
) -> DocumentVariants:
    original_pages = render_document(doc, dpi)

    rendered_positions: list[RenderedPosition] = []
    for word in positions:
        patch0, patch1 = render_variant_patches(
            doc, word, dpi=dpi, delta_px=delta_px, pad_pts=pad_pts
        )
        pixel_bbox = _pixel_bbox(word.bbox, pad_pts, dpi)
        rendered_positions.append(
            RenderedPosition(
                position=word, patch_bit0=patch0, patch_bit1=patch1, pixel_bbox=pixel_bbox
            )
        )

    # Base pages: a single clone with every mark position's own (unpadded)
    # bbox redacted — this is the "clean slate" every variant patch gets
    # pasted onto at assembly time.
    base_doc = pymupdf.open("pdf", doc.write())
    try:
        pages_with_marks = {word.page_index for word in positions}
        for word in positions:
            base_doc[word.page_index].add_redact_annot(pymupdf.Rect(word.bbox), fill=(1, 1, 1))
        for page_index in pages_with_marks:
            base_doc[page_index].apply_redactions()
        base_pages = render_document(base_doc, dpi)
    finally:
        base_doc.close()

    return DocumentVariants(
        dpi=dpi,
        original_pages=original_pages,
        base_pages=base_pages,
        rendered_positions=rendered_positions,
    )
