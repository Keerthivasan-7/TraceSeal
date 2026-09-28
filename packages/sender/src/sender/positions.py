"""Mark-position selection via PyMuPDF word boxes (spec Section 9).

Words of 4+ characters, a header/footer exclusion margin (likely to be
cropped in a leaked capture), a per-page cap, and — the geometrically
load-bearing constraint — no two selected positions' *padded* patch
regions may overlap.

Padded-bbox overlap, not a simple center-to-center distance, is what
actually matters: `variants.py` renders each position as a patch padded by
``patch_pad_pts`` on every side, and `assemble.py` pastes those patches
onto the page independently. If two padded patches overlap, whichever gets
pasted second silently overwrites part of the first, corrupting both
positions' final pixels — found empirically via a test that pasted a
random codeword and diffed the assembled page against each position's own
recorded patch (see docs/DECISIONS.md ADR-0006). A center-distance
threshold doesn't reliably prevent this because word widths vary; a direct
overlap check on the actual padded rectangles does.
"""

from __future__ import annotations

from dataclasses import dataclass

import pymupdf

DEFAULT_MIN_WORD_LEN = 4
DEFAULT_PATCH_PAD_PTS = 6.0
DEFAULT_EXTRA_GAP_PTS = 4.0
DEFAULT_MARGIN_FRAC = 0.1
DEFAULT_MAX_PER_PAGE = 300


@dataclass(frozen=True)
class WordBox:
    page_index: int
    bbox: tuple[float, float, float, float]  # (x0, y0, x1, y1), PDF points
    text: str

    @property
    def center(self) -> tuple[float, float]:
        x0, y0, x1, y1 = self.bbox
        return (x0 + x1) / 2.0, (y0 + y1) / 2.0


def _page_word_boxes(page: pymupdf.Page, page_index: int) -> list[WordBox]:
    return [
        WordBox(page_index=page_index, bbox=(w[0], w[1], w[2], w[3]), text=w[4])
        for w in page.get_text("words")
    ]


def _expand(
    bbox: tuple[float, float, float, float], pad: float
) -> tuple[float, float, float, float]:
    x0, y0, x1, y1 = bbox
    return (x0 - pad, y0 - pad, x1 + pad, y1 + pad)


def _rects_overlap(
    a: tuple[float, float, float, float], b: tuple[float, float, float, float]
) -> bool:
    ax0, ay0, ax1, ay1 = a
    bx0, by0, bx1, by1 = b
    return ax0 < bx1 and bx0 < ax1 and ay0 < by1 and by0 < ay1


def select_positions(
    doc: pymupdf.Document,
    *,
    min_word_len: int = DEFAULT_MIN_WORD_LEN,
    patch_pad_pts: float = DEFAULT_PATCH_PAD_PTS,
    extra_gap_pts: float = DEFAULT_EXTRA_GAP_PTS,
    margin_frac: float = DEFAULT_MARGIN_FRAC,
    max_per_page: int = DEFAULT_MAX_PER_PAGE,
) -> list[WordBox]:
    """Select mark positions across every page of ``doc``, in reading order.

    ``patch_pad_pts`` must match the padding `variants.py` will render each
    patch with (its default does); ``extra_gap_pts`` adds a little further
    breathing room between adjacent padded patches.
    """
    if not 0.0 <= margin_frac < 0.5:
        raise ValueError("margin_frac must be in [0, 0.5)")
    half_gap = extra_gap_pts / 2.0
    selected: list[WordBox] = []
    for page_index in range(doc.page_count):
        page = doc[page_index]
        page_height = page.rect.height
        top = margin_frac * page_height
        bottom = (1.0 - margin_frac) * page_height
        candidates = [
            wb
            for wb in _page_word_boxes(page, page_index)
            if len(wb.text) >= min_word_len and top <= wb.bbox[1] and wb.bbox[3] <= bottom
        ]
        accepted: list[WordBox] = []
        accepted_padded: list[tuple[float, float, float, float]] = []
        for wb in candidates:
            padded = _expand(wb.bbox, patch_pad_pts + half_gap)
            if any(_rects_overlap(padded, other) for other in accepted_padded):
                continue
            accepted.append(wb)
            accepted_padded.append(padded)
            if len(accepted) >= max_per_page:
                break
        selected.extend(accepted)
    return selected
