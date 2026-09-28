"""Quality gate (spec Section 9): every assembled page must be visually
indistinguishable from the original, whichever variant bit it's built
from.

Two complementary checks per page/variant-bit:

- **Whole-page SSIM** against the original rendering (spec's literal
  wording) plus a whole-page max-pixel-delta report. This is what's
  actually achievable and meaningful at the *document* level — a page is
  mostly unmarked background, so this easily clears a high bar for a
  legitimately rendered variant.
- **Per-position corruption check**: whole-page SSIM alone can't catch a
  single badly broken patch (confirmed empirically: zeroing one patch out
  entirely barely moved a whole-page SSIM score). Comparing each position's
  own bit-0 vs bit-1 patch and flagging an anomalously large *changed-pixel
  fraction* does catch it — a legitimate micro-shift changes roughly 10-15%
  of a patch's pixels (measured), so a fraction far above that (default
  bound: 50%) means something is actually broken (wrong font, wrong
  content, a rendering failure), not just the intended shift. Pixel-precise
  SSIM on the tiny patch itself was tried first and rejected: even a
  perfect, correctly-shifted patch scores ~0.6-0.7 there, because SSIM's
  small local windows are inherently oversensitive to a couple of pixels of
  edge misalignment on thin text strokes — not a defect, just a property of
  the metric on this kind of content.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from skimage.metrics import structural_similarity

from sender.assemble import assemble_document
from sender.variants import DocumentVariants

DEFAULT_SSIM_THRESHOLD = 0.98
DEFAULT_MAX_CHANGED_FRACTION = 0.5
_CHANGE_PIXEL_TOLERANCE = 30  # per-channel abs delta below this doesn't count as "changed"


def _whole_page_ssim(a: np.ndarray, b: np.ndarray) -> float:
    return float(structural_similarity(a, b, channel_axis=2, data_range=255))


@dataclass(frozen=True)
class PagePassResult:
    page_index: int
    variant_bit: int
    ssim: float
    max_abs_delta: int
    passed: bool


@dataclass(frozen=True)
class PositionCorruptionResult:
    position_index: int
    changed_fraction: float
    passed: bool


@dataclass(frozen=True)
class QualityGateReport:
    ssim_threshold: float
    max_changed_fraction: float
    pages: list[PagePassResult]
    positions: list[PositionCorruptionResult]

    @property
    def passed(self) -> bool:
        return all(p.passed for p in self.pages) and all(p.passed for p in self.positions)


def run_quality_gate(
    doc_variants: DocumentVariants,
    *,
    ssim_threshold: float = DEFAULT_SSIM_THRESHOLD,
    max_changed_fraction: float = DEFAULT_MAX_CHANGED_FRACTION,
) -> QualityGateReport:
    pages: list[PagePassResult] = []
    n_positions = len(doc_variants.rendered_positions)

    for variant_bit in (0, 1):
        codeword = np.full(n_positions, variant_bit, dtype=np.int8)
        assembled = assemble_document(doc_variants, codeword)
        for page_index, (original, page) in enumerate(
            zip(doc_variants.original_pages, assembled, strict=True)
        ):
            ssim_score = _whole_page_ssim(original, page)
            max_delta = int(np.abs(original.astype(int) - page.astype(int)).max())
            pages.append(
                PagePassResult(
                    page_index=page_index,
                    variant_bit=variant_bit,
                    ssim=ssim_score,
                    max_abs_delta=max_delta,
                    passed=ssim_score >= ssim_threshold,
                )
            )

    positions: list[PositionCorruptionResult] = []
    for idx, rp in enumerate(doc_variants.rendered_positions):
        delta = np.abs(rp.patch_bit0.astype(int) - rp.patch_bit1.astype(int)).max(axis=2)
        changed_fraction = float((delta > _CHANGE_PIXEL_TOLERANCE).mean())
        positions.append(
            PositionCorruptionResult(
                position_index=idx,
                changed_fraction=changed_fraction,
                passed=changed_fraction <= max_changed_fraction,
            )
        )

    return QualityGateReport(
        ssim_threshold=ssim_threshold,
        max_changed_fraction=max_changed_fraction,
        pages=pages,
        positions=positions,
    )
