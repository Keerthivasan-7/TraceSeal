"""Per-position informed detection (spec Section 11 step 5).

For each mark position: search a small margin around its recorded
``pixel_bbox`` in the (globally-registered) artifact for the
best-correlating location of each of that position's two known variant
patches, via normalised cross-correlation template matching. Whichever
patch's best local match scores higher is the observed symbol; if the two
best scores are too close to call, the position is erased (``nan``)
instead of guessed — `tscore.tardos` is erasure-aware by design.

The local per-position search (not just a direct crop-and-compare at the
globally registered location) turned out to be load-bearing, not optional
polish — this is `docs/DECISIONS.md` ADR-0010: ORB+RANSAC's *global*
homography (`align.py`) can carry several pixels of residual drift even
with hundreds of inlier matches (measured: a real run had 371/561 inliers
yet a 5.7px/3.2px translation error) — small next to a whole page, but
larger than the 1.5px shift this whole scheme depends on detecting. A
direct crop at that drifted location got only 25/49 positions right
(worse than coin-flipping) on the affected page; searching an 8px margin
locally around each position independently — the numerically robust
alternative to the spec's suggested ECC refinement, which failed to
converge on this same case — recovered 49/49. This is exactly the
"RANSAC homography, then local refinement per region" spec Section 11
step 4 describes, just via template-match search rather than ECC.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import cv2
import numpy as np
from sender.variants import RenderedPosition

DEFAULT_CONFIDENCE_THRESHOLD = 0.05
DEFAULT_SEARCH_MARGIN_PX = 10


def _ncc(a: np.ndarray, b: np.ndarray) -> float:
    a_flat = a.astype(np.float64).ravel() - a.mean()
    b_flat = b.astype(np.float64).ravel() - b.mean()
    denom = float(np.linalg.norm(a_flat) * np.linalg.norm(b_flat))
    if denom == 0.0:
        return 0.0
    return float(np.dot(a_flat, b_flat) / denom)


def _best_local_match(search_region: np.ndarray, patch: np.ndarray) -> float:
    ph, pw = patch.shape[:2]
    if search_region.shape[0] < ph or search_region.shape[1] < pw:
        # Search region too small (near a page edge) to slide the patch at
        # all — fall back to a direct, unrefined comparison.
        crop = search_region[:ph, :pw]
        return _ncc(crop, patch) if crop.shape[:2] == (ph, pw) else 0.0
    result = cv2.matchTemplate(search_region, patch, cv2.TM_CCOEFF_NORMED)
    return float(result.max())


@dataclass(frozen=True)
class PositionObservation:
    position_index: int
    observed_bit: float  # 0.0, 1.0, or nan (erasure)
    score_bit0: float
    score_bit1: float

    @property
    def confidence(self) -> float:
        return abs(self.score_bit1 - self.score_bit0)

    @property
    def is_erasure(self) -> bool:
        return math.isnan(self.observed_bit)


def detect_positions(
    aligned_artifact: np.ndarray,
    rendered_positions: list[RenderedPosition],
    *,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    search_margin_px: int = DEFAULT_SEARCH_MARGIN_PX,
) -> list[PositionObservation]:
    """Detect the observed bit at every position whose search region fits
    inside ``aligned_artifact``; positions that don't (e.g. on a different
    page than the one actually captured) are skipped, not erased — an
    erasure means "we looked and couldn't tell", not "we didn't look"."""
    height, width = aligned_artifact.shape[:2]
    observations: list[PositionObservation] = []
    for idx, rp in enumerate(rendered_positions):
        x0, y0, x1, y1 = rp.pixel_bbox
        sx0, sy0 = max(x0 - search_margin_px, 0), max(y0 - search_margin_px, 0)
        sx1, sy1 = min(x1 + search_margin_px, width), min(y1 + search_margin_px, height)
        if sx0 >= sx1 or sy0 >= sy1:
            continue
        search_region = aligned_artifact[sy0:sy1, sx0:sx1]

        score0 = _best_local_match(search_region, rp.patch_bit0)
        score1 = _best_local_match(search_region, rp.patch_bit1)
        if abs(score1 - score0) < confidence_threshold:
            observed_bit = math.nan
        else:
            observed_bit = 1.0 if score1 > score0 else 0.0
        observations.append(
            PositionObservation(
                position_index=idx, observed_bit=observed_bit, score_bit0=score0, score_bit1=score1
            )
        )
    return observations
