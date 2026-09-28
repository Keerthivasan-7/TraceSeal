"""Feature-based artifact registration (spec Section 11 step 4).

ORB keypoints + a ratio-tested Hamming matcher + RANSAC homography, then
warp the artifact into the reference image's pixel coordinate frame. The
reference is the base page with variant-bit-0 assembled everywhere (spec:
"matched against the original base-plus-variant-0 rendering").

Measured against the real M2 demo scenario before relying on this
(docs/DECISIONS.md ADR-0009): a screenshot downscaled to 50% of the
original 300 DPI render recovers a homography within ~0.05% of the true
2.0x scale, with 374/561 matches surviving as RANSAC inliers, and the
warped result matches the reference at mean pixel difference 3.7/255
(anti-aliasing/resampling noise from the downscale-then-warp round trip,
not a misalignment).
"""

from __future__ import annotations

from dataclasses import dataclass

import cv2
import numpy as np

DEFAULT_MAX_FEATURES = 3000
DEFAULT_RATIO_TEST = 0.75
DEFAULT_RANSAC_REPROJ_THRESHOLD = 5.0
MIN_GOOD_MATCHES = 10


class RegistrationError(Exception):
    """Raised when an artifact can't be reliably registered against the
    reference (too few features/matches, or homography estimation failed).
    """


@dataclass(frozen=True)
class AlignmentResult:
    warped: np.ndarray
    homography: np.ndarray
    n_keypoints_artifact: int
    n_keypoints_reference: int
    n_good_matches: int
    n_inliers: int

    @property
    def inlier_ratio(self) -> float:
        return self.n_inliers / self.n_good_matches if self.n_good_matches else 0.0


def _to_gray(image: np.ndarray) -> np.ndarray:
    result: np.ndarray = cv2.cvtColor(image, cv2.COLOR_RGB2GRAY)
    return result


def register(
    artifact: np.ndarray,
    reference: np.ndarray,
    *,
    max_features: int = DEFAULT_MAX_FEATURES,
    ratio_test: float = DEFAULT_RATIO_TEST,
    ransac_reproj_threshold: float = DEFAULT_RANSAC_REPROJ_THRESHOLD,
) -> AlignmentResult:
    """Register ``artifact`` against ``reference``, warping it into
    ``reference``'s pixel coordinate frame."""
    orb = cv2.ORB_create(nfeatures=max_features)  # type: ignore[attr-defined]
    kp_artifact, des_artifact = orb.detectAndCompute(_to_gray(artifact), None)
    kp_reference, des_reference = orb.detectAndCompute(_to_gray(reference), None)
    if des_artifact is None or des_reference is None:
        raise RegistrationError("no ORB features detected in artifact or reference")

    matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
    raw_matches = matcher.knnMatch(des_artifact, des_reference, k=2)
    good_matches = [m for m, n in raw_matches if m.distance < ratio_test * n.distance]
    if len(good_matches) < MIN_GOOD_MATCHES:
        raise RegistrationError(
            f"only {len(good_matches)} good feature matches (need >= {MIN_GOOD_MATCHES})"
        )

    src_points = [kp_artifact[m.queryIdx].pt for m in good_matches]
    dst_points = [kp_reference[m.trainIdx].pt for m in good_matches]
    src_pts = np.float32(src_points).reshape(-1, 1, 2)  # type: ignore[arg-type]
    dst_pts = np.float32(dst_points).reshape(-1, 1, 2)  # type: ignore[arg-type]
    homography, inlier_mask = cv2.findHomography(
        src_pts, dst_pts, cv2.RANSAC, ransac_reproj_threshold
    )
    if homography is None:
        raise RegistrationError("homography estimation failed")

    ref_height, ref_width = reference.shape[:2]
    warped = cv2.warpPerspective(
        artifact, homography, (ref_width, ref_height), borderValue=(255, 255, 255)
    )

    return AlignmentResult(
        warped=warped,
        homography=homography,
        n_keypoints_artifact=len(kp_artifact),
        n_keypoints_reference=len(kp_reference),
        n_good_matches=len(good_matches),
        n_inliers=int(inlier_mask.sum()) if inlier_mask is not None else 0,
    )
