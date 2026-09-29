"""The declarative list of every condition spec Section 15 requires — the
single source of truth `harness.py`, `demo_m7.py`, and
`tests/test_conditions.py` all read from, so "every required condition was
actually run" is a mechanical check, not an eyeball review.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import numpy as np

from attacklab.distortions import (
    add_gaussian_noise,
    adjust_brightness_contrast,
    crop_fraction,
    gaussian_blur,
    jpeg_recompress,
    perspective_warp,
    print_scan_pipeline,
    resize_scale,
    rotate_degrees,
    screen_camera_pipeline,
)

Apply = Callable[[np.ndarray, np.random.Generator], np.ndarray]


@dataclass(frozen=True)
class DistortionCondition:
    name: str
    apply: Apply
    params: dict[str, object] = field(default_factory=dict)


def _jpeg(quality: int) -> DistortionCondition:
    return DistortionCondition(
        f"jpeg_q{quality}", lambda img, rng: jpeg_recompress(img, quality), {"quality": quality}
    )


def _resize(scale: float) -> DistortionCondition:
    return DistortionCondition(
        f"resize_x{scale}", lambda img, rng: resize_scale(img, scale), {"scale": scale}
    )


def _crop(pct: int) -> DistortionCondition:
    fraction = pct / 100.0
    return DistortionCondition(
        f"crop_{pct}pct", lambda img, rng: crop_fraction(img, fraction, rng), {"fraction": fraction}
    )


def _rotate(degrees: float) -> DistortionCondition:
    sign = "+" if degrees >= 0 else "-"
    return DistortionCondition(
        f"rotate_{sign}{abs(degrees):g}deg",
        lambda img, rng: rotate_degrees(img, degrees),
        {"degrees": degrees},
    )


def _blur(sigma: float) -> DistortionCondition:
    return DistortionCondition(
        f"blur_sigma{sigma:g}", lambda img, rng: gaussian_blur(img, sigma), {"sigma": sigma}
    )


# spec Section 15: "noise" and "brightness and contrast" are each named as
# one condition (not a swept range like JPEG/resize/crop/rotation/blur), so
# one representative parameter set is used for each — moderate,
# phone-camera-like sensor noise and a moderate exposure shift.
_NOISE_SIGMA = 8.0
_BRIGHTNESS_DELTA = 15.0
_CONTRAST_FACTOR = 1.15

SYNTHETIC_CONDITIONS: list[DistortionCondition] = [
    *(_jpeg(q) for q in (90, 70, 50, 30)),
    *(_resize(s) for s in (0.75, 0.5)),
    *(_crop(p) for p in (10, 30, 50)),
    *(_rotate(d) for d in (1.0, -1.0, 3.0, -3.0)),
    DistortionCondition("perspective_warp", perspective_warp),
    *(_blur(s) for s in (0.5, 1.0, 1.5)),
    DistortionCondition(
        "noise",
        lambda img, rng: add_gaussian_noise(img, _NOISE_SIGMA, rng),
        {"sigma": _NOISE_SIGMA},
    ),
    DistortionCondition(
        "brightness_contrast",
        lambda img, rng: adjust_brightness_contrast(img, _BRIGHTNESS_DELTA, _CONTRAST_FACTOR),
        {"brightness": _BRIGHTNESS_DELTA, "contrast": _CONTRAST_FACTOR},
    ),
    DistortionCondition("screen_camera", screen_camera_pipeline),
    DistortionCondition("print_scan", print_scan_pipeline),
]


@dataclass(frozen=True)
class CollusionCondition:
    strategy: str  # "majority" | "minority" | "random" | "interleave" | "patch_averaging"
    c: int

    @property
    def name(self) -> str:
        return f"collusion_{self.strategy}_c{self.c}"


COLLUSION_STRATEGIES = ("majority", "minority", "random", "interleave", "patch_averaging")

COLLUSION_CONDITIONS: list[CollusionCondition] = [
    CollusionCondition(strategy=strategy, c=c)
    for c in (2, 3, 4)
    for strategy in COLLUSION_STRATEGIES
]
