from __future__ import annotations

from attacklab.conditions import COLLUSION_CONDITIONS, COLLUSION_STRATEGIES, SYNTHETIC_CONDITIONS

# Spec Section 15's exact required condition list, mirrored here as a
# reference so a typo or an accidentally-removed condition in
# conditions.py fails this test rather than silently shrinking coverage.
_EXPECTED_JPEG_Q = {90, 70, 50, 30}
_EXPECTED_RESIZE_SCALES = {0.75, 0.5}
_EXPECTED_CROP_PCT = {10, 30, 50}
_EXPECTED_ROTATIONS = {1.0, -1.0, 3.0, -3.0}
_EXPECTED_BLUR_SIGMAS = {0.5, 1.0, 1.5}


def test_no_duplicate_synthetic_condition_names() -> None:
    names = [c.name for c in SYNTHETIC_CONDITIONS]
    assert len(names) == len(set(names))


def test_every_jpeg_quality_present() -> None:
    qualities = {c.params["quality"] for c in SYNTHETIC_CONDITIONS if c.name.startswith("jpeg_q")}
    assert qualities == _EXPECTED_JPEG_Q


def test_every_resize_scale_present() -> None:
    scales = {c.params["scale"] for c in SYNTHETIC_CONDITIONS if c.name.startswith("resize_x")}
    assert scales == _EXPECTED_RESIZE_SCALES


def test_every_crop_fraction_present() -> None:
    fractions = {c.params["fraction"] for c in SYNTHETIC_CONDITIONS if c.name.startswith("crop_")}
    assert fractions == {p / 100.0 for p in _EXPECTED_CROP_PCT}


def test_every_rotation_present() -> None:
    degrees = {c.params["degrees"] for c in SYNTHETIC_CONDITIONS if c.name.startswith("rotate_")}
    assert degrees == _EXPECTED_ROTATIONS


def test_every_blur_sigma_present() -> None:
    sigmas = {c.params["sigma"] for c in SYNTHETIC_CONDITIONS if c.name.startswith("blur_sigma")}
    assert sigmas == _EXPECTED_BLUR_SIGMAS


def test_singleton_named_conditions_present() -> None:
    names = {c.name for c in SYNTHETIC_CONDITIONS}
    expected_names = (
        "perspective_warp",
        "noise",
        "brightness_contrast",
        "screen_camera",
        "print_scan",
    )
    for expected in expected_names:
        assert expected in names


def test_no_duplicate_collusion_conditions() -> None:
    pairs = [(c.strategy, c.c) for c in COLLUSION_CONDITIONS]
    assert len(pairs) == len(set(pairs))


def test_every_collusion_c_and_strategy_combination_present() -> None:
    pairs = {(c.strategy, c.c) for c in COLLUSION_CONDITIONS}
    expected = {(strategy, c) for c in (2, 3, 4) for strategy in COLLUSION_STRATEGIES}
    assert pairs == expected
