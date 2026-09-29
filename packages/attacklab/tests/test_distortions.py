from __future__ import annotations

import numpy as np
import pytest

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


@pytest.fixture
def sample_image() -> np.ndarray:
    # A synthetic gradient + checkerboard pattern, not flat/noise, so
    # compression/blur/rotation produce a real, measurable difference.
    height, width = 120, 200
    y, x = np.mgrid[0:height, 0:width]
    gradient = ((x * 255 // width) + (y * 255 // height)) // 2
    checker = ((x // 10 + y // 10) % 2) * 255
    channel = np.clip(gradient // 2 + checker // 2, 0, 255).astype(np.uint8)
    return np.stack([channel, channel, channel], axis=-1)


def _mean_abs_diff(a: np.ndarray, b: np.ndarray) -> float:
    a32, b32 = a.astype(np.float64), b.astype(np.float64)
    if a32.shape != b32.shape:
        return float("inf")
    return float(np.abs(a32 - b32).mean())


class TestDeterminism:
    def test_jpeg_recompress_deterministic(self, sample_image: np.ndarray) -> None:
        assert np.array_equal(jpeg_recompress(sample_image, 70), jpeg_recompress(sample_image, 70))

    def test_resize_scale_deterministic(self, sample_image: np.ndarray) -> None:
        assert np.array_equal(resize_scale(sample_image, 0.5), resize_scale(sample_image, 0.5))

    def test_rotate_degrees_deterministic(self, sample_image: np.ndarray) -> None:
        assert np.array_equal(rotate_degrees(sample_image, 3.0), rotate_degrees(sample_image, 3.0))

    def test_gaussian_blur_deterministic(self, sample_image: np.ndarray) -> None:
        assert np.array_equal(gaussian_blur(sample_image, 1.0), gaussian_blur(sample_image, 1.0))

    def test_brightness_contrast_deterministic(self, sample_image: np.ndarray) -> None:
        a = adjust_brightness_contrast(sample_image, 15.0, 1.15)
        b = adjust_brightness_contrast(sample_image, 15.0, 1.15)
        assert np.array_equal(a, b)

    def test_crop_fraction_deterministic_given_seed(self, sample_image: np.ndarray) -> None:
        a = crop_fraction(sample_image, 0.3, np.random.default_rng(7))
        b = crop_fraction(sample_image, 0.3, np.random.default_rng(7))
        assert np.array_equal(a, b)

    def test_perspective_warp_deterministic_given_seed(self, sample_image: np.ndarray) -> None:
        a = perspective_warp(sample_image, np.random.default_rng(7))
        b = perspective_warp(sample_image, np.random.default_rng(7))
        assert np.array_equal(a, b)

    def test_add_gaussian_noise_deterministic_given_seed(self, sample_image: np.ndarray) -> None:
        a = add_gaussian_noise(sample_image, 8.0, np.random.default_rng(7))
        b = add_gaussian_noise(sample_image, 8.0, np.random.default_rng(7))
        assert np.array_equal(a, b)

    def test_screen_camera_pipeline_deterministic_given_seed(
        self, sample_image: np.ndarray
    ) -> None:
        a = screen_camera_pipeline(sample_image, np.random.default_rng(7))
        b = screen_camera_pipeline(sample_image, np.random.default_rng(7))
        assert np.array_equal(a, b)

    def test_print_scan_pipeline_deterministic_given_seed(self, sample_image: np.ndarray) -> None:
        a = print_scan_pipeline(sample_image, np.random.default_rng(7))
        b = print_scan_pipeline(sample_image, np.random.default_rng(7))
        assert np.array_equal(a, b)


class TestInvariantsAndDirection:
    def test_jpeg_output_dtype_and_shape(self, sample_image: np.ndarray) -> None:
        out = jpeg_recompress(sample_image, 70)
        assert out.dtype == np.uint8
        assert out.shape == sample_image.shape

    def test_jpeg_lower_quality_differs_more(self, sample_image: np.ndarray) -> None:
        diff_high_q = _mean_abs_diff(sample_image, jpeg_recompress(sample_image, 90))
        diff_low_q = _mean_abs_diff(sample_image, jpeg_recompress(sample_image, 30))
        assert diff_low_q > diff_high_q

    def test_resize_scale_shrinks_dimensions(self, sample_image: np.ndarray) -> None:
        out = resize_scale(sample_image, 0.5)
        assert out.shape[0] == round(sample_image.shape[0] * 0.5)
        assert out.shape[1] == round(sample_image.shape[1] * 0.5)

    def test_crop_fraction_removes_roughly_the_requested_area(
        self, sample_image: np.ndarray
    ) -> None:
        out = crop_fraction(sample_image, 0.5, np.random.default_rng(0))
        assert out.shape == sample_image.shape
        white_fraction = float(np.mean(np.all(out == 255, axis=-1)))
        assert white_fraction == pytest.approx(0.5, abs=0.02)

    def test_crop_fraction_rejects_out_of_range(self, sample_image: np.ndarray) -> None:
        with pytest.raises(ValueError):
            crop_fraction(sample_image, 1.5, np.random.default_rng(0))

    def test_rotate_degrees_zero_is_near_identity(self, sample_image: np.ndarray) -> None:
        out = rotate_degrees(sample_image, 0.0)
        assert _mean_abs_diff(sample_image, out) < 1.0

    def test_gaussian_blur_zero_sigma_is_identity(self, sample_image: np.ndarray) -> None:
        out = gaussian_blur(sample_image, 0.0)
        assert np.array_equal(sample_image, out)

    def test_gaussian_blur_larger_sigma_blurs_more(self, sample_image: np.ndarray) -> None:
        diff_small = _mean_abs_diff(sample_image, gaussian_blur(sample_image, 0.5))
        diff_large = _mean_abs_diff(sample_image, gaussian_blur(sample_image, 1.5))
        assert diff_large > diff_small

    def test_add_gaussian_noise_changes_pixels(self, sample_image: np.ndarray) -> None:
        out = add_gaussian_noise(sample_image, 8.0, np.random.default_rng(0))
        assert out.dtype == np.uint8
        assert not np.array_equal(sample_image, out)

    def test_brightness_contrast_increases_mean(self, sample_image: np.ndarray) -> None:
        out = adjust_brightness_contrast(sample_image, 15.0, 1.0)
        assert out.astype(np.float64).mean() > sample_image.astype(np.float64).mean()

    def test_perspective_warp_output_shape_preserved(self, sample_image: np.ndarray) -> None:
        out = perspective_warp(sample_image, np.random.default_rng(0))
        assert out.shape == sample_image.shape

    def test_screen_camera_pipeline_output_dtype(self, sample_image: np.ndarray) -> None:
        out = screen_camera_pipeline(sample_image, np.random.default_rng(0))
        assert out.dtype == np.uint8
        assert out.ndim == 3

    def test_print_scan_pipeline_output_dtype(self, sample_image: np.ndarray) -> None:
        out = print_scan_pipeline(sample_image, np.random.default_rng(0))
        assert out.dtype == np.uint8
        assert out.shape == sample_image.shape
