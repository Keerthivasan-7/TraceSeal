"""Seeded, reproducible image distortions (spec Section 15).

Every function takes/returns an ``(H, W, 3) uint8`` array in the same
channel convention every other TraceSeal image (`sender`/`forensics`) uses
— the codebase never distinguishes RGB from BGR explicitly (see
`forensics.align._to_gray`'s `cv2.COLOR_RGB2GRAY`), and none of the
operations here (JPEG recompression, resizing, blur, noise, rotation,
perspective warp) depend on that distinction either, so channel order is
simply preserved end to end.

Every function that needs randomness takes an explicit
``rng: np.random.Generator`` parameter — never a global/module-level RNG —
so a single top-level seed threaded through the harness (a fresh
``np.random.default_rng(seed)`` per trial) makes every distortion
reproducible bit-for-bit. Functions with no random component (JPEG
recompression, resizing, blur, a fixed-degree rotation) simply don't take
one.
"""

from __future__ import annotations

import cv2
import numpy as np

WHITE = (255, 255, 255)


def jpeg_recompress(image: np.ndarray, quality: int) -> np.ndarray:
    """Re-encode/decode through JPEG at ``quality`` (0-100). Deterministic:
    JPEG's quantization has no random component."""
    ok, encoded = cv2.imencode(".jpg", image, [cv2.IMWRITE_JPEG_QUALITY, quality])
    if not ok:
        raise ValueError("JPEG encoding failed")
    decoded = cv2.imdecode(encoded, cv2.IMREAD_COLOR)
    if decoded is None:
        raise ValueError("JPEG decoding failed")
    return decoded


def resize_scale(image: np.ndarray, scale: float) -> np.ndarray:
    """Resize by ``scale`` (e.g. 0.5 halves both dimensions) — a genuinely
    smaller output array, the same "lower-resolution capture" shape
    `forensics.demo_m2._simulate_screenshot` already produces (registration
    recovers the scale change as part of its homography; the distortion
    itself doesn't need to undo it). Deterministic: no random component."""
    height, width = image.shape[:2]
    down_w, down_h = max(1, round(width * scale)), max(1, round(height * scale))
    interpolation = cv2.INTER_AREA if scale < 1.0 else cv2.INTER_LINEAR
    downscaled: np.ndarray = cv2.resize(image, (down_w, down_h), interpolation=interpolation)
    return downscaled


def crop_fraction(image: np.ndarray, fraction: float, rng: np.random.Generator) -> np.ndarray:
    """Remove ``fraction`` of the page's area as a single border strip (one
    of top/bottom/left/right, chosen by ``rng``) and pad the removed region
    back to white — simulates a capture that missed part of the page while
    keeping every mark position's pixel coordinates meaningful (an outright
    smaller output array would silently shift every remaining position).
    A vertical strip of width ``fraction * width`` removes exactly
    ``fraction`` of the total area (full height); a horizontal strip works
    the same way for height."""
    if not 0.0 < fraction < 1.0:
        raise ValueError("fraction must be in (0, 1)")
    height, width = image.shape[:2]
    side = rng.integers(0, 4)  # 0=left, 1=right, 2=top, 3=bottom
    out = image.copy()
    if side == 0:
        out[:, : round(width * fraction)] = WHITE
    elif side == 1:
        out[:, width - round(width * fraction) :] = WHITE
    elif side == 2:
        out[: round(height * fraction), :] = WHITE
    else:
        out[height - round(height * fraction) :, :] = WHITE
    return out


def rotate_degrees(image: np.ndarray, degrees: float) -> np.ndarray:
    """Rotate about the image centre by ``degrees``, filling exposed corners
    white. Deterministic given ``degrees``."""
    height, width = image.shape[:2]
    center = (width / 2.0, height / 2.0)
    matrix = cv2.getRotationMatrix2D(center, degrees, 1.0)
    rotated: np.ndarray = cv2.warpAffine(
        image, matrix, (width, height), borderValue=WHITE, flags=cv2.INTER_LINEAR
    )
    return rotated


def perspective_warp(
    image: np.ndarray, rng: np.random.Generator, *, max_corner_jitter_frac: float = 0.02
) -> np.ndarray:
    """Jitter each of the 4 page corners by up to
    ``max_corner_jitter_frac`` of the corresponding dimension and warp —
    simulates a slightly off-axis camera angle. Exposed regions fill
    white; output keeps the original dimensions (this distorts the page's
    own content, it does not simulate a photographed page against a
    background — see `packages/attacklab/README.md`'s real-capture caveat)."""
    height, width = image.shape[:2]
    src = np.array([[0, 0], [width, 0], [width, height], [0, height]], dtype=np.float32)
    jitter_x, jitter_y = width * max_corner_jitter_frac, height * max_corner_jitter_frac
    offsets = rng.uniform(-1.0, 1.0, size=(4, 2)) * [jitter_x, jitter_y]
    dst = (src + offsets).astype(np.float32)
    matrix = cv2.getPerspectiveTransform(src, dst)
    warped: np.ndarray = cv2.warpPerspective(
        image, matrix, (width, height), borderValue=WHITE, flags=cv2.INTER_LINEAR
    )
    return warped


def gaussian_blur(image: np.ndarray, sigma: float) -> np.ndarray:
    """Deterministic Gaussian blur at standard deviation ``sigma``."""
    if sigma <= 0.0:
        return image.copy()
    ksize = 2 * round(3.0 * sigma) + 1  # odd kernel wide enough to cover the given sigma
    blurred: np.ndarray = cv2.GaussianBlur(image, (ksize, ksize), sigmaX=sigma)
    return blurred


def add_gaussian_noise(image: np.ndarray, sigma: float, rng: np.random.Generator) -> np.ndarray:
    """Additive Gaussian sensor-noise simulation, clipped back to uint8
    range."""
    noise = rng.normal(0.0, sigma, size=image.shape)
    noisy = image.astype(np.float64) + noise
    return np.clip(noisy, 0, 255).astype(np.uint8)


def adjust_brightness_contrast(image: np.ndarray, brightness: float, contrast: float) -> np.ndarray:
    """``output = contrast * input + brightness``, clipped. Deterministic
    given both parameters."""
    adjusted = image.astype(np.float64) * contrast + brightness
    return np.clip(adjusted, 0, 255).astype(np.uint8)


def _bayer_dither(image: np.ndarray) -> np.ndarray:
    """A 4x4 ordered (Bayer) dither, approximating a halftone print's dot
    pattern — a standard, well-understood dithering technique, not an
    invented one."""
    bayer4 = np.array(
        [[0, 8, 2, 10], [12, 4, 14, 6], [3, 11, 1, 9], [15, 7, 13, 5]], dtype=np.float64
    )
    threshold_map = (bayer4 + 0.5) / 16.0 * 255.0
    height, width = image.shape[:2]
    tiled = np.tile(threshold_map, (height // 4 + 1, width // 4 + 1))[:height, :width]
    tiled3 = tiled[:, :, None]
    return np.where(image.astype(np.float64) > tiled3, 255, 0).astype(np.uint8)


def screen_camera_pipeline(image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    """Simulates photographing a screen displaying the document: a
    resolution-reducing resample, an additive moire grid, gamma correction,
    blur, sensor noise, then JPEG recompression — spec Section 15's named
    composite condition. Output is smaller than the input (registration
    recovers the scale change, same as a plain `resize_scale` distortion)."""
    resampled = resize_scale(image, 0.6)

    height, width = resampled.shape[:2]
    freq = rng.uniform(0.35, 0.55)  # cycles per pixel-ish, jittered per trial
    phase = rng.uniform(0.0, 2.0 * np.pi)
    y_idx, x_idx = np.mgrid[0:height, 0:width]
    moire = 6.0 * np.sin(freq * (x_idx + y_idx) + phase)
    moired = np.clip(resampled.astype(np.float64) + moire[:, :, None], 0, 255).astype(np.uint8)

    gamma = 1.15
    gamma_corrected = (255.0 * (moired.astype(np.float64) / 255.0) ** gamma).astype(np.uint8)

    blurred = gaussian_blur(gamma_corrected, 0.7)
    noisy = add_gaussian_noise(blurred, 6.0, rng)
    return jpeg_recompress(noisy, 80)


def print_scan_pipeline(image: np.ndarray, rng: np.random.Generator) -> np.ndarray:
    """Simulates printing then scanning the document: halftone (ordered
    dither), blur (dot gain), sensor noise, and a slight rotation — spec
    Section 15's named composite condition."""
    halftoned = _bayer_dither(image)
    blurred = gaussian_blur(halftoned, 0.8)
    noisy = add_gaussian_noise(blurred, 5.0, rng)
    angle = float(rng.uniform(-2.0, 2.0))
    return rotate_degrees(noisy, angle)
