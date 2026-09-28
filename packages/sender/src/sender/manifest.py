"""Position table and package manifest shapes (spec Section 8).

These match the manifest the future (M3) `.tspkg` format will carry
(page sizes, DPI, a position table with page index/bbox/patch shape), so
M3 doesn't need to redesign this — it will just add the encrypted-blob
fields around it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from sender.positions import DEFAULT_PATCH_PAD_PTS


class Position(BaseModel):
    """One mark position: a word-sized region on a page that carries one
    fingerprint bit once assembled."""

    index: int = Field(ge=0)
    page_index: int = Field(ge=0)
    bbox: tuple[float, float, float, float]  # (x0, y0, x1, y1), PDF points
    patch_pixel_shape: tuple[int, int]  # (height, width) at the manifest's DPI


class PackageManifest(BaseModel):
    dpi: int = Field(gt=0)
    page_sizes: list[tuple[float, float]]  # (width, height) in PDF points, per page
    positions: list[Position]


def position_pixel_bbox(
    position: Position, dpi: int, *, pad_pts: float = DEFAULT_PATCH_PAD_PTS
) -> tuple[int, int, int, int]:
    """Where a position's patch belongs on the full-page raster — the same
    computation `sender.variants._pixel_bbox` used to produce
    `patch_pixel_shape` in the first place, so `agent` (which only has the
    manifest, not the original `RenderedPosition` objects) can paste a
    decrypted patch back in the exact right place."""
    scale = dpi / 72.0
    x0, y0 = position.bbox[0], position.bbox[1]
    px0 = round((x0 - pad_pts) * scale)
    py0 = round((y0 - pad_pts) * scale)
    h, w = position.patch_pixel_shape
    return px0, py0, px0 + w, py0 + h
