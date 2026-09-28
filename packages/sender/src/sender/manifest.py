"""Position table and package manifest shapes (spec Section 8).

These match the manifest the future (M3) `.tspkg` format will carry
(page sizes, DPI, a position table with page index/bbox/patch shape), so
M3 doesn't need to redesign this — it will just add the encrypted-blob
fields around it.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


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
