"""Page rasterisation at a fixed DPI (spec Section 9: 300 DPI, lossless)."""

from __future__ import annotations

import numpy as np
import pymupdf

DEFAULT_DPI = 300


def points_to_pixel_scale(dpi: int) -> float:
    return dpi / 72.0


def render_page(page: pymupdf.Page, dpi: int = DEFAULT_DPI) -> np.ndarray:
    """Render a page to an ``(H, W, 3)`` uint8 RGB array at ``dpi``."""
    scale = points_to_pixel_scale(dpi)
    pix = page.get_pixmap(matrix=pymupdf.Matrix(scale, scale))
    arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width, pix.n)
    if pix.n == 4:
        arr = arr[:, :, :3]
    return arr.copy()


def render_document(doc: pymupdf.Document, dpi: int = DEFAULT_DPI) -> list[np.ndarray]:
    return [render_page(doc[i], dpi) for i in range(doc.page_count)]
