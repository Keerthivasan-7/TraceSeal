"""Paste codeword-selected variant patches onto the base pages.

Pure function over already-rendered data (no PDF/PyMuPDF objects), so this
is the same logic a future recipient-agent (M3) could reuse or reimplement
against its own in-memory-only constraints.
"""

from __future__ import annotations

import numpy as np

from sender.variants import DocumentVariants


def paste_patches(
    doc_variants: DocumentVariants, patches: list[np.ndarray]
) -> list[np.ndarray]:
    """Paste one already-chosen patch per mark position onto fresh copies of
    the base pages (index-aligned with ``rendered_positions``). Shared by
    :func:`assemble_document` (patch = whichever bit a codeword selects) and
    ``attacklab.collusion``'s pixel-level attack simulations (patch =
    whichever bit/pixel content a collusion strategy produces), so both
    stay pixel-identical to a real assembled page for any position they
    don't touch."""
    if len(patches) != len(doc_variants.rendered_positions):
        raise ValueError(
            f"{len(patches)} patches != {len(doc_variants.rendered_positions)} mark positions"
        )
    pages = [page.copy() for page in doc_variants.base_pages]
    for patch, rendered in zip(patches, doc_variants.rendered_positions, strict=True):
        page = pages[rendered.position.page_index]
        x0, y0, x1, y1 = rendered.pixel_bbox
        h, w = page.shape[:2]
        x1c, y1c = min(x1, w), min(y1, h)
        if x0 >= x1c or y0 >= y1c:
            continue  # patch fell entirely off the page raster (defensive; shouldn't happen)
        page[y0:y1c, x0:x1c] = patch[: y1c - y0, : x1c - x0]
    return pages


def assemble_document(doc_variants: DocumentVariants, codeword: np.ndarray) -> list[np.ndarray]:
    """Assemble one full document: every mark position gets whichever patch
    ``codeword`` selects for it (index-aligned with ``rendered_positions``)."""
    if len(codeword) != len(doc_variants.rendered_positions):
        raise ValueError(
            f"codeword length {len(codeword)} != "
            f"{len(doc_variants.rendered_positions)} mark positions"
        )
    patches = [
        rendered.patch_bit1 if int(bit) == 1 else rendered.patch_bit0
        for bit, rendered in zip(codeword, doc_variants.rendered_positions, strict=True)
    ]
    return paste_patches(doc_variants, patches)
