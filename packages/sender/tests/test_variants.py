import numpy as np
import pymupdf

from sender.positions import select_positions
from sender.variants import build_document_variants, render_variant_patches


def test_variant_patches_differ(sample_doc: pymupdf.Document) -> None:
    positions = select_positions(sample_doc, max_per_page=5)
    word = positions[0]
    patch0, patch1 = render_variant_patches(sample_doc, word, dpi=150)
    assert patch0.shape == patch1.shape
    diff = np.abs(patch0.astype(int) - patch1.astype(int))
    assert diff.max() > 0, "shifted variants must actually differ"


def test_build_document_variants_produces_one_rendered_position_per_input(
    sample_doc: pymupdf.Document,
) -> None:
    positions = select_positions(sample_doc, max_per_page=6)
    variants = build_document_variants(sample_doc, positions, dpi=150)
    assert len(variants.rendered_positions) == len(positions)
    assert len(variants.base_pages) == sample_doc.page_count
    assert len(variants.original_pages) == sample_doc.page_count


def test_base_page_differs_from_original_only_near_marked_positions(
    sample_doc: pymupdf.Document,
) -> None:
    positions = select_positions(sample_doc, max_per_page=6)
    variants = build_document_variants(sample_doc, positions, dpi=150)
    for page_index in {p.page_index for p in positions}:
        original = variants.original_pages[page_index]
        base = variants.base_pages[page_index]
        assert original.shape == base.shape
        diff = np.abs(original.astype(int) - base.astype(int))
        assert diff.max() > 0, "redaction should visibly blank the marked word"

    # A page's marked regions plus a small pad should account for
    # everywhere the base page differs from the original; check by masking
    # out those regions and confirming the remainder is unchanged.
    page_index = positions[0].page_index
    original = variants.original_pages[page_index].astype(int)
    base = variants.base_pages[page_index].astype(int)
    diff = np.abs(original - base)
    mask = np.zeros(diff.shape[:2], dtype=bool)
    for rp in variants.rendered_positions:
        if rp.position.page_index != page_index:
            continue
        x0, y0, x1, y1 = rp.pixel_bbox
        mask[max(y0, 0) : y1, max(x0, 0) : x1] = True
    outside_diff = diff[~mask]
    assert outside_diff.max() == 0
