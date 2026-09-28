import numpy as np
import pymupdf
import pytest

from sender.assemble import assemble_document
from sender.positions import select_positions
from sender.variants import build_document_variants


def _variants(sample_doc: pymupdf.Document, max_per_page: int = 6):
    positions = select_positions(sample_doc, max_per_page=max_per_page)
    return build_document_variants(sample_doc, positions, dpi=150)


def test_rejects_wrong_length_codeword(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    with pytest.raises(ValueError, match="codeword length"):
        assemble_document(variants, np.zeros(1, dtype=np.int8))


def test_all_zero_vs_all_one_codeword_differ_at_every_position(
    sample_doc: pymupdf.Document,
) -> None:
    variants = _variants(sample_doc)
    n = len(variants.rendered_positions)
    pages_bit0 = assemble_document(variants, np.zeros(n, dtype=np.int8))
    pages_bit1 = assemble_document(variants, np.ones(n, dtype=np.int8))
    for rp in variants.rendered_positions:
        x0, y0, x1, y1 = rp.pixel_bbox
        page_index = rp.position.page_index
        region0 = pages_bit0[page_index][y0:y1, x0:x1]
        region1 = pages_bit1[page_index][y0:y1, x0:x1]
        assert np.abs(region0.astype(int) - region1.astype(int)).max() > 0


def test_assembled_page_matches_selected_patch_exactly(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    n = len(variants.rendered_positions)
    rng = np.random.default_rng(0)
    codeword = rng.integers(0, 2, size=n).astype(np.int8)
    pages = assemble_document(variants, codeword)
    for bit, rp in zip(codeword, variants.rendered_positions, strict=True):
        expected_patch = rp.patch_bit1 if bit == 1 else rp.patch_bit0
        x0, y0, x1, y1 = rp.pixel_bbox
        actual = pages[rp.position.page_index][y0:y1, x0:x1]
        assert np.array_equal(actual, expected_patch)
