import dataclasses

import numpy as np
import pymupdf

from sender.positions import select_positions
from sender.quality_gate import run_quality_gate
from sender.variants import DocumentVariants, RenderedPosition, build_document_variants


def _variants(sample_doc: pymupdf.Document, max_per_page: int = 8) -> DocumentVariants:
    positions = select_positions(sample_doc, max_per_page=max_per_page)
    return build_document_variants(sample_doc, positions, dpi=150)


def test_quality_gate_passes_on_real_variants(sample_doc: pymupdf.Document) -> None:
    report = run_quality_gate(_variants(sample_doc))
    failing_pages = [
        (p.page_index, p.variant_bit, p.ssim, p.max_abs_delta)
        for p in report.pages
        if not p.passed
    ]
    failing_positions = [
        (p.position_index, p.changed_fraction) for p in report.positions if not p.passed
    ]
    assert report.passed, (failing_pages, failing_positions)
    assert all(p.ssim >= 0.98 for p in report.pages)


def test_legitimate_shift_changes_only_a_modest_fraction_of_each_patch(
    sample_doc: pymupdf.Document,
) -> None:
    # Empirically, a correct 2px shift changes roughly 10-15% of a patch's
    # pixels; this pins that down as a regression guard.
    report = run_quality_gate(_variants(sample_doc))
    assert all(p.changed_fraction < 0.3 for p in report.positions)


def test_quality_gate_fails_on_a_deliberately_broken_patch(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    broken = list(variants.rendered_positions)
    # Replace one patch with solid black, the same shape — a stand-in for a
    # badly broken variant render (e.g. wrong font/size/color/content).
    victim = broken[0]
    broken[0] = RenderedPosition(
        position=victim.position,
        patch_bit0=np.zeros_like(victim.patch_bit0),
        patch_bit1=victim.patch_bit1,
        pixel_bbox=victim.pixel_bbox,
    )
    broken_variants = dataclasses.replace(variants, rendered_positions=broken)

    report = run_quality_gate(broken_variants)
    assert not report.passed
    assert not report.positions[0].passed
    assert report.positions[0].changed_fraction > 0.5
