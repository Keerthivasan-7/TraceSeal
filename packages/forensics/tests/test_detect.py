import numpy as np
from sender.assemble import assemble_document
from sender.variants import DocumentVariants

from forensics.detect import detect_positions


def test_detects_known_codeword_on_unperturbed_page(variants: DocumentVariants) -> None:
    n = len(variants.rendered_positions)
    rng = np.random.default_rng(1)
    codeword = rng.integers(0, 2, size=n).astype(np.int8)
    pages = assemble_document(variants, codeword)

    page0_positions = [rp for rp in variants.rendered_positions if rp.position.page_index == 0]
    observations = detect_positions(pages[0], page0_positions)

    assert len(observations) == len(page0_positions)
    global_indices = [
        i for i, rp in enumerate(variants.rendered_positions) if rp.position.page_index == 0
    ]
    # Even on a perfectly unperturbed page, a handful of positions have a
    # genuinely small NCC gap (some words are just less distinctive) and
    # correctly erase rather than guess — Tardos accusation is designed to
    # tolerate exactly this (spec Section 10). What must hold is: erasures
    # stay rare, and every non-erased call is actually correct.
    erasures = sum(1 for obs in observations if obs.is_erasure)
    for obs in observations:
        if obs.is_erasure:
            continue
        true_bit = int(codeword[global_indices[obs.position_index]])
        assert int(obs.observed_bit) == true_bit
    assert erasures / len(observations) < 0.2


def test_erasure_when_patches_are_indistinguishable(variants: DocumentVariants) -> None:
    # Feed a position's own bit-0 patch pasted at its own location, but
    # with both candidate patches replaced by identical content so neither
    # can win — this should erase rather than guess.
    page0_positions = [rp for rp in variants.rendered_positions if rp.position.page_index == 0]
    rp = page0_positions[0]
    page = variants.base_pages[0].copy()
    x0, y0, x1, y1 = rp.pixel_bbox
    page[y0:y1, x0:x1] = rp.patch_bit0

    import dataclasses

    identical_position = dataclasses.replace(rp, patch_bit1=rp.patch_bit0)
    observations = detect_positions(page, [identical_position])
    assert observations[0].is_erasure
