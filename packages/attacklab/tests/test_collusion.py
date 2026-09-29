from __future__ import annotations

import numpy as np
import pytest
from sender.assemble import assemble_document
from sender.positions import WordBox
from sender.variants import DocumentVariants, RenderedPosition

from attacklab.collusion import (
    realize_patch_averaging_pages,
    select_bits_interleave,
    select_bits_majority,
    select_bits_minority,
    select_bits_random,
)

# Hand-worked 3-colluder, 5-position example. Position 0 is unanimous (all
# hold 1); the rest are split, chosen to make each strategy's expected
# output easy to verify by hand.
COALITION = np.array(
    [
        [1, 0, 1, 0, 1],  # colluder A
        [1, 1, 0, 0, 0],  # colluder B
        [1, 1, 1, 1, 0],  # colluder C
    ],
    dtype=np.int8,
)


def test_majority() -> None:
    # position 0: 1,1,1 -> 1 (unanimous)
    # position 1: 0,1,1 -> 1 (majority)
    # position 2: 1,0,1 -> 1 (majority)
    # position 3: 0,0,1 -> 0 (majority)
    # position 4: 1,0,0 -> 0 (majority)
    expected = np.array([1, 1, 1, 0, 0], dtype=np.int8)
    result = select_bits_majority(COALITION, np.random.default_rng(0))
    assert np.array_equal(result, expected)


def test_minority_respects_unanimous_position() -> None:
    # position 0 is unanimous (all 1) -> minority has no other value to
    # produce, so it stays 1, not the naive "flip of majority" (0).
    # position 1: 0,1,1 -> majority 1 -> minority 0
    # position 2: 1,0,1 -> majority 1 -> minority 0
    # position 3: 0,0,1 -> majority 0 -> minority 1
    # position 4: 1,0,0 -> majority 0 -> minority 1
    expected = np.array([1, 0, 0, 1, 1], dtype=np.int8)
    result = select_bits_minority(COALITION, np.random.default_rng(0))
    assert np.array_equal(result, expected)


def test_random_always_picks_a_real_coalition_bit() -> None:
    rng = np.random.default_rng(42)
    result = select_bits_random(COALITION, rng)
    for i in range(COALITION.shape[1]):
        assert result[i] in COALITION[:, i]


def test_interleave_cycles_through_members_in_order() -> None:
    # c=3, so position i picks colluder (i % 3): A, B, C, A, B
    expected = np.array(
        [COALITION[0, 0], COALITION[1, 1], COALITION[2, 2], COALITION[0, 3], COALITION[1, 4]],
        dtype=np.int8,
    )
    result = select_bits_interleave(COALITION, np.random.default_rng(0))
    assert np.array_equal(result, expected)


def test_bitwise_strategy_output_is_realizable_via_assemble_document() -> None:
    # Every strategy's pirate bit at every position is, by construction,
    # some coalition member's own real bit there — so the pirate PAGE is
    # exactly what sender.assemble.assemble_document produces from the
    # pirate bit array (see collusion.py's module docstring for why no
    # separate pixel-realization function exists for these strategies).
    variants = _tiny_variants(n_positions=5)
    pirate_bits = select_bits_majority(COALITION, np.random.default_rng(0))
    pages = assemble_document(variants, pirate_bits)
    assert len(pages) == 1


def _tiny_variants(n_positions: int) -> DocumentVariants:
    """A minimal, hand-built DocumentVariants — no PDF rendering needed for
    a pure pixel-compositing test."""
    page = np.full((40, 20 * n_positions, 3), 200, dtype=np.uint8)
    rendered_positions = []
    for i in range(n_positions):
        x0 = i * 20
        bbox_word = WordBox(page_index=0, bbox=(x0, 0.0, x0 + 10.0, 10.0), text=f"w{i}")
        patch0 = np.zeros((10, 10, 3), dtype=np.uint8)
        patch1 = np.full((10, 10, 3), 255, dtype=np.uint8)
        rendered_positions.append(
            RenderedPosition(
                position=bbox_word,
                patch_bit0=patch0,
                patch_bit1=patch1,
                pixel_bbox=(x0, 0, x0 + 10, 10),
            )
        )
    return DocumentVariants(
        dpi=100,
        original_pages=[page],
        base_pages=[page.copy()],
        rendered_positions=rendered_positions,
    )


def test_patch_averaging_is_noop_at_unanimous_position() -> None:
    variants = _tiny_variants(n_positions=1)
    codewords = {"A": np.array([1], dtype=np.int8), "B": np.array([1], dtype=np.int8)}
    pages = realize_patch_averaging_pages(variants, codewords)
    x0, y0, x1, y1 = variants.rendered_positions[0].pixel_bbox
    patch = pages[0][y0:y1, x0:x1]
    assert np.array_equal(patch, variants.rendered_positions[0].patch_bit1)


def test_patch_averaging_blends_at_split_position() -> None:
    variants = _tiny_variants(n_positions=1)
    codewords = {"A": np.array([0], dtype=np.int8), "B": np.array([1], dtype=np.int8)}
    pages = realize_patch_averaging_pages(variants, codewords)
    x0, y0, x1, y1 = variants.rendered_positions[0].pixel_bbox
    patch = pages[0][y0:y1, x0:x1]
    rp = variants.rendered_positions[0]
    assert not np.array_equal(patch, rp.patch_bit0)
    assert not np.array_equal(patch, rp.patch_bit1)
    # patch_bit0 is all 0, patch_bit1 is all 255 -> average is 127/128
    assert patch[0, 0, 0] in (127, 128)


def test_patch_averaging_rejects_empty_coalition() -> None:
    variants = _tiny_variants(n_positions=1)
    with pytest.raises(ValueError):
        realize_patch_averaging_pages(variants, {})
