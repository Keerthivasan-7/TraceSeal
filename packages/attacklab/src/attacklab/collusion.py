"""Collusion attacks (spec Section 15): ``c`` colluders combine their own
codewords/pages into one pirate copy.

Bit-selection strategies (majority, minority, random, interleave) mirror
`packages/tscore/tests/test_tardos.py::TestTardosMonteCarlo._run_trial`'s
exact reference semantics — including the "marking assumption" fix (at a
position where every colluder holds the same bit, the coalition has no
other value to physically produce there; only "minority" can otherwise
violate this). That test file keeps its own copy for the abstract
Monte-Carlo suite; this module is the one production copy other code
should import.

A key simplification versus a naive design: a bit-selection strategy's
pirate bit at every position is, by construction, always some coalition
member's own real codeword bit at that position — and since every session
shares the exact same two physical patches per position (`patch_bit0`/
`patch_bit1` from `sender.variants.build_document_variants`, differing only
in which bit each session's *codeword* happens to select), the resulting
pirate PAGE is already exactly what `sender.assemble.assemble_document`
produces when given the pirate bit array directly — no separate pixel-
realization function is needed, or would even mean anything different,
for the four bit-selection strategies. Patch averaging has no such
discrete bit output (it blends two colluders' own patches into pixel
content neither one's codeword alone selects), so it alone needs
`realize_patch_averaging_pages` below.
"""

from __future__ import annotations

from collections.abc import Callable

import numpy as np
from sender.assemble import paste_patches
from sender.variants import DocumentVariants

BitArray = np.ndarray  # dtype=int8, shape (L,)
CoalitionCodewords = np.ndarray  # dtype=int8, shape (c, L)


def select_bits_majority(
    coalition_codewords: CoalitionCodewords, rng: np.random.Generator
) -> BitArray:
    """Each position's pirate bit is whichever bit the majority of the
    coalition holds there. Naturally never violates the marking assumption:
    at a unanimous position the mean is exactly 0 or 1."""
    del rng  # deterministic given the coalition alone
    return (coalition_codewords.mean(axis=0) >= 0.5).astype(np.int8)


def select_bits_minority(
    coalition_codewords: CoalitionCodewords, rng: np.random.Generator
) -> BitArray:
    """The bit the minority of the coalition holds — except at a unanimous
    position, where there is no minority bit to output, so the shared bit
    is used instead (the marking-assumption fix)."""
    del rng
    unanimous_mask = np.all(coalition_codewords == coalition_codewords[0], axis=0)
    unanimous_value = coalition_codewords[0]
    raw = (coalition_codewords.mean(axis=0) < 0.5).astype(np.int8)
    return np.where(unanimous_mask, unanimous_value, raw).astype(np.int8)


def select_bits_random(
    coalition_codewords: CoalitionCodewords, rng: np.random.Generator
) -> BitArray:
    """At each position, pick a uniformly random coalition member's own
    bit."""
    c, length = coalition_codewords.shape
    pick = rng.integers(0, c, size=length)
    result: BitArray = coalition_codewords[pick, np.arange(length)].astype(np.int8)
    return result


def select_bits_interleave(
    coalition_codewords: CoalitionCodewords, rng: np.random.Generator
) -> BitArray:
    """Cycle through coalition members' own bits in a fixed round-robin
    order, position by position."""
    del rng
    c, length = coalition_codewords.shape
    idx = np.arange(length) % c
    result: BitArray = coalition_codewords[idx, np.arange(length)].astype(np.int8)
    return result


BitStrategy = Callable[[CoalitionCodewords, np.random.Generator], BitArray]

BIT_STRATEGIES: dict[str, BitStrategy] = {
    "majority": select_bits_majority,
    "minority": select_bits_minority,
    "random": select_bits_random,
    "interleave": select_bits_interleave,
}


def realize_patch_averaging_pages(
    variants: DocumentVariants,
    coalition_codewords: dict[str, np.ndarray],
) -> list[np.ndarray]:
    """Patch averaging: at every position, average every coalition member's
    own patch (``patch_bit1`` if that member's own codeword bit is 1, else
    ``patch_bit0``) into one blended patch and paste it. Unlike the
    bit-selection strategies above, this has no discrete pirate bit — the
    blended pixels aren't identical to either variant patch (except at a
    unanimous position, where averaging identical patches is a no-op) — so
    downstream bit-error-rate metrics must treat this attack as having no
    ground-truth bit sequence, not invent one."""
    session_ids = list(coalition_codewords)
    if not session_ids:
        raise ValueError("coalition_codewords must be non-empty")
    patches: list[np.ndarray] = []
    for i, rendered in enumerate(variants.rendered_positions):
        member_patches = [
            rendered.patch_bit1 if int(coalition_codewords[sid][i]) == 1 else rendered.patch_bit0
            for sid in session_ids
        ]
        stacked = np.stack(member_patches).astype(np.float64)
        averaged = np.clip(np.round(stacked.mean(axis=0)), 0, 255).astype(np.uint8)
        patches.append(averaged)
    return paste_patches(variants, patches)
