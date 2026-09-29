"""Builds the shared rendered-document + session-codewords scenario every
harness trial runs against — the production analogue of
`packages/forensics/tests/conftest.py`'s `variants` fixture, following
`forensics.demo_m2`'s exact construction order (bias vector, then
codewords, off the same RNG thread) for the same reason: determinism
end to end from one seed.

Deliberately does **not** call `tscore.tardos.plan_parameters` to target a
specific `n`/`c0`/`eps1` guarantee — like `forensics.demo_m2`, this uses
the sample document's own natural mark-position count directly. Whether
that budget is enough to hit a given `eps1` at realistic attack strengths
is exactly one of the things this milestone's own results should show,
honestly, not something the scenario should silently guarantee by
construction.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pymupdf
from sender.positions import select_positions
from sender.rasterize import DEFAULT_DPI
from sender.variants import DocumentVariants, build_document_variants
from tscore.tardos import assign_codeword, sample_bias_vector

DEFAULT_EPS1 = 1e-4
DEFAULT_BIAS_CUTOFF = 0.1


@dataclass(frozen=True)
class Scenario:
    variants: DocumentVariants
    bias: np.ndarray
    codewords: dict[str, np.ndarray]
    session_ids: list[str]
    eps1: float


def build_scenario(
    doc: pymupdf.Document,
    *,
    n_sessions: int,
    dpi: int = DEFAULT_DPI,
    eps1: float = DEFAULT_EPS1,
    bias_cutoff: float = DEFAULT_BIAS_CUTOFF,
    rng: np.random.Generator,
) -> Scenario:
    positions = select_positions(doc)
    variants = build_document_variants(doc, positions, dpi=dpi)
    bias = sample_bias_vector(len(variants.rendered_positions), cutoff=bias_cutoff, rng=rng)
    session_ids = [f"S-{i + 1:04d}" for i in range(n_sessions)]
    codewords = {sid: assign_codeword(bias, rng) for sid in session_ids}
    return Scenario(
        variants=variants, bias=bias, codewords=codewords, session_ids=session_ids, eps1=eps1
    )


def n_positions_on_page(scenario: Scenario, page_index: int) -> int:
    """How many of the document's mark positions actually belong to
    ``page_index`` — the correct `erasure_rate` denominator for a
    single-page leak (see `metrics.compute_trial_result`'s docstring),
    not the whole document's position count."""
    return sum(
        1
        for rp in scenario.variants.rendered_positions
        if rp.position.page_index == page_index
    )
