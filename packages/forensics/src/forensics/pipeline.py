"""Wires registration -> per-position detection -> Tardos accusation
together (spec Section 11).

M2 scope: the caller already knows which document and which page the
artifact is claimed to be (no OCR/vault lookup yet — see
docs/DECISIONS.md ADR-0009 and the M2 plan). Only positions belonging to
that page are ever considered; a leaked single page naturally can't cover
the whole document's codeword, which is exactly the erasure/rescaled-
threshold path `tscore.tardos` was built to handle.
"""

from __future__ import annotations

import math

import numpy as np
from sender.assemble import assemble_document
from sender.variants import DocumentVariants
from tscore.tardos import accuse, threshold

from forensics.align import register
from forensics.detect import DEFAULT_CONFIDENCE_THRESHOLD, detect_positions
from forensics.report import InvestigationReport


def investigate(
    artifact: np.ndarray,
    page_index: int,
    variants: DocumentVariants,
    codewords: dict[str, np.ndarray],
    bias_vector: np.ndarray,
    eps1: float,
    *,
    confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
) -> InvestigationReport:
    n_total = len(variants.rendered_positions)
    reference_pages = assemble_document(variants, np.zeros(n_total, dtype=np.int8))
    reference = reference_pages[page_index]

    alignment = register(artifact, reference)

    # `page_positions` and `page_to_global` are built from the same filter
    # in the same order, so `detect_positions`'s page-local
    # `position_index` (an index into `page_positions`) maps back to the
    # full codeword's index via `page_to_global[local_idx]`.
    global_indices = [
        i
        for i, rp in enumerate(variants.rendered_positions)
        if rp.position.page_index == page_index
    ]
    page_positions = [variants.rendered_positions[i] for i in global_indices]
    page_to_global = dict(enumerate(global_indices))

    observations = detect_positions(
        alignment.warped, page_positions, confidence_threshold=confidence_threshold
    )

    observed_full = np.full(n_total, math.nan)
    n_erasures = 0
    for obs in observations:
        global_idx = page_to_global[obs.position_index]
        observed_full[global_idx] = obs.observed_bit
        if obs.is_erasure:
            n_erasures += 1

    n_observed = int(np.count_nonzero(~np.isnan(observed_full)))
    scores = accuse(codewords, observed_full, bias_vector, eps1)
    z = threshold(n_observed, eps1)

    return InvestigationReport(
        scores=scores,
        threshold=z,
        eps1=eps1,
        n_observed=n_observed,
        n_total_positions=n_total,
        n_erasures=n_erasures,
    )
