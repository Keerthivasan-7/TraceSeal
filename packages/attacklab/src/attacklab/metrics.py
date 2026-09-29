"""Per-trial and per-condition metrics (spec Section 15): bit error rate,
erasure rate, top-1 correct attribution, innocent accusations, and
runtime.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from forensics.report import InvestigationReport


@dataclass(frozen=True)
class TrialResult:
    condition: str
    trial_seed: int
    page_index: int
    true_source_sessions: frozenset[str]
    bit_error_rate: float  # nan if not applicable (patch averaging) or n_observed == 0
    erasure_rate: float
    n_erasures: int
    n_observed: int
    n_total_positions: int
    top1_correct: bool
    n_innocent_accused: int
    n_candidate_sessions: int  # denominator for the innocent-accusation rate
    runtime_ms: float
    registration_failed: bool


def compute_trial_result(
    *,
    condition: str,
    trial_seed: int,
    page_index: int,
    true_source_sessions: frozenset[str],
    report: InvestigationReport | None,
    ground_truth_bits: np.ndarray | None,
    n_candidate_sessions: int,
    n_page_positions: int,
    runtime_ms: float,
) -> TrialResult:
    """Build one `TrialResult`. ``report`` is `None` when registration
    failed outright (`forensics.align.RegistrationError`) — recorded as a
    total erasure with no accusation, not a crash, since "registration
    failed entirely under this condition" is itself a real, reportable
    outcome. ``ground_truth_bits`` is `None` for patch-averaging trials,
    which have no discrete pirate bit sequence — `bit_error_rate` is `nan`
    in that case, reported explicitly as not applicable rather than
    omitted.

    ``n_page_positions`` — the number of mark positions that actually
    belong to the leaked page — is the `erasure_rate` denominator, NOT
    `report.n_total_positions` (the whole document's position count).
    `forensics.pipeline.investigate` always sizes its `observed_bits`
    array to the whole document, since a single leaked page structurally
    can never cover another page's positions; dividing by the document
    total would give every single-page trial an artificial erasure-rate
    floor around ``1 - (positions on this page / positions in the whole
    document)`` regardless of how mild or severe the actual distortion
    is — confirmed empirically the first time this milestone's harness
    actually ran (every condition showed ~0.69-0.81 erasure rate with no
    visible relationship to distortion severity, because the real signal
    was buried under that structural floor)."""
    if report is None:
        return TrialResult(
            condition=condition,
            trial_seed=trial_seed,
            page_index=page_index,
            true_source_sessions=true_source_sessions,
            bit_error_rate=math.nan,
            erasure_rate=1.0,
            n_erasures=0,
            n_observed=0,
            n_total_positions=0,
            top1_correct=False,
            n_innocent_accused=0,
            n_candidate_sessions=n_candidate_sessions,
            runtime_ms=runtime_ms,
            registration_failed=True,
        )

    observed_mask = ~np.isnan(report.observed_bits)
    n_observed = int(np.count_nonzero(observed_mask))
    n_total = report.n_total_positions
    erasure_rate = 1.0 - (n_observed / n_page_positions if n_page_positions else 0.0)

    if ground_truth_bits is None or n_observed == 0:
        bit_error_rate = math.nan
    else:
        mismatches = int(
            np.count_nonzero(
                report.observed_bits[observed_mask] != ground_truth_bits[observed_mask]
            )
        )
        bit_error_rate = mismatches / n_observed

    top1_correct = report.top_session is not None and report.top_session in true_source_sessions
    n_innocent = sum(1 for sid in report.accused_sessions if sid not in true_source_sessions)

    return TrialResult(
        condition=condition,
        trial_seed=trial_seed,
        page_index=page_index,
        true_source_sessions=true_source_sessions,
        bit_error_rate=bit_error_rate,
        erasure_rate=erasure_rate,
        n_erasures=report.n_erasures,
        n_observed=n_observed,
        n_total_positions=n_total,
        top1_correct=top1_correct,
        n_innocent_accused=n_innocent,
        n_candidate_sessions=n_candidate_sessions,
        runtime_ms=runtime_ms,
        registration_failed=False,
    )


@dataclass(frozen=True)
class ConditionSummary:
    condition: str
    n_trials: int
    mean_bit_error_rate: float  # nan if every trial in the condition had bit_error_rate=nan
    mean_erasure_rate: float
    top1_accuracy: float
    total_innocent_accusations: int
    innocent_accusation_rate: float
    mean_runtime_ms: float
    median_runtime_ms: float
    max_runtime_ms: float
    n_registration_failures: int


def _mean_ignoring_nan(values: list[float]) -> float:
    finite = [v for v in values if not math.isnan(v)]
    return float(np.mean(finite)) if finite else math.nan


def summarize_condition(results: list[TrialResult]) -> ConditionSummary:
    if not results:
        raise ValueError("results must be non-empty")
    condition = results[0].condition
    if any(r.condition != condition for r in results):
        raise ValueError("all results must share the same condition")

    runtimes = [r.runtime_ms for r in results]
    total_innocent = sum(r.n_innocent_accused for r in results)
    total_non_source_candidates = sum(
        max(r.n_candidate_sessions - len(r.true_source_sessions), 0) for r in results
    )

    return ConditionSummary(
        condition=condition,
        n_trials=len(results),
        mean_bit_error_rate=_mean_ignoring_nan([r.bit_error_rate for r in results]),
        mean_erasure_rate=float(np.mean([r.erasure_rate for r in results])),
        top1_accuracy=float(np.mean([r.top1_correct for r in results])),
        total_innocent_accusations=total_innocent,
        innocent_accusation_rate=(
            total_innocent / total_non_source_candidates if total_non_source_candidates else 0.0
        ),
        mean_runtime_ms=float(np.mean(runtimes)),
        median_runtime_ms=float(np.median(runtimes)),
        max_runtime_ms=float(np.max(runtimes)),
        n_registration_failures=sum(1 for r in results if r.registration_failed),
    )
