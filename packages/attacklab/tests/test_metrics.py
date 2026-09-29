from __future__ import annotations

import math

import numpy as np
import pytest
from forensics.report import InvestigationReport

from attacklab.metrics import compute_trial_result, summarize_condition


def _report(
    *, scores: dict[str, float], threshold: float, observed_bits: np.ndarray, n_erasures: int
) -> InvestigationReport:
    return InvestigationReport(
        scores=scores,
        threshold=threshold,
        eps1=1e-4,
        n_observed=int(np.count_nonzero(~np.isnan(observed_bits))),
        n_total_positions=len(observed_bits),
        n_erasures=n_erasures,
        observed_bits=observed_bits,
    )


def test_bit_error_rate_counts_mismatches_on_observed_positions_only() -> None:
    ground_truth = np.array([1, 0, 1, 0, 1], dtype=np.int8)
    # position 1 erased (nan); of the 4 observed, position 2 is wrong.
    observed = np.array([1.0, math.nan, 0.0, 0.0, 1.0])
    report = _report(scores={"S-1": 0.0}, threshold=10.0, observed_bits=observed, n_erasures=1)
    result = compute_trial_result(
        condition="c", trial_seed=0, page_index=0, true_source_sessions=frozenset({"S-1"}),
        report=report, ground_truth_bits=ground_truth, n_candidate_sessions=3,
        n_page_positions=len(observed), runtime_ms=1.0,
    )
    assert result.bit_error_rate == pytest.approx(1 / 4)
    assert result.erasure_rate == pytest.approx(1 / 5)
    assert result.n_observed == 4


def test_bit_error_rate_is_nan_when_ground_truth_is_none() -> None:
    observed = np.array([1.0, 0.0, 1.0])
    report = _report(scores={"S-1": 0.0}, threshold=10.0, observed_bits=observed, n_erasures=0)
    result = compute_trial_result(
        condition="c", trial_seed=0, page_index=0, true_source_sessions=frozenset({"S-1", "S-2"}),
        report=report, ground_truth_bits=None, n_candidate_sessions=3,
        n_page_positions=len(observed), runtime_ms=1.0,
    )
    assert math.isnan(result.bit_error_rate)


def test_bit_error_rate_is_nan_when_nothing_observed() -> None:
    observed = np.array([math.nan, math.nan])
    ground_truth = np.array([1, 0], dtype=np.int8)
    report = _report(scores={"S-1": 0.0}, threshold=10.0, observed_bits=observed, n_erasures=2)
    result = compute_trial_result(
        condition="c", trial_seed=0, page_index=0, true_source_sessions=frozenset({"S-1"}),
        report=report, ground_truth_bits=ground_truth, n_candidate_sessions=3,
        n_page_positions=len(observed), runtime_ms=1.0,
    )
    assert math.isnan(result.bit_error_rate)
    assert result.erasure_rate == 1.0


def test_registration_failure_is_total_erasure_no_accusation() -> None:
    result = compute_trial_result(
        condition="c", trial_seed=0, page_index=0, true_source_sessions=frozenset({"S-1"}),
        report=None, ground_truth_bits=None, n_candidate_sessions=3,
        n_page_positions=5, runtime_ms=5.0,
    )
    assert result.registration_failed is True
    assert result.erasure_rate == 1.0
    assert math.isnan(result.bit_error_rate)
    assert result.top1_correct is False
    assert result.n_innocent_accused == 0


def test_top1_correct_and_innocent_accusations() -> None:
    observed = np.array([1.0, 1.0, 1.0])
    # S-1 (true source) scores highest and clears threshold; S-2 also
    # clears threshold but isn't a true source -> one innocent accusation.
    report = _report(
        scores={"S-1": 20.0, "S-2": 15.0, "S-3": 2.0},
        threshold=10.0,
        observed_bits=observed,
        n_erasures=0,
    )
    result = compute_trial_result(
        condition="c", trial_seed=0, page_index=0, true_source_sessions=frozenset({"S-1"}),
        report=report, ground_truth_bits=None, n_candidate_sessions=3,
        n_page_positions=len(observed), runtime_ms=1.0,
    )
    assert result.top1_correct is True
    assert result.n_innocent_accused == 1


def test_summarize_condition_aggregates_across_trials() -> None:
    report_a = _report(
        scores={"S-1": 20.0}, threshold=10.0, observed_bits=np.array([1.0]), n_erasures=0
    )
    a = compute_trial_result(
        condition="cond", trial_seed=0, page_index=0, true_source_sessions=frozenset({"S-1"}),
        report=report_a,
        ground_truth_bits=np.array([1], dtype=np.int8), n_candidate_sessions=3,
        n_page_positions=1, runtime_ms=10.0,
    )
    b = compute_trial_result(
        condition="cond", trial_seed=1, page_index=0, true_source_sessions=frozenset({"S-1"}),
        report=None, ground_truth_bits=None, n_candidate_sessions=3,
        n_page_positions=1, runtime_ms=20.0,
    )
    summary = summarize_condition([a, b])
    assert summary.n_trials == 2
    assert summary.n_registration_failures == 1
    assert summary.top1_accuracy == 0.5
    assert summary.mean_runtime_ms == pytest.approx(15.0)
