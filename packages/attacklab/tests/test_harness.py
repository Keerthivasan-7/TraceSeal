from __future__ import annotations

import math
from pathlib import Path

from attacklab.conditions import CollusionCondition, DistortionCondition
from attacklab.distortions import jpeg_recompress
from attacklab.harness import (
    run_collusion_condition,
    run_real_capture_folder,
    run_synthetic_condition,
    summarize_all,
    write_results_csv,
)
from attacklab.scenario import Scenario


def _jpeg_q70_condition() -> DistortionCondition:
    return DistortionCondition(
        "jpeg_q70", lambda img, rng: jpeg_recompress(img, 70), {"quality": 70}
    )


def test_run_synthetic_condition_produces_sane_results(scenario: Scenario) -> None:
    condition = _jpeg_q70_condition()
    results = run_synthetic_condition(condition, scenario, n_trials=2, base_seed=1000)
    assert len(results) == 2
    for r in results:
        assert r.condition == "jpeg_q70"
        assert 0.0 <= r.erasure_rate <= 1.0
        assert r.runtime_ms > 0.0
        assert r.n_candidate_sessions == len(scenario.session_ids)


def test_run_collusion_condition_bitwise_produces_sane_results(scenario: Scenario) -> None:
    condition = CollusionCondition(strategy="majority", c=2)
    results = run_collusion_condition(condition, scenario, n_trials=2, base_seed=2000)
    assert len(results) == 2
    for r in results:
        assert r.condition == "collusion_majority_c2"
        assert len(r.true_source_sessions) == 2
        assert 0.0 <= r.erasure_rate <= 1.0
        assert r.runtime_ms > 0.0


def test_run_collusion_condition_patch_averaging_has_no_bit_error_rate(
    scenario: Scenario,
) -> None:
    condition = CollusionCondition(strategy="patch_averaging", c=2)
    results = run_collusion_condition(condition, scenario, n_trials=1, base_seed=3000)
    assert len(results) == 1
    assert math.isnan(results[0].bit_error_rate)


def test_run_real_capture_folder_returns_empty_for_missing_dir(
    tmp_path: Path, scenario: Scenario
) -> None:
    assert run_real_capture_folder(tmp_path / "nonexistent", scenario) == []


def test_write_results_csv_produces_well_formed_output(tmp_path: Path, scenario: Scenario) -> None:
    condition = _jpeg_q70_condition()
    results = run_synthetic_condition(condition, scenario, n_trials=2, base_seed=1000)
    csv_path = tmp_path / "results.csv"
    write_results_csv(
        csv_path,
        results,
        git_commit="abc123",
        seed=42,
        condition_params={"jpeg_q70": {"quality": 70}},
    )
    assert csv_path.exists()
    lines = csv_path.read_text().strip().splitlines()
    assert len(lines) == 1 + len(results)  # header + one row per trial
    assert "git_commit" in lines[0]


def test_summarize_all_skips_empty_condition_lists() -> None:
    assert summarize_all({"empty": []}) == []
