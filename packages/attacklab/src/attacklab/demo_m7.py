"""Milestone M7 acceptance script (spec Section 17):

    "docs/RESULTS.md is generated; phone-photo and print-scan results are
    reported honestly."

Runs every spec Section 15 synthetic distortion and collusion condition as
real trials (real rendering, real distortion/collusion pixels, real
`forensics.pipeline.investigate` calls), evaluates `attacklab/real/`
identically (empty this milestone — reported as such, not skipped), and
writes `docs/RESULTS.md` + `attacklab/out/results.csv`. Exits non-zero if
any required condition didn't actually run or if fewer trials landed than
requested — "results must be real" is enforced mechanically here, not left
to an eyeball review. `docs/RESULTS.md`'s header records `git rev-parse
HEAD` (via `attacklab.harness.git_commit`) at run time; run this against a
committed tree if that commit needs to be reproducible.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
from sender.sample_doc import build_sample_document

from attacklab.conditions import COLLUSION_CONDITIONS, SYNTHETIC_CONDITIONS
from attacklab.harness import (
    git_commit,
    render_results_markdown,
    run_collusion_condition,
    run_real_capture_folder,
    run_synthetic_condition,
    summarize_all,
    write_results_csv,
)
from attacklab.metrics import TrialResult
from attacklab.scenario import DEFAULT_EPS1, build_scenario

TOP_LEVEL_SEED = 20270115
N_SESSIONS = 8
PAGE_COUNT = 3
DPI = 150
N_TRIALS_PER_CONDITION = 5
SEED_STRIDE = 10_000  # keeps every condition's trial seeds non-overlapping

# Deliberately cwd-based, not derived from __file__ — see
# sender.demo_m1's docstring for why (this module gets pip-installed too).
# Both `make demo-m7` and the Docker Compose service invoke this with the
# repo root as the working directory.
DEFAULT_RESULTS_MD = Path.cwd() / "docs" / "RESULTS.md"
DEFAULT_OUT_DIR = Path.cwd() / "attacklab" / "out"
DEFAULT_REAL_DIR = Path.cwd() / "attacklab" / "real"


def run(
    *,
    results_md: Path = DEFAULT_RESULTS_MD,
    out_dir: Path = DEFAULT_OUT_DIR,
    real_dir: Path = DEFAULT_REAL_DIR,
) -> bool:
    print("== TraceSeal M7 demo: attack lab ==")

    doc = build_sample_document(page_count=PAGE_COUNT)
    try:
        rng = np.random.default_rng(TOP_LEVEL_SEED)
        scenario = build_scenario(doc, n_sessions=N_SESSIONS, dpi=DPI, eps1=DEFAULT_EPS1, rng=rng)
    finally:
        doc.close()

    n_positions = len(scenario.variants.rendered_positions)
    print(
        f"sample document: {PAGE_COUNT} pages, {n_positions} mark positions, "
        f"{N_SESSIONS} sessions, {len(SYNTHETIC_CONDITIONS)} synthetic + "
        f"{len(COLLUSION_CONDITIONS)} collusion conditions, "
        f"{N_TRIALS_PER_CONDITION} trials each"
    )

    all_trials: list[TrialResult] = []
    condition_params: dict[str, dict[str, object]] = {}
    synthetic_by_condition: dict[str, list[TrialResult]] = {}
    collusion_by_condition: dict[str, list[TrialResult]] = {}

    for i, synth_condition in enumerate(SYNTHETIC_CONDITIONS):
        base_seed = TOP_LEVEL_SEED + i * SEED_STRIDE
        results = run_synthetic_condition(
            synth_condition, scenario, n_trials=N_TRIALS_PER_CONDITION, base_seed=base_seed
        )
        synthetic_by_condition[synth_condition.name] = results
        condition_params[synth_condition.name] = synth_condition.params
        all_trials.extend(results)
        print(f"  [{synth_condition.name}] {len(results)} trials")

    for i, collusion_condition in enumerate(COLLUSION_CONDITIONS):
        base_seed = TOP_LEVEL_SEED + (len(SYNTHETIC_CONDITIONS) + i) * SEED_STRIDE
        results = run_collusion_condition(
            collusion_condition, scenario, n_trials=N_TRIALS_PER_CONDITION, base_seed=base_seed
        )
        collusion_by_condition[collusion_condition.name] = results
        condition_params[collusion_condition.name] = {
            "strategy": collusion_condition.strategy,
            "c": collusion_condition.c,
        }
        all_trials.extend(results)
        print(f"  [{collusion_condition.name}] {len(results)} trials")

    real_capture = run_real_capture_folder(real_dir, scenario)
    print(f"real-capture folder ({real_dir}): {len(real_capture)} file(s) evaluated")

    commit = git_commit()
    write_results_csv(
        out_dir / "results.csv",
        all_trials,
        git_commit=commit,
        seed=TOP_LEVEL_SEED,
        condition_params=condition_params,
    )
    render_results_markdown(
        synthetic_summaries=summarize_all(synthetic_by_condition),
        collusion_summaries=summarize_all(collusion_by_condition),
        real_capture=real_capture,
        git_commit=commit,
        seed=TOP_LEVEL_SEED,
        n_sessions=N_SESSIONS,
        n_positions=n_positions,
        eps1=DEFAULT_EPS1,
        n_trials=N_TRIALS_PER_CONDITION,
        out_path=results_md,
    )

    expected_conditions = {c.name for c in SYNTHETIC_CONDITIONS} | {
        c.name for c in COLLUSION_CONDITIONS
    }
    covered_conditions = {t.condition for t in all_trials}
    missing = expected_conditions - covered_conditions
    expected_row_count = len(expected_conditions) * N_TRIALS_PER_CONDITION

    ok = not missing and expected_row_count == len(all_trials)
    status = "PASS" if ok else "FAIL"
    print(f"\n[{status}] {len(all_trials)} trials across {len(covered_conditions)} conditions")
    if missing:
        print(f"[FAIL] conditions never run: {sorted(missing)}")
    if expected_row_count != len(all_trials):
        print(f"[FAIL] expected {expected_row_count} total trials, got {len(all_trials)}")
    print(f"Results written to {results_md} and {out_dir / 'results.csv'}")
    return ok


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-md", type=Path, default=DEFAULT_RESULTS_MD)
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--real-dir", type=Path, default=DEFAULT_REAL_DIR)
    args = parser.parse_args()
    ok = run(results_md=args.results_md, out_dir=args.out_dir, real_dir=args.real_dir)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
