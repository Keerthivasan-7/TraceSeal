"""Runs trials, aggregates metrics, and writes `docs/RESULTS.md` +
`attacklab/out/results.csv` (spec Section 15). Every trial is a real
`forensics.pipeline.investigate` call over real (distorted or colluded)
pixels — never a mocked or simulated score.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
import time
from dataclasses import asdict
from pathlib import Path

import numpy as np
from forensics.align import RegistrationError
from forensics.pipeline import investigate
from forensics.report import InvestigationReport
from PIL import Image
from sender.assemble import assemble_document

from attacklab.collusion import BIT_STRATEGIES, realize_patch_averaging_pages
from attacklab.conditions import CollusionCondition, DistortionCondition
from attacklab.metrics import (
    ConditionSummary,
    TrialResult,
    compute_trial_result,
    summarize_condition,
)
from attacklab.scenario import Scenario, n_positions_on_page

_REAL_CAPTURE_EXTENSIONS = {".jpg", ".jpeg", ".png"}
_SESSION_TOKEN_RE = re.compile(r"(S-\d+)")
_PAGE_TOKEN_RE = re.compile(r"page(\d+)", re.IGNORECASE)


def _timed_investigate(
    artifact: np.ndarray, page_index: int, scenario: Scenario
) -> tuple[InvestigationReport | None, float]:
    """Runs `investigate`, timing only the investigation itself (not
    whatever distortion/compositing produced ``artifact``) — a
    `RegistrationError` is caught and reported as `None` (a total,
    honestly-recorded erasure), not a crash."""
    start = time.perf_counter()
    try:
        report = investigate(
            artifact,
            page_index,
            scenario.variants,
            scenario.codewords,
            scenario.bias,
            scenario.eps1,
        )
    except RegistrationError:
        report = None
    runtime_ms = (time.perf_counter() - start) * 1000.0
    return report, runtime_ms


def run_synthetic_condition(
    condition: DistortionCondition,
    scenario: Scenario,
    *,
    n_trials: int,
    base_seed: int,
) -> list[TrialResult]:
    n_pages = len(scenario.variants.base_pages)
    results: list[TrialResult] = []
    for trial in range(n_trials):
        seed = base_seed + trial
        rng = np.random.default_rng(seed)
        leaking_session = scenario.session_ids[trial % len(scenario.session_ids)]
        page_index = trial % n_pages

        clean_pages = assemble_document(scenario.variants, scenario.codewords[leaking_session])
        distorted = condition.apply(clean_pages[page_index], rng)

        report, runtime_ms = _timed_investigate(distorted, page_index, scenario)
        results.append(
            compute_trial_result(
                condition=condition.name,
                trial_seed=seed,
                page_index=page_index,
                true_source_sessions=frozenset({leaking_session}),
                report=report,
                ground_truth_bits=scenario.codewords[leaking_session],
                n_candidate_sessions=len(scenario.session_ids),
                n_page_positions=n_positions_on_page(scenario, page_index),
                runtime_ms=runtime_ms,
            )
        )
    return results


def run_collusion_condition(
    condition: CollusionCondition,
    scenario: Scenario,
    *,
    n_trials: int,
    base_seed: int,
) -> list[TrialResult]:
    n_pages = len(scenario.variants.base_pages)
    session_pool = np.array(scenario.session_ids)
    results: list[TrialResult] = []
    for trial in range(n_trials):
        seed = base_seed + trial
        rng = np.random.default_rng(seed)
        coalition = list(rng.choice(session_pool, size=condition.c, replace=False))
        page_index = trial % n_pages
        coalition_codewords = {sid: scenario.codewords[sid] for sid in coalition}

        if condition.strategy == "patch_averaging":
            pages = realize_patch_averaging_pages(scenario.variants, coalition_codewords)
            ground_truth_bits = None
        else:
            stacked = np.stack([coalition_codewords[sid] for sid in coalition])
            pirate_bits = BIT_STRATEGIES[condition.strategy](stacked, rng)
            pages = assemble_document(scenario.variants, pirate_bits)
            ground_truth_bits = pirate_bits

        report, runtime_ms = _timed_investigate(pages[page_index], page_index, scenario)
        results.append(
            compute_trial_result(
                condition=condition.name,
                trial_seed=seed,
                page_index=page_index,
                true_source_sessions=frozenset(coalition),
                report=report,
                ground_truth_bits=ground_truth_bits,
                n_candidate_sessions=len(scenario.session_ids),
                n_page_positions=n_positions_on_page(scenario, page_index),
                runtime_ms=runtime_ms,
            )
        )
    return results


def run_real_capture_folder(real_dir: Path, scenario: Scenario) -> list[dict[str, object]]:
    """Evaluates every image file in ``real_dir`` identically to a
    synthetic trial. Returns an empty list (not an error) when the folder
    doesn't exist or holds no images — the M7 milestone ships this folder
    empty; `harness.render_results_markdown` reports that honestly rather
    than omitting the section. A filename may optionally encode its true
    session (``S-0004``) and page (``page1``) for top-1/BER-style
    cross-checking; captures without either are still detected/scored, just
    without a ground truth to compare against."""
    if not real_dir.exists():
        return []
    paths = sorted(
        p
        for p in real_dir.iterdir()
        if p.is_file() and p.suffix.lower() in _REAL_CAPTURE_EXTENSIONS
    )
    entries: list[dict[str, object]] = []
    for path in paths:
        image = np.array(Image.open(path).convert("RGB"))
        session_match = _SESSION_TOKEN_RE.search(path.stem)
        page_match = _PAGE_TOKEN_RE.search(path.stem)
        page_index = int(page_match.group(1)) if page_match else 0
        true_session = session_match.group(1) if session_match else None

        report, runtime_ms = _timed_investigate(image, page_index, scenario)
        top_session = report.top_session if report else None
        entries.append(
            {
                "filename": path.name,
                "true_session": true_session,
                "page_index": page_index,
                "registration_failed": report is None,
                "top_session": top_session,
                "score": report.scores.get(top_session) if report and top_session else None,
                "threshold": report.threshold if report else None,
                "n_observed": report.n_observed if report else 0,
                "n_total_positions": report.n_total_positions if report else 0,
                "runtime_ms": runtime_ms,
            }
        )
    return entries


def git_commit() -> str:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607 - fixed args, controlled container
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def write_results_csv(
    path: Path,
    trials: list[TrialResult],
    *,
    git_commit: str,
    seed: int,
    condition_params: dict[str, dict[str, object]],
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "git_commit",
        "seed",
        "condition",
        "condition_params_json",
        "trial_seed",
        "page_index",
        "true_source_sessions",
        "bit_error_rate",
        "erasure_rate",
        "n_erasures",
        "n_observed",
        "n_total_positions",
        "top1_correct",
        "n_innocent_accused",
        "n_candidate_sessions",
        "runtime_ms",
        "registration_failed",
    ]
    with path.open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for trial in trials:
            row = asdict(trial)
            row["true_source_sessions"] = ",".join(sorted(trial.true_source_sessions))
            row["condition_params_json"] = json.dumps(condition_params.get(trial.condition, {}))
            row["git_commit"] = git_commit
            row["seed"] = seed
            writer.writerow(row)


def _format_rate(value: float) -> str:
    return "n/a" if np.isnan(value) else f"{value:.4f}"


def _summary_row(summary: ConditionSummary) -> str:
    innocent_rate = _format_rate(summary.innocent_accusation_rate)
    return (
        f"| {summary.condition} | {summary.n_trials} | {_format_rate(summary.mean_bit_error_rate)} "
        f"| {_format_rate(summary.mean_erasure_rate)} | {summary.top1_accuracy:.2%} "
        f"| {summary.total_innocent_accusations} ({innocent_rate}) "
        f"| {summary.mean_runtime_ms:.1f} | {summary.n_registration_failures} |"
    )


def render_results_markdown(
    *,
    synthetic_summaries: list[ConditionSummary],
    collusion_summaries: list[ConditionSummary],
    real_capture: list[dict[str, object]],
    git_commit: str,
    seed: int,
    n_sessions: int,
    n_positions: int,
    eps1: float,
    n_trials: int,
    out_path: Path,
) -> None:
    header_table = (
        "| Condition | Trials | Mean BER | Mean Erasure Rate | Top-1 Accuracy "
        "| Innocent Accusations (total / rate) | Mean Runtime (ms) | Registration Failures |\n"
        "|---|---|---|---|---|---|---|---|"
    )
    lines = [
        "# Attack Lab Results",
        "",
        "Generated by `python -m attacklab.demo_m7` — never hand-edited.",
        "",
        f"- Git commit: `{git_commit}`",
        f"- Top-level seed: `{seed}`",
        f"- Tardos parameters: n={n_sessions}, eps1={eps1:g}, document positions={n_positions}",
        f"- Trials per condition: {n_trials}",
        "",
        "## Synthetic distortions",
        "",
        header_table,
    ]
    lines.extend(_summary_row(s) for s in synthetic_summaries)
    lines.extend(
        [
            "",
            "## Collusion",
            "",
            "`Mean BER` is `n/a` for `patch_averaging` rows — patch averaging blends pixel "
            "content that no discrete pirate bit sequence describes, so no bit-error rate "
            "applies (see `packages/attacklab/src/attacklab/collusion.py`).",
            "",
            header_table,
        ]
    )
    lines.extend(_summary_row(s) for s in collusion_summaries)
    lines.extend(["", "## Real-capture (`attacklab/real/`)", ""])
    if not real_capture:
        lines.append(
            "No real-capture data was supplied for this milestone. `attacklab/real/` "
            "contains no phone photos or scans as of this run; this section will "
            "populate automatically the next time the harness runs against a "
            "non-empty folder — see `packages/attacklab/README.md` for the expected "
            "filename format."
        )
    else:
        lines.append(
            "| Filename | Detected? | Top-1 Session | Score | Threshold | Positions Observed "
            "| Runtime (ms) |\n|---|---|---|---|---|---|---|"
        )
        for entry in real_capture:
            detected = "no (registration failed)" if entry["registration_failed"] else "yes"
            score = entry["score"]
            score_str = f"{score:.2f}" if isinstance(score, float) else "n/a"
            threshold = entry["threshold"]
            threshold_str = f"{threshold:.2f}" if isinstance(threshold, float) else "n/a"
            lines.append(
                f"| {entry['filename']} | {detected} | {entry['top_session'] or 'n/a'} "
                f"| {score_str} | {threshold_str} "
                f"| {entry['n_observed']}/{entry['n_total_positions']} "
                f"| {entry['runtime_ms']:.1f} |"
            )
    lines.append("")
    out_path.write_text("\n".join(lines))


def summarize_all(results_by_condition: dict[str, list[TrialResult]]) -> list[ConditionSummary]:
    return [summarize_condition(results) for results in results_by_condition.values() if results]
