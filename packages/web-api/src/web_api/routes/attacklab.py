"""Attack Lab (spec Section 14.8): the real robustness/collusion-resistance
results — `docs/RESULTS.md` (written only by `python -m attacklab.demo_m7`,
never hand-edited, never by this route) plus a small, clearly-labeled live
"quick run" using the same real `attacklab.harness` trial functions, for a
demo-able sample distinct from the full authoritative benchmark.
"""

from __future__ import annotations

import math
import re
from typing import Any

import numpy as np
from attacklab.conditions import COLLUSION_CONDITIONS, SYNTHETIC_CONDITIONS
from attacklab.harness import run_collusion_condition, run_synthetic_condition, summarize_all
from attacklab.metrics import ConditionSummary
from attacklab.scenario import build_scenario
from fastapi import APIRouter, HTTPException
from sender.sample_doc import build_sample_document

from web_api.deps import SettingsDep

router = APIRouter(prefix="/attacklab", tags=["attacklab"])

QUICK_RUN_SEED = 990101
QUICK_RUN_N_SESSIONS = 8
QUICK_RUN_N_TRIALS = 2
QUICK_RUN_SYNTHETIC = SYNTHETIC_CONDITIONS[:3]
QUICK_RUN_COLLUSION = COLLUSION_CONDITIONS[:2]

_TABLE_ROW_RE = re.compile(r"^\|(.+)\|$")


def _nan_to_none(value: float) -> float | None:
    return None if isinstance(value, float) and math.isnan(value) else value


def _summary_to_dict(summary: ConditionSummary) -> dict[str, Any]:
    return {
        "condition": summary.condition,
        "n_trials": summary.n_trials,
        "mean_bit_error_rate": _nan_to_none(summary.mean_bit_error_rate),
        "mean_erasure_rate": _nan_to_none(summary.mean_erasure_rate),
        "top1_accuracy": summary.top1_accuracy,
        "total_innocent_accusations": summary.total_innocent_accusations,
        "innocent_accusation_rate": _nan_to_none(summary.innocent_accusation_rate),
        "mean_runtime_ms": summary.mean_runtime_ms,
        "n_registration_failures": summary.n_registration_failures,
    }


def _parse_results_table(lines: list[str], start: int) -> tuple[list[dict[str, str]], int]:
    """Parses one markdown table starting at `lines[start]` (the header
    row) — the exact schema `attacklab.harness.render_results_markdown`
    always writes. Returns (rows, index of the line after the table)."""
    header_match = _TABLE_ROW_RE.match(lines[start].strip())
    if not header_match:
        return [], start
    headers = [h.strip() for h in header_match.group(1).split("|")]
    idx = start + 2  # skip the header and the |---|---| separator row
    rows: list[dict[str, str]] = []
    while idx < len(lines):
        match = _TABLE_ROW_RE.match(lines[idx].strip())
        if not match:
            break
        cells = [c.strip() for c in match.group(1).split("|")]
        rows.append(dict(zip(headers, cells, strict=False)))
        idx += 1
    return rows, idx


@router.get("/results")
def get_results(settings: SettingsDep) -> dict[str, Any]:
    """The full, authoritative benchmark from `docs/RESULTS.md`. Returns
    both the raw markdown (always shown — the source of truth) and a
    best-effort parse of its two tables for a nicer UI; parsing failure
    never hides the raw text."""
    results_path = settings.docs_dir / "RESULTS.md"
    if not results_path.exists():
        raise HTTPException(status_code=404, detail=f"{results_path} not found")
    text = results_path.read_text()
    lines = text.splitlines()

    synthetic_rows: list[dict[str, str]] = []
    collusion_rows: list[dict[str, str]] = []
    try:
        for i, line in enumerate(lines):
            if line.strip().startswith("| Condition |") and not synthetic_rows:
                synthetic_rows, _ = _parse_results_table(lines, i)
            elif line.strip().startswith("| Condition |") and synthetic_rows and not collusion_rows:
                collusion_rows, _ = _parse_results_table(lines, i)
    except Exception:  # noqa: BLE001 - parsing is best-effort; raw markdown is authoritative
        synthetic_rows, collusion_rows = [], []

    return {"markdown": text, "synthetic": synthetic_rows, "collusion": collusion_rows}


@router.post("/quick-run")
def quick_run() -> dict[str, Any]:
    """A small, seeded, real subset (3 synthetic + 2 collusion conditions,
    2 trials each) of the exact same `attacklab.harness` trial functions
    `python -m attacklab.demo_m7` runs at full scale — for a live demo
    button, never a substitute for the full benchmark in `docs/RESULTS.md`.
    """
    doc = build_sample_document()
    rng = np.random.default_rng(QUICK_RUN_SEED)
    scenario = build_scenario(doc, n_sessions=QUICK_RUN_N_SESSIONS, rng=rng)
    doc.close()

    results_by_condition = {}
    for synthetic_condition in QUICK_RUN_SYNTHETIC:
        results_by_condition[synthetic_condition.name] = run_synthetic_condition(
            synthetic_condition, scenario, n_trials=QUICK_RUN_N_TRIALS, base_seed=QUICK_RUN_SEED
        )
    for collusion_condition in QUICK_RUN_COLLUSION:
        results_by_condition[collusion_condition.name] = run_collusion_condition(
            collusion_condition, scenario, n_trials=QUICK_RUN_N_TRIALS, base_seed=QUICK_RUN_SEED
        )

    summaries = summarize_all(results_by_condition)
    return {
        "seed": QUICK_RUN_SEED,
        "n_sessions": QUICK_RUN_N_SESSIONS,
        "n_trials": QUICK_RUN_N_TRIALS,
        "eps1": scenario.eps1,
        "n_positions": len(scenario.variants.rendered_positions),
        "conditions": [_summary_to_dict(s) for s in summaries],
    }
