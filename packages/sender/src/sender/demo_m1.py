"""Milestone M1 acceptance script (spec Section 17):

    "A 3-page sample PDF produces 5 assembled copies; the quality gate
    passes; the Tardos simulation meets its bounds."

The Tardos *simulation* bound-check itself is the separate, slower
Monte-Carlo suite in `packages/tscore/tests/test_tardos.py` (run via
`make test-tardos-sim`) — this script covers the other two: it builds the
synthetic sample document, runs the variant engine and quality gate, and
assembles 5 per-session copies using real Tardos codewords, honestly
reporting whatever collusion-resistance parameters this particular
document's mark-position budget can actually support (see
`tscore.tardos.plan_parameters` — a short synthetic document is expected to
fall well short of the naive n=5/c0=3/eps1=1e-4 target, and that fallback
is exercised here deliberately, not hidden).
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image
from tscore.tardos import assign_codeword, plan_parameters, sample_bias_vector

from sender.assemble import assemble_document
from sender.positions import select_positions
from sender.quality_gate import run_quality_gate
from sender.sample_doc import build_sample_document
from sender.variants import build_document_variants

N_SESSIONS = 5
EPS1 = 1e-4
MAX_C0 = 3
BIAS_CUTOFF = 0.1
RNG_SEED = 20260101  # fixed so the demo is reproducible run to run

# Deliberately cwd-based, not derived from __file__: under a real (non-
# editable) pip install — e.g. inside the Docker image — __file__ resolves
# into site-packages, nowhere near the repo. Both `make demo-m1` and the
# Docker Compose service invoke this with the repo root as the working
# directory, which is also the assumed convention for any local run.
DEFAULT_OUTPUT_DIR = Path.cwd() / "demo" / "out" / "m1"


def _save_pages(session_id: str, pages: list[np.ndarray], out_dir: Path) -> list[Path]:
    session_dir = out_dir / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for page_index, page in enumerate(pages):
        path = session_dir / f"page_{page_index + 1}.png"
        Image.fromarray(page).save(path)
        paths.append(path)
    return paths


def run(output_dir: Path = DEFAULT_OUTPUT_DIR) -> bool:
    print("== TraceSeal M1 demo: variant engine + quality gate + Tardos ==")

    doc = build_sample_document()
    print(f"sample document: {doc.page_count} pages (synthetic content only)")

    positions = select_positions(doc)
    print(f"mark positions selected: {len(positions)}")
    if not positions:
        print("[FAIL] no mark positions found — sample document has no eligible words")
        return False

    print("rendering variants and building the base pages ...")
    variants = build_document_variants(doc, positions)

    print("running the quality gate ...")
    gate_report = run_quality_gate(variants)
    for page_result in gate_report.pages:
        status = "PASS" if page_result.passed else "FAIL"
        print(
            f"  [{status}] page {page_result.page_index} variant-bit {page_result.variant_bit}: "
            f"whole-page SSIM={page_result.ssim:.4f} "
            f"(threshold {gate_report.ssim_threshold}), max|delta|={page_result.max_abs_delta}"
        )
    failing_positions = [p for p in gate_report.positions if not p.passed]
    print(
        f"  per-position corruption check: {len(gate_report.positions)} positions, "
        f"{len(failing_positions)} failing "
        f"(changed-fraction threshold {gate_report.max_changed_fraction})"
    )
    if not gate_report.passed:
        print("[FAIL] quality gate did not pass — refusing to package (see spec Section 9)")
        return False
    print("[PASS] quality gate")

    try:
        plan = plan_parameters(
            available_positions=len(positions), n=N_SESSIONS, eps1=EPS1, max_c0=MAX_C0
        )
        if plan.degraded:
            print(
                f"[WARNING] document supports only c0={plan.c0} "
                f"(requested max_c0={plan.requested_c0}) at n={N_SESSIONS}, eps1={EPS1}; "
                f"collusion-resistance claim is reduced accordingly, not silently ignored."
            )
        else:
            print(f"Tardos parameters: c0={plan.c0} achieved at n={N_SESSIONS}, eps1={EPS1}")
    except ValueError as exc:
        print(
            f"[WARNING] {exc} — proceeding with {len(positions)}-bit per-session codewords "
            "for demonstration only, with NO formal collusion-resistance guarantee at this "
            "n/eps1. A real deployment would refuse to distribute under these conditions."
        )

    rng = np.random.default_rng(RNG_SEED)
    bias = sample_bias_vector(len(positions), cutoff=BIAS_CUTOFF, rng=rng)
    session_ids = [f"S-{i + 1:04d}" for i in range(N_SESSIONS)]
    codewords = {sid: assign_codeword(bias, rng) for sid in session_ids}

    print(f"assembling {N_SESSIONS} per-session copies ...")
    output_dir.mkdir(parents=True, exist_ok=True)
    for sid in session_ids:
        pages = assemble_document(variants, codewords[sid])
        paths = _save_pages(sid, pages, output_dir)
        print(f"  {sid}: {len(paths)} page(s) -> {paths[0].parent}")

    print(f"[PASS] {N_SESSIONS} assembled copies written under {output_dir}")
    print(
        "Inspect them visually: every session's pages should look identical to a human, "
        "differing only in which (invisible-to-the-eye) word-shift variant each carries."
    )
    return True


def main() -> int:
    ok = run()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
