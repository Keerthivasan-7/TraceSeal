"""Milestone M2 acceptance script (spec Section 17):

    "Top-1 attribution across 5 sessions from clean PNG screenshots is
    100%, with 0 innocent accusations."

Builds the same 5-session scenario `sender.demo_m1` does, then for each
session in turn: simulates a "clean screenshot" of one of that session's
pages (resized to a different DPI/scale than the 300 DPI original, saved
as a real PNG and reloaded — a genuine encode/decode round trip, not an
in-memory shortcut), runs it through the forensics pipeline, and checks
that only the actual leaking session is accused.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
from PIL import Image
from sender.assemble import assemble_document
from sender.positions import select_positions
from sender.sample_doc import build_sample_document
from sender.variants import build_document_variants
from tscore.tardos import assign_codeword, sample_bias_vector

from forensics.pipeline import investigate

N_SESSIONS = 5
EPS1 = 1e-4
BIAS_CUTOFF = 0.1
SCREENSHOT_SCALE = 0.5  # simulates a lower-DPI viewer/screen capture
RNG_SEED = 20260215

DEFAULT_OUTPUT_DIR = Path.cwd() / "demo" / "out" / "m2"


def _simulate_screenshot(page: np.ndarray, out_path: Path, *, scale: float) -> np.ndarray:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.fromarray(page)
    resized = img.resize(
        (round(img.width * scale), round(img.height * scale)), Image.Resampling.LANCZOS
    )
    resized.save(out_path)
    return np.array(Image.open(out_path).convert("RGB"))


def run(output_dir: Path = DEFAULT_OUTPUT_DIR) -> bool:
    print("== TraceSeal M2 demo: forensics on clean screenshots ==")

    doc = build_sample_document()
    positions = select_positions(doc)
    variants = build_document_variants(doc, positions)
    n_positions = len(variants.rendered_positions)
    n_pages = len(variants.base_pages)
    print(f"sample document: {n_pages} pages, {n_positions} mark positions")

    rng = np.random.default_rng(RNG_SEED)
    bias = sample_bias_vector(n_positions, cutoff=BIAS_CUTOFF, rng=rng)
    session_ids = [f"S-{i + 1:04d}" for i in range(N_SESSIONS)]
    codewords = {sid: assign_codeword(bias, rng) for sid in session_ids}

    all_correct = True
    for trial, leaking_session in enumerate(session_ids):
        leak_page_index = trial % n_pages
        pages = assemble_document(variants, codewords[leaking_session])
        artifact_path = output_dir / f"leak_{leaking_session}_page{leak_page_index}.png"
        artifact = _simulate_screenshot(
            pages[leak_page_index], artifact_path, scale=SCREENSHOT_SCALE
        )

        report = investigate(artifact, leak_page_index, variants, codewords, bias, EPS1)
        # Require the leak to actually clear the threshold (be "accused"),
        # not just have the highest raw score among 5 candidates — those
        # aren't the same thing when nothing clears the bar at all.
        attributed = leaking_session in report.accused_sessions
        correct = report.top_session == leaking_session
        innocents = [sid for sid in report.accused_sessions if sid != leaking_session]
        ok = attributed and correct and not innocents
        all_correct = all_correct and ok

        status = "PASS" if ok else "FAIL"
        top = report.top_session
        assert top is not None  # report.scores always has all 5 sessions in this demo
        print(
            f"[{status}] leaked {leaking_session} page {leak_page_index} -> "
            f"top suspect {top} (score {report.scores[top]:.2f}, "
            f"threshold {report.threshold:.2f}); innocents accused: {innocents or 'none'}"
        )
        print(f"        {report.summary()}")

    if all_correct:
        print(f"\n[PASS] {N_SESSIONS}/{N_SESSIONS} sessions correctly attributed, 0 innocents")
    else:
        print(f"\n[FAIL] not all {N_SESSIONS} trials attributed correctly (see above)")
    print(f"Simulated screenshots written under {output_dir}")
    return all_correct


def main() -> int:
    ok = run()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
