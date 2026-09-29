# attack-lab

Milestone M7's reproducible distortion + collusion harness (spec Section
15). Runs entirely in-process — no live cluster, no ledger/keyrelease/CA —
against `sender`'s variant rendering and `forensics`'s registration/
detection/accusation pipeline directly, so every trial is fast, seeded, and
independently reproducible.

```bash
make test-attacklab   # unit tests: distortion determinism, collusion
                       # bit-strategy correctness, metrics formulas,
                       # condition-list completeness, a small real
                       # end-to-end smoke run
make demo-m7           # the full M7 acceptance run: every spec Section 15
                       # synthetic distortion + collusion condition, writes
                       # docs/RESULTS.md and attacklab/out/results.csv
```

## Layout

- `src/attacklab/distortions.py` — seeded synthetic distortions (JPEG,
  resize, crop, rotation, perspective warp, blur, noise, brightness/
  contrast, a simulated screen-camera pipeline, a simulated print-scan
  pipeline).
- `src/attacklab/collusion.py` — the four bit-selection collusion
  strategies (majority/minority/random/interleave) plus patch averaging,
  the one strategy that needs real pixel blending rather than an abstract
  bit choice.
- `src/attacklab/metrics.py` — per-trial and per-condition metrics: bit
  error rate, erasure rate, top-1 correct attribution, innocent
  accusations, runtime.
- `src/attacklab/conditions.py` — the declarative list of every condition
  spec Section 15 requires; `tests/test_conditions.py` checks nothing is
  missing or duplicated.
- `src/attacklab/scenario.py` — builds one shared rendered document +
  session codewords per run.
- `src/attacklab/harness.py` — runs trials, aggregates metrics, writes
  `docs/RESULTS.md` and `attacklab/out/results.csv`.
- `src/attacklab/demo_m7.py` — the milestone acceptance script
  (`python -m attacklab.demo_m7`).
- `../../attacklab/real/` (repo root, not under this package) — drop real
  phone-photo/scan captures here; see that directory's own README for the
  expected filename convention. Ships empty for M7 — reported honestly in
  `docs/RESULTS.md`, not hidden.
- `../../attacklab/out/` (repo root, gitignored) — `results.csv`, written
  fresh by every harness run.

## Honest scope for M7

- Only variant A (micro-shift) is evaluated — it's the only variant type
  that was ever built (M1-M6). Variants B (glyph micro-scale) and C
  (stroke-weight), which spec Section 9 named as "behind flags and
  evaluated in the attack lab," were never implemented; see
  `docs/DECISIONS.md` for the ADR recording this as deferred.
- No page-detection/perspective-correction step exists for separating a
  photographed page from its background (spec Section 11 step 2) — see
  `../../attacklab/real/README.md`'s "known limitation" section and
  `docs/DECISIONS.md`.
- Collusion trials draw a random coalition from the scenario's own
  sessions each trial; they are not combined with synthetic distortions in
  the same trial (spec lists them as separate suites).
