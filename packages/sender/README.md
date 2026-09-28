# sender-station

**M1 scope implemented:** the variant/watermark engine and quality gate.
`packages/sender/src/sender/`:

- `sample_doc.py` — the synthetic demo document.
- `positions.py` — mark-position selection (word boxes, header/footer
  margin, non-overlapping padded patch regions).
- `variants.py` — Variant A (micro-shift) rendering: redact + reinsert the
  target word at `±delta_px` on a full-page clone, then crop the patch back
  out (see `docs/DECISIONS.md` ADR-0006 for why, including two rejected
  approaches).
- `manifest.py` — the position-table/manifest shape the future `.tspkg`
  format will carry.
- `assemble.py` — paste a codeword-selected patch per position onto the
  base pages.
- `quality_gate.py` — whole-page SSIM + a per-position corruption check
  (ADR-0007).
- `demo_m1.py` — the M1 acceptance script (`make demo-m1`).

**Not yet implemented:** encryption, `K_A`/`K_B`/`S_v` generation, Shamir
share distribution to Key-Release nodes, packaging into `.tspkg`, ledger
registration — all **Milestone M3** (see `docs/SPEC.md` Section 7.2). Only
Variant A (micro-shift) exists; Variant B/C are evaluated later, in the
attack lab (M7).

See `docs/SPEC.md` Section 4, Section 7.2 and Section 9.
