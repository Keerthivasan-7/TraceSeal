# forensics

**M2 scope implemented:** registration, per-position detection, and Tardos
accusation against a *known* document. `packages/forensics/src/forensics/`:

- `align.py` — ORB keypoints + RANSAC homography, warping an artifact into
  the reference (base-plus-variant-0) page's coordinate frame.
- `detect.py` — per-position detection via local template-match search
  (not a direct crop-and-compare — see `docs/DECISIONS.md` ADR-0010 for
  why that turned out to be necessary, not optional).
- `pipeline.py` — wires registration → detection → `tscore.tardos`
  accusation together, restricted to whichever positions fall on the
  artifact's actual page.
- `report.py` — the statistical-conclusion summary text (never claims
  guilt or intent; always states its own limitations).
- `demo_m2.py` — the M2 acceptance script (`make demo-m2`): leaks each of
  5 sessions' pages in turn as a simulated rescaled screenshot and checks
  attribution.

**Not yet implemented:** OCR/document identification across a vault (no
vault exists until M3+M5), perspective correction for photos, print-scan
robustness (M7's attack lab), evidence-bundle signing and ledger-backed
verification (M5), soft confidence-weighted Tardos scoring — see
`docs/DECISIONS.md` ADR-0009 for why each is deliberately deferred rather
than built speculatively now.

See `docs/SPEC.md` Section 4, Section 10, and Section 11.
