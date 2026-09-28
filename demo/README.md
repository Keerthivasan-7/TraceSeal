# demo

`generate_sample_pdf.py` writes the synthetic M1 sample document to disk
for manual inspection (`python demo/generate_sample_pdf.py`); the actual
`make demo-m1` acceptance script builds it in memory directly via
`sender.sample_doc.build_sample_document()` and doesn't need this file.

`out/` (gitignored) holds `make demo-m1`'s 5 assembled per-session copies
under `out/m1/S-000N/page_N.png` — generated output, not source.

The curated, presentation-quality `OPERATION_PLAN.pdf` and seed script used
by the full `make demo`/`make e2e` (Milestone M8) are a separate, later
addition — see `docs/DECISIONS.md` ADR-0005.
