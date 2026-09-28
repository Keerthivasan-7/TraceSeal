#!/usr/bin/env python3
"""Write the synthetic M1 sample PDF to disk (for manual inspection).

Requires the `sender` package to be installed (see packages/sender). Not
needed for `make demo-m1` itself, which builds the document in memory via
`sender.sample_doc.build_sample_document()` directly.

Usage: python demo/generate_sample_pdf.py [output_path]
"""

from __future__ import annotations

import sys
from pathlib import Path

from sender.sample_doc import build_sample_document

DEFAULT_OUTPUT = Path(__file__).parent / "out" / "SAMPLE_OPERATION_PLAN.pdf"


def main() -> None:
    output_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT
    output_path.parent.mkdir(parents=True, exist_ok=True)
    doc = build_sample_document()
    doc.save(output_path)
    doc.close()
    print(f"wrote {output_path} ({output_path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
