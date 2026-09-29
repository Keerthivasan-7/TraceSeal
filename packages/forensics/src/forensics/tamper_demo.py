"""Spec Section 18 demo step 9: copy a genuine `.tsev`, flip one byte in
its `bundle.cbor`, and confirm `traceseal-verify` rejects the copy while
the original still verifies. `zipfile` has no in-place edit, so this
rebuilds the whole archive, copying every other entry verbatim and only
mutating `bundle.cbor`'s bytes — exactly tampering case 1 of the M5 plan's
tampering table (caught by the outer bundle signature alone)."""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path

DEFAULT_SOURCE = Path.cwd() / "demo" / "out" / "m5" / "case.tsev"
DEFAULT_OUTPUT = Path.cwd() / "demo" / "out" / "m5" / "case_tampered.tsev"


def tamper(source: Path = DEFAULT_SOURCE, output: Path = DEFAULT_OUTPUT) -> None:
    with zipfile.ZipFile(source, "r") as src:
        names = src.namelist()
        contents = {name: src.read(name) for name in names}

    bundle_cbor = bytearray(contents["bundle.cbor"])
    bundle_cbor[-1] ^= 0x01
    contents["bundle.cbor"] = bytes(bundle_cbor)

    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as dst:
        for name in names:
            dst.writestr(name, contents[name])


def main() -> int:
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SOURCE
    output = Path(sys.argv[2]) if len(sys.argv) > 2 else DEFAULT_OUTPUT
    tamper(source, output)
    print(f"[PASS] wrote tampered copy (one byte flipped in bundle.cbor) to {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
