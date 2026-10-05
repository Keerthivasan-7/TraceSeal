#!/usr/bin/env python3
"""Verify an evidence bundle in a container with NO network, then do it again on a
copy with one byte changed — the original verifies, the tampered copy is rejected.

Usage: python scripts/verify_offline.py path/to/case.tsev

The verifier image depends only on `tscore` (no ledger, no keys, no server): it
re-checks every signature, ledger proof, commitment and Tardos score from the
bundle alone. The tampered copy is written next to the original as
`<name>-tampered.tsev`; your original is never modified.
"""

from __future__ import annotations

import os
import subprocess
import sys
import zipfile
from pathlib import Path


def verify(bundle: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{bundle.resolve()}:/in/case.tsev:ro",
         "traceseal/verifier:m5", "traceseal-verify", "/in/case.tsev"],
        capture_output=True, text=True, timeout=120, env=env, check=False,
    )  # fmt: skip


def message(result: subprocess.CompletedProcess[str]) -> str:
    """The verifier's verdict line, without liboqs's unrelated start-up notice."""
    lines = [
        line.strip()
        for line in (result.stdout + result.stderr).splitlines()
        if line.strip() and "faulthandler" not in line
    ]
    return lines[0][-200:] if lines else ""


def tamper(source: Path, target: Path) -> None:
    """Rebuild the archive with one byte of the signed bundle flipped (the same
    method as `forensics.tamper_demo`)."""
    with zipfile.ZipFile(source) as src:
        contents = {name: src.read(name) for name in src.namelist()}
    mutated = bytearray(contents["bundle.cbor"])
    # Mid-bundle, so the structure still parses and what fails is the signature itself.
    mutated[len(mutated) // 2] ^= 0x01
    contents["bundle.cbor"] = bytes(mutated)
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as dst:
        for name, content in contents.items():
            dst.writestr(name, content)


def main() -> int:
    if len(sys.argv) != 2 or not Path(sys.argv[1]).is_file():
        print(__doc__)
        return 2
    bundle = Path(sys.argv[1])
    print(f"verifying {bundle.name} in a container with --network none ...\n")
    good = verify(bundle)
    print(f"  ORIGINAL  -> {'VALID' if good.returncode == 0 else 'REJECTED'}  {message(good)}")

    bad_path = bundle.with_name(bundle.stem + "-tampered.tsev")
    tamper(bundle, bad_path)
    print("\nnow flipping ONE bit inside the signed bundle ...\n")
    bad = verify(bad_path)
    print(f"  TAMPERED  -> {'VALID' if bad.returncode == 0 else 'REJECTED'}  {message(bad)}")
    return 0 if good.returncode == 0 and bad.returncode != 0 else 1


if __name__ == "__main__":
    sys.exit(main())
