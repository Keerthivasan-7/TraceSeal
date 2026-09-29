"""`traceseal-verify` CLI (spec Section 4, Section 7.5 step 5): unzips a
`.tsev` evidence bundle, reconstructs the exact signed bytes from
`bundle.cbor` + `signature.json`, and calls
`tscore.evidence.verify_evidence_bundle` — the SAME function
`forensics.investigation.build_evidence_bundle` already called on itself
before ever writing the bundle to disk (single source of truth; see that
module's docstring). This package imports nothing but `tscore` — checked
literally by this Dockerfile never copying any other TraceSeal package in.

Usage: ``traceseal-verify case.tsev`` — prints ``VALID: ...`` and exits 0
on success, or ``INVALID: <reason>`` and exits 1 on any failure, including
a malformed/corrupted archive.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path


def verify_tsev(path: Path) -> tuple[bool, str]:
    """Returns `(ok, message)` — never raises for an invalid bundle (a
    corrupt file, an unreadable zip, a missing member, or a failed
    cryptographic check are all just "not valid", not a crash)."""
    from tscore.errors import VerificationError
    from tscore.evidence import verify_evidence_bundle
    from tscore.records import SignedSubmission

    try:
        with zipfile.ZipFile(path, "r") as zf:
            envelope_cbor = zf.read("bundle.cbor")
            signature_json = zf.read("signature.json")
            report_pdf_bytes = zf.read("report.pdf") if "report.pdf" in zf.namelist() else None
    except (OSError, zipfile.BadZipFile, KeyError) as exc:
        return False, f"could not read {path}: {exc}"

    import json

    try:
        signature_data = json.loads(signature_json)
        submission = SignedSubmission(
            envelope_cbor=envelope_cbor,
            signer_id=signature_data["signer_id"],
            signature=bytes.fromhex(signature_data["signature"]),
        )
    except Exception as exc:  # noqa: BLE001 - any malformed signature.json is just "invalid"
        return False, f"signature.json is malformed: {exc}"

    try:
        bundle = verify_evidence_bundle(submission, report_pdf_bytes=report_pdf_bytes)
    except VerificationError as exc:
        return False, str(exc)

    return True, (
        f"case {bundle.case_id!r} / document {bundle.doc_id!r}: signature, ledger proofs, "
        f"commitments, and Tardos scores all independently re-verified "
        f"({len(bundle.suspects)} candidate session(s))"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path, help="path to a .tsev evidence bundle")
    args = parser.parse_args()

    ok, message = verify_tsev(args.bundle)
    if ok:
        print(f"VALID: {message}")
        return 0
    print(f"INVALID: {message}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
