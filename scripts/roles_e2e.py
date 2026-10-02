#!/usr/bin/env python3
"""End-to-end acceptance run of the isolated-roles deployment, through the real
consoles and the real nginx edge — the same HTTP calls the UI makes.

  command   releases a document to officer-a and officer-b
  officer-a opens it (own passphrase, own container); so does officer-b
  officer-b tries to open officer-a's copy                     -> denied
  officer-a "photographs" the page (simulated capture)         -> a PNG file
  command   is handed that file and investigates               -> accuses officer-a
  command   issues the evidence bundle; a container with NO network verifies it
  ... and a single tampered byte makes that verification fail.

Usage: python scripts/roles_e2e.py [--pdf demo/sample.pdf]
Needs `scripts/roles.sh provision` + `up` first. Exit status is non-zero on any FAIL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import zipfile
from pathlib import Path

from edge_client import credentials, login, request

ROOT = Path(__file__).resolve().parent.parent
results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> bool:
    results.append((ok, name, detail))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  — {detail}" if detail else ""), flush=True)
    return ok


def need(ok: bool, name: str, detail: str = "") -> None:
    """A check later steps depend on: stop the run if it fails."""
    if not check(ok, name, detail):
        summarize()
        sys.exit(1)


def jbody(raw: bytes) -> dict:  # type: ignore[type-arg]
    try:
        return json.loads(raw)  # type: ignore[no-any-return]
    except ValueError:
        return {"raw": raw[:200].decode(errors="replace")}


def verify_offline(bundle: Path) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    return subprocess.run(
        ["docker", "run", "--rm", "--network", "none", "-v", f"{bundle.resolve()}:/in/case.tsev:ro",
         "traceseal/verifier:m5", "traceseal-verify", "/in/case.tsev"],
        capture_output=True, text=True, timeout=120, env=env, check=False,
    )  # fmt: skip


def summarize() -> None:
    failed = [r for r in results if not r[0]]
    print(f"\n{len(results) - len(failed)} passed, {len(failed)} failed")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--pdf", type=Path, default=ROOT / "demo" / "sample.pdf")
    args = parser.parse_args()

    creds = credentials(str(ROOT / "demo" / "roles" / "CREDENTIALS.local.txt"))
    need(bool(creds), "credentials file present", "run scripts/roles.sh provision")

    command = login("command", creds["command"])
    a = login("officer-a", creds["officer-a"])
    b = login("officer-b", creds["officer-b"])
    need(all([command, a, b]), "command, officer-a and officer-b log in with their own passphrases")
    assert command and a and b

    try:
        # ---- command releases a document ---------------------------------------------------
        status, _, raw = request(
            "command", "POST", "/distribute/analyze", command,
            files={"file": (args.pdf.name, args.pdf.read_bytes())},
        )  # fmt: skip
        analysis = jbody(raw)
        need(status == 200 and analysis["quality_gate"]["passed"], "command: analyse + quality gate", f"HTTP {status}")
        draft_id = analysis["draft_id"]

        status, _, raw = request(
            "command", "POST", f"/distribute/{draft_id}/release", command,
            body={"recipient_officer_ids": ["officer-a", "officer-b"]},
        )  # fmt: skip
        release = jbody(raw)
        need(status == 200, "command: release to officer-a and officer-b", f"HTTP {status} {release.get('detail', '')}")
        doc_id = release["doc_id"]

        # ---- each officer opens it on their own workstation --------------------------------
        pages = {}
        for officer, cookie in (("officer-a", a), ("officer-b", b)):
            status, _, raw = request(officer, "GET", f"/officers/{officer}/documents", cookie)
            need(status == 200 and doc_id in {d["doc_id"] for d in json.loads(raw)},
                 f"{officer}: sees the document on its own console")  # fmt: skip
            status, _, raw = request(officer, "POST", f"/officers/{officer}/documents/{doc_id}/open", cookie, body={})
            opened = jbody(raw)
            need(status == 200 and opened.get("page_count", 0) > 0,
                 f"{officer}: decrypts via the key-release quorum", f"HTTP {status} {opened.get('detail', '')}")  # fmt: skip
            status, headers, png = request(officer, "GET", f"/officers/{officer}/documents/{doc_id}/pages/0", cookie)
            need(status == 200 and headers.get("Cache-Control") == "no-store",
                 f"{officer}: page served from memory, not cacheable")  # fmt: skip
            pages[officer] = hashlib.sha256(png).hexdigest()
        check(pages["officer-a"] != pages["officer-b"],
              "the two officers' assembled copies are forensically distinct")  # fmt: skip

        # ---- isolation holds in the middle of a live session -------------------------------
        status, _, _ = request("command", "GET", "/officers/officer-a/documents", command)
        check(status == 404, "command console cannot read an officer's documents at all", f"HTTP {status}")
        status, _, _ = request("officer-a", "GET", f"/officers/officer-b/documents", a)
        check(status == 403, "officer-a's session is refused on officer-b's documents", f"HTTP {status}")

        # ---- forwarding: officer-b presents officer-a's copy -------------------------------
        status, _, raw = request(
            "officer-b", "POST", f"/officers/officer-b/documents/{doc_id}/open", b,
            body={"claim_officer_id": "officer-a"},
        )  # fmt: skip
        detail = jbody(raw).get("detail", "")
        # Refused by the key-release node's identity check (the certificate presented is not
        # officer-b's). Note: this path does NOT write an OPEN_DENIED ledger record — that
        # record is only produced by the later client-side SealedHeader check.
        check(status == 403 and "does not match" in detail,
              "officer-b presenting officer-a's copy is refused by the key-release quorum",
              f"HTTP {status}")  # fmt: skip

        # ---- the leak travels as a file ----------------------------------------------------
        status, _, leak = request(
            "officer-a", "POST", f"/officers/officer-a/documents/{doc_id}/pages/0/leak?distortion=screen_camera", a
        )
        need(status == 200 and leak[:4] == b"\x89PNG", "officer-a: simulated screen photo captured (a file)", f"{len(leak)} bytes")

        status, _, raw = request(
            "command", "POST", "/investigate/open", command,
            fields={"doc_id": doc_id, "page_index": "0", "distortion": "none"},
            files={"file": ("leak.png", leak)},
        )  # fmt: skip
        case = jbody(raw)
        need(status == 200, "command: investigates the handed-over file", f"HTTP {status} {case.get('detail', '')}")
        accused = [s["officer_id"] for s in case["suspects"] if s["accused"]]
        check(accused == ["officer-a"], "the pipeline accuses officer-a and only officer-a", f"accused={accused}")

        # ---- evidence bundle, verified by a container with no network ----------------------
        status, _, raw = request("command", "POST", f"/investigate/{case['case_id']}/issue-report", command)
        need(status == 200, "command: signs and issues the evidence bundle", f"HTTP {status}")
        status, _, tsev = request("command", "GET", f"/investigate/{case['case_id']}/download/tsev", command)
        need(status == 200 and len(tsev) > 0, "command: downloads the .tsev bundle", f"{len(tsev)} bytes")

        out = ROOT / "demo" / "out"
        out.mkdir(parents=True, exist_ok=True)
        good = out / "roles-case.tsev"
        good.write_bytes(tsev)
        ok = verify_offline(good)
        check(ok.returncode == 0, "bundle verifies in a container with --network none", ok.stdout.strip()[-100:])

        # Tamper the way the project's own tamper demo does: rebuild the archive with one
        # entry changed. (A flip elsewhere in the zip can land in bundle.json, which is
        # informational and deliberately never read by the verifier.)
        for entry, label in (("bundle.cbor", "one flipped byte in the signed bundle"),
                             ("report.pdf", "a swapped report.pdf")):  # fmt: skip
            bad = out / f"roles-case-tampered-{entry.split('.')[0]}.tsev"
            with zipfile.ZipFile(good) as src:
                contents = {name: src.read(name) for name in src.namelist()}
            mutated = bytearray(contents[entry])
            mutated[-1] ^= 0x01
            contents[entry] = bytes(mutated)
            with zipfile.ZipFile(bad, "w", zipfile.ZIP_DEFLATED) as dst:
                for name, content in contents.items():
                    dst.writestr(name, content)
            result = verify_offline(bad)
            check(result.returncode != 0, f"offline verification rejects {label}", f"exit {result.returncode}")
    finally:
        for host, cookie in (("command", command), ("officer-a", a), ("officer-b", b)):
            request(host, "POST", "/session/logout", cookie)

    summarize()
    return 1 if any(not r[0] for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
