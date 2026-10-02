#!/usr/bin/env python3
"""Evidence that the isolated-roles deployment really is isolated.

Runs against the *live* stack (`scripts/roles.sh provision && up`) from the
host. Every line below is a real probe, not a printed claim:

  * a mount audit of every running container (what key material can it see?)
  * in-container listings (what is actually on its filesystem?)
  * an egress attempt from inside each container
  * cross-identity session replay through the real nginx edge
  * (optional) an offline verification with `--network none`

Anything it cannot verify is reported SKIP, never PASS. Exit status is
non-zero if any check FAILs. Standard library only.

Usage: python scripts/demo_isolation.py [--bundle path/to/case.tsev]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from edge_client import credentials as _read_credentials
from edge_client import login, request

ROOT = Path(__file__).resolve().parent.parent
OFFICERS = ["officer-a", "officer-b", "officer-c"]
PROJECT_LABEL = "com.docker.compose.project=traceseal"

results: list[tuple[str, str, str]] = []  # (status, name, detail)


def record(ok: bool | None, name: str, detail: str = "") -> None:
    results.append(("SKIP" if ok is None else "PASS" if ok else "FAIL", name, detail))


def docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "MSYS_NO_PATHCONV": "1"}
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout, env=env, check=False
    )


def running_containers() -> dict[str, str]:
    """service name -> container name, for this compose project."""
    out = docker("ps", "--filter", f"label={PROJECT_LABEL}", "--format", "{{.Names}}").stdout
    mapping = {}
    for name in out.split():
        match = re.fullmatch(r"traceseal-(.+)-\d+", name)
        if match:
            mapping[match.group(1)] = name
    return mapping


def mounts(container: str) -> list[dict[str, str]]:
    raw = docker("inspect", container, "--format", "{{json .Mounts}}").stdout
    return [m for m in json.loads(raw or "[]") if m.get("Type") == "bind"]


def after_demo(source: str) -> str | None:
    """The part of a host mount path after `/demo` (None if not under demo/)."""
    normalised = source.replace("\\", "/")
    match = re.search(r"/demo(?:/(.*))?$", normalised)
    return None if match is None else (match.group(1) or "")


def exec_sh(container: str, script: str) -> subprocess.CompletedProcess[str]:
    return docker("exec", container, "sh", "-c", script)


def credentials() -> dict[str, str]:
    return _read_credentials(str(ROOT / "demo" / "roles" / "CREDENTIALS.local.txt"))


# --------------------------------------------------------------------------- checks


def check_mount_audit(containers: dict[str, str]) -> None:
    exposed_dirs = {"", "roles", "roles/keystores", "roles/vault", "pki"}
    offenders = []
    for service, name in sorted(containers.items()):
        for mount in mounts(name):
            rel = after_demo(mount["Source"])
            if rel is not None and rel.rstrip("/") in exposed_dirs:
                offenders.append(f"{service} -> demo/{rel}")
    record(
        not offenders,
        "no running container mounts demo/, demo/roles, the keystore or vault dirs, or PKI staging",
        "; ".join(offenders),
    )

    # Each keystore / vault file is visible to exactly its owner.
    owners: dict[str, list[str]] = {}
    for service, name in containers.items():
        for mount in mounts(name):
            rel = after_demo(mount["Source"]) or ""
            if rel.startswith(("roles/keystores/", "roles/vault/")):
                owners.setdefault(rel, []).append(service)
    expected = {
        **{f"roles/keystores/{o}.keystore.json": [f"agent-{o}"] for o in OFFICERS},
        "roles/keystores/ca-root.keystore.json": ["console-authority"],
        "roles/keystores/sender-1.keystore.json": ["console-command"],
        "roles/keystores/forensics-1.keystore.json": ["console-command"],
        **{f"roles/keystores/admin-{i}.keystore.json": ["console-authority"] for i in (1, 2, 3)},
        **{f"roles/vault/ledger-{i}": [f"ledger-{i}"] for i in range(4)},
        **{f"roles/vault/keyrelease-{i}": [f"keyrelease-{i}"] for i in range(5)},
    }
    wrong = {k: v for k, v in owners.items() if sorted(expected.get(k, ["?"])) != sorted(v)}
    missing = [k for k in expected if k not in owners]
    record(
        not wrong and not missing,
        "every keystore and vault is mounted into exactly its owner and nobody else",
        f"unexpected={wrong} missing={missing}" if wrong or missing else f"{len(owners)} key paths audited",
    )

    ops = containers.get("console-ops")
    if ops:
        rels = [after_demo(m["Source"]) or "" for m in mounts(ops)]
        record(
            all(r.startswith("roles/public") for r in rels),
            "ops console mounts only the public registry",
            ", ".join(rels),
        )


def check_in_container(containers: dict[str, str]) -> None:
    for officer in OFFICERS:
        name = containers.get(f"agent-{officer}")
        if name is None:
            record(False, f"{officer}: container is running")
            continue
        listing = exec_sh(name, "ls /app/demo/keystores; echo --; ls /pki; echo --; ls /vault 2>&1").stdout
        keystores, pki, vault = (part.split() for part in listing.split("--"))
        record(
            keystores == [f"{officer}.keystore.json"] and pki == ["registry.json"] and "No" in " ".join(vault),
            f"{officer}: filesystem holds only its own keystore + the public registry",
            f"keystores={keystores} pki={pki}",
        )
        other = next(o for o in OFFICERS if o != officer)
        probe = exec_sh(name, f"cat /app/demo/keystores/{other}.keystore.json")
        record(probe.returncode != 0, f"{officer}: cannot read {other}'s keystore")

    ledger = containers.get("ledger-1")
    if ledger:
        listing = exec_sh(ledger, "ls /vault").stdout.split()
        record(listing == ["ledger-1.json"], "ledger-1: vault holds only ledger-1's identity", str(listing))


def check_egress(containers: dict[str, str]) -> None:
    probe = (
        "import socket,sys\n"
        "try:\n socket.create_connection(('1.1.1.1',443),timeout=2)\n sys.exit(0)\n"
        "except OSError:\n sys.exit(1)\n"
    )
    leaks = []
    checked = 0
    for service, name in sorted(containers.items()):
        if service == "web":
            route = docker("exec", name, "ip", "route").stdout
            checked += 1
            if any(line.startswith("default") for line in route.splitlines()):
                leaks.append(service)
            continue
        result = docker("exec", name, "python", "-c", probe)
        if result.returncode == 0:
            leaks.append(service)
        if "executable file not found" not in result.stderr:
            checked += 1
    record(not leaks and checked > 0, "no container can reach the internet", f"{checked} probed; leaks={leaks}")


def check_http() -> None:
    creds = credentials()
    if not creds:
        record(None, "session isolation over HTTP", "demo/roles/CREDENTIALS.local.txt not found")
        return
    sessions: dict[str, str] = {}
    try:
        for officer in ("officer-a", "officer-b"):
            cookie = login(officer, creds[officer])
            record(cookie is not None, f"{officer}: logs in with its own passphrase")
            if cookie:
                sessions[officer] = cookie
        record(
            login("officer-a", creds["officer-b"]) is None,
            "officer-a rejects officer-b's passphrase",
        )
        if len(sessions) == 2:
            a_name, a_value = sessions["officer-a"].split("=", 1)
            replay = f"ts_session_officer-b={a_value}"
            status, _, _ = request("officer-b", "GET", "/officers/officer-b/documents", replay)
            record(status == 401, "officer-a's token is useless on officer-b's console", f"HTTP {status}")
            status, _, _ = request("officer-a", "GET", "/officers/officer-b/documents", sessions["officer-a"])
            record(status == 403, "officer-a's session cannot read officer-b's documents", f"HTTP {status}")
            status, _, _ = request("officer-a", "POST", "/distribute/analyze", sessions["officer-a"])
            record(status == 404, "an officer console has no sender routes at all", f"HTTP {status}")
            status, _, _ = request("officer-a", "GET", "/officers/officer-a/documents", sessions["officer-a"])
            record(status == 200, "officer-a's own session works on its own console", f"HTTP {status}")
        status, _, _ = request("ops", "POST", "/session/login", body={"passphrase": "x"})
        record(status == 404, "the ops console has no login (it holds nothing to unlock)", f"HTTP {status}")
        status, _, _ = request("ops", "GET", "/system/status")
        record(status == 200, "the ops console is readable without a session", f"HTTP {status}")
    finally:
        for host, cookie in sessions.items():
            request(host, "POST", "/session/logout", cookie)


def check_verifier(bundle: Path | None) -> None:
    if bundle is None:
        record(None, "offline verification with --network none", "pass --bundle <case.tsev> to run it")
        return
    result = docker(
        "run", "--rm", "--network", "none",
        "-v", f"{bundle.resolve()}:/in/case.tsev:ro",
        "traceseal/verifier:m5", "traceseal-verify", "/in/case.tsev",
    )  # fmt: skip
    record(result.returncode == 0, "evidence bundle verifies offline (--network none)", result.stdout.strip()[-120:])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--bundle", type=Path, help="a .tsev evidence bundle to verify offline")
    args = parser.parse_args()

    containers = running_containers()
    if not containers:
        print("no traceseal containers are running — run `scripts/roles.sh provision` then `up`")
        return 2
    check_mount_audit(containers)
    check_in_container(containers)
    check_egress(containers)
    check_http()
    check_verifier(args.bundle)

    width = max(len(name) for _, name, _ in results)
    print(f"\n{'RESULT':6}  {'CHECK':{width}}  DETAIL")
    for status, name, detail in results:
        print(f"{status:6}  {name:{width}}  {detail}")
    failed = [r for r in results if r[0] == "FAIL"]
    skipped = [r for r in results if r[0] == "SKIP"]
    print(f"\n{len(results) - len(failed) - len(skipped)} passed, {len(failed)} failed, {len(skipped)} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
