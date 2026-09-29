"""Forwarding-detection demo (spec Section 18 item 5: "Officer D tries to
open Officer C's copy: denied, and the event appears live."). Thin wrapper
around the same `open_document`/`verify_copy_binding` production code path
`agent.demo_m3` uses — `--claim-cert-of` is the only difference: it builds
the `DecryptRequest` with a DIFFERENT officer's `recipient_cert_hash` than
the caller's own, which is exactly the concrete exploit the server-side
recipient-identity check (`keyrelease.node`) and the client-side
`SealedHeader` check (`agent.decrypt.verify_copy_binding`) both
independently catch (docs/DECISIONS.md).

Usage: docker compose run --rm agent python -m agent.demo_m4 \\
    --officer d --claim-cert-of officer-c --doc-id doc-m3-demo
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_PKI_DIR = Path.cwd() / "demo" / "pki"
DEFAULT_BLOB_DIR = Path.cwd() / "demo" / "blob"
DEFAULT_KEYRELEASE_URL = "http://keyrelease-0:8000"
DEFAULT_LEDGER_URL = "http://ledger-0:8000"


def run(
    officer_id: str,
    claim_cert_of: str,
    doc_id: str,
    *,
    pki_dir: Path = DEFAULT_PKI_DIR,
    blob_dir: Path = DEFAULT_BLOB_DIR,
    keyrelease_url: str = DEFAULT_KEYRELEASE_URL,
    ledger_url: str = DEFAULT_LEDGER_URL,
) -> bool:
    import os

    from ca.keys import load_identity
    from ca.registry import load_registry, sig_public_key
    from ledger.backend import build_ledger_client
    from tscore.hashing import sha3_256

    from agent.decrypt import DecryptRequestDeniedError, ForwardedCopyError, open_document

    print(
        f"== TraceSeal M4 demo: {officer_id} attempts to open "
        f"{claim_cert_of}'s copy of {doc_id} =="
    )

    identity = load_identity(pki_dir / f"{officer_id}.json")
    registry = load_registry(pki_dir / "registry.json")
    claimed_entry = registry[claim_cert_of]
    if "certificate_cbor" not in claimed_entry:
        print(f"[FAIL] no certificate on file for {claim_cert_of!r}")
        return False
    claimed_cert_hash = sha3_256(bytes.fromhex(claimed_entry["certificate_cbor"]))

    package_path = blob_dir / doc_id / "package.json"
    # Deliberately use the CLAIMED officer's wrapped K_A — the file this
    # officer would need to have obtained (e.g. via a leaked/misdirected
    # blob-store artifact) to plausibly attempt opening that other
    # officer's copy at all.
    wrapped_k_a_path = blob_dir / doc_id / "wrapped_k_a" / f"{claim_cert_of}.bin"
    if not package_path.exists() or not wrapped_k_a_path.exists():
        print(
            f"[FAIL] blob store missing package or wrapped K_A for "
            f"{claim_cert_of!r} / {doc_id!r}"
        )
        return False

    ledger_client = build_ledger_client(
        os.environ.get("LEDGER_BACKEND", "lite"), ledger_leader_url=ledger_url
    )

    def lookup_public_key(signer_id: str) -> tuple[str, bytes]:
        return sig_public_key(load_registry(pki_dir / "registry.json"), signer_id)

    outbox_path = blob_dir.parent / "agent-state" / officer_id / "outbox.jsonl"

    try:
        open_document(
            identity,
            doc_id,
            package_path,
            wrapped_k_a_path,
            claimed_cert_hash,
            keyrelease_url,
            ledger_client,
            lookup_public_key,
            outbox_path,
        )
    except ForwardedCopyError as exc:
        print(f"[PASS] OPEN_DENIED logged — forwarding detected: {exc}")
        return True
    except DecryptRequestDeniedError as exc:
        print(f"[PASS] key-release node refused the mismatched request server-side: {exc}")
        return True

    print("[FAIL] expected the forwarding attempt to be denied, but it succeeded")
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--officer", required=True, help="the officer actually running this agent")
    parser.add_argument(
        "--claim-cert-of", required=True, help="the OTHER officer's identity being impersonated"
    )
    parser.add_argument("--doc-id", default="doc-m3-demo")
    parser.add_argument("--pki-dir", type=Path, default=DEFAULT_PKI_DIR)
    parser.add_argument("--blob-dir", type=Path, default=DEFAULT_BLOB_DIR)
    parser.add_argument("--keyrelease-url", default=DEFAULT_KEYRELEASE_URL)
    parser.add_argument("--ledger-url", default=DEFAULT_LEDGER_URL)
    args = parser.parse_args()

    def full_id(officer: str) -> str:
        return officer if officer.startswith("officer-") else f"officer-{officer}"

    ok = run(
        full_id(args.officer),
        full_id(args.claim_cert_of),
        args.doc_id,
        pki_dir=args.pki_dir,
        blob_dir=args.blob_dir,
        keyrelease_url=args.keyrelease_url,
        ledger_url=args.ledger_url,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
