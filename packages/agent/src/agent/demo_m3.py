"""Per-officer CLI: run one full decrypt session against a running
key-release node and ledger (spec Section 7.3). M3 scope: a one-shot
script invoked once per officer — `docker compose run --rm agent python -m
agent.demo_m3 --officer a`, mirroring `sender.demo_m1`'s standalone-script
shape (see that module's docstring on why this isn't a persistent service
yet). The multi-service M3 acceptance run (CA seed -> sender distribute ->
one of these per officer) is orchestrated by `sender.demo_m3`.

Deliberately cwd-based paths, not derived from `__file__` — see
`sender.demo_m1`'s docstring for why (this module gets pip-installed too).
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
    doc_id: str,
    *,
    pki_dir: Path = DEFAULT_PKI_DIR,
    blob_dir: Path = DEFAULT_BLOB_DIR,
    keyrelease_url: str = DEFAULT_KEYRELEASE_URL,
    ledger_url: str = DEFAULT_LEDGER_URL,
) -> bool:
    from ca.keys import load_identity
    from ca.registry import load_registry, sig_public_key
    from ledger.client import LedgerClient
    from tscore.hashing import sha3_256

    from agent.decrypt import DecryptRequestDeniedError, ForwardedCopyError, open_document

    print(f"== TraceSeal M3 demo: decrypt session for {officer_id} / {doc_id} ==")

    identity = load_identity(pki_dir / f"{officer_id}.json")
    registry = load_registry(pki_dir / "registry.json")
    entry = registry[officer_id]
    if "certificate_cbor" not in entry:
        print(f"[FAIL] no certificate on file for {officer_id!r}")
        return False
    cert_hash = sha3_256(bytes.fromhex(entry["certificate_cbor"]))

    package_path = blob_dir / doc_id / "package.json"
    wrapped_k_a_path = blob_dir / doc_id / "wrapped_k_a" / f"{officer_id}.bin"
    if not package_path.exists() or not wrapped_k_a_path.exists():
        print(f"[FAIL] blob store missing package or wrapped K_A for {officer_id!r} / {doc_id!r}")
        print("       (run sender.demo_m3 first to register and distribute the document)")
        return False

    ledger_client = LedgerClient(ledger_url)

    def lookup_public_key(signer_id: str) -> tuple[str, bytes]:
        return sig_public_key(load_registry(pki_dir / "registry.json"), signer_id)

    outbox_path = blob_dir.parent / "agent-state" / officer_id / "outbox.jsonl"

    try:
        result = open_document(
            identity,
            doc_id,
            package_path,
            wrapped_k_a_path,
            cert_hash,
            keyrelease_url,
            ledger_client,
            lookup_public_key,
            outbox_path,
        )
    except DecryptRequestDeniedError as exc:
        print(f"[FAIL] key-release node denied the decrypt request: {exc}")
        return False
    except ForwardedCopyError as exc:
        print(f"[FAIL] forwarding detected — OPEN_DENIED logged: {exc}")
        return False

    print(f"session_id: {result.session_id}")
    print(f"receipt tx_id (finalized on the ledger): {result.receipt_tx_id}")
    print(f"pages assembled in memory: {len(result.pages)}")
    print(
        "[PASS] this officer's copy was assembled entirely in memory — no plaintext "
        "page was ever written to disk."
    )
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--officer", required=True, help="officer letter, e.g. 'a' or 'officer-a'")
    parser.add_argument("--doc-id", default="doc-m3-demo")
    parser.add_argument("--pki-dir", type=Path, default=DEFAULT_PKI_DIR)
    parser.add_argument("--blob-dir", type=Path, default=DEFAULT_BLOB_DIR)
    parser.add_argument("--keyrelease-url", default=DEFAULT_KEYRELEASE_URL)
    parser.add_argument("--ledger-url", default=DEFAULT_LEDGER_URL)
    args = parser.parse_args()

    officer_id = args.officer if args.officer.startswith("officer-") else f"officer-{args.officer}"
    ok = run(
        officer_id,
        args.doc_id,
        pki_dir=args.pki_dir,
        blob_dir=args.blob_dir,
        keyrelease_url=args.keyrelease_url,
        ledger_url=args.ledger_url,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
