"""One-time M6 bootstrap step with no LedgerLite equivalent: registers
every identity in the PKI registry (`ca.seed`'s output) into the Fabric
chaincode's own on-chain identity registry
(`chaincode/traceseal/contract.go`'s `RegisterIdentity`) — a record's
`SubmitRecord`/`AddCosignature` call fails outright if its signer isn't
registered here first, so this must run once, after `ca.seed`, before any
of `sender.demo_m3`/`agent.demo_m3`/`ca.demo_m4`/`ledger.cosigner` can
submit anything with `LEDGER_BACKEND=fabric`.

Usage: ``python -m ledger.seed_fabric_identities``
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ca.registry import load_registry

from ledger.fabric_client import FabricLedgerClient

DEFAULT_PKI_DIR = Path(os.environ.get("PKI_DIR", "/pki"))
DEFAULT_GATEWAY_URL = "http://fabric-gateway:8000"


def seed_fabric_identities(pki_dir: Path, gateway_url: str) -> int:
    registry = load_registry(pki_dir / "registry.json")
    ledger_client = FabricLedgerClient(gateway_url)
    count = 0
    for identity_id, entry in registry.items():
        sig_alg = entry.get("sig_alg")
        sig_public_key_hex = entry.get("sig_public_key")
        if not sig_alg or not sig_public_key_hex:
            continue
        ledger_client.register_identity(identity_id, sig_alg, bytes.fromhex(sig_public_key_hex))
        count += 1
    return count


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pki-dir", type=Path, default=DEFAULT_PKI_DIR)
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    args = parser.parse_args()

    count = seed_fabric_identities(args.pki_dir, args.gateway_url)
    print(f"[PASS] registered {count} identities on-chain")
    return 0


if __name__ == "__main__":
    sys.exit(main())
