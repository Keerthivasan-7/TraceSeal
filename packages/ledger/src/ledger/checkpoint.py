"""SLH-DSA checkpoints (spec Section 12: "SLH-DSA checkpoints every K
blocks are exported to a file and a printable QR sheet"). Signs a manifest
of every co-signable record's `(tx_id, record_hash)` pair currently on the
Fabric ledger with the CA root's own SLH-DSA-SHA2-128s key (no separate
checkpoint identity — `ca-root` already IS this system's SLH-DSA root of
trust) and writes it as a JSON file plus a QR-code PNG of that same JSON.

Honesty note: this checkpoints a manifest of record hashes queried at
export time, not a running Merkle accumulator over the whole ledger's
history — the same honestly-scoped "no Merkle tree" limitation
`tscore.evidence`'s own docstring already states for LedgerLite
(docs/DECISIONS.md ADR-0027) applies here too. The QR PNG is a demo
export (a file on disk) — labelled as such, not an actual printed/
scanned physical workflow or an HSM/WORM device.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import qrcode
from ca.keys import Identity, load_identity
from tscore.hashing import sha3_256
from tscore.sig import sign as sig_sign
from tscore.sig import verify as sig_verify

from ledger.cosigner import COSIGNED_DOMAINS
from ledger.fabric_client import FabricLedgerClient

# /pki, not cwd-relative demo/pki — see ledger.cosigner's identical
# comment; both scripts run inside the same `ledger` package image.
DEFAULT_PKI_DIR = Path(os.environ.get("PKI_DIR", "/pki"))
DEFAULT_GATEWAY_URL = "http://fabric-gateway:8000"
DEFAULT_OUTPUT_DIR = Path(os.environ.get("CHECKPOINT_DIR", "/checkpoints"))


def build_checkpoint(ledger_client: FabricLedgerClient, ca_identity: Identity) -> dict[str, object]:
    records = []
    for domain in COSIGNED_DOMAINS:
        records.extend(ledger_client.query(domain=domain))
    records.sort(key=lambda r: r.tx_id)  # deterministic manifest ordering

    manifest = "|".join(f"{r.tx_id}:{r.record_hash}" for r in records)
    manifest_hash = sha3_256(manifest.encode())
    signature = sig_sign(ca_identity.sig_alg, ca_identity.sig_secret_key, manifest_hash)

    return {
        "record_count": len(records),
        "manifest_hash": manifest_hash.hex(),
        "checkpoint_authority_id": ca_identity.identity_id,
        "sig_alg": ca_identity.sig_alg,
        "signature": signature.hex(),
        "built_at": time.time(),
    }


def verify_checkpoint(checkpoint: dict[str, object], sig_public_key: bytes) -> bool:
    """Independently re-verifies a checkpoint's own SLH-DSA signature over
    its own recorded `manifest_hash` — does NOT re-derive the manifest
    from a live ledger (that would need the same records still present)."""
    manifest_hash = bytes.fromhex(str(checkpoint["manifest_hash"]))
    signature = bytes.fromhex(str(checkpoint["signature"]))
    return sig_verify(str(checkpoint["sig_alg"]), sig_public_key, manifest_hash, signature)


def write_checkpoint(checkpoint: dict[str, object], output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    height = checkpoint["record_count"]
    json_path = output_dir / f"checkpoint-{height}.json"
    json_path.write_text(json.dumps(checkpoint, indent=2))

    # SLH-DSA-SHA2-128s signatures (~7.8 KB hex-encoded) can't fit in any
    # QR code version (max ~2.9 KB at version 40, error correction L) —
    # the QR carries a compact fingerprint for manual cross-check against
    # the JSON file on disk, not a self-contained, independently
    # verifiable artifact (that still requires the full JSON + signature).
    qr_payload = {
        "manifest_hash": checkpoint["manifest_hash"],
        "record_count": checkpoint["record_count"],
        "checkpoint_authority_id": checkpoint["checkpoint_authority_id"],
        "built_at": checkpoint["built_at"],
    }
    qr_path = output_dir / f"checkpoint-{height}.png"
    image = qrcode.make(json.dumps(qr_payload))
    image.save(qr_path)
    return json_path, qr_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pki-dir", type=Path, default=DEFAULT_PKI_DIR)
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR)
    args = parser.parse_args()

    ca_identity = load_identity(args.pki_dir / "ca-root.json")
    ledger_client = FabricLedgerClient(args.gateway_url)
    checkpoint = build_checkpoint(ledger_client, ca_identity)
    json_path, qr_path = write_checkpoint(checkpoint, args.output_dir)

    ok = verify_checkpoint(checkpoint, ca_identity.sig_public_key)
    status = "PASS" if ok else "FAIL"
    print(
        f"[{status}] checkpoint over {checkpoint['record_count']} records written to "
        f"{json_path} (+ QR at {qr_path})"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
