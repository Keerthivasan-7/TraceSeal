"""Generates every M3 demo identity's keys and the shared public registry
(docs/DECISIONS.md — the seed-script stand-in for M4's real ledger-backed
enrolment ceremony).

Usage: python -m ca.seed [output_dir]  (default: demo/pki)
"""

from __future__ import annotations

import sys
from pathlib import Path

from ca.issue import issue_certificate
from ca.keys import ROOT_SIG_ALG, generate_identity, save_identity
from ca.registry import Registry, build_registry_entry, save_registry

LEDGER_REPLICAS = 4
KEYRELEASE_NODES = 5
OFFICER_IDS = ["officer-a", "officer-b", "officer-c", "officer-d", "officer-e"]
SENDER_ID = "sender-1"

DEFAULT_OUTPUT_DIR = Path.cwd() / "demo" / "pki"


def seed_all(output_dir: Path = DEFAULT_OUTPUT_DIR) -> Registry:
    registry: Registry = {}

    ca_identity = generate_identity("ca-root", sig_alg=ROOT_SIG_ALG, with_kem=False)
    save_identity(ca_identity, output_dir / "ca-root.json")
    registry[ca_identity.identity_id] = build_registry_entry(ca_identity)

    for i in range(LEDGER_REPLICAS):
        identity = generate_identity(f"ledger-{i}", with_kem=False)
        save_identity(identity, output_dir / f"{identity.identity_id}.json")
        registry[identity.identity_id] = build_registry_entry(identity)

    for i in range(KEYRELEASE_NODES):
        identity = generate_identity(f"keyrelease-{i}", with_kem=True)
        save_identity(identity, output_dir / f"{identity.identity_id}.json")
        registry[identity.identity_id] = build_registry_entry(identity)

    sender_identity = generate_identity(SENDER_ID, with_kem=True)
    save_identity(sender_identity, output_dir / f"{SENDER_ID}.json")
    registry[SENDER_ID] = build_registry_entry(sender_identity)

    for officer_id in OFFICER_IDS:
        identity = generate_identity(officer_id, with_kem=True)
        save_identity(identity, output_dir / f"{officer_id}.json")
        cert, signature = issue_certificate(
            ca_identity,
            officer_id,
            identity.sig_public_key,
            identity.kem_public_key or b"",
        )
        registry[officer_id] = build_registry_entry(
            identity, certificate_cbor=cert.to_canonical_cbor(), certificate_signature=signature
        )

    save_registry(registry, output_dir / "registry.json")
    return registry


def main() -> None:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT_DIR
    registry = seed_all(output_dir)
    print(f"seeded {len(registry)} identities under {output_dir}")
    for identity_id in registry:
        print(f"  {identity_id}")


if __name__ == "__main__":
    main()
