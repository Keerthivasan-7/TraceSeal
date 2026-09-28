"""Generates every M4 demo identity's raw keypairs and the registry skeleton
(docs/DECISIONS.md ADR-0020). Officer certificates are NOT issued here —
officers get a real ML-DSA+ML-KEM keypair (needed to build a CSR) but no
certificate; certificates only come from the real quorum ceremony
(`ca.enrolment`), driven end-to-end by `ca.demo_m4` against a live ledger.
Infrastructure identities (CA root, ledger replicas, key-release nodes,
sender, admins) are still bootstrapped directly here — someone has to seed
the first trust anchors, and that's a deployment concern, not "enrolling an
officer" in the spec's sense.

Usage: python -m ca.seed [output_dir]  (default: demo/pki)
"""

from __future__ import annotations

import sys
from pathlib import Path

from ca.keys import ROOT_SIG_ALG, generate_identity, save_identity
from ca.registry import Registry, build_registry_entry, save_registry

LEDGER_REPLICAS = 4
KEYRELEASE_NODES = 5
OFFICER_IDS = ["officer-a", "officer-b", "officer-c", "officer-d", "officer-e"]
SENDER_ID = "sender-1"
ADMIN_IDS = ["admin-1", "admin-2", "admin-3"]
ENROLL_QUORUM = 2  # of len(ADMIN_IDS); spec's stated default, "2 of 3, configurable"

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

    for admin_id in ADMIN_IDS:
        identity = generate_identity(admin_id, with_kem=False)
        save_identity(identity, output_dir / f"{admin_id}.json")
        registry[admin_id] = build_registry_entry(identity)

    for officer_id in OFFICER_IDS:
        identity = generate_identity(officer_id, with_kem=True)
        save_identity(identity, output_dir / f"{officer_id}.json")
        registry[officer_id] = build_registry_entry(identity)

    save_registry(registry, output_dir / "registry.json")
    return registry


def main() -> None:
    output_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_OUTPUT_DIR
    registry = seed_all(output_dir)
    print(f"seeded {len(registry)} identities under {output_dir}")
    for identity_id in registry:
        note = " (no certificate yet — run ca.demo_m4)" if identity_id in OFFICER_IDS else ""
        print(f"  {identity_id}{note}")


if __name__ == "__main__":
    main()
