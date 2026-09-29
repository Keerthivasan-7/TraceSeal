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
FORENSICS_ID = "forensics-1"
FABRIC_VALIDATOR_IDS = [
    "fabric-validator-1",
    "fabric-validator-2",
    "fabric-validator-3",
    "fabric-validator-4",
]
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

    # M5: forensics only ever signs the evidence bundle (ML-DSA) — vault
    # reveal (docs/DECISIONS.md ADR-0026) runs over plain internal HTTP,
    # matching every other inter-service call today, so it needs no KEM
    # key and, like the other infra identities above, no CA-issued
    # certificate (only officers get one, via the real quorum ceremony).
    forensics_identity = generate_identity(FORENSICS_ID, with_kem=False)
    save_identity(forensics_identity, output_dir / f"{FORENSICS_ID}.json")
    registry[FORENSICS_ID] = build_registry_entry(forensics_identity)

    # M6: one ML-DSA-65 identity per Fabric validator org (spec Section 12:
    # "validator organisations additionally co-sign block hashes with
    # ML-DSA") — distinct from that org's Fabric-level x509 MSP identity,
    # which is a completely separate PKI (cryptogen-generated, see
    # fabric-network/); this is the TraceSeal-PKI identity whose public
    # key gets registered on-chain (chaincode's RegisterIdentity) so the
    # chaincode can verify the co-signature itself. Sig-only, no
    # certificate, same infra-identity pattern as forensics-1.
    for validator_id in FABRIC_VALIDATOR_IDS:
        identity = generate_identity(validator_id, with_kem=False)
        save_identity(identity, output_dir / f"{validator_id}.json")
        registry[validator_id] = build_registry_entry(identity)

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
