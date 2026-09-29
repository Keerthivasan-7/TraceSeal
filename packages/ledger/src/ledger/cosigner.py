"""M6 ML-DSA block co-signing (spec Section 12): each Fabric validator org
runs one instance of this against ITS OWN identity, watching every known
signing domain for records it hasn't co-signed yet and appending its own
ML-DSA-65 co-signature (chaincode's `AddCosignature`) — the additional PQC
layer on top of Fabric's own (ECDSA) endorsement/ordering, satisfying the
spec's honesty requirement: "Fabric's internal transport is still ECDSA
... evidence verification depends only on PQC signatures."

No LedgerLite equivalent exists — LedgerLite's own replicas already
co-sign PQC-natively, synchronously, at write time
(`ledger.node.LedgerNode.finalize`); this module exists only because
Fabric's own write path has nowhere to hang that extra PQC step, so it
happens as a separate, post-hoc pass instead (docs/DECISIONS.md ADR-0031).

Usage: ``python -m ledger.cosigner --org 1`` (repeated once per org, each
against its own `fabric-validator-<N>` identity).
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from ca.keys import Identity, load_identity
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_DOC_REGISTER,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_INVESTIGATION_OPENED,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_RECEIPT,
    DOMAIN_REPORT_ISSUED,
    DOMAIN_REVOKE_FINAL,
)
from tscore.sig import sign as sig_sign

from ledger.fabric_client import FabricLedgerClient

# Every signing domain that ever gets submitted to the ledger and should
# carry a PQC co-signature — deliberately excludes DOMAIN_EVIDENCE_BUNDLE
# (never itself a ledger record, only an M5 bundle payload) and
# DOMAIN_CERTIFICATE/DOMAIN_CSR/enrol-approve/revoke-approve/open-event/
# open-denied (spec Section 12 only asks for block co-signing of the
# core protocol's operational records, not every signed artifact that
# happens to reuse the SignedSubmission shape).
COSIGNED_DOMAINS = (
    DOMAIN_DOC_REGISTER,
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_RECEIPT,
    DOMAIN_ENROLL_FINAL,
    DOMAIN_REVOKE_FINAL,
    DOMAIN_INVESTIGATION_OPENED,
    DOMAIN_REPORT_ISSUED,
)

# /pki, not a cwd-relative demo/pki — matches ledger.main/ledger.service's
# OWN convention (this module runs inside the same `ledger` package image,
# which mounts ./demo/pki:/pki, not the broader ./demo:/app/demo mount
# sender/agent/ca/forensics's demo scripts use).
DEFAULT_PKI_DIR = Path(os.environ.get("PKI_DIR", "/pki"))
DEFAULT_GATEWAY_URL = "http://fabric-gateway:8000"


def cosign_once(
    ledger_client: FabricLedgerClient, validator_identity: Identity, org_validator_id: str
) -> int:
    """One pass over every co-signable domain; returns how many new
    co-signatures this org actually added."""
    added = 0
    for domain in COSIGNED_DOMAINS:
        for record in ledger_client.query(domain=domain):
            if org_validator_id in record.quorum_signer_ids:
                continue
            envelope_cbor = bytes.fromhex(record.envelope_cbor)
            signature = sig_sign(
                validator_identity.sig_alg, validator_identity.sig_secret_key, envelope_cbor
            )
            try:
                ledger_client.add_cosignature(record.tx_id, org_validator_id, signature)
                added += 1
            except Exception:  # noqa: BLE001, S112 - a race with another poll cycle isn't fatal
                continue
    return added


def run_forever(
    ledger_client: FabricLedgerClient,
    validator_identity: Identity,
    org_validator_id: str,
    *,
    poll_interval_s: float = 2.0,
) -> None:
    print(f"ledger.cosigner: {org_validator_id} watching {len(COSIGNED_DOMAINS)} domains")
    while True:
        added = cosign_once(ledger_client, validator_identity, org_validator_id)
        if added:
            print(f"{org_validator_id}: co-signed {added} record(s)")
        time.sleep(poll_interval_s)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--org", type=int, required=True, help="validator org number, 1-4")
    parser.add_argument("--pki-dir", type=Path, default=DEFAULT_PKI_DIR)
    parser.add_argument("--gateway-url", default=DEFAULT_GATEWAY_URL)
    parser.add_argument("--poll-interval", type=float, default=2.0)
    args = parser.parse_args()

    org_validator_id = f"fabric-validator-{args.org}"
    validator_identity = load_identity(args.pki_dir / f"{org_validator_id}.json")
    ledger_client = FabricLedgerClient(args.gateway_url)
    run_forever(
        ledger_client, validator_identity, org_validator_id, poll_interval_s=args.poll_interval
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
