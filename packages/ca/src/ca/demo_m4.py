"""Milestone M4 acceptance script — the real enrolment/revocation ceremony
(spec Section 18 demo items 2 and the revocation half implied by Section
7.1 step 5), driven against a live LedgerLite cluster.

    docker compose run --rm ca python -m ca.demo_m4              # enrol every officer
    docker compose run --rm ca python -m ca.demo_m4 --revoke officer-e

Assumes `ca.seed` has already run (writing `demo/pki/`: infra identities,
admin identities, and each officer's raw keypair — no certificates yet) and
the ledger cluster is already up (`make up` / the `e2e`/`demo-m4` Makefile
targets). Enrolling replaces `ca.seed`'s old direct-issuance shortcut with
the real 2-of-3 admin quorum (docs/DECISIONS.md ADR-0011, ADR-0019).

Deliberately cwd-based paths, not derived from `__file__` — see
`sender.demo_m1`'s docstring for why.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

DEFAULT_PKI_DIR = Path.cwd() / "demo" / "pki"
DEFAULT_LEDGER_LEADER_URL = "http://ledger-0:8000"


def enrol_officer(
    officer_id: str,
    *,
    pki_dir: Path = DEFAULT_PKI_DIR,
    ledger_leader_url: str = DEFAULT_LEDGER_LEADER_URL,
) -> bool:
    from ledger.client import LedgerClient
    from tscore.records import DOMAIN_ENROLL_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        propose_enrolment,
        submit_approval,
    )
    from ca.keys import load_identity
    from ca.registry import build_registry_entry, load_registry, save_registry
    from ca.seed import ADMIN_IDS, ENROLL_QUORUM

    ledger_client = LedgerClient(ledger_leader_url)
    ca_identity = load_identity(pki_dir / "ca-root.json")
    admins = [load_identity(pki_dir / f"{admin_id}.json") for admin_id in ADMIN_IDS]
    officer = load_identity(pki_dir / f"{officer_id}.json")

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins[0], officer_id, "1st Unit", "analyst", csr
    )
    for admin in admins[:ENROLL_QUORUM]:
        submit_approval(ledger_client, admin, proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE)

    cert, signature = finalize_enrolment(
        ledger_client, ca_identity, officer_id, proposal_tx_id, csr, set(ADMIN_IDS)
    )

    registry = load_registry(pki_dir / "registry.json")
    registry[officer_id] = build_registry_entry(
        officer, certificate_cbor=cert.to_canonical_cbor(), certificate_signature=signature
    )
    save_registry(registry, pki_dir / "registry.json")

    print(f"[PASS] {officer_id} enrolled: {ENROLL_QUORUM}-of-{len(ADMIN_IDS)} admin quorum reached")
    return True


def revoke_officer(
    officer_id: str,
    *,
    pki_dir: Path = DEFAULT_PKI_DIR,
    ledger_leader_url: str = DEFAULT_LEDGER_LEADER_URL,
    reason: str = "demo revocation",
) -> bool:
    from ledger.client import LedgerClient
    from tscore.hashing import sha3_256
    from tscore.records import DOMAIN_REVOKE_APPROVE

    from ca.enrolment import finalize_revocation, propose_revocation, submit_approval
    from ca.keys import load_identity
    from ca.registry import load_registry
    from ca.seed import ADMIN_IDS, ENROLL_QUORUM

    ledger_client = LedgerClient(ledger_leader_url)
    ca_identity = load_identity(pki_dir / "ca-root.json")
    admins = [load_identity(pki_dir / f"{admin_id}.json") for admin_id in ADMIN_IDS]

    registry = load_registry(pki_dir / "registry.json")
    entry = registry.get(officer_id, {})
    if "certificate_cbor" not in entry:
        print(f"[FAIL] {officer_id!r} has no certificate on file — nothing to revoke")
        return False
    cert_hash = sha3_256(bytes.fromhex(entry["certificate_cbor"]))

    proposal_tx_id = propose_revocation(ledger_client, admins[0], officer_id, cert_hash, reason)
    for admin in admins[:ENROLL_QUORUM]:
        submit_approval(ledger_client, admin, proposal_tx_id, domain=DOMAIN_REVOKE_APPROVE)

    finalize_revocation(ledger_client, ca_identity, officer_id, proposal_tx_id, set(ADMIN_IDS))
    print(f"[PASS] {officer_id} revoked: {ENROLL_QUORUM}-of-{len(ADMIN_IDS)} admin quorum reached")
    return True


def main() -> int:
    from ca.seed import OFFICER_IDS

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pki-dir", type=Path, default=DEFAULT_PKI_DIR)
    parser.add_argument("--ledger-leader-url", default=DEFAULT_LEDGER_LEADER_URL)
    parser.add_argument(
        "--revoke", metavar="OFFICER_ID", help="revoke one officer instead of enrolling everyone"
    )
    args = parser.parse_args()

    print("== TraceSeal M4 demo: enrolment / revocation ceremony ==")

    if args.revoke:
        ok = revoke_officer(
            args.revoke, pki_dir=args.pki_dir, ledger_leader_url=args.ledger_leader_url
        )
        return 0 if ok else 1

    ok = True
    for officer_id in OFFICER_IDS:
        ok = enrol_officer(
            officer_id, pki_dir=args.pki_dir, ledger_leader_url=args.ledger_leader_url
        ) and ok
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
