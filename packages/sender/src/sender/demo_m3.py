"""Milestone M3 acceptance script — the sender's half (spec Section 17:
"Full crypto protocol: sender, key-release x5, agent, LedgerLite,
commit-before-release, receipts. Acceptance: `make e2e` passes.").

Assumes the CA has already been seeded (`python -m ca.seed`, writing
`demo/pki/`) and the ledger + key-release containers are already up
(`make up`) — this script does only the sender's own job: build a package
from the synthetic sample document, Shamir-split and distribute its
release secret plus the Tardos bias vector to all 5 running key-release
nodes, wrap `K_A` for each of the 5 seeded officers, and register the
document on the ledger. `agent.demo_m3` (run once per officer, in its own
container) does the recipient's half.

Deliberately cwd-based paths, not derived from `__file__` — see
`sender.demo_m1`'s docstring for why.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
from ca.keys import load_identity
from ca.registry import kem_public_key, load_registry
from ca.seed import OFFICER_IDS, SENDER_ID
from ledger.backend import build_ledger_client
from tscore.hashing import sha3_256
from tscore.release_secret import bias_vector_to_bytes, combine_release_secret
from tscore.tardos import plan_parameters, sample_bias_vector

from sender.distribute import (
    KeyReleaseNodeInfo,
    RecipientInfo,
    register_document,
    register_shares,
    wrap_k_a_for_recipients,
)
from sender.package import build_package, compute_package_hash, generate_document_keys, save_package
from sender.positions import select_positions
from sender.sample_doc import build_sample_document
from sender.variants import build_document_variants

DEFAULT_PKI_DIR = Path.cwd() / "demo" / "pki"
DEFAULT_BLOB_DIR = Path.cwd() / "demo" / "blob"
DEFAULT_LEDGER_LEADER_URL = "http://ledger-0:8000"
KEYRELEASE_NODE_COUNT = 5
DOC_ID = "doc-m3-demo"
EPS1 = 1e-4
MAX_C0 = 3
BIAS_CUTOFF = 0.1
RNG_SEED = 20260301


def run(
    *,
    pki_dir: Path = DEFAULT_PKI_DIR,
    blob_dir: Path = DEFAULT_BLOB_DIR,
    ledger_leader_url: str = DEFAULT_LEDGER_LEADER_URL,
    doc_id: str = DOC_ID,
) -> bool:
    print("== TraceSeal M3 demo: sender registration + distribution ==")

    registry = load_registry(pki_dir / "registry.json")
    sender_identity = load_identity(pki_dir / f"{SENDER_ID}.json")

    doc = build_sample_document()
    positions = select_positions(doc)
    print(f"mark positions selected: {len(positions)}")
    if not positions:
        print("[FAIL] no mark positions found — sample document has no eligible words")
        return False
    variants = build_document_variants(doc, positions)
    doc.close()

    try:
        plan = plan_parameters(
            available_positions=len(positions), n=len(OFFICER_IDS), eps1=EPS1, max_c0=MAX_C0
        )
        if plan.degraded:
            print(
                f"[WARNING] document supports only c0={plan.c0} "
                f"(requested max_c0={plan.requested_c0}) at n={len(OFFICER_IDS)}, eps1={EPS1}"
            )
        tardos_c0 = plan.c0
    except ValueError as exc:
        print(f"[WARNING] {exc} — registering with c0={MAX_C0} without a formal guarantee")
        tardos_c0 = MAX_C0

    k_a, k_b, s_v = generate_document_keys()
    package = build_package(variants, doc_id, k_a, k_b, s_v)
    package_path = blob_dir / doc_id / "package.json"
    save_package(package, package_path)
    package_hash = compute_package_hash(package_path)
    print(f"package written to {package_path}")

    nodes = []
    for i in range(KEYRELEASE_NODE_COUNT):
        node_id = f"keyrelease-{i}"
        kem_alg, kem_pub = kem_public_key(registry, node_id)
        nodes.append(
            KeyReleaseNodeInfo(
                identity_id=node_id,
                url=f"http://{node_id}:8000",
                kem_alg=kem_alg,
                kem_public_key=kem_pub,
            )
        )

    rng = np.random.default_rng(RNG_SEED)
    bias_vector = sample_bias_vector(len(positions), cutoff=BIAS_CUTOFF, rng=rng)
    secret = combine_release_secret(k_b, s_v)
    bias_bytes = bias_vector_to_bytes(bias_vector)

    print(f"registering shares with all {KEYRELEASE_NODE_COUNT} key-release nodes ...")
    register_shares(
        doc_id,
        secret,
        bias_bytes,
        nodes,
        sender_identity.sig_alg,
        sender_identity.sig_secret_key,
        sender_identity.identity_id,
    )

    recipients = []
    cert_hashes = []
    for officer_id in OFFICER_IDS:
        entry = registry[officer_id]
        cert_hash = sha3_256(bytes.fromhex(entry["certificate_cbor"]))
        cert_hashes.append(cert_hash)
        kem_alg, kem_pub = kem_public_key(registry, officer_id)
        recipients.append(
            RecipientInfo(
                identity_id=officer_id, cert_hash=cert_hash, kem_alg=kem_alg, kem_public_key=kem_pub
            )
        )

    print(f"wrapping K_A for {len(recipients)} officers ...")
    wrapped_k_a = wrap_k_a_for_recipients(k_a, doc_id, recipients)
    for officer_id, wrapped in wrapped_k_a.items():
        path = blob_dir / doc_id / "wrapped_k_a" / f"{officer_id}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(wrapped)

    print("submitting DOC_REGISTER to the ledger and waiting for finality ...")
    ledger_client = build_ledger_client(
        os.environ.get("LEDGER_BACKEND", "lite"), ledger_leader_url=ledger_leader_url
    )
    tx_id = register_document(
        ledger_client,
        doc_id=doc_id,
        package_hash=package_hash,
        recipient_cert_hashes=cert_hashes,
        policy_hash=sha3_256(b"traceseal/policy/v1/default"),
        positions_count=len(positions),
        tardos_n=len(OFFICER_IDS),
        tardos_c0=tardos_c0,
        tardos_eps1=EPS1,
        sender_sig_alg=sender_identity.sig_alg,
        sender_secret_key=sender_identity.sig_secret_key,
        sender_id=sender_identity.identity_id,
    )
    print(f"[PASS] document {doc_id!r} registered and finalized on the ledger: tx_id={tx_id}")
    print(
        f"Officers can now run, per officer: "
        f"python -m agent.demo_m3 --officer <a..e> --doc-id {doc_id}"
    )
    return True


def main() -> int:
    ok = run()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
