"""Milestone M5 acceptance script (spec Section 17 / Section 18 demo step
9):

    "Evidence bundle + standalone verifier + signed PDF report ...
    Acceptance: Verifier passes on a genuine bundle and fails on each
    tampering case."

Assumes the CA has already been seeded and the ledger + key-release
cluster are already up (`make up`), exactly like `sender.demo_m3`. Unlike
that script, this one runs its own fresh document registration AND one
real officer decrypt session inline (a distinct `doc_id`, so it never
depends on `sender.demo_m3`/`agent.demo_m3` having been run first) —
because the leaked "screenshot" this demo investigates is a screenshot of
that officer's own genuinely-decrypted page (the actual protocol's own
output — spec Section 2: "decryption itself produces the forensic
fingerprint"), not a locally-reassembled stand-in.

Then runs the full M5 investigation pipeline end to end: open
investigation -> reveal vault -> forensic detection -> build + self-check
+ sign the evidence bundle -> issue the downstream report record -> write
`case.tsev` + (inside it) `report.pdf` under `demo/out/m5/`.

`traceseal-verify` (packages/verifier) is run separately, against this
script's output, by `make demo-m5` — this script's job ends once
`case.tsev` is on disk.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import numpy as np
from agent.decrypt import open_document
from ca.keys import load_identity
from ca.registry import kem_public_key, load_registry, sig_public_key
from ca.seed import FORENSICS_ID, OFFICER_IDS, SENDER_ID
from keyrelease.client import KeyReleaseClient
from ledger.backend import LedgerBackend, build_ledger_client
from PIL import Image
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
from tscore.evidence import decode_record_payload
from tscore.hashing import sha3_256
from tscore.records import DocRegisterRecord
from tscore.release_secret import (
    bias_vector_from_bytes,
    bias_vector_to_bytes,
    combine_release_secret,
)
from tscore.tardos import plan_parameters, sample_bias_vector

from forensics.investigation import (
    build_evidence_bundle,
    build_trust_roots,
    find_doc_register_proof,
    gather_candidate_codewords,
    issue_report,
    open_investigation,
    write_tsev,
)
from forensics.pipeline import investigate

DEFAULT_PKI_DIR = Path.cwd() / "demo" / "pki"
DEFAULT_BLOB_DIR = Path.cwd() / "demo" / "blob"
DEFAULT_OUTPUT_DIR = Path.cwd() / "demo" / "out" / "m5"
DEFAULT_LEDGER_LEADER_URL = "http://ledger-0:8000"
DEFAULT_KEYRELEASE_URL_TEMPLATE = "http://keyrelease-{i}:8000"
KEYRELEASE_NODE_COUNT = 5
DOC_ID = "doc-m5-demo"
CASE_ID = "case-m5-demo"
OFFICER_ID = "officer-a"
LEAK_PAGE_INDEX = 0
EPS1 = 1e-4
MAX_C0 = 3
BIAS_CUTOFF = 0.1
RNG_SEED = 20260401
SCREENSHOT_SCALE = 0.5  # simulates a lower-DPI viewer/screen capture, same as forensics.demo_m2


def _register_and_distribute(
    pki_dir: Path, blob_dir: Path, ledger_client: LedgerBackend
) -> tuple[Path, Path]:
    registry = load_registry(pki_dir / "registry.json")
    sender_identity = load_identity(pki_dir / f"{SENDER_ID}.json")

    doc = build_sample_document()
    positions = select_positions(doc)
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
    package = build_package(variants, DOC_ID, k_a, k_b, s_v)
    package_path = blob_dir / DOC_ID / "package.json"
    save_package(package, package_path)
    package_hash = compute_package_hash(package_path)

    nodes = []
    for i in range(KEYRELEASE_NODE_COUNT):
        node_id = f"keyrelease-{i}"
        kem_alg, kem_pub = kem_public_key(registry, node_id)
        nodes.append(
            KeyReleaseNodeInfo(
                identity_id=node_id,
                url=DEFAULT_KEYRELEASE_URL_TEMPLATE.format(i=i),
                kem_alg=kem_alg,
                kem_public_key=kem_pub,
            )
        )

    rng = np.random.default_rng(RNG_SEED)
    bias_vector = sample_bias_vector(len(positions), cutoff=BIAS_CUTOFF, rng=rng)
    secret = combine_release_secret(k_b, s_v)
    bias_bytes = bias_vector_to_bytes(bias_vector)
    register_shares(
        DOC_ID,
        secret,
        bias_bytes,
        nodes,
        sender_identity.sig_alg,
        sender_identity.sig_secret_key,
        sender_identity.identity_id,
    )

    entry = registry[OFFICER_ID]
    cert_hash = sha3_256(bytes.fromhex(entry["certificate_cbor"]))
    officer_kem_alg, officer_kem_pub = kem_public_key(registry, OFFICER_ID)
    recipients = [
        RecipientInfo(
            identity_id=OFFICER_ID,
            cert_hash=cert_hash,
            kem_alg=officer_kem_alg,
            kem_public_key=officer_kem_pub,
        )
    ]
    wrapped_k_a = wrap_k_a_for_recipients(k_a, DOC_ID, recipients)
    wrapped_path = blob_dir / DOC_ID / "wrapped_k_a" / f"{OFFICER_ID}.bin"
    wrapped_path.parent.mkdir(parents=True, exist_ok=True)
    wrapped_path.write_bytes(wrapped_k_a[OFFICER_ID])

    tx_id = register_document(
        ledger_client,
        doc_id=DOC_ID,
        package_hash=package_hash,
        recipient_cert_hashes=[cert_hash],
        policy_hash=sha3_256(b"traceseal/policy/v1/default"),
        positions_count=len(positions),
        tardos_n=len(OFFICER_IDS),
        tardos_c0=tardos_c0,
        tardos_eps1=EPS1,
        sender_sig_alg=sender_identity.sig_alg,
        sender_secret_key=sender_identity.sig_secret_key,
        sender_id=sender_identity.identity_id,
    )
    print(f"document {DOC_ID!r} registered and finalized: tx_id={tx_id}")
    return package_path, wrapped_path


def _decrypt_officer_session(
    pki_dir: Path,
    blob_dir: Path,
    ledger_client: LedgerBackend,
    package_path: Path,
    wrapped_path: Path,
) -> list[np.ndarray]:
    identity = load_identity(pki_dir / f"{OFFICER_ID}.json")
    registry = load_registry(pki_dir / "registry.json")
    cert_hash = sha3_256(bytes.fromhex(registry[OFFICER_ID]["certificate_cbor"]))

    def lookup_public_key(signer_id: str) -> tuple[str, bytes]:
        return sig_public_key(load_registry(pki_dir / "registry.json"), signer_id)

    outbox_path = blob_dir.parent / "agent-state" / OFFICER_ID / "outbox.jsonl"
    result = open_document(
        identity,
        DOC_ID,
        package_path,
        wrapped_path,
        cert_hash,
        DEFAULT_KEYRELEASE_URL_TEMPLATE.format(i=0),
        ledger_client,
        lookup_public_key,
        outbox_path,
    )
    print(f"officer session decrypted in memory: session_id={result.session_id}")
    return result.pages


def _simulate_screenshot(
    page: np.ndarray, out_path: Path, *, scale: float
) -> tuple[np.ndarray, bytes]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    img = Image.fromarray(page)
    resized = img.resize(
        (round(img.width * scale), round(img.height * scale)), Image.Resampling.LANCZOS
    )
    resized.save(out_path)
    artifact_bytes = out_path.read_bytes()
    return np.array(Image.open(out_path).convert("RGB")), artifact_bytes


def run(
    *,
    pki_dir: Path = DEFAULT_PKI_DIR,
    blob_dir: Path = DEFAULT_BLOB_DIR,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    ledger_leader_url: str = DEFAULT_LEDGER_LEADER_URL,
) -> bool:
    print("== TraceSeal M5 demo: evidence bundle + signed PDF report ==")

    ledger_client = build_ledger_client(
        os.environ.get("LEDGER_BACKEND", "lite"), ledger_leader_url=ledger_leader_url
    )
    keyrelease_client = KeyReleaseClient(
        {
            f"keyrelease-{i}": DEFAULT_KEYRELEASE_URL_TEMPLATE.format(i=i)
            for i in range(KEYRELEASE_NODE_COUNT)
        }
    )
    registry = load_registry(pki_dir / "registry.json")
    forensics_identity = load_identity(pki_dir / f"{FORENSICS_ID}.json")

    package_path, wrapped_path = _register_and_distribute(pki_dir, blob_dir, ledger_client)
    pages = _decrypt_officer_session(pki_dir, blob_dir, ledger_client, package_path, wrapped_path)

    leaked_page = pages[LEAK_PAGE_INDEX]
    artifact_path = output_dir / f"leak_page{LEAK_PAGE_INDEX}.png"
    artifact, artifact_bytes = _simulate_screenshot(
        leaked_page, artifact_path, scale=SCREENSHOT_SCALE
    )
    artifact_hash = sha3_256(artifact_bytes)
    print(f"simulated leaked screenshot written to {artifact_path}")

    investigation_opened_proof = open_investigation(
        CASE_ID, artifact_hash, forensics_identity, ledger_client
    )
    doc_register_proof = find_doc_register_proof(ledger_client, DOC_ID)

    candidates = gather_candidate_codewords(DOC_ID, ledger_client, keyrelease_client)
    print(f"candidate sessions revealed from the key-release vault: {len(candidates)}")

    doc = build_sample_document()
    positions = select_positions(doc)
    variants = build_document_variants(doc, positions)
    doc.close()

    codewords = {
        c.session_id: np.frombuffer(c.revealed_codeword, dtype=np.int8) for c in candidates
    }
    bias_vector_bytes = keyrelease_client.reveal_bias_vector(DOC_ID)
    bias_vector = bias_vector_from_bytes(bias_vector_bytes, len(positions))

    report = investigate(artifact, LEAK_PAGE_INDEX, variants, codewords, bias_vector, EPS1)
    print(f"        {report.summary()}")

    doc_register = decode_record_payload(doc_register_proof, DocRegisterRecord)

    trust_roots = build_trust_roots(registry)
    signed_bundle, bundle, report_pdf_bytes = build_evidence_bundle(
        case_id=CASE_ID,
        doc_id=DOC_ID,
        artifact_hash=artifact_hash,
        tardos_n=doc_register.tardos_n,
        tardos_c0=doc_register.tardos_c0,
        tardos_eps1=EPS1,
        n_observed=report.n_observed,
        n_total_positions=report.n_total_positions,
        n_erasures=report.n_erasures,
        threshold=report.threshold,
        observed_bits=[float(x) for x in report.observed_bits],
        revealed_bias_vector=bias_vector_bytes,
        candidates=candidates,
        scores=report.scores,
        accused_sessions=set(report.accused_sessions),
        investigation_opened_proof=investigation_opened_proof,
        doc_register_proof=doc_register_proof,
        trust_roots=trust_roots,
        forensics_identity=forensics_identity,
    )
    print("[PASS] evidence bundle built, self-checked, signed, and independently re-verified")

    report_tx_id = issue_report(
        CASE_ID, DOC_ID, signed_bundle, report_pdf_bytes, forensics_identity, ledger_client
    )
    print(f"REPORT_ISSUED committed to the ledger: tx_id={report_tx_id}")

    tsev_path = output_dir / "case.tsev"
    write_tsev(tsev_path, signed_bundle, bundle, report_pdf_bytes)
    print(f"[PASS] evidence bundle written to {tsev_path}")
    print(
        "Run 'traceseal-verify "
        f"{tsev_path}' to independently verify it (depends only on tscore)."
    )
    return True


def main() -> int:
    ok = run()
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
