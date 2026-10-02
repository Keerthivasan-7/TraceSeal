"""Distribute (spec Section 14.3): upload a document, review the selected
mark positions, the quality-gate report, and the planned Tardos parameters,
then release it to a chosen set of already-enrolled officers.

Two-step flow, mirroring `sender.demo_m3`'s real call sequence but against
an uploaded document and a caller-chosen recipient subset instead of the
fixed sample document and all five officers:

- `POST /distribute/analyze` renders the uploaded PDF, selects mark
  positions, builds the dual-variant patches, and runs the quality gate —
  the expensive, purely computational half — and caches the result
  in-memory as a `DistributeDraft` so `/release` doesn't have to redo it.
- `POST /distribute/{draft_id}/release` Shamir-splits the release secret
  across the key-release nodes, KEM-wraps K_A for each chosen recipient,
  and registers the document on the ledger — refusing to proceed if the
  cached quality gate didn't pass.
"""

from __future__ import annotations

import io
import uuid
from typing import Any

import numpy as np
import pymupdf
from ca.registry import kem_public_key, load_registry
from ca.seed import SENDER_ID
from fastapi import APIRouter, HTTPException, Response, UploadFile
from PIL import Image
from pydantic import BaseModel
from sender.distribute import (
    KeyReleaseNodeInfo,
    RecipientInfo,
    register_document,
    register_shares,
    wrap_k_a_for_recipients,
)
from sender.package import build_package, compute_package_hash, generate_document_keys, save_package
from sender.positions import select_positions
from sender.quality_gate import run_quality_gate
from sender.variants import build_document_variants
from tscore.hashing import sha3_256
from tscore.release_secret import bias_vector_to_bytes, combine_release_secret
from tscore.tardos import plan_parameters, sample_bias_vector

from web_api.deps import AppStateDep, LedgerBackendDep, SettingsDep
from web_api.identities import resolve_identity
from web_api.identity_status import current_cert_hash, is_revoked
from web_api.state import DistributeDraft, bounded_insert

router = APIRouter(prefix="/distribute", tags=["distribute"])

# Mirrors sender.demo_m3's own constants — see that module for why these
# particular values (2 px @ 300 DPI shift margin, c0 <= 3 collusion
# resistance, a bias-vector cutoff that keeps every position informative).
EPS1 = 1e-4
MAX_C0 = 3
BIAS_CUTOFF = 0.1
DEFAULT_POLICY_HASH_INPUT = b"traceseal/policy/v1/default"


@router.post("/analyze")
async def analyze(file: UploadFile, app_state: AppStateDep) -> dict[str, Any]:
    data = await file.read()
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception as exc:  # noqa: BLE001 - pymupdf has no narrow "bad PDF" exception type
        raise HTTPException(status_code=400, detail=f"could not parse PDF: {exc}") from exc

    positions = select_positions(doc)
    if not positions:
        doc.close()
        raise HTTPException(
            status_code=400, detail="no eligible mark positions found in this document"
        )
    variants = build_document_variants(doc, positions)
    doc.close()

    quality_report = run_quality_gate(variants)

    doc_id = f"doc-{uuid.uuid4().hex[:12]}"
    draft_id = uuid.uuid4().hex
    bounded_insert(
        app_state.distribute_drafts,
        draft_id,
        DistributeDraft(draft_id=draft_id, doc_id=doc_id, variants=variants, quality_report=quality_report),
    )

    return {
        "draft_id": draft_id,
        "doc_id": doc_id,
        "page_count": len(variants.original_pages),
        "positions_count": len(positions),
        "positions": [
            {"index": idx, "page_index": rp.position.page_index, "pixel_bbox": list(rp.pixel_bbox)}
            for idx, rp in enumerate(variants.rendered_positions)
        ],
        "quality_gate": {
            "passed": quality_report.passed,
            "ssim_threshold": quality_report.ssim_threshold,
            "max_changed_fraction": quality_report.max_changed_fraction,
            "pages": [
                {
                    "page_index": p.page_index,
                    "variant_bit": p.variant_bit,
                    "ssim": p.ssim,
                    "max_abs_delta": p.max_abs_delta,
                    "passed": p.passed,
                }
                for p in quality_report.pages
            ],
            "worst_position_changed_fraction": max(
                (p.changed_fraction for p in quality_report.positions), default=0.0
            ),
        },
    }


@router.get("/{draft_id}/pages/{page_index}")
def get_preview_page(draft_id: str, page_index: int, app_state: AppStateDep) -> Response:
    draft = app_state.distribute_drafts.get(draft_id)
    if draft is None:
        raise HTTPException(status_code=404, detail=f"no draft {draft_id!r}")
    if page_index < 0 or page_index >= len(draft.variants.original_pages):
        raise HTTPException(status_code=404, detail=f"no page {page_index}")
    buf = io.BytesIO()
    Image.fromarray(draft.variants.original_pages[page_index]).save(buf, format="PNG")
    return Response(content=buf.getvalue(), media_type="image/png")


class ReleaseRequest(BaseModel):
    recipient_officer_ids: list[str]


@router.post("/{draft_id}/release")
def release(
    draft_id: str,
    body: ReleaseRequest,
    ledger: LedgerBackendDep,
    settings: SettingsDep,
    app_state: AppStateDep,
) -> dict[str, Any]:
    draft = app_state.distribute_drafts.get(draft_id)
    if draft is None:
        raise HTTPException(status_code=404, detail=f"no draft {draft_id!r}")
    if not draft.quality_report.passed:
        raise HTTPException(
            status_code=400, detail="quality gate did not pass for this draft — cannot release"
        )
    if not body.recipient_officer_ids:
        raise HTTPException(status_code=400, detail="at least one recipient is required")

    registry = load_registry(settings.pki_dir / "registry.json")
    recipients: list[RecipientInfo] = []
    cert_hashes: list[bytes] = []
    for officer_id in body.recipient_officer_ids:
        cert_hash_hex = current_cert_hash(ledger, officer_id)
        if cert_hash_hex is None:
            raise HTTPException(status_code=400, detail=f"{officer_id!r} is not enrolled")
        if is_revoked(ledger, cert_hash_hex):
            raise HTTPException(status_code=400, detail=f"{officer_id!r}'s certificate is revoked")
        cert_hash = bytes.fromhex(cert_hash_hex)
        kem_alg, kem_pub = kem_public_key(registry, officer_id)
        recipients.append(
            RecipientInfo(
                identity_id=officer_id, cert_hash=cert_hash, kem_alg=kem_alg, kem_public_key=kem_pub
            )
        )
        cert_hashes.append(cert_hash)

    sender_identity = resolve_identity(settings, app_state, SENDER_ID)
    doc_id = draft.doc_id
    variants = draft.variants
    positions_count = len(variants.rendered_positions)

    try:
        plan = plan_parameters(
            available_positions=positions_count, n=len(recipients), eps1=EPS1, max_c0=MAX_C0
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    k_a, k_b, s_v = generate_document_keys()
    package = build_package(variants, doc_id, k_a, k_b, s_v)
    package_path = settings.blob_dir / doc_id / "package.json"
    save_package(package, package_path)
    package_hash = compute_package_hash(package_path)

    nodes: list[KeyReleaseNodeInfo] = []
    for i in range(settings.keyrelease_node_count):
        node_id = f"keyrelease-{i}"
        node_kem_alg, node_kem_pub = kem_public_key(registry, node_id)
        nodes.append(
            KeyReleaseNodeInfo(
                identity_id=node_id,
                url=settings.keyrelease_url_template.format(i=i),
                kem_alg=node_kem_alg,
                kem_public_key=node_kem_pub,
            )
        )

    rng = np.random.default_rng()
    bias_vector = sample_bias_vector(positions_count, cutoff=BIAS_CUTOFF, rng=rng)
    secret = combine_release_secret(k_b, s_v)
    bias_bytes = bias_vector_to_bytes(bias_vector)

    register_shares(
        doc_id,
        secret,
        bias_bytes,
        nodes,
        sender_identity.sig_alg,
        sender_identity.sig_secret_key,
        sender_identity.identity_id,
    )

    wrapped_k_a = wrap_k_a_for_recipients(k_a, doc_id, recipients)
    for officer_id, wrapped in wrapped_k_a.items():
        path = settings.blob_dir / doc_id / "wrapped_k_a" / f"{officer_id}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(wrapped)

    tx_id = register_document(
        ledger,
        doc_id=doc_id,
        package_hash=package_hash,
        recipient_cert_hashes=cert_hashes,
        policy_hash=sha3_256(DEFAULT_POLICY_HASH_INPUT),
        positions_count=positions_count,
        tardos_n=len(recipients),
        tardos_c0=plan.c0,
        tardos_eps1=EPS1,
        sender_sig_alg=sender_identity.sig_alg,
        sender_secret_key=sender_identity.sig_secret_key,
        sender_id=sender_identity.identity_id,
    )

    bounded_insert(app_state.released_documents, doc_id, app_state.distribute_drafts.pop(draft_id))

    return {
        "doc_id": doc_id,
        "tx_id": tx_id,
        "recipients": body.recipient_officer_ids,
        "tardos_c0": plan.c0,
        "tardos_degraded": plan.degraded,
    }
