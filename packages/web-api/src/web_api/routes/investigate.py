"""Investigate (spec Section 14.6): upload a leaked artifact (or simulate
one from an officer's already-open session), watch the real pipeline run —
alignment, per-position detection, Tardos accusation — then build, sign,
and export the evidence bundle. Every step here calls `forensics.*`
directly; this module only wires HTTP around it and keeps the pipeline's
otherwise-discarded intermediate stages alive for the live visualization
(`forensics.pipeline.investigate_verbose`, added for exactly this screen).
"""

from __future__ import annotations

import io
import uuid
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import numpy as np
from attacklab.distortions import print_scan_pipeline, screen_camera_pipeline
from ca.keys import load_identity
from ca.registry import load_registry
from ca.seed import FORENSICS_ID
from fastapi import APIRouter, Form, HTTPException, Response, UploadFile
from forensics.investigation import (
    build_evidence_bundle,
    build_trust_roots,
    find_doc_register_proof,
    gather_candidate_codewords,
    issue_report,
    open_investigation,
    write_tsev,
)
from forensics.pipeline import investigate_verbose
from keyrelease.client import KeyReleaseClient
from PIL import Image
from tscore.evidence import decode_record_payload
from tscore.hashing import sha3_256
from tscore.records import DocRegisterRecord
from tscore.release_secret import bias_vector_from_bytes

from web_api.deps import AppStateDep, LedgerBackendDep, SettingsDep
from web_api.state import AppState, InvestigationRun

router = APIRouter(prefix="/investigate", tags=["investigate"])

# Must match the eps1 every document is planned/registered under
# (web_api.routes.distribute.EPS1) — the Tardos threshold calculation
# depends on it matching what the document was actually built for.
EPS1 = 1e-4


def _png_bytes(array: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(array).save(buf, format="PNG")
    return buf.getvalue()


def _keyrelease_client(settings: SettingsDep) -> KeyReleaseClient:
    urls = {
        f"keyrelease-{i}": settings.keyrelease_url_template.format(i=i)
        for i in range(settings.keyrelease_node_count)
    }
    return KeyReleaseClient(urls)


@router.post("/open")
async def open_case(
    settings: SettingsDep,
    ledger: LedgerBackendDep,
    app_state: AppStateDep,
    doc_id: str = Form(...),
    page_index: int = Form(...),
    source_officer_id: str | None = Form(None),
    distortion: str = Form("none"),
    file: UploadFile | None = None,
) -> dict[str, Any]:
    draft = app_state.released_documents.get(doc_id)
    if draft is None:
        raise HTTPException(
            status_code=404,
            detail=f"{doc_id!r} was not released via this session — nothing to investigate",
        )
    variants = draft.variants
    if page_index < 0 or page_index >= len(variants.original_pages):
        raise HTTPException(status_code=400, detail=f"no page {page_index}")

    if file is not None:
        data = await file.read()
        artifact = np.array(Image.open(io.BytesIO(data)).convert("RGB"))
    elif source_officer_id is not None:
        session = app_state.open_sessions.get(f"{source_officer_id}:{doc_id}")
        if session is None:
            raise HTTPException(
                status_code=404,
                detail=f"{source_officer_id!r} has no open session for {doc_id!r}",
            )
        if page_index >= len(session.pages):
            raise HTTPException(status_code=400, detail=f"session has no page {page_index}")
        page = session.pages[page_index]
        rng = np.random.default_rng()
        if distortion == "screen_camera":
            artifact = screen_camera_pipeline(page, rng)
        elif distortion == "print_scan":
            artifact = print_scan_pipeline(page, rng)
        elif distortion == "none":
            artifact = page
        else:
            raise HTTPException(status_code=400, detail=f"unknown distortion {distortion!r}")
    else:
        raise HTTPException(
            status_code=400, detail="provide either an uploaded file or source_officer_id"
        )

    artifact_bytes = _png_bytes(artifact)
    artifact_hash = sha3_256(artifact_bytes)

    forensics_identity = load_identity(settings.pki_dir / f"{FORENSICS_ID}.json")
    case_id = f"case-{uuid.uuid4().hex[:12]}"

    investigation_opened_proof = open_investigation(
        case_id, artifact_hash, forensics_identity, ledger
    )
    doc_register_proof = find_doc_register_proof(ledger, doc_id)
    doc_register = decode_record_payload(doc_register_proof, DocRegisterRecord)

    keyrelease_client = _keyrelease_client(settings)
    candidates = gather_candidate_codewords(doc_id, ledger, keyrelease_client)
    if not candidates:
        raise HTTPException(
            status_code=400,
            detail=f"no decrypt sessions found on the ledger for {doc_id!r} — nothing to accuse",
        )
    codewords = {
        c.session_id: np.frombuffer(c.revealed_codeword, dtype=np.int8) for c in candidates
    }
    bias_vector_bytes = keyrelease_client.reveal_bias_vector(doc_id)
    bias_vector = bias_vector_from_bytes(bias_vector_bytes, len(variants.rendered_positions))

    report, artifacts = investigate_verbose(
        artifact, page_index, variants, codewords, bias_vector, EPS1
    )

    registry = load_registry(settings.pki_dir / "registry.json")
    trust_roots = build_trust_roots(registry)

    app_state.investigations[case_id] = InvestigationRun(
        case_id=case_id,
        doc_id=doc_id,
        page_index=page_index,
        artifact=artifact,
        aligned=artifacts.alignment.warped,
        observations=artifacts.observations,
        page_to_global=artifacts.page_to_global,
        report=report,
        candidates=candidates,
        bias_vector_bytes=bias_vector_bytes,
        artifact_hash=artifact_hash,
        investigation_opened_proof=investigation_opened_proof,
        doc_register_proof=doc_register_proof,
        trust_roots=trust_roots,
        tardos_n=doc_register.tardos_n,
        tardos_c0=doc_register.tardos_c0,
        tardos_eps1=EPS1,
    )

    accused = set(report.accused_sessions)
    officer_by_session = {c.session_id: c.officer_id for c in candidates}
    return {
        "case_id": case_id,
        "doc_id": doc_id,
        "page_index": page_index,
        "threshold": report.threshold,
        "n_observed": report.n_observed,
        "n_total_positions": report.n_total_positions,
        "n_erasures": report.n_erasures,
        "summary": report.summary(),
        "suspects": [
            {
                "session_id": session_id,
                "officer_id": officer_by_session.get(session_id, "unknown"),
                "score": score,
                "accused": session_id in accused,
            }
            for session_id, score in sorted(report.scores.items(), key=lambda kv: -kv[1])
        ],
    }


def _require_run(app_state: AppState, case_id: str) -> InvestigationRun:
    run = app_state.investigations.get(case_id)
    if run is None:
        raise HTTPException(status_code=404, detail=f"no investigation {case_id!r}")
    return run


@router.get("/{case_id}/pipeline/detected-page")
def get_detected_page(case_id: str, app_state: AppStateDep) -> Response:
    run = _require_run(app_state, case_id)
    return Response(content=_png_bytes(run.artifact), media_type="image/png")


@router.get("/{case_id}/pipeline/aligned-overlay")
def get_aligned_overlay(case_id: str, app_state: AppStateDep) -> Response:
    run = _require_run(app_state, case_id)
    return Response(content=_png_bytes(run.aligned), media_type="image/png")


@router.get("/{case_id}/pipeline/observations")
def get_observations(case_id: str, app_state: AppStateDep) -> list[dict[str, Any]]:
    run = _require_run(app_state, case_id)
    variants = app_state.released_documents[run.doc_id].variants
    result = []
    for obs in run.observations:
        global_idx = run.page_to_global[obs.position_index]
        rp = variants.rendered_positions[global_idx]
        result.append(
            {
                "position_index": global_idx,
                "pixel_bbox": list(rp.pixel_bbox),
                "observed_bit": None if obs.is_erasure else obs.observed_bit,
                "confidence": obs.confidence,
                "is_erasure": obs.is_erasure,
            }
        )
    return result


@router.post("/{case_id}/issue-report")
def issue_case_report(
    case_id: str, settings: SettingsDep, ledger: LedgerBackendDep, app_state: AppStateDep
) -> dict[str, Any]:
    run = _require_run(app_state, case_id)
    if run.tsev_bytes is not None:
        raise HTTPException(status_code=400, detail="report already issued for this case")

    forensics_identity = load_identity(settings.pki_dir / f"{FORENSICS_ID}.json")
    accused = set(run.report.accused_sessions)
    signed_bundle, bundle, report_pdf_bytes = build_evidence_bundle(
        case_id=run.case_id,
        doc_id=run.doc_id,
        artifact_hash=run.artifact_hash,
        tardos_n=run.tardos_n,
        tardos_c0=run.tardos_c0,
        tardos_eps1=run.tardos_eps1,
        n_observed=run.report.n_observed,
        n_total_positions=run.report.n_total_positions,
        n_erasures=run.report.n_erasures,
        threshold=run.report.threshold,
        observed_bits=[float(x) for x in run.report.observed_bits],
        revealed_bias_vector=run.bias_vector_bytes,
        candidates=run.candidates,
        scores=run.report.scores,
        accused_sessions=accused,
        investigation_opened_proof=run.investigation_opened_proof,
        doc_register_proof=run.doc_register_proof,
        trust_roots=run.trust_roots,
        forensics_identity=forensics_identity,
    )
    report_tx_id = issue_report(
        run.case_id, run.doc_id, signed_bundle, report_pdf_bytes, forensics_identity, ledger
    )

    tsev_buf = io.BytesIO()
    with TemporaryDirectory() as tmp:
        tsev_path = Path(tmp) / "case.tsev"
        write_tsev(tsev_path, signed_bundle, bundle, report_pdf_bytes)
        tsev_buf.write(tsev_path.read_bytes())

    run.signed_bundle = signed_bundle
    run.bundle = bundle
    run.report_pdf_bytes = report_pdf_bytes
    run.tsev_bytes = tsev_buf.getvalue()

    return {
        "case_id": case_id,
        "report_tx_id": report_tx_id,
        "accused_sessions": sorted(accused),
    }


@router.get("/{case_id}/download/tsev")
def download_tsev(case_id: str, app_state: AppStateDep) -> Response:
    run = _require_run(app_state, case_id)
    if run.tsev_bytes is None:
        raise HTTPException(status_code=404, detail="report not yet issued for this case")
    return Response(
        content=run.tsev_bytes,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{case_id}.tsev"'},
    )


@router.get("/{case_id}/download/report.pdf")
def download_report_pdf(case_id: str, app_state: AppStateDep) -> Response:
    run = _require_run(app_state, case_id)
    if run.report_pdf_bytes is None:
        raise HTTPException(status_code=404, detail="report not yet issued for this case")
    return Response(
        content=run.report_pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{case_id}-report.pdf"'},
    )
