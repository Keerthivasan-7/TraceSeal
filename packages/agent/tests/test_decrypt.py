"""Full recipient-agent decrypt session against a real 4-replica ledger +
5-node key-release cluster, wired in-process (no Docker). Covers the M3
acceptance path from the agent's side (a genuine signed `DecryptRequest`, a
genuine KEM-unwrapped `KeyGrant`, correctly assembled pages, and a
finalized `Receipt` on the ledger) plus M4's copy-binding/forwarding-
detection checks."""

import numpy as np
import pytest

from helpers import (
    build_keyrelease_cluster,
    build_ledger_client,
    build_lookup_public_key,
    build_sample_package,
    distribute_document,
    officer_cert_hash,
    seed_pki,
    submit_enroll_final,
    wrap_k_a_for_officer,
)

pytestmark = pytest.mark.requires_liboqs

DOC_ID = "doc-agent-1"


def _setup(tmp_path):  # type: ignore[no-untyped-def]
    pki_dir = tmp_path / "pki"
    identities = seed_pki(pki_dir)
    ledger_client = build_ledger_client(pki_dir, tmp_path)
    submit_enroll_final(ledger_client, identities["ca"], "officer-a", identities["cert"])
    submit_enroll_final(ledger_client, identities["ca"], "officer-b", identities["cert_b"])
    http_client, node0_url, apps = build_keyrelease_cluster(pki_dir, tmp_path, ledger_client)

    package, package_path, variants, k_a, k_b, s_v = build_sample_package(tmp_path, DOC_ID)
    cert_hash = officer_cert_hash(identities)
    distribute_document(
        pki_dir,
        apps,
        ledger_client,
        DOC_ID,
        package_path,
        len(package.manifest.positions),
        k_b,
        s_v,
        cert_hash,
    )
    wrapped_k_a_path = tmp_path / "blobstore" / DOC_ID / "wrapped_k_a" / "officer-a.bin"
    wrap_k_a_for_officer(pki_dir, DOC_ID, k_a, wrapped_k_a_path)

    return {
        "pki_dir": pki_dir,
        "ledger_client": ledger_client,
        "http_client": http_client,
        "node0_url": node0_url,
        "package": package,
        "package_path": package_path,
        "variants": variants,
        "cert_hash": cert_hash,
        "wrapped_k_a_path": wrapped_k_a_path,
        "outbox_path": tmp_path / "outbox.jsonl",
        "identities": identities,
    }


def test_open_document_assembles_correct_pages_and_finalizes_receipt(tmp_path) -> None:
    from ca.keys import load_identity
    from tscore.hashing import sha3_256

    from agent.decrypt import open_document

    ctx = _setup(tmp_path)
    officer = load_identity(ctx["pki_dir"] / "officer-a.json")
    lookup_public_key = build_lookup_public_key(ctx["pki_dir"])

    result = open_document(
        officer,
        DOC_ID,
        ctx["package_path"],
        ctx["wrapped_k_a_path"],
        ctx["cert_hash"],
        ctx["node0_url"],
        ctx["ledger_client"],
        lookup_public_key,
        ctx["outbox_path"],
        http_client=ctx["http_client"],
    )

    variants = ctx["variants"]
    assert len(result.pages) == len(variants.base_pages)

    # Every position's assembled patch must be exactly one of the two
    # possible variant renderings (never corrupted, never some other mix).
    for rp in variants.rendered_positions:
        x0, y0, x1, y1 = rp.pixel_bbox
        page = result.pages[rp.position.page_index]
        assembled_patch = page[y0:y1, x0:x1]
        matches_bit0 = np.array_equal(assembled_patch, rp.patch_bit0)
        matches_bit1 = np.array_equal(assembled_patch, rp.patch_bit1)
        assert matches_bit0 or matches_bit1

    # The finalized Receipt on the ledger must commit to exactly the pages
    # this call returned.
    record = ctx["ledger_client"].get(result.receipt_tx_id)
    from tscore.records import ReceiptRecord
    from tscore.schemas import SignedEnvelope

    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(record.envelope_cbor))
    receipt = ReceiptRecord.from_canonical_cbor(envelope.payload)
    assert receipt.session_id == result.session_id
    expected_hash = sha3_256(b"".join(page.tobytes() for page in result.pages))
    assert receipt.assembled_pages_hash == expected_hash


def test_open_document_submits_open_event_before_receipt(tmp_path) -> None:
    from ca.keys import load_identity

    from agent.decrypt import open_document

    ctx = _setup(tmp_path)
    officer = load_identity(ctx["pki_dir"] / "officer-a.json")
    lookup_public_key = build_lookup_public_key(ctx["pki_dir"])

    result = open_document(
        officer,
        DOC_ID,
        ctx["package_path"],
        ctx["wrapped_k_a_path"],
        ctx["cert_hash"],
        ctx["node0_url"],
        ctx["ledger_client"],
        lookup_public_key,
        ctx["outbox_path"],
        http_client=ctx["http_client"],
    )

    from tscore.records import DOMAIN_OPEN_EVENT

    open_event_records = ctx["ledger_client"].query(domain=DOMAIN_OPEN_EVENT)
    assert len(open_event_records) == 1
    open_event_height = ctx["ledger_client"].get(open_event_records[0].tx_id).height
    receipt_height = ctx["ledger_client"].get(result.receipt_tx_id).height
    assert open_event_height < receipt_height


def test_open_document_rejects_with_no_registered_document(tmp_path) -> None:
    from ca.keys import load_identity

    from agent.decrypt import DecryptRequestDeniedError, open_document

    ctx = _setup(tmp_path)
    officer = load_identity(ctx["pki_dir"] / "officer-a.json")
    lookup_public_key = build_lookup_public_key(ctx["pki_dir"])

    with pytest.raises(DecryptRequestDeniedError):
        open_document(
            officer,
            "some-other-doc-never-registered",
            ctx["package_path"],
            ctx["wrapped_k_a_path"],
            ctx["cert_hash"],
            ctx["node0_url"],
            ctx["ledger_client"],
            lookup_public_key,
            ctx["outbox_path"],
            http_client=ctx["http_client"],
        )


def test_open_document_rejects_self_declared_wrong_cert_hash(tmp_path) -> None:
    """Officer B signs a real DecryptRequest with their OWN key but
    self-declares officer A's cert_hash. The server-side check
    (keyrelease.node._current_cert_hash) catches this before ever issuing a
    SealedHeader — this is decision 6's closed single-actor framing gap."""
    from ca.keys import load_identity

    from agent.decrypt import DecryptRequestDeniedError, open_document

    ctx = _setup(tmp_path)
    officer_b = load_identity(ctx["pki_dir"] / "officer-b.json")
    lookup_public_key = build_lookup_public_key(ctx["pki_dir"])

    with pytest.raises(DecryptRequestDeniedError, match="recipient_cert_hash"):
        open_document(
            officer_b,
            DOC_ID,
            ctx["package_path"],
            ctx["wrapped_k_a_path"],
            ctx["cert_hash"],  # officer-a's cert hash, not officer-b's own
            ctx["node0_url"],
            ctx["ledger_client"],
            lookup_public_key,
            ctx["outbox_path"],
            http_client=ctx["http_client"],
        )


def test_verify_copy_binding_rejects_a_header_naming_a_different_recipient(tmp_path) -> None:
    """Unit-level: a legitimate SealedHeader issued for officer A is handed
    to verify_copy_binding under officer B's own cert hash — simulating a
    misdirected response reaching the wrong agent. No HTTP involved."""
    from ca.keys import load_identity
    from sender.package import compute_package_hash
    from tscore.records import DOMAIN_OPEN_DENIED

    from agent.decrypt import ForwardedCopyError, request_key_grant, verify_copy_binding

    ctx = _setup(tmp_path)
    officer_a = load_identity(ctx["pki_dir"] / "officer-a.json")
    officer_b = load_identity(ctx["pki_dir"] / "officer-b.json")
    lookup_public_key = build_lookup_public_key(ctx["pki_dir"])
    package_hash = compute_package_hash(ctx["package_path"])

    grant_response = request_key_grant(
        officer_a,
        DOC_ID,
        package_hash,
        ctx["cert_hash"],
        ctx["node0_url"],
        http_client=ctx["http_client"],
    )

    officer_b_cert_hash = b"\xbb" * 32
    with pytest.raises(ForwardedCopyError):
        verify_copy_binding(
            officer_b,
            DOC_ID,
            grant_response.session_id,
            grant_response.sealed_header_cbor,
            grant_response.header_signer_ids,
            grant_response.header_signatures,
            officer_b_cert_hash,
            lookup_public_key,
            ctx["ledger_client"],
            ctx["outbox_path"],
        )

    denied_records = ctx["ledger_client"].query(domain=DOMAIN_OPEN_DENIED)
    assert len(denied_records) == 1


def test_verify_copy_binding_rejects_an_under_quorum_header(tmp_path) -> None:
    from ca.keys import load_identity
    from sender.package import compute_package_hash
    from tscore.errors import VerificationError

    from agent.decrypt import request_key_grant, verify_copy_binding

    ctx = _setup(tmp_path)
    officer_a = load_identity(ctx["pki_dir"] / "officer-a.json")
    lookup_public_key = build_lookup_public_key(ctx["pki_dir"])
    package_hash = compute_package_hash(ctx["package_path"])

    grant_response = request_key_grant(
        officer_a,
        DOC_ID,
        package_hash,
        ctx["cert_hash"],
        ctx["node0_url"],
        http_client=ctx["http_client"],
    )

    # Truncate the quorum to below threshold — a malformed/under-quorum
    # response, not evidence of forwarding.
    with pytest.raises(VerificationError):
        verify_copy_binding(
            officer_a,
            DOC_ID,
            grant_response.session_id,
            grant_response.sealed_header_cbor,
            grant_response.header_signer_ids[:1],
            grant_response.header_signatures[:1],
            ctx["cert_hash"],
            lookup_public_key,
            ctx["ledger_client"],
            ctx["outbox_path"],
        )
