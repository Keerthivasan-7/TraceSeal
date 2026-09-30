from __future__ import annotations

from ca.keys import load_identity
from ca.seed import SENDER_ID
from fastapi.testclient import TestClient
from ledger.client import LedgerClient
from sender.distribute import register_document
from tscore.hashing import sha3_256
from tscore.records import (
    DOMAIN_DECRYPT_REQUEST_LEDGER,
    DOMAIN_KEYGRANT_ISSUED,
    DOMAIN_OPEN_EVENT,
    DOMAIN_RECEIPT,
    DecryptRequestLedgerRecord,
    KeyGrantIssuedRecord,
    OpenEventRecord,
    ReceiptRecord,
    make_submission,
)

from web_api.config import Settings


def _register_doc(ledger_client: LedgerClient, settings: Settings, doc_id: str) -> None:
    sender_identity = load_identity(settings.pki_dir / f"{SENDER_ID}.json")
    register_document(
        ledger_client,
        doc_id=doc_id,
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=sha3_256(b"x"),
        positions_count=100,
        tardos_n=2,
        tardos_c0=2,
        tardos_eps1=1e-4,
        sender_sig_alg=sender_identity.sig_alg,
        sender_secret_key=sender_identity.sig_secret_key,
        sender_id=sender_identity.identity_id,
    )


def _submit(  # type: ignore[no-untyped-def]
    ledger_client: LedgerClient, settings: Settings, signer_id: str, domain: str, record
) -> None:
    identity = load_identity(settings.pki_dir / f"{signer_id}.json")
    submission = make_submission(
        identity.sig_alg, identity.sig_secret_key, identity.identity_id, domain, record
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=10.0)


def test_list_documents_empty_initially(client: TestClient) -> None:
    response = client.get("/monitor/documents")
    assert response.status_code == 200
    assert response.json() == []


def test_timeline_for_unregistered_doc_is_empty(client: TestClient) -> None:
    response = client.get("/monitor/documents/doc-unknown/timeline")
    assert response.status_code == 200
    body = response.json()
    assert body["sessions"] == []
    assert body["open_denied"] == []


def test_timeline_groups_session_events_by_session_id(
    client: TestClient, ledger_client: LedgerClient, settings: Settings
) -> None:
    doc_id = "doc-monitor-1"
    _register_doc(ledger_client, settings, doc_id)

    _submit(
        ledger_client,
        settings,
        "keyrelease-0",
        DOMAIN_DECRYPT_REQUEST_LEDGER,
        DecryptRequestLedgerRecord(
            doc_id=doc_id,
            session_id="s-test-1",
            recipient_envelope_cbor=b"\x00",
            recipient_signer_id="officer-a",
            recipient_signature=b"\x00",
            codeword_commitment=b"\x00" * 32,
        ),
    )
    _submit(
        ledger_client,
        settings,
        "keyrelease-0",
        DOMAIN_KEYGRANT_ISSUED,
        KeyGrantIssuedRecord(
            session_id="s-test-1",
            grant_ciphertext_hash=b"\x00" * 32,
            contributing_node_ids=["keyrelease-0", "keyrelease-1", "keyrelease-2"],
            contributing_signatures=[b"\x00", b"\x00", b"\x00"],
        ),
    )
    _submit(
        ledger_client,
        settings,
        "officer-a",
        DOMAIN_RECEIPT,
        ReceiptRecord(session_id="s-test-1", assembled_pages_hash=b"\x00" * 32),
    )
    _submit(
        ledger_client,
        settings,
        "officer-a",
        DOMAIN_OPEN_EVENT,
        OpenEventRecord(session_id="s-test-1", doc_id=doc_id),
    )

    response = client.get(f"/monitor/documents/{doc_id}/timeline")
    assert response.status_code == 200
    body = response.json()
    assert len(body["sessions"]) == 1
    session = body["sessions"][0]
    assert session["session_id"] == "s-test-1"
    assert session["officer_id"] == "officer-a"
    stages = [e["stage"] for e in session["events"]]
    assert set(stages) == {"request", "keygrant", "receipt", "open"}
    heights = [e["height"] for e in session["events"]]
    assert heights == sorted(heights)
