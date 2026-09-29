from __future__ import annotations

from pathlib import Path

from ca.keys import load_identity
from fastapi.testclient import TestClient
from ledger.client import LedgerClient
from tscore.records import DOMAIN_DOC_REGISTER, DocRegisterRecord, make_submission


def _submit_doc_register(ledger_client: LedgerClient, pki_dir: Path, doc_id: str) -> str:
    sender_identity = load_identity(pki_dir / "sender-1.json")
    record = DocRegisterRecord(
        doc_id=doc_id,
        package_hash=b"\x00" * 32,
        recipient_cert_hashes=[b"\x00" * 32],
        policy_hash=b"\x00" * 32,
        positions_count=10,
        tardos_n=5,
        tardos_c0=3,
        tardos_eps1=1e-4,
    )
    submission = make_submission(
        sender_identity.sig_alg,
        sender_identity.sig_secret_key,
        sender_identity.identity_id,
        DOMAIN_DOC_REGISTER,
        record,
    )
    tx_id = ledger_client.submit(submission)
    ledger_client.wait_final(tx_id, timeout_s=10.0)
    return tx_id


def test_replicas_are_all_valid_on_a_fresh_cluster(client: TestClient) -> None:
    response = client.get("/ledger/replicas")
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert len(body["replicas"]) == 4


def test_records_lists_a_real_submitted_record(
    client: TestClient, ledger_client: LedgerClient, pki_dir: Path
) -> None:
    tx_id = _submit_doc_register(ledger_client, pki_dir, "doc-web-api-test")

    response = client.get("/ledger/records", params={"domain": DOMAIN_DOC_REGISTER})
    assert response.status_code == 200
    records = response.json()
    assert len(records) == 1
    assert records[0]["tx_id"] == tx_id
    assert records[0]["payload"]["doc_id"] == "doc-web-api-test"


def test_record_proof_verifies_a_genuine_record(
    client: TestClient, ledger_client: LedgerClient, pki_dir: Path
) -> None:
    tx_id = _submit_doc_register(ledger_client, pki_dir, "doc-web-api-test-2")

    response = client.get(f"/ledger/records/{tx_id}/proof")
    assert response.status_code == 200
    body = response.json()
    assert body["verified"] is True
    assert body["verification_error"] is None


def test_record_proof_404s_for_unknown_tx_id(client: TestClient) -> None:
    response = client.get("/ledger/records/does-not-exist/proof")
    assert response.status_code == 404
