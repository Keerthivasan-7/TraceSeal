from __future__ import annotations

from fastapi.testclient import TestClient


def _enrol(client: TestClient, officer_id: str) -> None:
    propose = client.post(f"/identity/officers/{officer_id}/propose-enrol", json={})
    assert propose.status_code == 200
    tx_id = propose.json()["proposal_tx_id"]

    for admin_id in ("admin-1", "admin-2"):
        approve = client.post(f"/identity/proposals/{tx_id}/approve", json={"admin_id": admin_id})
        assert approve.status_code == 200

    finalize = client.post(f"/identity/proposals/{tx_id}/finalize")
    assert finalize.status_code == 200
    assert finalize.json() == {"officer_id": officer_id, "status": "enrolled"}


def test_registry_lists_admins_and_not_enrolled_officers(client: TestClient) -> None:
    response = client.get("/identity/registry")
    assert response.status_code == 200
    rows = {r["identity_id"]: r for r in response.json()}
    assert rows["admin-1"]["status"] == "active"
    assert rows["officer-a"]["status"] == "not enrolled"


def test_full_enrolment_ceremony_via_http(client: TestClient) -> None:
    _enrol(client, "officer-a")

    registry = {r["identity_id"]: r for r in client.get("/identity/registry").json()}
    assert registry["officer-a"]["status"] == "active"
    assert registry["officer-a"]["cert_hash"] is not None


def test_finalize_before_quorum_is_rejected(client: TestClient) -> None:
    propose = client.post("/identity/officers/officer-b/propose-enrol", json={})
    tx_id = propose.json()["proposal_tx_id"]
    client.post(f"/identity/proposals/{tx_id}/approve", json={"admin_id": "admin-1"})

    finalize = client.post(f"/identity/proposals/{tx_id}/finalize")
    assert finalize.status_code == 400


def test_proposals_shows_live_approval_progress(client: TestClient) -> None:
    propose = client.post("/identity/officers/officer-c/propose-enrol", json={})
    tx_id = propose.json()["proposal_tx_id"]

    before = next(p for p in client.get("/identity/proposals").json() if p["tx_id"] == tx_id)
    assert before["approvals"] == 0
    assert before["quorum_threshold"] == 2

    client.post(f"/identity/proposals/{tx_id}/approve", json={"admin_id": "admin-1"})

    after = next(p for p in client.get("/identity/proposals").json() if p["tx_id"] == tx_id)
    assert after["approvals"] == 1


def test_revocation_ceremony_via_http(client: TestClient) -> None:
    _enrol(client, "officer-d")

    propose = client.post(
        "/identity/officers/officer-d/propose-revoke", json={"reason": "test revocation"}
    )
    assert propose.status_code == 200
    tx_id = propose.json()["proposal_tx_id"]

    for admin_id in ("admin-1", "admin-2"):
        approve = client.post(
            f"/identity/proposals/{tx_id}/approve-revoke", json={"admin_id": admin_id}
        )
        assert approve.status_code == 200

    finalize = client.post(f"/identity/proposals/{tx_id}/finalize-revoke")
    assert finalize.status_code == 200
    assert finalize.json() == {"officer_id": "officer-d", "status": "revoked"}

    registry = {r["identity_id"]: r for r in client.get("/identity/registry").json()}
    assert registry["officer-d"]["status"] == "revoked"


def test_unknown_officer_id_404s(client: TestClient) -> None:
    response = client.post("/identity/officers/officer-does-not-exist/propose-enrol", json={})
    assert response.status_code == 404
