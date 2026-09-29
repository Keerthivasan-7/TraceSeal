from __future__ import annotations

from fastapi.testclient import TestClient


def test_status_shape_with_empty_ledger(client: TestClient) -> None:
    response = client.get("/system/status")
    assert response.status_code == 200
    body = response.json()
    assert body["air_gap"]["cloud_dependencies"] == "NONE"
    assert body["counts"] == {
        "documents": 0,
        "sessions": 0,
        "open_investigations": 0,
        "ledger_height": 0,
    }
    assert body["replicas"] is not None
    assert len(body["replicas"]) == 4
    assert all(r["internally_valid"] for r in body["replicas"])
    assert body["recent_events"] == []


def test_egress_test_returns_a_real_live_result(client: TestClient) -> None:
    # Doesn't assert which way it comes out — this genuinely attempts a
    # live outbound call, so the assertion only checks the response shape,
    # not the network environment pytest happens to run in.
    response = client.get("/system/egress-test")
    assert response.status_code == 200
    body = response.json()
    assert isinstance(body["egress_blocked"], bool)
