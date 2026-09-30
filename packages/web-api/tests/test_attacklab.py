from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_results_not_found_404s_when_no_results_file(client: TestClient) -> None:
    response = client.get("/attacklab/results")
    assert response.status_code == 404


def test_results_parses_real_markdown(app: FastAPI, client: TestClient) -> None:
    docs_dir = app.state.settings.docs_dir
    docs_dir.mkdir(parents=True, exist_ok=True)
    (docs_dir / "RESULTS.md").write_text(
        "# Attack Lab Results\n\n"
        "- Git commit: `abc123`\n\n"
        "## Synthetic distortions\n\n"
        "| Condition | Trials | Mean BER | Mean Erasure Rate | Top-1 Accuracy "
        "| Innocent Accusations (total / rate) | Mean Runtime (ms) | Registration Failures |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| jpeg_q90 | 5 | 0.0100 | 0.0200 | 100.00% | 0 (0.0000) | 210.5 | 0 |\n\n"
        "## Collusion\n\n"
        "| Condition | Trials | Mean BER | Mean Erasure Rate | Top-1 Accuracy "
        "| Innocent Accusations (total / rate) | Mean Runtime (ms) | Registration Failures |\n"
        "|---|---|---|---|---|---|---|---|\n"
        "| collusion_majority_c2 | 5 | 0.0300 | 0.0100 | 80.00% | 1 (0.2000) | 230.1 | 0 |\n"
    )

    response = client.get("/attacklab/results")
    assert response.status_code == 200
    body = response.json()
    assert "Attack Lab Results" in body["markdown"]
    assert len(body["synthetic"]) == 1
    assert body["synthetic"][0]["Condition"] == "jpeg_q90"
    assert len(body["collusion"]) == 1
    assert body["collusion"][0]["Condition"] == "collusion_majority_c2"


def test_quick_run_returns_real_condition_summaries(client: TestClient) -> None:
    response = client.post("/attacklab/quick-run")
    assert response.status_code == 200
    body = response.json()
    assert body["n_trials"] == 2
    assert len(body["conditions"]) == 5  # 3 synthetic + 2 collusion
    for condition in body["conditions"]:
        assert condition["n_trials"] == 2
        assert condition["mean_runtime_ms"] >= 0
