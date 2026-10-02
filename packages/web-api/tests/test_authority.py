"""The isolated enrolment authority: two-person approval where each admin
supplies *their own* passphrase, a CA custodian login, and an officer-built
CSR handed over as a file. No admin, CA, or officer private key is read from
disk anywhere in these flows."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from ledger.client import LedgerClient

from role_helpers import PASSPHRASES, build_role_app, seed_role_keystores
from web_api.config import Settings

LOGIN = "/session/login"


@pytest.fixture
def inbox(tmp_path: Path) -> Path:
    return tmp_path / "inbox"


@pytest.fixture
def isolated(settings: Settings, inbox: Path, ledger_client: LedgerClient) -> Settings:
    """Keystores sealed, then every raw private key removed from the PKI dir
    (only the public registry stays) — so any code path that still tried to
    read a raw identity file would fail loudly. Depends on `ledger_client` so
    the in-process ledger replicas have loaded their own identities first."""
    seed_role_keystores(settings)
    for path in settings.pki_dir.glob("*.json"):
        if path.name != "registry.json":
            path.unlink()
    return replace(settings, enrol_inbox_dir=inbox)


@pytest.fixture
def officer(isolated: Settings, ledger_client: LedgerClient) -> Iterator[TestClient]:
    with TestClient(build_role_app(isolated, ledger_client, "officer", "officer-a")) as c:
        assert c.post(LOGIN, json={"passphrase": PASSPHRASES["officer-a"]}).status_code == 200
        yield c


@pytest.fixture
def authority(isolated: Settings, ledger_client: LedgerClient):  # type: ignore[no-untyped-def]
    app = build_role_app(isolated, ledger_client, "authority")
    with TestClient(app) as c:
        assert c.post(LOGIN, json={"passphrase": PASSPHRASES["ca-root"]}).status_code == 200
        yield c, app


def _approve(
    client: TestClient, tx: str, admin: str, passphrase: str | None, kind: str = "approve"
):  # type: ignore[no-untyped-def]
    return client.post(
        f"/identity/proposals/{tx}/{kind}", json={"admin_id": admin, "passphrase": passphrase}
    )


def _propose(client: TestClient, passphrase: str | None = PASSPHRASES["admin-1"]):  # type: ignore[no-untyped-def]
    return client.post(
        "/identity/officers/officer-a/propose-enrol", json={"passphrase": passphrase}
    )


def test_officer_publishes_a_csr_for_the_authority(officer: TestClient, inbox: Path) -> None:
    response = officer.post("/officers/officer-a/enrolment-request")
    assert response.status_code == 200
    assert len(response.json()["csr_hash"]) == 64
    written = json.loads((inbox / "officer-a" / "csr.json").read_text())
    assert written["signer_id"] == "officer-a"


def test_officer_cannot_request_enrolment_for_someone_else(officer: TestClient) -> None:
    assert officer.post("/officers/officer-b/enrolment-request").status_code == 403


def test_full_two_person_enrolment_without_any_raw_private_key(
    officer: TestClient,
    authority,
    isolated: Settings,  # type: ignore[no-untyped-def]
) -> None:
    client, app = authority
    officer.post("/officers/officer-a/enrolment-request")

    proposal = _propose(client)
    assert proposal.status_code == 200, proposal.text
    tx = proposal.json()["proposal_tx_id"]
    assert _approve(client, tx, "admin-1", PASSPHRASES["admin-1"]).status_code == 200
    assert _approve(client, tx, "admin-2", PASSPHRASES["admin-2"]).status_code == 200
    finalized = client.post(f"/identity/proposals/{tx}/finalize")
    assert finalized.status_code == 200, finalized.text
    assert finalized.json() == {"officer_id": "officer-a", "status": "enrolled"}

    registry = json.loads((isolated.pki_dir / "registry.json").read_text())
    assert registry["officer-a"]["certificate_cbor"]
    row = next(
        r for r in client.get("/identity/registry").json() if r["identity_id"] == "officer-a"
    )
    assert row["status"] == "active"
    # Dual control: no admin key was ever left in session memory — only the custodian's.
    assert set(app.state.app_state.unlocked) == {"ca-root"}


def test_one_admin_cannot_approve_for_another(officer: TestClient, authority) -> None:  # type: ignore[no-untyped-def]
    client, _ = authority
    officer.post("/officers/officer-a/enrolment-request")
    tx = _propose(client).json()["proposal_tx_id"]
    # admin-1's passphrase presented as admin-2 (and vice versa) is just a wrong passphrase.
    assert _approve(client, tx, "admin-2", PASSPHRASES["admin-1"]).status_code == 401
    assert _approve(client, tx, "admin-1", PASSPHRASES["admin-2"]).status_code == 401


def test_approval_needs_a_passphrase_and_it_must_be_right(officer: TestClient, authority) -> None:  # type: ignore[no-untyped-def]
    client, app = authority
    officer.post("/officers/officer-a/enrolment-request")
    tx = _propose(client).json()["proposal_tx_id"]
    assert _approve(client, tx, "admin-1", None).status_code == 400
    assert _approve(client, tx, "admin-1", "").status_code == 400
    assert _approve(client, tx, "admin-1", "wrong").status_code == 401
    kinds = [e["kind"] for e in app.state.app_state.events.recent()]
    assert "admin_auth_failed" in kinds
    assert "wrong" not in str(app.state.app_state.events.recent())


def test_admin_passphrase_guessing_is_throttled_per_admin(officer: TestClient, authority) -> None:  # type: ignore[no-untyped-def]
    client, _ = authority
    officer.post("/officers/officer-a/enrolment-request")
    tx = _propose(client).json()["proposal_tx_id"]
    for _ in range(5):
        assert _approve(client, tx, "admin-1", "guess").status_code == 401
    blocked = _approve(client, tx, "admin-1", PASSPHRASES["admin-1"])
    assert blocked.status_code == 429  # even the right passphrase, during backoff
    # admin-2 is a different person: unaffected.
    assert _approve(client, tx, "admin-2", PASSPHRASES["admin-2"]).status_code == 200


def test_finalize_requires_the_custodian_and_a_quorum(
    officer: TestClient, isolated: Settings, ledger_client: LedgerClient
) -> None:
    officer.post("/officers/officer-a/enrolment-request")
    with TestClient(build_role_app(isolated, ledger_client, "authority")) as client:
        # Not logged in at all -> 401.
        assert client.post("/identity/proposals/tx/finalize").status_code == 401
        client.post(LOGIN, json={"passphrase": PASSPHRASES["ca-root"]})
        tx = _propose(client).json()["proposal_tx_id"]
        _approve(client, tx, "admin-1", PASSPHRASES["admin-1"])
        # One approval of the two required: the ceremony itself refuses.
        assert client.post(f"/identity/proposals/{tx}/finalize").status_code == 400


def test_proposal_without_an_officer_request_is_404(authority) -> None:  # type: ignore[no-untyped-def]
    client, _ = authority
    response = _propose(client)
    assert response.status_code == 404
    assert "workstation" in response.json()["detail"]


def test_revocation_is_also_two_person_and_custodian_gated(
    officer: TestClient,
    authority,  # type: ignore[no-untyped-def]
) -> None:
    client, _ = authority
    officer.post("/officers/officer-a/enrolment-request")
    tx = _propose(client).json()["proposal_tx_id"]
    for admin in ("admin-1", "admin-2"):
        _approve(client, tx, admin, PASSPHRASES[admin])
    assert client.post(f"/identity/proposals/{tx}/finalize").status_code == 200

    revoke = client.post(
        "/identity/officers/officer-a/propose-revoke",
        json={"reason": "test", "passphrase": PASSPHRASES["admin-1"]},
    )
    assert revoke.status_code == 200, revoke.text
    rtx = revoke.json()["proposal_tx_id"]
    for admin in ("admin-1", "admin-2"):
        assert _approve(client, rtx, admin, PASSPHRASES[admin], "approve-revoke").status_code == 200
    assert client.post(f"/identity/proposals/{rtx}/finalize-revoke").status_code == 200
    row = next(
        r for r in client.get("/identity/registry").json() if r["identity_id"] == "officer-a"
    )
    assert row["status"] == "revoked"


def test_registry_entry_for_other_keys_is_refused(
    officer: TestClient,
    authority,
    isolated: Settings,  # type: ignore[no-untyped-def]
) -> None:
    client, _ = authority
    officer.post("/officers/officer-a/enrolment-request")
    tx = _propose(client).json()["proposal_tx_id"]
    for admin in ("admin-1", "admin-2"):
        _approve(client, tx, admin, PASSPHRASES[admin])
    registry_path = isolated.pki_dir / "registry.json"
    registry = json.loads(registry_path.read_text())
    registry["officer-a"]["sig_public_key"] = "00" * 32  # registry disagrees with the CSR's key
    registry_path.write_text(json.dumps(registry))
    assert client.post(f"/identity/proposals/{tx}/finalize").status_code == 409
