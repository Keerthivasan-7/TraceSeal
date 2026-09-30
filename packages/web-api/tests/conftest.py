from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from ca.seed import seed_all
from fastapi import FastAPI
from fastapi.testclient import TestClient
from ledger.client import LedgerClient

from helpers import build_ledger_client
from web_api.config import Settings
from web_api.deps import get_ledger_backend, get_ledger_client
from web_api.main import create_app


@pytest.fixture
def pki_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "pki"
    seed_all(directory)
    return directory


@pytest.fixture
def ledger_client(pki_dir: Path, tmp_path: Path) -> LedgerClient:
    ledger_data_dir = tmp_path / "ledger-data"
    ledger_data_dir.mkdir()
    return build_ledger_client(pki_dir, ledger_data_dir)


@pytest.fixture
def settings(pki_dir: Path, tmp_path: Path) -> Settings:
    return Settings(
        pki_dir=pki_dir,
        demo_dir=tmp_path / "demo",
        blob_dir=tmp_path / "demo" / "blob",
        keystore_dir=tmp_path / "demo" / "keystores",
    )


@pytest.fixture
def app(settings: Settings, ledger_client: LedgerClient) -> FastAPI:
    application = create_app(settings)
    application.dependency_overrides[get_ledger_backend] = lambda: ledger_client
    application.dependency_overrides[get_ledger_client] = lambda: ledger_client
    return application


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c
