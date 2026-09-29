"""Same liboqs-presence auto-skip as packages/tscore/tests/conftest.py."""

from __future__ import annotations

import ctypes.util
import os
import platform
from pathlib import Path

import pytest


def _liboqs_shared_lib_present() -> bool:
    install_dir = Path(os.environ.get("OQS_INSTALL_PATH", str(Path.home() / "_oqs")))
    system = platform.system()
    if system == "Darwin":
        candidates = [install_dir / "lib" / "liboqs.dylib"]
    elif system == "Windows":
        bin_dir = install_dir / "bin"
        candidates = [bin_dir / "oqs.dll", bin_dir / "liboqs.dll"]
    else:
        candidates = [install_dir / "lib" / "liboqs.so", install_dir / "lib64" / "liboqs.so"]
    if any(candidate.exists() for candidate in candidates):
        return True
    return ctypes.util.find_library("oqs") is not None


_LIBOQS_AVAILABLE = _liboqs_shared_lib_present()


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if _LIBOQS_AVAILABLE:
        return
    skip_liboqs = pytest.mark.skip(
        reason="liboqs shared library not found — run `make test` in Docker"
    )
    for item in items:
        if "requires_liboqs" in item.keywords:
            item.add_marker(skip_liboqs)
