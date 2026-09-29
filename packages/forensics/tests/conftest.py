"""Shared fixtures, plus the same liboqs-presence auto-skip as
`packages/tscore/tests/conftest.py` — M5's `test_investigation.py` is this
package's first `requires_liboqs` suite (M2's forensics needed no real
crypto)."""

from __future__ import annotations

import ctypes.util
import os
import platform
from collections.abc import Iterator
from pathlib import Path

import pytest
from sender.positions import select_positions
from sender.sample_doc import build_sample_document
from sender.variants import DocumentVariants, build_document_variants


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


@pytest.fixture
def variants() -> Iterator[DocumentVariants]:
    # Not capped down like sender's own unit-test fixtures: the Tardos
    # accusation needs a realistic number of positions per page to produce
    # a confidently-above-threshold score at all (this is the same
    # position-budget-vs-eps1 tension ADR-0009's context and M1's
    # plan_parameters fallback are about) — too few positions and even a
    # correct attribution won't clear the threshold. ~50/page (this
    # document's natural density) matches what demo_m2 actually uses.
    doc = build_sample_document(page_count=2)
    positions = select_positions(doc)
    result = build_document_variants(doc, positions, dpi=150)
    yield result
    doc.close()
