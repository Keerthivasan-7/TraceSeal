from __future__ import annotations

from collections.abc import Iterator

import numpy as np
import pytest
from sender.sample_doc import build_sample_document

from attacklab.scenario import Scenario, build_scenario


@pytest.fixture
def scenario() -> Iterator[Scenario]:
    # Small and low-DPI purely for test speed — a real harness run
    # (attacklab.demo_m7) uses a larger, higher-resolution scenario.
    doc = build_sample_document(page_count=1)
    rng = np.random.default_rng(1)
    result = build_scenario(doc, n_sessions=4, dpi=100, rng=rng)
    yield result
    doc.close()
