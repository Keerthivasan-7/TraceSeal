from collections.abc import Iterator

import pytest
from sender.positions import select_positions
from sender.sample_doc import build_sample_document
from sender.variants import DocumentVariants, build_document_variants


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
