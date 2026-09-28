from collections.abc import Iterator

import pymupdf
import pytest

_BODY_TEXT = (
    "This synthetic classified operation plan document contains several distinct "
    "words for testing purposes today. Another paragraph provides additional "
    "vocabulary spread evenly across multiple lines within this generated page. "
    "Further sentences ensure sufficient candidate positions remain available "
    "after applying spacing and margin filters. TraceSeal never distributes real "
    "documents in tests or demos, only generated placeholder content like this."
)


@pytest.fixture
def sample_doc() -> Iterator[pymupdf.Document]:
    doc = pymupdf.open()
    for _ in range(2):
        page = doc.new_page(width=612, height=792)
        # A bounded textbox (not raw insert_text) so lines wrap within the
        # page instead of running off the right edge.
        page.insert_textbox(pymupdf.Rect(72, 150, 540, 700), _BODY_TEXT, fontsize=11)
    yield doc
    doc.close()
