import pymupdf

from sender.positions import select_positions


def test_selects_only_words_at_or_above_min_length(sample_doc: pymupdf.Document) -> None:
    positions = select_positions(sample_doc, min_word_len=4)
    assert positions
    assert all(len(p.text) >= 4 for p in positions)


def test_padded_patch_regions_never_overlap(sample_doc: pymupdf.Document) -> None:
    pad, gap = 6.0, 4.0
    positions = select_positions(sample_doc, patch_pad_pts=pad, extra_gap_pts=gap)

    def padded(bbox: tuple[float, float, float, float]) -> tuple[float, float, float, float]:
        half = pad + gap / 2.0
        x0, y0, x1, y1 = bbox
        return (x0 - half, y0 - half, x1 + half, y1 + half)

    by_page: dict[int, list] = {}
    for p in positions:
        by_page.setdefault(p.page_index, []).append(p)
    for page_positions in by_page.values():
        for i, a in enumerate(page_positions):
            ax0, ay0, ax1, ay1 = padded(a.bbox)
            for b in page_positions[i + 1 :]:
                bx0, by0, bx1, by1 = padded(b.bbox)
                overlap = ax0 < bx1 and bx0 < ax1 and ay0 < by1 and by0 < ay1
                assert not overlap, f"{a.text!r} and {b.text!r} padded patches overlap"


def test_excludes_header_and_footer_margin(sample_doc: pymupdf.Document) -> None:
    page_height = sample_doc[0].rect.height
    margin_frac = 0.15
    positions = select_positions(sample_doc, margin_frac=margin_frac)
    top = margin_frac * page_height
    bottom = (1.0 - margin_frac) * page_height
    for p in positions:
        assert top <= p.bbox[1]
        assert p.bbox[3] <= bottom


def test_respects_max_per_page_cap(sample_doc: pymupdf.Document) -> None:
    positions = select_positions(sample_doc, max_per_page=3)
    by_page: dict[int, int] = {}
    for p in positions:
        by_page[p.page_index] = by_page.get(p.page_index, 0) + 1
    assert all(count <= 3 for count in by_page.values())


def test_rejects_bad_margin_frac(sample_doc: pymupdf.Document) -> None:
    import pytest

    with pytest.raises(ValueError):
        select_positions(sample_doc, margin_frac=0.6)
