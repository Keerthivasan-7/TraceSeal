import numpy as np
from PIL import Image
from sender.assemble import assemble_document
from sender.variants import DocumentVariants
from tscore.tardos import assign_codeword, sample_bias_vector

from forensics.pipeline import investigate


def test_investigate_attributes_correct_session_from_rescaled_screenshot(
    variants: DocumentVariants,
) -> None:
    n = len(variants.rendered_positions)
    rng = np.random.default_rng(7)
    bias = sample_bias_vector(n, cutoff=0.1, rng=rng)
    session_ids = [f"S-{i + 1:04d}" for i in range(5)]
    codewords = {sid: assign_codeword(bias, rng) for sid in session_ids}

    leaking_session = "S-0003"
    page_index = 0
    pages = assemble_document(variants, codewords[leaking_session])
    img = Image.fromarray(pages[page_index])
    scaled = img.resize((round(img.width * 0.6), round(img.height * 0.6)), Image.LANCZOS)
    artifact = np.array(scaled)

    report = investigate(artifact, page_index, variants, codewords, bias, eps1=1e-4)

    assert leaking_session in report.accused_sessions
    assert report.top_session == leaking_session
    assert [sid for sid in report.accused_sessions if sid != leaking_session] == []


def test_report_summary_has_no_guilt_or_intent_language(variants: DocumentVariants) -> None:
    n = len(variants.rendered_positions)
    rng = np.random.default_rng(3)
    bias = sample_bias_vector(n, cutoff=0.1, rng=rng)
    session_ids = [f"S-{i + 1:04d}" for i in range(3)]
    codewords = {sid: assign_codeword(bias, rng) for sid in session_ids}

    pages = assemble_document(variants, codewords["S-0001"])
    report = investigate(pages[0], 0, variants, codewords, bias, eps1=1e-4)

    summary = report.summary().lower()
    # The honest disclaimer legitimately contains the words "guilt" and
    # "intent" (as a negation: "not a legal determination of guilt or
    # intent") — what must never appear is an affirmative claim of either.
    for forbidden in ("is guilty", "proves guilt", "proves intent", "certainly"):
        assert forbidden not in summary
    assert "not a legal determination of guilt or intent" in summary
    assert "statistical" in summary
