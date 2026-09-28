import numpy as np
import pytest
from PIL import Image
from sender.assemble import assemble_document
from sender.variants import DocumentVariants

from forensics.align import RegistrationError, register


def _reference_page(variants: DocumentVariants, page_index: int = 0) -> np.ndarray:
    n = len(variants.rendered_positions)
    pages = assemble_document(variants, np.zeros(n, dtype=np.int8))
    return pages[page_index]


def test_register_same_size_is_near_identity(variants: DocumentVariants) -> None:
    reference = _reference_page(variants)
    result = register(reference, reference)
    assert result.n_inliers > 20
    assert result.inlier_ratio > 0.5
    diff = np.abs(result.warped.astype(int) - reference.astype(int))
    assert diff.mean() < 1.0


def test_register_recovers_rescaled_artifact(variants: DocumentVariants) -> None:
    reference = _reference_page(variants)
    img = Image.fromarray(reference)
    scale = 0.6
    scaled = img.resize((round(img.width * scale), round(img.height * scale)), Image.LANCZOS)
    artifact = np.array(scaled)

    result = register(artifact, reference)
    assert result.n_inliers >= 10
    recovered_scale = (result.homography[0, 0] + result.homography[1, 1]) / 2.0
    assert recovered_scale == pytest.approx(1.0 / scale, rel=0.05)
    diff = np.abs(result.warped.astype(int) - reference.astype(int))
    assert diff.mean() < 15.0  # resampling noise from the round trip, not misalignment


def test_register_raises_on_blank_images() -> None:
    blank_a = np.full((200, 200, 3), 255, dtype=np.uint8)
    blank_b = np.full((200, 200, 3), 255, dtype=np.uint8)
    with pytest.raises(RegistrationError):
        register(blank_a, blank_b)
