import numpy as np
import pymupdf
import pytest
from tscore.errors import TamperError

from sender.package import (
    build_package,
    derive_k_base,
    derive_variant_key,
    generate_document_keys,
    open_base_page,
    open_variant_patch,
)
from sender.positions import select_positions
from sender.variants import build_document_variants


def _variants(sample_doc: pymupdf.Document, max_per_page: int = 6):
    positions = select_positions(sample_doc, max_per_page=max_per_page)
    return build_document_variants(sample_doc, positions, dpi=150)


def test_derive_k_base_is_deterministic_and_order_sensitive() -> None:
    k_a, k_b = b"\x01" * 32, b"\x02" * 32
    assert derive_k_base(k_a, k_b, "doc-1") == derive_k_base(k_a, k_b, "doc-1")
    assert derive_k_base(k_a, k_b, "doc-1") == derive_k_base(k_b, k_a, "doc-1")  # xor is symmetric
    assert derive_k_base(k_a, k_b, "doc-1") != derive_k_base(k_a, k_b, "doc-2")


def test_derive_variant_key_differs_per_position_and_bit() -> None:
    s_v = b"\x03" * 32
    k_0_0 = derive_variant_key(s_v, "doc-1", 0, 0)
    k_0_1 = derive_variant_key(s_v, "doc-1", 0, 1)
    k_1_0 = derive_variant_key(s_v, "doc-1", 1, 0)
    assert len({k_0_0, k_0_1, k_1_0}) == 3


def test_build_and_open_package_round_trip(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    k_a, k_b, s_v = generate_document_keys()
    k_base = derive_k_base(k_a, k_b, "doc-1")
    package = build_package(variants, "doc-1", k_a, k_b, s_v)

    for page_index, original in enumerate(variants.base_pages):
        recovered = open_base_page(package, page_index, k_base)
        assert np.array_equal(recovered, original)

    for idx, rp in enumerate(variants.rendered_positions):
        for bit, expected in enumerate([rp.patch_bit0, rp.patch_bit1]):
            key = derive_variant_key(s_v, "doc-1", idx, bit)
            recovered = open_variant_patch(package, idx, bit, key)
            assert np.array_equal(recovered, expected)


def test_open_base_page_rejects_wrong_k_base(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    k_a, k_b, s_v = generate_document_keys()
    package = build_package(variants, "doc-1", k_a, k_b, s_v)

    wrong_k_base = derive_k_base(b"\xff" * 32, b"\xee" * 32, "doc-1")
    with pytest.raises(TamperError):
        open_base_page(package, 0, wrong_k_base)


def test_open_base_page_rejects_wrong_doc_id_header(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    k_a, k_b, s_v = generate_document_keys()
    k_base = derive_k_base(k_a, k_b, "doc-1")
    package = build_package(variants, "doc-1", k_a, k_b, s_v)
    # Simulate presenting the package under a different doc_id — the AAD
    # header binds ciphertext to its own doc_id, so this must fail rather
    # than silently decrypting under a mismatched context.
    import dataclasses

    relabeled = dataclasses.replace(package, doc_id="doc-2")
    with pytest.raises(TamperError):
        open_base_page(relabeled, 0, k_base)


def test_open_variant_patch_rejects_wrong_key(sample_doc: pymupdf.Document) -> None:
    variants = _variants(sample_doc)
    k_a, k_b, s_v = generate_document_keys()
    package = build_package(variants, "doc-1", k_a, k_b, s_v)

    wrong_key = derive_variant_key(b"\x00" * 32, "doc-1", 0, 0)
    with pytest.raises(TamperError):
        open_variant_patch(package, 0, 0, wrong_key)


def test_save_and_load_package_round_trip(sample_doc: pymupdf.Document, tmp_path) -> None:
    from sender.package import load_package, save_package

    variants = _variants(sample_doc)
    k_a, k_b, s_v = generate_document_keys()
    k_base = derive_k_base(k_a, k_b, "doc-1")
    package = build_package(variants, "doc-1", k_a, k_b, s_v)

    path = tmp_path / "blobstore" / "doc-1" / "package.json"
    save_package(package, path)
    restored = load_package(path)

    assert restored.doc_id == package.doc_id
    assert restored.manifest == package.manifest
    assert restored.base_pages_ciphertext == package.base_pages_ciphertext
    assert restored.variant_ciphertexts == package.variant_ciphertexts

    # And the restored package still decrypts correctly.
    recovered = open_base_page(restored, 0, k_base)
    original = open_base_page(package, 0, k_base)
    assert np.array_equal(recovered, original)
