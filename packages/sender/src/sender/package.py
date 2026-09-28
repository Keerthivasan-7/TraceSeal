"""Encrypted `.tspkg` packaging and opening (spec Sections 7.2, 8, 9).

Builds directly on M1's `DocumentVariants`: PNG-encodes each base page and
each position's two variant patches, then AES-GCM-encrypts each (spec
Section 3). Base pages are encrypted under a single `K_base`; each variant
patch under its own key derived from the variant master secret `S_v` —
exactly the manifest shape `sender.manifest`'s own docstring already
flagged M3 would add encrypted-blob fields around.

Key generation (`K_A`/`K_B`/`S_v`) and Shamir distribution live in
`sender.distribute`, not here — this module only knows how to turn a
`DocumentVariants` plus already-derived keys into ciphertext, and back.
`derive_k_base`/`derive_variant_key` live in `tscore.release_secret`, not
here, since `keyrelease` and `agent` both need to derive the exact same
keys independently.
"""

from __future__ import annotations

import io
import json
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from PIL import Image
from tscore.aead import open_ as aead_open
from tscore.aead import seal as aead_seal
from tscore.release_secret import derive_k_base, derive_variant_key, generate_document_keys

from sender.manifest import PackageManifest, Position
from sender.variants import DocumentVariants

__all__ = [
    "EncryptedPackage",
    "build_package",
    "compute_package_hash",
    "derive_k_base",
    "derive_variant_key",
    "generate_document_keys",
    "load_package",
    "open_base_page",
    "open_variant_patch",
    "save_package",
]


def _png_bytes(page: np.ndarray) -> bytes:
    buf = io.BytesIO()
    Image.fromarray(page).save(buf, format="PNG")
    return buf.getvalue()


def _png_to_array(data: bytes) -> np.ndarray:
    return np.array(Image.open(io.BytesIO(data)).convert("RGB"))


def _package_header(doc_id: str) -> bytes:
    return f"traceseal/tspkg/v1/{doc_id}".encode()


@dataclass(frozen=True)
class EncryptedPackage:
    doc_id: str
    manifest: PackageManifest
    base_pages_ciphertext: list[bytes]
    variant_ciphertexts: list[tuple[bytes, bytes]]  # (bit0, bit1), aligned with manifest.positions


def build_package(
    variants: DocumentVariants, doc_id: str, k_a: bytes, k_b: bytes, s_v: bytes
) -> EncryptedPackage:
    header = _package_header(doc_id)
    k_base = derive_k_base(k_a, k_b, doc_id)

    base_pages_ciphertext = [
        aead_seal(k_base, _png_bytes(page), header) for page in variants.base_pages
    ]

    positions: list[Position] = []
    variant_ciphertexts: list[tuple[bytes, bytes]] = []
    for idx, rp in enumerate(variants.rendered_positions):
        key0 = derive_variant_key(s_v, doc_id, idx, 0)
        key1 = derive_variant_key(s_v, doc_id, idx, 1)
        variant_ciphertexts.append(
            (
                aead_seal(key0, _png_bytes(rp.patch_bit0), header),
                aead_seal(key1, _png_bytes(rp.patch_bit1), header),
            )
        )
        positions.append(
            Position(
                index=idx,
                page_index=rp.position.page_index,
                bbox=rp.position.bbox,
                patch_pixel_shape=rp.patch_bit0.shape[:2],
            )
        )

    scale = 72.0 / variants.dpi
    page_sizes = [
        (page.shape[1] * scale, page.shape[0] * scale) for page in variants.original_pages
    ]
    manifest = PackageManifest(dpi=variants.dpi, page_sizes=page_sizes, positions=positions)

    return EncryptedPackage(
        doc_id=doc_id,
        manifest=manifest,
        base_pages_ciphertext=base_pages_ciphertext,
        variant_ciphertexts=variant_ciphertexts,
    )


def open_base_page(package: EncryptedPackage, page_index: int, k_base: bytes) -> np.ndarray:
    header = _package_header(package.doc_id)
    plaintext = aead_open(k_base, package.base_pages_ciphertext[page_index], header)
    return _png_to_array(plaintext)


def open_variant_patch(
    package: EncryptedPackage, position_index: int, bit: int, variant_key: bytes
) -> np.ndarray:
    header = _package_header(package.doc_id)
    ciphertext = package.variant_ciphertexts[position_index][bit]
    plaintext = aead_open(variant_key, ciphertext, header)
    return _png_to_array(plaintext)


def save_package(package: EncryptedPackage, path: Path) -> None:
    """Write an `EncryptedPackage` to the shared filesystem blob store
    (spec Section 5: "MinIO or a local filesystem blob store" — M3 scoping
    decision picks the latter, see docs/DECISIONS.md). Only ciphertext and
    the (non-secret) manifest are ever written here."""
    data = {
        "doc_id": package.doc_id,
        "manifest": package.manifest.model_dump(mode="json"),
        "base_pages_ciphertext": [ct.hex() for ct in package.base_pages_ciphertext],
        "variant_ciphertexts": [
            [ct0.hex(), ct1.hex()] for ct0, ct1 in package.variant_ciphertexts
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))


def compute_package_hash(path: Path) -> bytes:
    """Hash of the package file as written to the blob store — what
    `DocRegisterRecord.package_hash` commits to and what a recipient's
    `DecryptRequest.package_hash` must match, so both sides are provably
    talking about the same bytes."""
    from tscore.hashing import sha3_256

    return sha3_256(path.read_bytes())


def load_package(path: Path) -> EncryptedPackage:
    data = json.loads(path.read_text())
    manifest = PackageManifest.model_validate(data["manifest"])
    return EncryptedPackage(
        doc_id=data["doc_id"],
        manifest=manifest,
        base_pages_ciphertext=[bytes.fromhex(ct) for ct in data["base_pages_ciphertext"]],
        variant_ciphertexts=[
            (bytes.fromhex(ct0), bytes.fromhex(ct1)) for ct0, ct1 in data["variant_ciphertexts"]
        ],
    )
