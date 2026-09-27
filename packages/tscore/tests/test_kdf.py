from tscore.kdf import derive, domain_info


def test_derive_is_reproducible() -> None:
    ikm = b"shared-secret-material"
    info = domain_info("variant", b"doc-1", b"\x00\x05", b"\x01")
    assert derive(ikm, info) == derive(ikm, info)


def test_domain_separation_different_info_different_output() -> None:
    ikm = b"shared-secret-material"
    info_bit0 = domain_info("variant", b"doc-1", b"\x00\x05", b"\x00")
    info_bit1 = domain_info("variant", b"doc-1", b"\x00\x05", b"\x01")
    assert derive(ikm, info_bit0) != derive(ikm, info_bit1)


def test_domain_info_length_prefix_prevents_boundary_ambiguity() -> None:
    # Naive concatenation would make these collide: "ab"+"c" == "a"+"bc".
    info_1 = domain_info("x", b"ab", b"c")
    info_2 = domain_info("x", b"a", b"bc")
    assert info_1 != info_2


def test_derive_respects_requested_length() -> None:
    out = derive(b"ikm", b"info", length=64)
    assert len(out) == 64


def test_salt_changes_output() -> None:
    ikm, info = b"ikm-material", b"info-string"
    assert derive(ikm, info, salt=b"salt-a") != derive(ikm, info, salt=b"salt-b")
