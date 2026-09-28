import pytest

pytestmark = pytest.mark.requires_liboqs


def test_generate_identity_with_kem() -> None:
    from ca.keys import generate_identity

    identity = generate_identity("keyrelease-0", with_kem=True)
    assert identity.sig_alg == "ML-DSA-65"
    assert identity.kem_alg == "ML-KEM-768"
    assert identity.kem_public_key is not None


def test_generate_identity_without_kem_for_root() -> None:
    from ca.keys import ROOT_SIG_ALG, generate_identity

    identity = generate_identity("ca-root", sig_alg=ROOT_SIG_ALG, with_kem=False)
    assert identity.sig_alg == ROOT_SIG_ALG
    assert identity.kem_alg is None


def test_save_and_load_identity_round_trip(tmp_path) -> None:
    from ca.keys import generate_identity, load_identity, save_identity

    identity = generate_identity("officer-a", with_kem=True)
    path = tmp_path / "officer-a.json"
    save_identity(identity, path)
    restored = load_identity(path)
    assert restored == identity


def test_issue_and_verify_certificate() -> None:
    from ca.issue import issue_certificate, verify_certificate
    from ca.keys import ROOT_SIG_ALG, generate_identity

    ca_identity = generate_identity("ca-root", sig_alg=ROOT_SIG_ALG, with_kem=False)
    officer = generate_identity("officer-a", with_kem=True)

    cert, signature = issue_certificate(
        ca_identity, "officer-a", officer.sig_public_key, officer.kem_public_key or b""
    )
    assert cert.subject_id == "officer-a"
    assert cert.issuer_id == "ca-root"
    assert verify_certificate(cert, signature, ca_identity.sig_alg, ca_identity.sig_public_key)


def test_verify_certificate_rejects_wrong_ca_key() -> None:
    from ca.issue import issue_certificate, verify_certificate
    from ca.keys import ROOT_SIG_ALG, generate_identity

    ca_identity = generate_identity("ca-root", sig_alg=ROOT_SIG_ALG, with_kem=False)
    other_ca = generate_identity("ca-impostor", sig_alg=ROOT_SIG_ALG, with_kem=False)
    officer = generate_identity("officer-a", with_kem=True)

    cert, signature = issue_certificate(
        ca_identity, "officer-a", officer.sig_public_key, officer.kem_public_key or b""
    )
    assert not verify_certificate(cert, signature, other_ca.sig_alg, other_ca.sig_public_key)
