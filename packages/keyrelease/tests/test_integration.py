"""Full protocol integration tests: a real 4-replica ledger + 5-node
key-release cluster wired together in-process (no Docker). Covers the M3
acceptance criterion directly (a genuine end-to-end KeyGrant issuance, and
the "grant-before-finality is impossible" property) plus M4's server-side
recipient-identity and revocation checks and SealedHeader issuance."""

import numpy as np
import pytest

from helpers import (
    InProcessReleasePeer,
    build_decrypt_request,
    build_keyrelease_nodes,
    build_ledger_client,
    register_all_shares,
    seed_pki,
    submit_doc_register,
    submit_enroll_final,
)

pytestmark = pytest.mark.requires_liboqs

POSITIONS_COUNT = 10
DOC_ID = "doc-1"


def _setup(tmp_path):  # type: ignore[no-untyped-def]
    from tscore.hashing import sha3_256

    pki_dir = tmp_path / "pki"
    identities = seed_pki(pki_dir)
    ledger_client = build_ledger_client(pki_dir, tmp_path)
    submit_enroll_final(ledger_client, identities["ca"], "officer-a", identities["cert"])
    nodes = build_keyrelease_nodes(pki_dir, tmp_path, ledger_client)

    rng = np.random.default_rng(0)
    from tscore.tardos import sample_bias_vector

    bias_vector = sample_bias_vector(POSITIONS_COUNT, cutoff=0.1, rng=rng)
    k_b = b"\x11" * 32
    s_v = b"\x22" * 32
    register_all_shares(pki_dir, nodes, DOC_ID, k_b, s_v, bias_vector)
    submit_doc_register(ledger_client, pki_dir, DOC_ID, POSITIONS_COUNT)
    cert_hash = sha3_256(identities["cert"].to_canonical_cbor())

    return pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash


def test_full_decrypt_session_issues_a_correct_key_grant(tmp_path) -> None:
    from tscore.kem import kem_open
    from tscore.records import KeyGrant
    from tscore.release_secret import derive_variant_key

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    coordinator = nodes["keyrelease-0"]
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]

    submission = build_decrypt_request(pki_dir, DOC_ID, "S-0001", cert_hash)
    result = coordinator.handle_decrypt_request(submission, peers)

    officer = identities["officer"]
    from tscore.kdf import domain_info

    header = b"traceseal/keygrant/v1/S-0001"
    info = domain_info("keygrant", DOC_ID.encode(), b"S-0001")
    grant_cbor = kem_open(
        officer.kem_secret_key, result.wrapped_grant, header=header, info=info, alg=officer.kem_alg
    )
    grant = KeyGrant.from_canonical_cbor(grant_cbor)

    assert grant.session_id == "S-0001"
    assert grant.k_b == k_b
    assert len(grant.variant_keys) == POSITIONS_COUNT
    # We don't know the assigned codeword bits here (that's the point —
    # only the coordinator knows), but every returned key must be *some*
    # position's correctly-derived variant key for one of the two bits.
    for i, key in enumerate(grant.variant_keys):
        assert key in (
            derive_variant_key(s_v, DOC_ID, i, 0),
            derive_variant_key(s_v, DOC_ID, i, 1),
        )


def test_key_grant_response_includes_a_sealed_header_that_verifies(tmp_path) -> None:
    from ca.registry import load_registry, sig_public_key
    from tscore.records import SealedHeader
    from tscore.sig import verify as sig_verify

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    coordinator = nodes["keyrelease-0"]
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]

    submission = build_decrypt_request(pki_dir, DOC_ID, "S-header", cert_hash)
    result = coordinator.handle_decrypt_request(submission, peers)

    header = SealedHeader.from_canonical_cbor(result.sealed_header_cbor)
    assert header.doc_id == DOC_ID
    assert header.session_id == "S-header"
    assert header.recipient_cert_hash == cert_hash

    assert len(set(result.header_signer_ids)) >= 3
    registry = load_registry(pki_dir / "registry.json")
    for signer_id, signature in zip(
        result.header_signer_ids, result.header_signatures, strict=True
    ):
        alg, public_key = sig_public_key(registry, signer_id)
        assert sig_verify(alg, public_key, result.sealed_header_cbor, signature)


def test_decrypt_request_rejected_for_mismatched_cert_hash(tmp_path) -> None:
    from tscore.errors import VerificationError

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    coordinator = nodes["keyrelease-0"]
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]

    # officer-a signs the request but self-declares a DIFFERENT (bogus)
    # recipient_cert_hash than their own real, enrolled certificate.
    bogus_cert_hash = b"\xff" * 32
    submission = build_decrypt_request(pki_dir, DOC_ID, "S-mismatch", bogus_cert_hash)

    with pytest.raises(VerificationError, match="recipient_cert_hash"):
        coordinator.handle_decrypt_request(submission, peers)


def test_decrypt_request_rejected_for_revoked_certificate(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.records import DOMAIN_REVOKE_FINAL, RevokeFinalRecord, make_submission

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    coordinator = nodes["keyrelease-0"]
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]

    ca_identity = identities["ca"]
    revoke_record = RevokeFinalRecord(
        officer_id="officer-a", proposal_tx_id="test-revoke-proposal", cert_hash=cert_hash
    )
    revoke_submission = make_submission(
        ca_identity.sig_alg,
        ca_identity.sig_secret_key,
        ca_identity.identity_id,
        DOMAIN_REVOKE_FINAL,
        revoke_record,
    )
    tx_id = ledger_client.submit(revoke_submission)
    ledger_client.wait_final(tx_id, timeout_s=10.0)

    submission = build_decrypt_request(pki_dir, DOC_ID, "S-revoked", cert_hash)
    with pytest.raises(VerificationError, match="revoked"):
        coordinator.handle_decrypt_request(submission, peers)


def test_release_share_denied_without_a_finalized_decrypt_request(tmp_path) -> None:
    from keyrelease.node import ShareReleaseDenied

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    node = nodes["keyrelease-1"]

    # No DecryptRequest for this session was ever submitted to the ledger.
    with pytest.raises(ShareReleaseDenied):
        node.release_share("S-never-submitted", DOC_ID)


def test_release_share_denied_for_wrong_doc_id(tmp_path) -> None:
    from keyrelease.node import ShareReleaseDenied

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    coordinator = nodes["keyrelease-0"]
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]
    submission = build_decrypt_request(pki_dir, DOC_ID, "S-0002", cert_hash)
    coordinator.handle_decrypt_request(submission, peers)

    # The session IS final, but for a different doc_id than what was requested.
    with pytest.raises(ShareReleaseDenied):
        nodes["keyrelease-2"].release_share("S-0002", "some-other-doc")


def test_policy_rejects_exceeding_max_sessions_per_recipient(tmp_path) -> None:
    from tscore.errors import VerificationError

    from keyrelease.node import PolicyConfig

    pki_dir, ledger_client, nodes, identities, k_b, s_v, cert_hash = _setup(tmp_path)
    coordinator = nodes["keyrelease-0"]
    coordinator.policy = PolicyConfig(max_sessions_per_recipient=1)
    peers = [InProcessReleasePeer(nodes[n]) for n in nodes if n != "keyrelease-0"]

    first = build_decrypt_request(pki_dir, DOC_ID, "S-first", cert_hash)
    coordinator.handle_decrypt_request(first, peers)

    second = build_decrypt_request(pki_dir, DOC_ID, "S-second", cert_hash)
    with pytest.raises(VerificationError, match="policy"):
        coordinator.handle_decrypt_request(second, peers)
