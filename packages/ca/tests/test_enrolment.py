"""Real enrolment/revocation ceremony against a 4-replica LedgerLite
cluster wired in-process (no Docker). Covers the M4 acceptance path: a
genuine 2-of-3 admin quorum issuing a certificate, and every negative case
the ceremony is supposed to reject."""

import pytest

from helpers import build_ledger_client, seed_enrolment_pki

pytestmark = pytest.mark.requires_liboqs

ADMIN_IDS = {"admin-1", "admin-2", "admin-3"}


def _setup(tmp_path):  # type: ignore[no-untyped-def]
    pki_dir = tmp_path / "pki"
    identities = seed_enrolment_pki(pki_dir)
    ledger_client = build_ledger_client(pki_dir, tmp_path)
    return identities, ledger_client


def test_full_enrolment_ceremony_issues_a_valid_certificate(tmp_path) -> None:
    from tscore.records import DOMAIN_ENROLL_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        propose_enrolment,
        submit_approval,
    )
    from ca.issue import verify_certificate

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]
    ca_identity = identities["ca"]

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins["admin-1"], officer.identity_id, "1st Unit", "analyst", csr
    )
    submit_approval(
        ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )
    submit_approval(
        ledger_client, admins["admin-2"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )

    cert, signature = finalize_enrolment(
        ledger_client, ca_identity, officer.identity_id, proposal_tx_id, csr, ADMIN_IDS
    )

    assert cert.subject_id == officer.identity_id
    assert cert.ml_dsa_public_key == officer.sig_public_key
    assert verify_certificate(cert, signature, ca_identity.sig_alg, ca_identity.sig_public_key)


def test_finalize_rejects_below_quorum(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.records import DOMAIN_ENROLL_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        propose_enrolment,
        submit_approval,
    )

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins["admin-1"], officer.identity_id, "1st Unit", "analyst", csr
    )
    submit_approval(
        ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )

    with pytest.raises(VerificationError, match="approvals"):
        finalize_enrolment(
            ledger_client, identities["ca"], officer.identity_id, proposal_tx_id, csr, ADMIN_IDS
        )


def test_finalize_ignores_approval_from_a_non_admin_identity(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.records import DOMAIN_ENROLL_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        propose_enrolment,
        submit_approval,
    )

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins["admin-1"], officer.identity_id, "1st Unit", "analyst", csr
    )
    submit_approval(
        ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )
    # A technically-valid, ledger-finalized approval from a non-admin
    # identity (the officer approving their own enrolment) must not count.
    submit_approval(ledger_client, officer, proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE)

    with pytest.raises(VerificationError, match="approvals"):
        finalize_enrolment(
            ledger_client, identities["ca"], officer.identity_id, proposal_tx_id, csr, ADMIN_IDS
        )


def test_finalize_ignores_duplicate_approvals_from_the_same_admin(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.records import DOMAIN_ENROLL_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        propose_enrolment,
        submit_approval,
    )

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins["admin-1"], officer.identity_id, "1st Unit", "analyst", csr
    )
    # Same admin approves twice — should still only count once.
    submit_approval(
        ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )
    submit_approval(
        ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )

    with pytest.raises(VerificationError, match="approvals"):
        finalize_enrolment(
            ledger_client, identities["ca"], officer.identity_id, proposal_tx_id, csr, ADMIN_IDS
        )


def test_propose_rejects_csr_with_mismatched_subject_id(tmp_path) -> None:
    from tscore.errors import VerificationError

    from ca.enrolment import build_and_self_sign_csr, propose_enrolment

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]

    csr = build_and_self_sign_csr(officer)
    with pytest.raises(VerificationError, match="subject_id"):
        propose_enrolment(
            ledger_client, admins["admin-1"], "officer-b", "1st Unit", "analyst", csr
        )


def test_finalize_rejects_a_swapped_csr(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.records import DOMAIN_ENROLL_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        propose_enrolment,
        submit_approval,
    )
    from ca.keys import generate_identity

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins["admin-1"], officer.identity_id, "1st Unit", "analyst", csr
    )
    submit_approval(
        ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )
    submit_approval(
        ledger_client, admins["admin-2"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE
    )

    # A different keypair claiming the SAME officer_id, self-signed — its
    # own CSR self-signature verifies fine, but its hash won't match the
    # one already committed in the proposal.
    impostor = generate_identity(officer.identity_id, with_kem=True)
    impostor_csr = build_and_self_sign_csr(impostor)

    with pytest.raises(VerificationError, match="CSR"):
        finalize_enrolment(
            ledger_client,
            identities["ca"],
            officer.identity_id,
            proposal_tx_id,
            impostor_csr,
            ADMIN_IDS,
        )


def test_revocation_mirror_requires_quorum_and_admin_filtering(tmp_path) -> None:
    from tscore.errors import VerificationError
    from tscore.hashing import sha3_256
    from tscore.records import DOMAIN_ENROLL_APPROVE, DOMAIN_REVOKE_APPROVE

    from ca.enrolment import (
        build_and_self_sign_csr,
        finalize_enrolment,
        finalize_revocation,
        propose_enrolment,
        propose_revocation,
        submit_approval,
    )

    identities, ledger_client = _setup(tmp_path)
    officer = identities["officer"]
    admins = identities["admins"]
    ca_identity = identities["ca"]

    csr = build_and_self_sign_csr(officer)
    proposal_tx_id = propose_enrolment(
        ledger_client, admins["admin-1"], officer.identity_id, "1st Unit", "analyst", csr
    )
    submit_approval(ledger_client, admins["admin-1"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE)
    submit_approval(ledger_client, admins["admin-2"], proposal_tx_id, domain=DOMAIN_ENROLL_APPROVE)
    cert, _ = finalize_enrolment(
        ledger_client, ca_identity, officer.identity_id, proposal_tx_id, csr, ADMIN_IDS
    )
    cert_hash = sha3_256(cert.to_canonical_cbor())

    revoke_tx_id = propose_revocation(
        ledger_client, admins["admin-1"], officer.identity_id, cert_hash, "lost device"
    )
    submit_approval(ledger_client, admins["admin-1"], revoke_tx_id, domain=DOMAIN_REVOKE_APPROVE)

    with pytest.raises(VerificationError, match="approvals"):
        finalize_revocation(
            ledger_client, ca_identity, officer.identity_id, revoke_tx_id, ADMIN_IDS
        )

    submit_approval(ledger_client, admins["admin-3"], revoke_tx_id, domain=DOMAIN_REVOKE_APPROVE)
    finalize_revocation(ledger_client, ca_identity, officer.identity_id, revoke_tx_id, ADMIN_IDS)

    from tscore.records import DOMAIN_REVOKE_FINAL, RevokeFinalRecord
    from tscore.schemas import SignedEnvelope

    records = ledger_client.query(domain=DOMAIN_REVOKE_FINAL)
    assert len(records) == 1
    envelope = SignedEnvelope.from_canonical_cbor(bytes.fromhex(records[0].envelope_cbor))
    final = RevokeFinalRecord.from_canonical_cbor(envelope.payload)
    assert final.officer_id == officer.identity_id
    assert final.cert_hash == cert_hash
