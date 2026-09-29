// Package main implements the TraceSeal chaincode (spec Section 12, M6):
// a generic append-only signed-record store, mirroring LedgerLite's own
// data model (packages/ledger/src/ledger/store.py's StoredRecord) closely
// enough that tscore.evidence's LedgerRecordProof/verify_record_proof —
// written for M5 against LedgerLite — needs ZERO changes to verify a
// Fabric-backed proof too (docs/DECISIONS.md ADR-0031). This chaincode
// does the one thing LedgerLite's Python code did in ledger.node: verify
// a submitter's real ML-DSA-65 signature (via Cloudflare CIRCL, FIPS 204)
// against an on-chain identity registry before ever accepting a record —
// never trusting a caller-supplied key.
//
// record_hash uses the IDENTICAL formula as tscore.chain.compute_record_hash
// (sha3_256(prev_hash | tx_id | envelope_cbor | joined_quorum_signer_ids)),
// recomputed fresh whenever AddCosignature appends a new validator
// co-signature — safe here (unlike a literal cross-record chain) because
// every Fabric record's own prev_hash is a fixed constant, never another
// record's live record_hash (ADR-0031: Fabric's own block structure
// already gives tamper-evident ordering; LedgerLite's own prev_hash chain
// exists only because LedgerLite has nothing else to lean on, ADR-0012/
// ADR-0027).
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
	"golang.org/x/crypto/sha3"
)

// GenesisHash mirrors packages/ledger/src/ledger/store.py's GENESIS_HASH —
// every Fabric record's fixed prev_hash (ADR-0031: no real record-to-record
// chain under this backend).
const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

// Exactly tscore.sig's own two mechanism strings (ML_DSA_65 /
// SLH_DSA_SHA2_128S) — ca-root signs EnrollFinalRecord/RevokeFinalRecord
// with SLH-DSA, not ML-DSA, so both must be chaincode-verifiable for a
// genuine drop-in Fabric replacement of LedgerLite (which verifies
// whichever alg a submitter's registry entry names, generically, via
// tscore.sig.verify).
const (
	mlDSA65        = "ML-DSA-65"
	slhDSASHA2128s = "SLH_DSA_PURE_SHA2_128S"
)

// TraceSealContract implements the generic signed-record store.
type TraceSealContract struct {
	contractapi.Contract
}

// IdentityEntry is one registered public key (mirrors ca.registry's
// sig_alg/sig_public_key fields exactly, hex-encoded for JSON transport).
type IdentityEntry struct {
	SigAlg       string `json:"sig_alg"`
	SigPublicKey string `json:"sig_public_key"`
}

// Record mirrors ledger.store.StoredRecord field-for-field (hex-encoded
// bytes fields, since chaincode state and JSON transport are both text).
type Record struct {
	Height             int      `json:"height"`
	TxID               string   `json:"tx_id"`
	Domain             string   `json:"domain"`
	EnvelopeCBOR       string   `json:"envelope_cbor"`
	SubmitterID        string   `json:"submitter_id"`
	SubmitterSignature string   `json:"submitter_signature"`
	PrevHash           string   `json:"prev_hash"`
	RecordHash         string   `json:"record_hash"`
	CreatedAt          float64  `json:"created_at"`
	QuorumSignerIDs    []string `json:"quorum_signer_ids"`
	QuorumSignatures   []string `json:"quorum_signatures"`
}

func recordKey(txID string) string { return "record:" + txID }

func identityKey(identityID string) string { return "identity:" + identityID }

func computeRecordHash(prevHash, txID string, envelopeCBOR []byte, quorumSignerIDs []string) (string, error) {
	prevHashBytes, err := hex.DecodeString(prevHash)
	if err != nil {
		return "", fmt.Errorf("invalid prev_hash: %w", err)
	}
	h := sha3.New256()
	h.Write(prevHashBytes)
	h.Write([]byte("|"))
	h.Write([]byte(txID))
	h.Write([]byte("|"))
	h.Write(envelopeCBOR)
	h.Write([]byte("|"))
	h.Write([]byte(strings.Join(quorumSignerIDs, ",")))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifySignature dispatches on sigAlg exactly the way tscore.sig.verify
// does (one shared entry point, alg-generic) — never assume ML-DSA-65 just
// because that's what most identities use.
func verifySignature(sigAlg, sigPublicKeyHex string, message, signature []byte) (bool, error) {
	pubBytes, err := hex.DecodeString(sigPublicKeyHex)
	if err != nil {
		return false, fmt.Errorf("invalid public key hex: %w", err)
	}
	switch sigAlg {
	case mlDSA65:
		var pk mldsa65.PublicKey
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, fmt.Errorf("invalid ML-DSA-65 public key: %w", err)
		}
		return mldsa65.Verify(&pk, message, nil, signature), nil
	case slhDSASHA2128s:
		pk := slhdsa.PublicKey{ID: slhdsa.SHA2_128s}
		if err := pk.UnmarshalBinary(pubBytes); err != nil {
			return false, fmt.Errorf("invalid SLH-DSA-SHA2-128s public key: %w", err)
		}
		return slhdsa.Verify(&pk, slhdsa.NewMessage(message), signature, []byte{}), nil
	default:
		return false, fmt.Errorf("unsupported sig_alg %q", sigAlg)
	}
}

// RegisterIdentity seeds one identity's public key into the on-chain
// registry (mirrors ca.seed/ca.registry's bootstrap role — an
// initialization step, not an ongoing security boundary, since these are
// public keys). Re-registering the SAME identity with the SAME key is a
// no-op; re-registering with a DIFFERENT key is rejected, so a live
// registry entry can never be silently swapped out from under already-
// issued records.
func (c *TraceSealContract) RegisterIdentity(ctx contractapi.TransactionContextInterface, identityID, sigAlg, sigPublicKeyHex string) error {
	if sigAlg != mlDSA65 && sigAlg != slhDSASHA2128s {
		return fmt.Errorf(
			"unsupported sig_alg %q (only %q and %q are verified on-chain)",
			sigAlg, mlDSA65, slhDSASHA2128s,
		)
	}
	if _, err := hex.DecodeString(sigPublicKeyHex); err != nil {
		return fmt.Errorf("invalid sig_public_key hex: %w", err)
	}
	existingBytes, err := ctx.GetStub().GetState(identityKey(identityID))
	if err != nil {
		return err
	}
	if existingBytes != nil {
		var existing IdentityEntry
		if err := json.Unmarshal(existingBytes, &existing); err != nil {
			return err
		}
		if existing.SigAlg != sigAlg || existing.SigPublicKey != sigPublicKeyHex {
			return fmt.Errorf("identity %q is already registered with a different key", identityID)
		}
		return nil
	}
	entry := IdentityEntry{SigAlg: sigAlg, SigPublicKey: sigPublicKeyHex}
	entryBytes, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(identityKey(identityID), entryBytes)
}

func (c *TraceSealContract) getIdentity(ctx contractapi.TransactionContextInterface, identityID string) (*IdentityEntry, error) {
	entryBytes, err := ctx.GetStub().GetState(identityKey(identityID))
	if err != nil {
		return nil, err
	}
	if entryBytes == nil {
		return nil, fmt.Errorf("no registered identity %q", identityID)
	}
	var entry IdentityEntry
	if err := json.Unmarshal(entryBytes, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// SubmitRecord verifies submitterID's real ML-DSA-65 signature over the
// exact envelope_cbor bytes (never a reconstructed object — same "sign
// the exact bytes" discipline as tscore.schemas.verify_envelope_bytes),
// rejects a duplicate tx_id (idempotency), and appends the record with a
// fixed GenesisHash prev_hash (ADR-0031) and an empty quorum (populated
// later by AddCosignature). Domain is an explicit argument, not parsed
// from envelope_cbor — chaincode never needs a CBOR decoder; domain is a
// query-optimization index only, never used for the actual signature
// verification (which is over the real envelope_cbor bytes regardless of
// what domain string a caller claims).
func (c *TraceSealContract) SubmitRecord(ctx contractapi.TransactionContextInterface, txID, domain, envelopeCBORHex, submitterID, submitterSignatureHex string) error {
	existing, err := ctx.GetStub().GetState(recordKey(txID))
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("tx_id %q already submitted (idempotency)", txID)
	}

	envelopeCBOR, err := hex.DecodeString(envelopeCBORHex)
	if err != nil {
		return fmt.Errorf("invalid envelope_cbor hex: %w", err)
	}
	signature, err := hex.DecodeString(submitterSignatureHex)
	if err != nil {
		return fmt.Errorf("invalid submitter_signature hex: %w", err)
	}

	identity, err := c.getIdentity(ctx, submitterID)
	if err != nil {
		return err
	}
	ok, err := verifySignature(identity.SigAlg, identity.SigPublicKey, envelopeCBOR, signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("submitter signature from %q does not verify", submitterID)
	}

	recordHash, err := computeRecordHash(GenesisHash, txID, envelopeCBOR, nil)
	if err != nil {
		return err
	}

	height, err := c.nextHeight(ctx)
	if err != nil {
		return err
	}

	timestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return err
	}

	record := Record{
		Height:             height,
		TxID:               txID,
		Domain:             domain,
		EnvelopeCBOR:       envelopeCBORHex,
		SubmitterID:        submitterID,
		SubmitterSignature: submitterSignatureHex,
		PrevHash:           GenesisHash,
		RecordHash:         recordHash,
		CreatedAt:          float64(timestamp.Seconds) + float64(timestamp.Nanos)/1e9,
		QuorumSignerIDs:    []string{},
		QuorumSignatures:   []string{},
	}
	recordBytes, err := json.Marshal(record)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(recordKey(txID), recordBytes); err != nil {
		return err
	}

	compositeKey, err := ctx.GetStub().CreateCompositeKey("domain~txid", []string{domain, txID})
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(compositeKey, []byte{0x00})
}

func (c *TraceSealContract) nextHeight(ctx contractapi.TransactionContextInterface) (int, error) {
	const key = "chain_height"
	raw, err := ctx.GetStub().GetState(key)
	if err != nil {
		return 0, err
	}
	next := 0
	if raw != nil {
		current, err := strconv.Atoi(string(raw))
		if err != nil {
			return 0, err
		}
		next = current + 1
	}
	if err := ctx.GetStub().PutState(key, []byte(strconv.Itoa(next))); err != nil {
		return 0, err
	}
	return next, nil
}

// AddCosignature appends orgValidatorID's ML-DSA-65 co-signature over the
// record's OWN envelope_cbor bytes (spec Section 12: "validator
// organisations additionally co-sign block hashes with ML-DSA") — the
// same message every quorum signer in LedgerLite already signs
// (tscore.evidence.verify_record_proof verifies every quorum signature
// against proof.envelope_cbor, not a hash of it), so the resulting
// LedgerRecordProof is byte-for-byte compatible with M5's existing
// verification code. Rejects a duplicate signer (idempotency) and cross-
// checks the calling Fabric client's own MSPID against orgValidatorID's
// expected org, in addition to the real ML-DSA verification.
func (c *TraceSealContract) AddCosignature(ctx contractapi.TransactionContextInterface, txID, orgValidatorID, signatureHex string) error {
	recordBytes, err := ctx.GetStub().GetState(recordKey(txID))
	if err != nil {
		return err
	}
	if recordBytes == nil {
		return fmt.Errorf("no such record %q", txID)
	}
	var record Record
	if err := json.Unmarshal(recordBytes, &record); err != nil {
		return err
	}
	for _, existing := range record.QuorumSignerIDs {
		if existing == orgValidatorID {
			return fmt.Errorf("org %q has already co-signed record %q", orgValidatorID, txID)
		}
	}

	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	envelopeCBOR, err := hex.DecodeString(record.EnvelopeCBOR)
	if err != nil {
		return err
	}
	identity, err := c.getIdentity(ctx, orgValidatorID)
	if err != nil {
		return err
	}
	ok, err := verifySignature(identity.SigAlg, identity.SigPublicKey, envelopeCBOR, signature)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("co-signature from %q does not verify", orgValidatorID)
	}

	record.QuorumSignerIDs = append(record.QuorumSignerIDs, orgValidatorID)
	record.QuorumSignatures = append(record.QuorumSignatures, signatureHex)
	recordHash, err := computeRecordHash(record.PrevHash, record.TxID, envelopeCBOR, record.QuorumSignerIDs)
	if err != nil {
		return err
	}
	record.RecordHash = recordHash

	updatedBytes, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(recordKey(txID), updatedBytes)
}

// GetRecord returns the full record (including submitter_signature) as
// JSON — chaincode state IS the authoritative source, so there is no
// operational-vs-evidentiary redaction split here the way ADR-0023
// required for LedgerLite's own two routes; that split, if wanted, is the
// Go gateway's job at the HTTP-facing layer, not chaincode's.
func (c *TraceSealContract) GetRecord(ctx contractapi.TransactionContextInterface, txID string) (string, error) {
	recordBytes, err := ctx.GetStub().GetState(recordKey(txID))
	if err != nil {
		return "", err
	}
	if recordBytes == nil {
		return "", fmt.Errorf("no such record %q", txID)
	}
	return string(recordBytes), nil
}

// QueryRecordsByDomain returns every record whose Domain field (an
// explicit SubmitRecord argument, not independently verified against
// envelope_cbor's own embedded domain — see SubmitRecord's docstring)
// matches, as a JSON array, via a composite-key range scan (no CouchDB
// needed for this — ADR-0031).
func (c *TraceSealContract) QueryRecordsByDomain(ctx contractapi.TransactionContextInterface, domain string) (string, error) {
	iterator, err := ctx.GetStub().GetStateByPartialCompositeKey("domain~txid", []string{domain})
	if err != nil {
		return "", err
	}
	defer iterator.Close()

	records := []Record{}
	for iterator.HasNext() {
		kv, err := iterator.Next()
		if err != nil {
			return "", err
		}
		_, parts, err := ctx.GetStub().SplitCompositeKey(kv.Key)
		if err != nil {
			return "", err
		}
		if len(parts) != 2 {
			return "", errors.New("malformed domain~txid composite key")
		}
		txID := parts[1]
		recordBytes, err := ctx.GetStub().GetState(recordKey(txID))
		if err != nil {
			return "", err
		}
		if recordBytes == nil {
			continue
		}
		var record Record
		if err := json.Unmarshal(recordBytes, &record); err != nil {
			return "", err
		}
		records = append(records, record)
	}
	out, err := json.Marshal(records)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
