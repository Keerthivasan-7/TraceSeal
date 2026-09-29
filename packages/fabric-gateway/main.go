// fabric-gateway is a thin REST facade in front of the real
// `hyperledger/fabric-gateway` Go SDK (spec Section 12, M6) — there is no
// official Fabric Gateway SDK for Python, so this is the one place Go is
// unavoidable on the client-reaching side. It exposes the SAME HTTP shape
// `packages/ledger/src/ledger/service.py` already does
// (`POST /submit`, `GET /records/{tx_id}`, `GET /records/{tx_id}/proof`),
// so `ledger.fabric_client.FabricLedgerClient` can be nearly identical to
// `ledger.client.LedgerClient`, just pointed at this service instead.
//
// This program is NOT a Fabric node — it holds one client identity (an
// admin user from one peer org) and talks to the already-running peers/
// orderers over the real Fabric Gateway gRPC protocol. All the actual
// cryptographic verification (ML-DSA/SLH-DSA submitter signatures,
// ML-DSA validator co-signatures) happens inside the chaincode
// (chaincode/traceseal), never here — this service is a dumb relay.
package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	names, err := dir.Readdirnames(1)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(path.Join(dirPath, names[0]))
}

func newGrpcConnection(peerEndpoint, gatewayPeer, tlsCACertPath string) (*grpc.ClientConn, error) {
	pem, err := os.ReadFile(tlsCACertPath)
	if err != nil {
		return nil, fmt.Errorf("reading TLS CA cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(pool, gatewayPeer)
	return grpc.NewClient(peerEndpoint, grpc.WithTransportCredentials(creds))
}

func newIdentity(mspID, certDir string) (*identity.X509Identity, error) {
	pem, err := readFirstFile(certDir)
	if err != nil {
		return nil, fmt.Errorf("reading client cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, err
	}
	return identity.NewX509Identity(mspID, cert)
}

func newSign(keyDir string) (identity.Sign, error) {
	pem, err := readFirstFile(keyDir)
	if err != nil {
		return nil, fmt.Errorf("reading client key: %w", err)
	}
	key, err := identity.PrivateKeyFromPEM(pem)
	if err != nil {
		return nil, err
	}
	return identity.NewPrivateKeySign(key)
}

type server struct {
	contract *client.Contract
}

func randomTxID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func writeJSONError(w http.ResponseWriter, status int, err error) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"detail": err.Error()})
}

type submitRequest struct {
	Domain       string `json:"domain"`
	EnvelopeCBOR string `json:"envelope_cbor"`
	SignerID     string `json:"signer_id"`
	Signature    string `json:"signature"`
}

func (s *server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req submitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	txID, err := randomTxID()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	_, err = s.contract.SubmitTransaction(
		"SubmitRecord", txID, req.Domain, req.EnvelopeCBOR, req.SignerID, req.Signature,
	)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"tx_id": txID})
}

type registerIdentityRequest struct {
	IdentityID   string `json:"identity_id"`
	SigAlg       string `json:"sig_alg"`
	SigPublicKey string `json:"sig_public_key"`
}

func (s *server) handleRegisterIdentity(w http.ResponseWriter, r *http.Request) {
	var req registerIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	_, err := s.contract.SubmitTransaction("RegisterIdentity", req.IdentityID, req.SigAlg, req.SigPublicKey)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

type addCosignatureRequest struct {
	TxID           string `json:"tx_id"`
	OrgValidatorID string `json:"org_validator_id"`
	Signature      string `json:"signature"`
}

func (s *server) handleAddCosignature(w http.ResponseWriter, r *http.Request) {
	var req addCosignatureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	_, err := s.contract.SubmitTransaction("AddCosignature", req.TxID, req.OrgValidatorID, req.Signature)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// redact drops submitter_signature — mirrors ADR-0023's operational-vs-
// evidentiary route split, now enforced here instead of in chaincode (see
// chaincode/traceseal/contract.go's GetRecord docstring).
func redact(record map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range record {
		if k == "submitter_signature" {
			continue
		}
		out[k] = v
	}
	return out
}

func (s *server) getRecord(txID string) (map[string]any, error) {
	result, err := s.contract.EvaluateTransaction("GetRecord", txID)
	if err != nil {
		return nil, err
	}
	var record map[string]any
	if err := json.Unmarshal(result, &record); err != nil {
		return nil, err
	}
	return record, nil
}

func (s *server) handleGetRecord(w http.ResponseWriter, r *http.Request, txID string) {
	record, err := s.getRecord(txID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err)
		return
	}
	_ = json.NewEncoder(w).Encode(redact(record))
}

func (s *server) handleGetRecordProof(w http.ResponseWriter, r *http.Request, txID string) {
	record, err := s.getRecord(txID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, err)
		return
	}
	_ = json.NewEncoder(w).Encode(record)
}

func (s *server) handleQueryByDomain(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeJSONError(w, http.StatusBadRequest, fmt.Errorf("domain query parameter is required"))
		return
	}
	result, err := s.contract.EvaluateTransaction("QueryRecordsByDomain", domain)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	var records []map[string]any
	if err := json.Unmarshal(result, &records); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err)
		return
	}
	redacted := make([]map[string]any, len(records))
	for i, record := range records {
		redacted[i] = redact(record)
	}
	_ = json.NewEncoder(w).Encode(redacted)
}

func main() {
	mspID := envOr("GATEWAY_MSPID", "Org1MSP")
	certDir := envOr("GATEWAY_CERT_DIR", "/crypto/user/msp/signcerts")
	keyDir := envOr("GATEWAY_KEY_DIR", "/crypto/user/msp/keystore")
	tlsCACertPath := envOr("GATEWAY_TLS_CA_CERT", "/crypto/peer-tls/ca.crt")
	peerEndpoint := envOr("GATEWAY_PEER_ENDPOINT", "peer0.org1.traceseal.local:7051")
	gatewayPeer := envOr("GATEWAY_PEER_NAME", "peer0.org1.traceseal.local")
	channelName := envOr("GATEWAY_CHANNEL", "tschannel")
	chaincodeName := envOr("GATEWAY_CHAINCODE", "traceseal")
	listenAddr := envOr("GATEWAY_LISTEN_ADDR", "0.0.0.0:8000")

	conn, err := newGrpcConnection(peerEndpoint, gatewayPeer, tlsCACertPath)
	if err != nil {
		panic(fmt.Errorf("grpc connection: %w", err))
	}
	defer conn.Close()

	id, err := newIdentity(mspID, certDir)
	if err != nil {
		panic(fmt.Errorf("identity: %w", err))
	}
	sign, err := newSign(keyDir)
	if err != nil {
		panic(fmt.Errorf("sign: %w", err))
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(conn),
		client.WithEvaluateTimeout(10*time.Second),
		client.WithEndorseTimeout(30*time.Second),
		client.WithSubmitTimeout(15*time.Second),
		client.WithCommitStatusTimeout(30*time.Second),
	)
	if err != nil {
		panic(fmt.Errorf("gateway connect: %w", err))
	}
	defer gw.Close()

	network := gw.GetNetwork(channelName)
	contract := network.GetContract(chaincodeName)
	srv := &server{contract: contract}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /submit", srv.handleSubmit)
	mux.HandleFunc("POST /register-identity", srv.handleRegisterIdentity)
	mux.HandleFunc("POST /add-cosignature", srv.handleAddCosignature)
	mux.HandleFunc("GET /records/{tx_id}", func(w http.ResponseWriter, r *http.Request) {
		srv.handleGetRecord(w, r, r.PathValue("tx_id"))
	})
	mux.HandleFunc("GET /records/{tx_id}/proof", func(w http.ResponseWriter, r *http.Request) {
		srv.handleGetRecordProof(w, r, r.PathValue("tx_id"))
	})
	mux.HandleFunc("GET /chain", srv.handleQueryByDomain)

	fmt.Printf("fabric-gateway listening on %s (channel=%s chaincode=%s)\n", listenAddr, channelName, chaincodeName)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		panic(err)
	}
}
