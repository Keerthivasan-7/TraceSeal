# TraceSeal — Architecture

Companion to [`SPEC.md`](SPEC.md). This file holds the component diagram and
the protocol sequence diagrams referenced from Spec Section 7. Diagrams are
Mermaid; render with any Mermaid-aware viewer (GitHub, VS Code extension, or
`mmdc`).

## Component diagram

All components run as containers on a single Docker network with
`internal: true` — no egress to the public internet at runtime. Only the
`web` UI and each `recipient-agent` are reachable from a browser, and only on
localhost/LAN.

```mermaid
flowchart TB
    subgraph internal["Internal Docker network (internal: true — no egress)"]
        CA["ca<br/>offline root CA (SLH-DSA)<br/>issues ML-DSA / ML-KEM certs"]

        SENDER["sender-station<br/>rasterise · mark positions · variants<br/>package · quality gate · K_A wrap"]

        subgraph KR["keyrelease (x5, independent authorities)"]
            KR1["node 1"]
            KR2["node 2"]
            KR3["node 3"]
            KR4["node 4"]
            KR5["node 5"]
        end

        subgraph LEDGER["ledger (LedgerBackend)"]
            LL["LedgerLite<br/>4 replicas, ML-DSA 3-of-4 quorum"]
            FAB["Fabric 3 SmartBFT<br/>(M6 target)<br/>Go chaincode, ML-DSA verify"]
        end

        FORENSICS["forensics<br/>artifact intake · alignment<br/>per-position detection · Tardos accusation"]

        VERIFIER["verifier-cli<br/>standalone, offline<br/>depends only on tscore"]

        ATTACKLAB["attack-lab<br/>distortion + collusion harness"]

        PG[(PostgreSQL 16<br/>metadata)]
        BLOB[(Blob store<br/>ciphertext only)]
        VAULT[("Forensic vault<br/>originals + both variants<br/>encrypted to forensic ML-KEM key")]

        subgraph AGENTS["recipient-agent (one per officer workstation)"]
            AG_A["Officer A agent<br/>+ keystore"]
            AG_B["Officer B agent<br/>+ keystore"]
            AG_DOTS["... officers C-E"]
        end

        WEB["web<br/>React UI: Command Center, Distribute,<br/>Monitor, Investigate, Ledger, Identity, Attack Lab"]
    end

    ADMIN(["Admin / approvers"])
    OFFICER(["Officer (browser, localhost)"])
    INVESTIGATOR(["Investigator"])

    ADMIN -->|enrolment proposals/approvals| WEB
    WEB --> CA
    WEB --> SENDER
    WEB --> FORENSICS
    WEB --> LEDGER
    WEB --> ATTACKLAB

    CA -->|reads quorum state| LEDGER
    SENDER -->|DOC_REGISTER| LEDGER
    SENDER -->|Shamir shares of K_B, S_v<br/>wrapped per node| KR
    SENDER --> BLOB
    SENDER -->|originals + variants| VAULT

    OFFICER -->|unlock, view| AGENTS
    AGENTS -->|DecryptRequest signed ML-DSA| KR
    KR -->|DECRYPT_REQUEST, KEYGRANT_ISSUED| LEDGER
    KR -->|KeyGrant wrapped to recipient| AGENTS
    AGENTS -->|RECEIPT signed| LEDGER
    AGENTS -->|fetch base+variant ciphertext| BLOB

    INVESTIGATOR -->|upload artifact| WEB
    WEB --> FORENSICS
    FORENSICS -->|reveal (X, salt), verify commitments| VAULT
    FORENSICS -->|read sessions, proofs| LEDGER
    FORENSICS -->|case.tsev + signed report| VERIFIER

    LL -.->|target impl swap, same LedgerBackend interface| FAB
```

---

## Protocol sequence diagrams (Spec Section 7)

### 7.1 Enrolment (G5)

```mermaid
sequenceDiagram
    participant Officer as Officer agent
    participant Admin
    participant Ledger
    participant CA as ca (offline root CA)

    Officer->>Officer: generate ML-DSA-65 + ML-KEM-768 keypairs locally
    Officer->>Officer: build CSR, sign with ML-DSA
    Officer->>Admin: CSR + csr_hash
    Admin->>Ledger: ENROLL_PROPOSE{officer_id, unit, role, csr_hash}
    loop M-of-N approvers (default 2 of 3)
        Admin->>Ledger: ENROLL_APPROVE (ML-DSA signed)
    end
    Ledger-->>CA: quorum reached
    CA->>CA: issue ML-DSA + ML-KEM certificates
    CA->>Ledger: ENROLL_FINAL{cert_hash}
    Note over Admin,Ledger: Revocation mirrors this:<br/>REVOKE_PROPOSE + quorum -> REVOKE_FINAL.<br/>Every service checks cert status against ledger state.
```

### 7.2 Document registration and distribution

```mermaid
sequenceDiagram
    participant Sender as sender-station
    participant Ledger
    participant KR as keyrelease (x5)
    participant Vault as Forensic vault

    Sender->>Sender: rasterise pages, select mark positions
    Sender->>Sender: render variants, build package (.tspkg)
    Sender->>Sender: quality gate (SSIM >= 0.98)
    Sender->>Sender: generate K_A, K_B, S_v
    Sender->>KR: Shamir shares of K_B, S_v (wrapped to each node's ML-KEM key)
    Sender->>Sender: wrap K_A to each recipient's ML-KEM key
    Sender->>Ledger: DOC_REGISTER{doc_id, H(package), recipient_cert_hashes[],<br/>policy_hash, positions_count, tardos_params} (signed)
    Sender->>Vault: original + variant set (encrypted to forensic ML-KEM key)
    Sender->>Sender: securely erase K_A, K_B, S_v from memory
```

### 7.3 Decryption session (R1-R5, commit-before-release)

```mermaid
sequenceDiagram
    participant Agent as recipient-agent
    participant KR as keyrelease coordinator
    participant Nodes as keyrelease nodes (>=3 of 5)
    participant Ledger
    participant Vault as Forensic vault

    Agent->>Agent: build DecryptRequest{doc_id, H(package),<br/>recipient_cert_hash, session_id, nonce, agent_time}
    Agent->>Agent: sign with ML-DSA
    Agent->>KR: DecryptRequest + signature
    KR->>KR: verify signature, cert status, policy, replay
    KR->>KR: assign codeword X_session ~ Tardos(p)
    KR->>KR: commit = SHA3-256(doc_id || session_id || X || salt)
    KR->>Vault: store (X, salt) encrypted to forensic vault key
    KR->>Ledger: DECRYPT_REQUEST{request, signature, codeword_commitment}
    Ledger-->>KR: wait_final() -> quorum certificate
    KR->>Nodes: request shares
    Nodes-->>KR: >=3 shares
    KR->>KR: reconstruct K_B, S_v transiently
    KR->>KR: derive selected variant keys k_{i,X_i}
    KR->>KR: build KeyGrant{session_id, K_B, [k_{i,X_i}]}, wrap to recipient
    KR->>Ledger: KEYGRANT_ISSUED{session_id, H(grant_ciphertext)} (co-signed by nodes)
    KR->>KR: zeroise K_B, S_v, variant keys
    KR->>Agent: KeyGrant (wrapped)
    Agent->>Agent: unwrap grant, K_base = HKDF(K_A xor K_B)
    Agent->>Agent: decrypt base pages + selected variants, assemble in memory
    Agent->>Ledger: RECEIPT{session_id, H(assembled_pages)} (ML-DSA signed)
```

### 7.4 Copy binding and open events (G1)

```mermaid
sequenceDiagram
    participant Agent as recipient-agent
    participant Ledger

    Note over Agent: Package carries SealedHeader{session_id?,<br/>recipient_cert_hash, doc_id, policy_id}<br/>signed by the Key-Release quorum
    Agent->>Agent: require keystore unlock
    Agent->>Agent: verify SealedHeader signature
    alt recipient_cert_hash == local identity
        Agent->>Agent: proceed to decrypt/assemble
        Agent->>Ledger: OPEN_EVENT
    else mismatch (forwarded copy)
        Agent->>Agent: refuse to open
        Agent->>Ledger: OPEN_DENIED{presented_by, owner, doc_id}
    end
    Note over Agent,Ledger: If ledger unreachable: queue signed event locally,<br/>flush later. Never open without at least<br/>a queued signed event.
```

### 7.5 Investigation (R9-R11)

```mermaid
sequenceDiagram
    participant Investigator
    participant Ledger
    participant Forensics as forensics
    participant Vault as Forensic vault
    participant Verifier as verifier-cli

    Investigator->>Forensics: upload artifact (PDF/PNG/JPG/photo/scan)
    Forensics->>Ledger: INVESTIGATION_OPENED{case_id, H(artifact)}
    Forensics->>Forensics: normalise, detect page, identify doc,<br/>fine registration, per-position detection
    Forensics->>Forensics: run Tardos accusation over issued sessions
    loop for each suspect session
        Forensics->>Vault: reveal (X, salt)
        Forensics->>Ledger: check commitment
        Forensics->>Forensics: verify DecryptRequest signature,<br/>KeyGrant co-signatures, receipt,<br/>ledger inclusion proof, quorum certificates
    end
    Forensics->>Forensics: build evidence bundle case.tsev<br/>(CBOR+JSON, hashes, scores, proofs, certs)
    Forensics->>Forensics: sign bundle (ML-DSA) + PDF report
    Forensics->>Ledger: REPORT_ISSUED
    Investigator->>Verifier: traceseal-verify case.tsev (offline, separate machine)
    Verifier->>Verifier: re-verify every signature, commitment,<br/>inclusion proof, accusation arithmetic (tscore only)
    Verifier-->>Investigator: VALID / INVALID + diagnostics
```
