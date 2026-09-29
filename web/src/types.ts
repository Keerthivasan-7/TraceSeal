export type JsonPayload = Record<string, unknown> | null;

export interface LedgerRecord {
  tx_id: string;
  height: number;
  domain: string;
  submitter_id: string;
  created_at: string;
  quorum_signer_ids: string[];
  payload: JsonPayload;
}

export interface ReplicaStatus {
  replica_id: string;
  height: number;
  internally_valid: boolean;
  first_bad_height: number | null;
}

export interface SystemStatus {
  air_gap: { network: string; cloud_dependencies: string };
  counts: {
    documents: number;
    sessions: number;
    open_investigations: number;
    ledger_height: number;
  };
  replicas: ReplicaStatus[] | null;
  recent_events: LedgerRecord[];
}

export interface EgressResult { egress_blocked: boolean; detail: string }

export interface RegistryEntry {
  identity_id: string;
  kind: "admin" | "officer";
  status: "active" | "not enrolled" | "revoked";
  cert_hash?: string | null;
}

export interface Proposal extends LedgerRecord {
  kind: "enrol" | "revoke";
  approvals: number;
  quorum_threshold: number;
  admin_count: number;
}

export interface ReplicaReport {
  ok: boolean;
  consensus_height: number;
  diverged_replica_ids: string[];
  replicas: ReplicaStatus[];
}

export interface RecordProof extends LedgerRecord {
  verified: boolean;
  verification_error: string | null;
}
