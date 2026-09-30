export type JsonPayload = Record<string, unknown> | null;

export interface LedgerRecord {
  tx_id: string;
  height: number;
  domain: string;
  submitter_id: string;
  created_at: number;
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

export interface PositionOverlay {
  index: number;
  page_index: number;
  pixel_bbox: [number, number, number, number];
}

export interface QualityGatePage {
  page_index: number;
  variant_bit: number;
  ssim: number;
  max_abs_delta: number;
  passed: boolean;
}

export interface QualityGateReport {
  passed: boolean;
  ssim_threshold: number;
  max_changed_fraction: number;
  pages: QualityGatePage[];
  worst_position_changed_fraction: number;
}

export interface DistributeDraft {
  draft_id: string;
  doc_id: string;
  page_count: number;
  positions_count: number;
  positions: PositionOverlay[];
  quality_gate: QualityGateReport;
}

export interface ReleaseResult {
  doc_id: string;
  tx_id: string;
  recipients: string[];
  tardos_c0: number;
  tardos_degraded: boolean;
}

export interface OfficerRow {
  officer_id: string;
  status: "active" | "not enrolled" | "revoked";
  unlocked: boolean;
}

export interface OfficerDocument {
  doc_id: string;
  positions_count?: number;
  tardos_n?: number;
  tardos_c0?: number;
  registered_at?: number;
}

export interface OpenResult {
  session_id: string;
  receipt_tx_id: string;
  page_count: number;
}
