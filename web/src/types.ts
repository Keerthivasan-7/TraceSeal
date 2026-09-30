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

export interface Suspect {
  session_id: string;
  officer_id: string;
  score: number;
  accused: boolean;
}

export interface InvestigationOpenResult {
  case_id: string;
  doc_id: string;
  page_index: number;
  threshold: number;
  n_observed: number;
  n_total_positions: number;
  n_erasures: number;
  summary: string;
  suspects: Suspect[];
}

export interface ObservationOverlay {
  position_index: number;
  pixel_bbox: [number, number, number, number];
  observed_bit: number | null;
  confidence: number;
  is_erasure: boolean;
}

export interface IssueReportResult {
  case_id: string;
  report_tx_id: string;
  accused_sessions: string[];
}

export interface TimelineEvent {
  stage: "request" | "keygrant" | "receipt" | "open";
  tx_id: string;
  height: number;
  created_at: number;
}

export interface SessionTimeline {
  session_id: string;
  officer_id: string;
  events: TimelineEvent[];
}

export interface OpenDeniedEvent {
  tx_id: string;
  height: number;
  created_at: number;
  presented_by: string;
  owner: string;
}

export interface DocumentTimeline {
  doc_id: string;
  sessions: SessionTimeline[];
  open_denied: OpenDeniedEvent[];
}

export interface MonitorDocument {
  doc_id: string;
  tx_id: string;
  registered_at: number;
}

export interface AttackLabResultRow {
  [column: string]: string;
}

export interface AttackLabResults {
  markdown: string;
  synthetic: AttackLabResultRow[];
  collusion: AttackLabResultRow[];
}

export interface QuickRunCondition {
  condition: string;
  n_trials: number;
  mean_bit_error_rate: number | null;
  mean_erasure_rate: number | null;
  top1_accuracy: number;
  total_innocent_accusations: number;
  innocent_accusation_rate: number | null;
  mean_runtime_ms: number;
  n_registration_failures: number;
}

export interface QuickRunResult {
  seed: number;
  n_sessions: number;
  n_trials: number;
  eps1: number;
  n_positions: number;
  conditions: QuickRunCondition[];
}
