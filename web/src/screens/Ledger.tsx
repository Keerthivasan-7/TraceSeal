import { useQuery } from "@tanstack/react-query";
import { X } from "lucide-react";

import { api, compactId, domainLabel } from "../api";
import { Badge, Button, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import { useConsoleStore } from "../store";
import type { LedgerRecord, RecordProof, ReplicaReport } from "../types";

const DOMAINS = [
  "traceseal/doc-register/v1",
  "traceseal/decrypt-request-ledger/v1",
  "traceseal/open-event/v1",
  "traceseal/open-denied/v1",
  "traceseal/enroll-final/v1",
  "traceseal/revoke-final/v1",
  "traceseal/investigation-opened/v1",
  "traceseal/report-issued/v1",
];

export function Ledger() {
  const { selectedProof, setSelectedProof } = useConsoleStore();
  const replicas = useQuery({
    queryKey: ["replicas"],
    queryFn: () => api<ReplicaReport>("/ledger/replicas"),
  });
  const records = useQuery({
    queryKey: ["ledger-records"],
    queryFn: async () => {
      const groups = await Promise.all(
        DOMAINS.map((domain) =>
          api<LedgerRecord[]>(
            `/ledger/records?domain=${encodeURIComponent(domain)}&limit=100`,
          ),
        ),
      );
      return groups.flat().sort((a, b) => b.height - a.height);
    },
  });
  const proof = useQuery({
    queryKey: ["record-proof", selectedProof],
    queryFn: () => api<RecordProof>(`/ledger/records/${selectedProof}/proof`),
    enabled: selectedProof !== null,
  });

  if (replicas.isLoading || records.isLoading) return <Loading />;
  if (replicas.error) return <ErrorState error={replicas.error} />;
  if (records.error) return <ErrorState error={records.error} />;

  return <div className="space-y-6 p-5 md:p-8">
    <div className="flex flex-col justify-between gap-3 md:flex-row md:items-end">
      <SectionTitle eyebrow="Tamper-evident record" title="Ledger integrity" />
      <Badge tone={replicas.data!.ok ? "good" : "bad"}>{replicas.data!.ok ? "quorum agrees" : "divergence detected"}</Badge>
    </div>
    <div className="grid gap-3 md:grid-cols-4">
      {replicas.data!.replicas.map((replica) => <Card key={replica.replica_id} className="p-4"><div className="flex items-center justify-between"><span className="font-mono text-xs text-white">{replica.replica_id}</span><span className={`h-2 w-2 rounded-full ${replica.internally_valid ? "bg-signal shadow-[0_0_8px_#64f4ac]" : "bg-danger"}`} /></div><div className="mt-5 font-mono text-2xl text-white">{replica.height}</div><div className="mt-1 font-mono text-[9px] uppercase text-slate-600">{replica.internally_valid ? "internally valid" : `first bad ${replica.first_bad_height ?? "unknown"}`}</div></Card>)}
    </div>
    <Card>
      <div className="grid grid-cols-[70px_1fr_140px_auto] gap-3 border-b border-line px-4 py-3 font-mono text-[9px] uppercase tracking-widest text-slate-600"><span>Height</span><span>Record</span><span>Submitter</span><span>Proof</span></div>
      <div className="divide-y divide-line">
        {records.data!.map((record) => <div key={record.tx_id} className="grid grid-cols-[70px_1fr_140px_auto] items-center gap-3 px-4 py-3 text-xs"><span className="font-mono text-signal">#{record.height}</span><div className="min-w-0"><div className="truncate uppercase text-slate-200">{domainLabel(record.domain)}</div><div className="mt-1 font-mono text-[9px] text-slate-600">{compactId(record.tx_id)}</div></div><span className="truncate font-mono text-[10px] text-slate-400">{record.submitter_id}</span><Button onClick={() => setSelectedProof(record.tx_id)}>Verify</Button></div>)}
        {records.data!.length === 0 && <div className="p-8 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">No matching records</div>}
      </div>
    </Card>
    {selectedProof && <div className="fixed inset-0 z-40 grid place-items-center bg-black/70 p-4 backdrop-blur-sm" onMouseDown={(event) => { if (event.currentTarget === event.target) setSelectedProof(null); }}><Card className="max-h-[85vh] w-full max-w-3xl overflow-auto shadow-2xl"><div className="sticky top-0 flex items-center justify-between border-b border-line bg-panel p-4"><div className="font-mono text-xs uppercase tracking-widest text-white">Independent record proof</div><button className="text-slate-500 hover:text-white" onClick={() => setSelectedProof(null)}><X size={18} /></button></div><div className="p-5">{proof.isLoading && <Loading label="Verifying signatures" />}{proof.error && <ErrorState error={proof.error} />}{proof.data && <><div className="mb-5 flex items-center justify-between"><Badge tone={proof.data.verified ? "good" : "bad"}>{proof.data.verified ? "cryptographically verified" : "invalid proof"}</Badge><span className="font-mono text-[10px] text-slate-500">height {proof.data.height}</span></div><dl className="grid gap-4 text-xs sm:grid-cols-[150px_1fr]">{[["Transaction", proof.data.tx_id], ["Domain", proof.data.domain], ["Submitter", proof.data.submitter_id], ["Quorum signers", proof.data.quorum_signer_ids.join(", ")], ["Verification error", proof.data.verification_error ?? "none"]].map(([key, value]) => <div key={key} className="contents"><dt className="font-mono uppercase text-slate-600">{key}</dt><dd className="break-all font-mono text-slate-300">{value}</dd></div>)}</dl><pre className="mt-6 overflow-auto border border-line bg-black/30 p-4 font-mono text-[10px] leading-5 text-slate-400">{JSON.stringify(proof.data.payload, null, 2)}</pre></>}</div></Card></div>}
  </div>;
}
