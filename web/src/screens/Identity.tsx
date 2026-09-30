import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, compactId, payloadString } from "../api";
import { Badge, Button, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import type { Proposal, RegistryEntry } from "../types";

const ADMINS = ["admin-1", "admin-2", "admin-3"];

export function Identity() {
  const queryClient = useQueryClient();
  const registry = useQuery({
    queryKey: ["registry"],
    queryFn: () => api<RegistryEntry[]>("/identity/registry"),
  });
  const proposals = useQuery({
    queryKey: ["proposals"],
    queryFn: () => api<Proposal[]>("/identity/proposals"),
  });
  const action = useMutation({
    mutationFn: ({ path, body }: { path: string; body?: object }) =>
      api(path, { method: "POST", body: JSON.stringify(body ?? {}) }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ["registry"] }),
        queryClient.invalidateQueries({ queryKey: ["proposals"] }),
      ]);
    },
  });

  if (registry.isLoading || proposals.isLoading) return <Loading />;
  if (registry.error) return <ErrorState error={registry.error} />;
  if (proposals.error) return <ErrorState error={proposals.error} />;

  return <div className="space-y-6 p-5 md:p-8">
    <SectionTitle eyebrow="Post-quantum registry" title="Identity & quorum enrolment" />
    {action.error && <ErrorState error={action.error} />}
    <div className="grid gap-6 xl:grid-cols-[1fr_1.1fr]">
      <Card>
        <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">Identity registry</div>
        <div className="divide-y divide-line">
          {registry.data!.map((entry) => <div key={entry.identity_id} className="flex flex-wrap items-center justify-between gap-3 p-4"><div><div className="font-mono text-xs text-white">{entry.identity_id}</div><div className="mt-1 font-mono text-[9px] uppercase text-muted">{entry.kind}{entry.cert_hash ? ` // ${compactId(entry.cert_hash, 7)}` : ""}</div></div><div className="flex items-center gap-2"><Badge tone={entry.status === "active" ? "good" : entry.status === "revoked" ? "bad" : "warn"}>{entry.status}</Badge>{entry.kind === "officer" && entry.status === "not enrolled" && <Button onClick={() => action.mutate({ path: `/identity/officers/${entry.identity_id}/propose-enrol` })}>Propose</Button>}{entry.kind === "officer" && entry.status === "active" && <Button className="border-danger/30 bg-danger/5 text-danger hover:border-danger" onClick={() => action.mutate({ path: `/identity/officers/${entry.identity_id}/propose-revoke`, body: { reason: "operator-requested demo revocation" } })}>Revoke</Button>}</div></div>)}
        </div>
      </Card>
      <Card>
        <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">Pending proposals</div>
        <div className="divide-y divide-line">
          {proposals.data!.map((proposal) => {
            const officer = payloadString(proposal.payload, "officer_id") ?? "unknown";
            const complete = proposal.approvals >= proposal.quorum_threshold;
            const approvalPath = proposal.kind === "enrol" ? "approve" : "approve-revoke";
            const finalPath = proposal.kind === "enrol" ? "finalize" : "finalize-revoke";
            return <div key={proposal.tx_id} className="space-y-4 p-4"><div className="flex items-start justify-between gap-3"><div><div className="font-mono text-xs text-white">{proposal.kind.toUpperCase()} // {officer}</div><div className="mt-1 font-mono text-[9px] text-muted">{compactId(proposal.tx_id)}</div></div><Badge tone={complete ? "good" : "warn"}>{proposal.approvals}/{proposal.quorum_threshold} approvals</Badge></div><div className="h-1 bg-white/5"><div className="h-full bg-signal transition-all" style={{ width: `${Math.min(100, (proposal.approvals / proposal.quorum_threshold) * 100)}%` }} /></div><div className="flex flex-wrap gap-2">{!complete && ADMINS.map((admin) => <Button key={admin} disabled={action.isPending} onClick={() => action.mutate({ path: `/identity/proposals/${proposal.tx_id}/${approvalPath}`, body: { admin_id: admin } })}>{admin} approve</Button>)}{complete && <Button disabled={action.isPending} onClick={() => action.mutate({ path: `/identity/proposals/${proposal.tx_id}/${finalPath}` })}>Finalise {proposal.kind}</Button>}</div></div>;
          })}
          {proposals.data!.length === 0 && <div className="p-8 text-center font-mono text-[10px] uppercase tracking-widest text-muted">No proposals recorded</div>}
        </div>
      </Card>
    </div>
  </div>;
}
