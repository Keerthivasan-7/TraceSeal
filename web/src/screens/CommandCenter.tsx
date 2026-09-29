import { useMutation, useQuery } from "@tanstack/react-query";
import { Activity, FileLock2, RadioTower, Search, ShieldCheck } from "lucide-react";

import { api, compactId, domainLabel } from "../api";
import { Badge, Button, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import type { EgressResult, SystemStatus } from "../types";

export function CommandCenter() {
  const status = useQuery({
    queryKey: ["system-status"],
    queryFn: () => api<SystemStatus>("/system/status"),
  });
  const egress = useMutation({
    mutationFn: () => api<EgressResult>("/system/egress-test"),
  });

  if (status.isLoading) return <Loading />;
  if (status.error) return <ErrorState error={status.error} />;
  const data = status.data!;
  const metrics = [
    ["Documents", data.counts.documents, FileLock2],
    ["Sessions", data.counts.sessions, RadioTower],
    ["Open cases", data.counts.open_investigations, Search],
    ["Ledger height", data.counts.ledger_height, Activity],
  ] as const;

  return <div className="space-y-6 p-5 md:p-8">
    <div className="flex flex-col justify-between gap-4 md:flex-row md:items-end">
      <SectionTitle eyebrow="Operational overview" title="Command Center" />
      <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Live refresh // 5 seconds</div>
    </div>

    <Card className="grid gap-5 p-5 md:grid-cols-[1fr_auto] md:items-center">
      <div className="flex items-start gap-4">
        <div className="grid h-12 w-12 shrink-0 place-items-center border border-signal/50 bg-signal/10 text-signal"><ShieldCheck /></div>
        <div>
          <div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold text-white">Air-gap posture</h3><Badge tone="good">enforced</Badge></div>
          <p className="mt-2 font-mono text-[11px] leading-5 text-slate-400">{data.air_gap.network}<br />Cloud dependencies: {data.air_gap.cloud_dependencies}</p>
          {egress.data && <p className="mt-3 text-xs text-slate-400"><Badge tone={egress.data.egress_blocked ? "good" : "bad"}>{egress.data.egress_blocked ? "egress blocked" : "egress open"}</Badge><span className="ml-3 font-mono text-[10px]">{egress.data.detail}</span></p>}
        </div>
      </div>
      <Button onClick={() => egress.mutate()} disabled={egress.isPending}>{egress.isPending ? "Testing…" : "Run live egress test"}</Button>
    </Card>

    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {metrics.map(([label, value, Icon]) => <Card key={label} className="p-5"><div className="flex items-center justify-between text-slate-500"><span className="font-mono text-[10px] uppercase tracking-widest">{label}</span><Icon size={16} /></div><div className="mt-5 font-mono text-3xl text-white">{value.toLocaleString()}</div></Card>)}
    </div>

    <div className="grid gap-6 xl:grid-cols-[0.85fr_1.4fr]">
      <Card>
        <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">Replica integrity</div>
        <div className="divide-y divide-line">
          {data.replicas?.map((replica) => <div key={replica.replica_id} className="flex items-center justify-between p-4"><div><div className="font-mono text-xs text-white">{replica.replica_id}</div><div className="mt-1 font-mono text-[10px] text-slate-600">height {replica.height}</div></div><Badge tone={replica.internally_valid ? "good" : "bad"}>{replica.internally_valid ? "chain valid" : `bad @ ${replica.first_bad_height ?? "?"}`}</Badge></div>)}
          {data.replicas === null && <div className="p-4 text-xs text-slate-500">Replica-level inspection is unavailable for this ledger backend.</div>}
        </div>
      </Card>
      <Card>
        <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">Recent finalised events</div>
        <div className="max-h-[390px] divide-y divide-line overflow-auto">
          {data.recent_events.map((event) => <div key={event.tx_id} className="grid grid-cols-[52px_1fr_auto] gap-3 p-4 text-xs"><span className="font-mono text-signal">#{event.height}</span><div><div className="uppercase text-slate-200">{domainLabel(event.domain)}</div><div className="mt-1 font-mono text-[10px] text-slate-600">{compactId(event.tx_id)} // {event.submitter_id}</div></div><Badge>{event.quorum_signer_ids.length} sigs</Badge></div>)}
          {data.recent_events.length === 0 && <div className="p-8 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">No ledger events yet</div>}
        </div>
      </Card>
    </div>
  </div>;
}
