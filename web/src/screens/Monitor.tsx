import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, Clock, KeyRound, Send, ShieldAlert } from "lucide-react";

import { api, compactId } from "../api";
import { Badge, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import type { DocumentTimeline, MonitorDocument } from "../types";

const STAGE_ICON: Record<string, React.ReactNode> = {
  request: <Send size={12} />,
  keygrant: <KeyRound size={12} />,
  receipt: <CheckCircle2 size={12} />,
  open: <Clock size={12} />,
};

export function Monitor() {
  const [selected, setSelected] = useState<string | null>(null);

  const documents = useQuery({
    queryKey: ["monitor-documents"],
    queryFn: () => api<MonitorDocument[]>("/monitor/documents"),
  });

  const timeline = useQuery({
    queryKey: ["timeline", selected],
    queryFn: () => api<DocumentTimeline>(`/monitor/documents/${selected}/timeline`),
    enabled: !!selected,
  });

  return (
    <div className="space-y-6 p-5 md:p-8">
      <SectionTitle eyebrow="Live oversight" title="Monitor" />

      {documents.isLoading && <Loading />}
      {documents.error && <ErrorState error={documents.error} />}

      <div className="grid gap-6 xl:grid-cols-[1fr_2fr]">
        <Card>
          <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
            Registered documents
          </div>
          <div className="divide-y divide-line">
            {(documents.data ?? []).map((d) => (
              <button
                key={d.doc_id}
                onClick={() => setSelected(d.doc_id)}
                className={`block w-full p-3 text-left font-mono text-xs transition ${
                  selected === d.doc_id ? "bg-signal/[0.08] text-signal" : "text-white hover:bg-white/[0.03]"
                }`}
              >
                {d.doc_id}
              </button>
            ))}
            {documents.data?.length === 0 && (
              <div className="p-8 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">
                No documents registered yet
              </div>
            )}
          </div>
        </Card>

        <Card>
          <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
            Session timeline{selected ? ` — ${selected}` : ""}
          </div>
          {!selected && (
            <div className="p-16 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">
              Pick a document to see its sessions
            </div>
          )}
          {timeline.isLoading && <Loading />}
          <div className="divide-y divide-line">
            {(timeline.data?.sessions ?? []).map((session) => (
              <div key={session.session_id} className="space-y-3 p-4">
                <div className="font-mono text-xs text-white">
                  {compactId(session.session_id, 10)} <span className="text-slate-500">// {session.officer_id}</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {session.events.map((event, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-1.5 border border-line px-2 py-1 font-mono text-[9px] uppercase tracking-widest text-slate-400"
                    >
                      {STAGE_ICON[event.stage]}
                      {event.stage}
                      <span className="text-slate-600">{compactId(event.tx_id, 5)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ))}
            {selected && timeline.data?.sessions.length === 0 && (
              <div className="p-8 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">
                No decrypt sessions recorded for this document
              </div>
            )}
          </div>
          {(timeline.data?.open_denied.length ?? 0) > 0 && (
            <div className="border-t border-line p-4">
              <div className="mb-3 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-danger">
                <ShieldAlert size={13} /> Forwarding attempts denied
              </div>
              <div className="space-y-2">
                {timeline.data!.open_denied.map((event) => (
                  <div key={event.tx_id} className="font-mono text-[10px] text-slate-400">
                    <Badge tone="bad">DENIED</Badge>{" "}
                    presented {compactId(event.presented_by, 8)} for owner {compactId(event.owner, 8)}{" "}
                    <span className="text-slate-600">{compactId(event.tx_id, 6)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
