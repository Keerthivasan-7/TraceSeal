import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { FlaskConical } from "lucide-react";

import { api } from "../api";
import { Badge, BusyBar, Button, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import { useElapsedSeconds } from "../hooks/useElapsedSeconds";
import type { AttackLabResultRow, AttackLabResults, QuickRunResult } from "../types";

function ResultsTable({ rows }: { rows: AttackLabResultRow[] }) {
  const first = rows[0];
  if (!first) return null;
  const columns = Object.keys(first);
  return (
    <div className="overflow-x-auto">
      <table className="w-full font-mono text-[10px]">
        <thead>
          <tr className="border-b border-line text-left uppercase tracking-widest text-muted">
            {columns.map((c) => (
              <th key={c} className="whitespace-nowrap px-2 py-2">{c}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {rows.map((row, i) => (
            <tr key={i} className="text-slate-300">
              {columns.map((c) => (
                <td key={c} className="whitespace-nowrap px-2 py-2">{row[c]}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function AttackLab() {
  const [showRaw, setShowRaw] = useState(false);

  const results = useQuery({
    queryKey: ["attacklab-results"],
    queryFn: () => api<AttackLabResults>("/attacklab/results"),
    retry: false,
  });

  const quickRun = useMutation({
    mutationFn: () => api<QuickRunResult>("/attacklab/quick-run", { method: "POST" }),
  });
  const quickRunSeconds = useElapsedSeconds(quickRun.isPending);

  return (
    <div className="space-y-6 p-5 md:p-8">
      <SectionTitle eyebrow="Robustness & collusion resistance" title="Attack Lab" />

      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between">
          <div className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-slate-400">
            <FlaskConical size={14} className="text-signal" /> Live quick run
          </div>
          <Button disabled={quickRun.isPending} onClick={() => quickRun.mutate()}>
            {quickRun.isPending ? "Running real trials…" : "Run quick demo"}
          </Button>
        </div>
        <p className="mb-4 font-mono text-[10px] leading-5 text-muted">
          A small, seeded, genuinely-run subset (3 distortions + 2 collusion strategies, 2 trials
          each) of the exact same pipeline the full benchmark below uses — not a substitute for it.
        </p>
        {quickRun.error && <ErrorState error={quickRun.error} />}
        {quickRun.isPending && <div className="mb-2"><BusyBar label="Running real trials against real distorted pixels" seconds={quickRunSeconds} /></div>}
        {quickRun.data && (
          <div className="space-y-2">
            <div className="font-mono text-[10px] text-muted">
              seed={quickRun.data.seed} // n={quickRun.data.n_sessions} // positions={quickRun.data.n_positions}
            </div>
            <ResultsTable
              rows={quickRun.data.conditions.map((c) => ({
                condition: c.condition,
                trials: String(c.n_trials),
                "mean BER": c.mean_bit_error_rate?.toFixed(4) ?? "n/a",
                "mean erasure": c.mean_erasure_rate?.toFixed(4) ?? "n/a",
                "top-1": `${(c.top1_accuracy * 100).toFixed(1)}%`,
                "innocent accused": String(c.total_innocent_accusations),
                "runtime (ms)": c.mean_runtime_ms.toFixed(1),
              }))}
            />
          </div>
        )}
      </Card>

      <Card className="p-5">
        <div className="mb-3 flex items-center justify-between">
          <div className="font-mono text-[10px] uppercase tracking-widest text-slate-400">
            Full benchmark — docs/RESULTS.md
          </div>
          <button
            onClick={() => setShowRaw((v) => !v)}
            className="font-mono text-[9px] uppercase tracking-widest text-muted hover:text-signal"
          >
            {showRaw ? "Show tables" : "Show raw markdown"}
          </button>
        </div>
        {results.isLoading && <Loading />}
        {results.error && (
          <div className="border border-warning/30 bg-warning/5 p-4 font-mono text-xs text-warning">
            No results file found — run <Badge tone="warn">make demo-m7</Badge> to generate
            docs/RESULTS.md.
          </div>
        )}
        {results.data && showRaw && (
          <pre className="max-h-[60vh] overflow-auto whitespace-pre-wrap font-mono text-[10px] text-slate-400">
            {results.data.markdown}
          </pre>
        )}
        {results.data && !showRaw && (
          <div className="space-y-6">
            <div>
              <div className="mb-2 font-mono text-[9px] uppercase tracking-widest text-muted">
                Synthetic distortions
              </div>
              <ResultsTable rows={results.data.synthetic} />
            </div>
            <div>
              <div className="mb-2 font-mono text-[9px] uppercase tracking-widest text-muted">
                Collusion
              </div>
              <ResultsTable rows={results.data.collusion} />
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
