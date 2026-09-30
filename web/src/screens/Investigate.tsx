import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Download, FileSearch, Network, ShieldAlert } from "lucide-react";

import { api, apiUpload, compactId } from "../api";
import { Badge, Button, Card, ErrorState, SectionTitle } from "../components/ui";
import type {
  IssueReportResult,
  InvestigationOpenResult,
  MonitorDocument,
  ObservationOverlay,
} from "../types";

const OFFICER_IDS = ["officer-a", "officer-b", "officer-c", "officer-d", "officer-e"];
type Stage = "detected" | "aligned" | "heatmap";

export function Investigate() {
  const [docId, setDocId] = useState("");
  const [pageIndex, setPageIndex] = useState(0);
  const [mode, setMode] = useState<"upload" | "simulate">("simulate");
  const [sourceOfficer, setSourceOfficer] = useState("officer-a");
  const [distortion, setDistortion] = useState("screen_camera");
  const [file, setFile] = useState<File | null>(null);
  const [stage, setStage] = useState<Stage>("aligned");
  const [imageSize, setImageSize] = useState<{ width: number; height: number } | null>(null);
  const [selectedNode, setSelectedNode] = useState<string | null>(null);

  const documents = useQuery({
    queryKey: ["monitor-documents"],
    queryFn: () => api<MonitorDocument[]>("/monitor/documents"),
  });

  const open = useMutation({
    mutationFn: () => {
      const form = new FormData();
      form.append("doc_id", docId);
      form.append("page_index", String(pageIndex));
      if (mode === "upload" && file) {
        form.append("file", file);
      } else {
        form.append("source_officer_id", sourceOfficer);
        form.append("distortion", distortion);
      }
      return apiUpload<InvestigationOpenResult>("/investigate/open", form);
    },
    onSuccess: () => {
      setImageSize(null);
    },
  });

  const caseId = open.data?.case_id;
  const observations = useQuery({
    queryKey: ["observations", caseId],
    queryFn: () => api<ObservationOverlay[]>(`/investigate/${caseId}/pipeline/observations`),
    enabled: !!caseId,
  });

  const issueReport = useMutation({
    mutationFn: () =>
      api<IssueReportResult>(`/investigate/${open.data!.case_id}/issue-report`, { method: "POST" }),
  });

  function reset() {
    open.reset();
    issueReport.reset();
    setSelectedNode(null);
  }

  const result = open.data;
  const maxScore = result ? Math.max(result.threshold, ...result.suspects.map((s) => s.score), 1) : 1;

  return (
    <div className="space-y-6 p-5 md:p-8">
      <SectionTitle eyebrow="Forensics" title="Investigate a leaked artifact" />

      {!result && (
        <Card className="max-w-2xl space-y-5 p-6">
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="space-y-1">
              <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Document ID</div>
              <input
                list="doc-ids"
                value={docId}
                onChange={(e) => setDocId(e.target.value)}
                placeholder="doc-xxxxxxxxxxxx"
                className="w-full border border-line bg-black/30 px-3 py-2 font-mono text-xs text-white outline-none focus:border-signal/40"
              />
              <datalist id="doc-ids">
                {(documents.data ?? []).map((d) => (
                  <option key={d.doc_id} value={d.doc_id} />
                ))}
              </datalist>
            </label>
            <label className="space-y-1">
              <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Leaked page index</div>
              <input
                type="number"
                min={0}
                value={pageIndex}
                onChange={(e) => setPageIndex(Number(e.target.value))}
                className="w-full border border-line bg-black/30 px-3 py-2 font-mono text-xs text-white outline-none focus:border-signal/40"
              />
            </label>
          </div>

          <div className="flex gap-2 font-mono text-[10px] uppercase tracking-widest">
            <button
              onClick={() => setMode("simulate")}
              className={`flex-1 border px-3 py-2 ${mode === "simulate" ? "border-signal/40 bg-signal/[0.08] text-signal" : "border-line text-slate-500"}`}
            >
              Simulate a leak
            </button>
            <button
              onClick={() => setMode("upload")}
              className={`flex-1 border px-3 py-2 ${mode === "upload" ? "border-signal/40 bg-signal/[0.08] text-signal" : "border-line text-slate-500"}`}
            >
              Upload artifact
            </button>
          </div>

          {mode === "simulate" ? (
            <div className="grid gap-4 sm:grid-cols-2">
              <label className="space-y-1">
                <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">From officer's open session</div>
                <select
                  value={sourceOfficer}
                  onChange={(e) => setSourceOfficer(e.target.value)}
                  className="w-full border border-line bg-black/30 px-3 py-2 font-mono text-xs text-white outline-none focus:border-signal/40"
                >
                  {OFFICER_IDS.map((o) => (
                    <option key={o} value={o}>{o}</option>
                  ))}
                </select>
              </label>
              <label className="space-y-1">
                <div className="font-mono text-[10px] uppercase tracking-widest text-slate-500">Capture distortion</div>
                <select
                  value={distortion}
                  onChange={(e) => setDistortion(e.target.value)}
                  className="w-full border border-line bg-black/30 px-3 py-2 font-mono text-xs text-white outline-none focus:border-signal/40"
                >
                  <option value="screen_camera">Screen camera</option>
                  <option value="print_scan">Print + scan</option>
                  <option value="none">None (raw page)</option>
                </select>
              </label>
            </div>
          ) : (
            <label className="block cursor-pointer border border-dashed border-line p-6 text-center font-mono text-xs uppercase tracking-widest text-slate-400 hover:border-signal/40">
              {file ? file.name : "Choose a leaked photo or scan"}
              <input
                type="file"
                accept="image/*"
                className="hidden"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
            </label>
          )}

          {open.error && <ErrorState error={open.error} />}

          <Button
            className="w-full justify-center"
            disabled={!docId || open.isPending || (mode === "upload" && !file)}
            onClick={() => open.mutate()}
          >
            {open.isPending ? "Running alignment, detection & accusation…" : "Open investigation"}
          </Button>
        </Card>
      )}

      {result && (
        <div className="space-y-6">
          <div className="grid gap-6 xl:grid-cols-[1.2fr_1fr]">
            <Card className="overflow-hidden">
              <div className="flex items-center justify-between border-b border-line p-4">
                <div className="font-mono text-[10px] uppercase tracking-widest text-slate-400">Pipeline</div>
                <div className="flex gap-1">
                  {(["detected", "aligned", "heatmap"] as Stage[]).map((s) => (
                    <button
                      key={s}
                      onClick={() => setStage(s)}
                      className={`border px-2 py-1 font-mono text-[9px] uppercase tracking-widest ${stage === s ? "border-signal/40 text-signal" : "border-line text-slate-500"}`}
                    >
                      {s}
                    </button>
                  ))}
                </div>
              </div>
              <div className="relative bg-black/40 p-4">
                <div className="relative mx-auto w-fit">
                  <img
                    key={`${result.case_id}-${stage}`}
                    src={`/api/investigate/${result.case_id}/pipeline/${stage === "heatmap" ? "aligned-overlay" : stage === "detected" ? "detected-page" : "aligned-overlay"}`}
                    alt={stage}
                    className="max-h-[60vh] w-auto border border-line"
                    onLoad={(e) => {
                      const img = e.currentTarget;
                      setImageSize({ width: img.naturalWidth, height: img.naturalHeight });
                    }}
                  />
                  {stage === "heatmap" &&
                    imageSize &&
                    (observations.data ?? []).map((obs) => {
                      const [x0, y0, x1, y1] = obs.pixel_bbox;
                      const color = obs.is_erasure ? "#f4c264" : obs.observed_bit === 1 ? "#64f4ac" : "#ff6b7a";
                      return (
                        <div
                          key={obs.position_index}
                          title={`bit ${obs.is_erasure ? "erased" : obs.observed_bit} / confidence ${obs.confidence.toFixed(3)}`}
                          className="absolute border"
                          style={{
                            left: `${(x0 / imageSize.width) * 100}%`,
                            top: `${(y0 / imageSize.height) * 100}%`,
                            width: `${((x1 - x0) / imageSize.width) * 100}%`,
                            height: `${((y1 - y0) / imageSize.height) * 100}%`,
                            borderColor: color,
                            backgroundColor: `${color}33`,
                          }}
                        />
                      );
                    })}
                </div>
              </div>
            </Card>

            <div className="space-y-6">
              <Card className="p-4">
                <p className="font-mono text-xs leading-6 text-slate-300">{result.summary}</p>
              </Card>
              <Card>
                <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
                  Suspects — score vs. threshold ({result.threshold.toFixed(2)})
                </div>
                <div className="space-y-3 p-4">
                  {result.suspects.map((s) => (
                    <div key={s.session_id} className="space-y-1">
                      <div className="flex items-center justify-between font-mono text-[10px] text-slate-400">
                        <span>{compactId(s.session_id, 10)} // {s.officer_id}</span>
                        <Badge tone={s.accused ? "bad" : "neutral"}>{s.score.toFixed(2)}</Badge>
                      </div>
                      <div className="relative h-2 bg-white/5">
                        <div
                          className={s.accused ? "absolute h-full bg-danger" : "absolute h-full bg-slate-600"}
                          style={{ width: `${Math.min(100, (s.score / maxScore) * 100)}%` }}
                        />
                        <div
                          className="absolute top-0 h-full w-px bg-signal"
                          style={{ left: `${Math.min(100, (result.threshold / maxScore) * 100)}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </Card>

              {!issueReport.data ? (
                <>
                  {issueReport.error && <ErrorState error={issueReport.error} />}
                  <Button
                    className="w-full justify-center"
                    disabled={issueReport.isPending}
                    onClick={() => issueReport.mutate()}
                  >
                    {issueReport.isPending ? "Signing evidence bundle…" : "Issue evidence report"}
                  </Button>
                </>
              ) : (
                <Card className="space-y-3 p-4">
                  <div className="flex items-center gap-2 text-signal">
                    <CheckCircle2 size={16} />
                    <span className="font-mono text-xs uppercase tracking-widest">Report issued & signed</span>
                  </div>
                  <div className="font-mono text-[10px] text-slate-500">
                    tx {compactId(issueReport.data.report_tx_id)}
                  </div>
                  <div className="flex gap-2">
                    <a href={`/api/investigate/${result.case_id}/download/tsev`} download>
                      <Button><Download size={12} className="mr-1 inline" /> case.tsev</Button>
                    </a>
                    <a href={`/api/investigate/${result.case_id}/download/report.pdf`} download>
                      <Button><Download size={12} className="mr-1 inline" /> report.pdf</Button>
                    </a>
                  </div>
                </Card>
              )}
              <Button onClick={reset}>New investigation</Button>
            </div>
          </div>

          <EvidenceGraph
            result={result}
            issued={issueReport.data ?? null}
            selectedNode={selectedNode}
            onSelect={setSelectedNode}
          />
        </div>
      )}
    </div>
  );
}

function EvidenceGraph({
  result,
  issued,
  selectedNode,
  onSelect,
}: {
  result: InvestigationOpenResult;
  issued: IssueReportResult | null;
  selectedNode: string | null;
  onSelect: (id: string | null) => void;
}) {
  const nodes: Array<{ id: string; label: string; sub: string; x: number; y: number; icon: React.ReactNode }> = [
    { id: "doc", label: result.doc_id, sub: "document", x: 50, y: 8, icon: <FileSearch size={13} /> },
    { id: "artifact", label: "artifact", sub: "leaked capture", x: 15, y: 30, icon: <ShieldAlert size={13} /> },
    { id: "case", label: result.case_id, sub: "investigation", x: 50, y: 30, icon: <Network size={13} /> },
    ...result.suspects.map((s, i) => ({
      id: s.session_id,
      label: s.session_id,
      sub: `${s.officer_id} — score ${s.score.toFixed(1)}`,
      x: 15 + (i * 70) / Math.max(1, result.suspects.length - 1 || 1),
      y: 58,
      icon: s.accused ? <AlertTriangle size={13} /> : <Network size={13} />,
    })),
    ...(issued ? [{ id: "report", label: "report.pdf / case.tsev", sub: "signed evidence bundle", x: 85, y: 30, icon: <CheckCircle2 size={13} /> }] : []),
  ];

  const edges: Array<[string, string]> = [
    ["artifact", "case"],
    ["doc", "case"],
    ...result.suspects.map((s): [string, string] => ["case", s.session_id]),
    ...(issued ? [["case", "report"] as [string, string]] : []),
  ];

  const selected = nodes.find((n) => n.id === selectedNode);

  return (
    <Card className="overflow-hidden">
      <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
        Evidence Graph
      </div>
      <div className="relative h-72 bg-black/40">
        <svg viewBox="0 0 100 70" className="h-full w-full" preserveAspectRatio="none">
          {edges.map(([a, b], i) => {
            const na = nodes.find((n) => n.id === a)!;
            const nb = nodes.find((n) => n.id === b)!;
            return (
              <line
                key={i}
                x1={na.x}
                y1={na.y}
                x2={nb.x}
                y2={nb.y}
                stroke="#202a32"
                strokeWidth={0.4}
              />
            );
          })}
        </svg>
        {nodes.map((n) => (
          <button
            key={n.id}
            onClick={() => onSelect(n.id)}
            className={`absolute flex -translate-x-1/2 -translate-y-1/2 flex-col items-center gap-1 border px-2 py-1.5 font-mono text-[9px] transition ${
              selectedNode === n.id
                ? "border-signal bg-signal/10 text-signal"
                : n.id !== "doc" && n.id !== "case" && n.id !== "artifact" && n.id !== "report" && result.suspects.find((s) => s.session_id === n.id)?.accused
                  ? "border-danger/50 bg-danger/5 text-danger"
                  : "border-line bg-panel text-slate-300 hover:border-slate-500"
            }`}
            style={{ left: `${n.x}%`, top: `${n.y}%` }}
          >
            <span className="flex items-center gap-1">{n.icon}{compactId(n.label, 8)}</span>
            <span className="text-slate-500">{n.sub}</span>
          </button>
        ))}
      </div>
      {selected && (
        <div className="border-t border-line p-3 font-mono text-[10px] text-slate-400">
          Selected: <span className="text-white">{selected.label}</span> — {selected.sub}
        </div>
      )}
    </Card>
  );
}
