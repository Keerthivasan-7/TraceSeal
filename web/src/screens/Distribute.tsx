import { useRef, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { CheckCircle2, ChevronLeft, ChevronRight, ShieldAlert, UploadCloud, XCircle } from "lucide-react";

import { api, apiUpload, compactId } from "../api";
import { Badge, Button, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import type { DistributeDraft, RegistryEntry, ReleaseResult } from "../types";

export function Distribute() {
  const [draft, setDraft] = useState<DistributeDraft | null>(null);
  const [released, setReleased] = useState<ReleaseResult | null>(null);
  const [page, setPage] = useState(0);
  const [showOverlay, setShowOverlay] = useState(true);
  const [recipients, setRecipients] = useState<Set<string>>(new Set());
  const [imageSize, setImageSize] = useState<{ width: number; height: number } | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const registry = useQuery({
    queryKey: ["registry"],
    queryFn: () => api<RegistryEntry[]>("/identity/registry"),
  });
  const officers = (registry.data ?? []).filter((r) => r.kind === "officer");

  const analyze = useMutation({
    mutationFn: (file: File) => {
      const form = new FormData();
      form.append("file", file);
      return apiUpload<DistributeDraft>("/distribute/analyze", form);
    },
    onSuccess: (data) => {
      setDraft(data);
      setReleased(null);
      setPage(0);
      setRecipients(new Set());
    },
  });

  const release = useMutation({
    mutationFn: () =>
      api<ReleaseResult>(`/distribute/${draft!.draft_id}/release`, {
        method: "POST",
        body: JSON.stringify({ recipient_officer_ids: Array.from(recipients) }),
      }),
    onSuccess: (data) => setReleased(data),
  });

  function reset() {
    setDraft(null);
    setReleased(null);
    analyze.reset();
    release.reset();
    if (fileInput.current) fileInput.current.value = "";
  }

  function toggleRecipient(id: string) {
    setRecipients((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  return (
    <div className="space-y-6 p-5 md:p-8">
      <SectionTitle eyebrow="Sender station" title="Distribute a document" />

      {!draft && (
        <Card className="p-10">
          <label className="flex cursor-pointer flex-col items-center gap-4 border border-dashed border-line py-16 text-center transition hover:border-signal/40 hover:bg-signal/[0.03]">
            <UploadCloud className="text-signal" size={32} />
            <div>
              <div className="font-mono text-xs uppercase tracking-widest text-white">
                {analyze.isPending ? "Rendering variants & running quality gate…" : "Drop a PDF, or click to choose one"}
              </div>
              <div className="mt-2 font-mono text-[10px] uppercase tracking-widest text-muted">
                Dual-variant rasterisation runs entirely on this machine — no upload leaves the air gap
              </div>
            </div>
            <input
              ref={fileInput}
              type="file"
              accept="application/pdf"
              className="hidden"
              disabled={analyze.isPending}
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) analyze.mutate(file);
              }}
            />
          </label>
          {analyze.error && <div className="mt-4"><ErrorState error={analyze.error} /></div>}
        </Card>
      )}

      {draft && !released && (
        <div className="grid gap-6 xl:grid-cols-[1.3fr_1fr]">
          <Card className="overflow-hidden">
            <div className="flex items-center justify-between border-b border-line p-4">
              <div className="font-mono text-[10px] uppercase tracking-widest text-slate-400">
                Page {page + 1} of {draft.page_count} — {draft.positions_count} mark positions selected
              </div>
              <label className="flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-muted">
                <input type="checkbox" checked={showOverlay} onChange={(e) => setShowOverlay(e.target.checked)} />
                Show mark positions
              </label>
            </div>
            <div className="relative bg-black/40 p-4">
              <div className="relative mx-auto w-fit">
                <img
                  key={page}
                  src={`/api/distribute/${draft.draft_id}/pages/${page}`}
                  alt={`Page ${page + 1} preview`}
                  className="max-h-[70vh] w-auto border border-line"
                  onLoad={(e) => {
                    const img = e.currentTarget;
                    setImageSize({ width: img.naturalWidth, height: img.naturalHeight });
                  }}
                />
                {showOverlay &&
                  imageSize &&
                  draft.positions
                    .filter((p) => p.page_index === page)
                    .map((p) => {
                      const [x0, y0, x1, y1] = p.pixel_bbox;
                      return (
                        <div
                          key={p.index}
                          className="absolute border border-signal/70 bg-signal/10"
                          style={{
                            left: `${(x0 / imageSize.width) * 100}%`,
                            top: `${(y0 / imageSize.height) * 100}%`,
                            width: `${((x1 - x0) / imageSize.width) * 100}%`,
                            height: `${((y1 - y0) / imageSize.height) * 100}%`,
                          }}
                        />
                      );
                    })}
              </div>
            </div>
            <div className="flex items-center justify-between border-t border-line p-3">
              <Button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                <ChevronLeft size={13} className="mr-1 inline" /> Prev
              </Button>
              <Button disabled={page >= draft.page_count - 1} onClick={() => setPage((p) => p + 1)}>
                Next <ChevronRight size={13} className="ml-1 inline" />
              </Button>
            </div>
          </Card>

          <div className="space-y-6">
            <Card>
              <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
                Quality gate
              </div>
              <div className="space-y-3 p-4">
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs text-white">
                    {draft.quality_gate.passed ? "Passed — safe to release" : "Failed — release blocked"}
                  </span>
                  <Badge tone={draft.quality_gate.passed ? "good" : "bad"}>
                    {draft.quality_gate.passed ? <CheckCircle2 size={11} className="mr-1 inline" /> : <XCircle size={11} className="mr-1 inline" />}
                    {draft.quality_gate.passed ? "pass" : "fail"}
                  </Badge>
                </div>
                {draft.quality_gate.pages.map((p) => (
                  <div key={`${p.page_index}-${p.variant_bit}`} className="flex items-center justify-between font-mono text-[10px] text-muted">
                    <span>page {p.page_index + 1} / variant bit {p.variant_bit}</span>
                    <span className={p.passed ? "text-signal" : "text-danger"}>SSIM {p.ssim.toFixed(4)}</span>
                  </div>
                ))}
                <div className="flex items-center justify-between font-mono text-[10px] text-muted">
                  <span>worst per-position change</span>
                  <span>{(draft.quality_gate.worst_position_changed_fraction * 100).toFixed(1)}%</span>
                </div>
              </div>
            </Card>

            <Card>
              <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
                Recipients
              </div>
              <div className="divide-y divide-line">
                {officers.map((o) => {
                  const eligible = o.status === "active";
                  return (
                    <label
                      key={o.identity_id}
                      className={`flex items-center justify-between gap-3 p-3 font-mono text-xs ${eligible ? "cursor-pointer text-white" : "cursor-not-allowed text-muted"}`}
                    >
                      <span className="flex items-center gap-3">
                        <input
                          type="checkbox"
                          disabled={!eligible}
                          checked={recipients.has(o.identity_id)}
                          onChange={() => toggleRecipient(o.identity_id)}
                        />
                        {o.identity_id}
                      </span>
                      <Badge tone={o.status === "active" ? "good" : o.status === "revoked" ? "bad" : "neutral"}>{o.status}</Badge>
                    </label>
                  );
                })}
              </div>
              {recipients.size === 1 && (
                <div className="flex items-start gap-2 border-t border-line p-3 font-mono text-[10px] text-warning">
                  <ShieldAlert size={13} className="mt-0.5 shrink-0" />
                  Tardos collusion resistance needs at least 2 recipients to mean anything — a single-recipient
                  release will be refused by the fingerprint planner.
                </div>
              )}
            </Card>

            {release.error && <ErrorState error={release.error} />}

            <div className="flex gap-3">
              <Button
                className="flex-1 justify-center"
                disabled={!draft.quality_gate.passed || recipients.size === 0 || release.isPending}
                onClick={() => release.mutate()}
              >
                {release.isPending ? "Releasing…" : `Release to ${recipients.size} officer${recipients.size === 1 ? "" : "s"}`}
              </Button>
              <Button onClick={reset}>Cancel</Button>
            </div>
          </div>
        </div>
      )}

      {released && (
        <Card className="p-8">
          <div className="flex items-center gap-3 text-signal">
            <CheckCircle2 size={22} />
            <div className="font-mono text-sm uppercase tracking-widest">Document registered & distributed</div>
          </div>
          <div className="mt-6 grid gap-4 font-mono text-xs text-slate-400 sm:grid-cols-2">
            <div><div className="text-[9px] uppercase tracking-widest text-muted">Document ID</div><div className="mt-1 text-white">{released.doc_id}</div></div>
            <div><div className="text-[9px] uppercase tracking-widest text-muted">Ledger tx</div><div className="mt-1 text-white">{compactId(released.tx_id)}</div></div>
            <div><div className="text-[9px] uppercase tracking-widest text-muted">Recipients</div><div className="mt-1 text-white">{released.recipients.join(", ")}</div></div>
            <div>
              <div className="text-[9px] uppercase tracking-widest text-muted">Tardos c0</div>
              <div className="mt-1 text-white">
                {released.tardos_c0}{" "}
                {released.tardos_degraded && <Badge tone="warn">degraded</Badge>}
              </div>
            </div>
          </div>
          <Button className="mt-8" onClick={reset}>Distribute another document</Button>
        </Card>
      )}
    </div>
  );
}
