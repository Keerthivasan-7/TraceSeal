import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, FileText, Lock, ShieldAlert, Unlock } from "lucide-react";

import { api, compactId } from "../api";
import { Badge, Button, Card, ErrorState, Loading, SectionTitle } from "../components/ui";
import type { OfficerDocument, OfficerRow, OpenResult } from "../types";

export function Inbox() {
  const queryClient = useQueryClient();
  const [active, setActive] = useState("officer-a");
  const [passphrase, setPassphrase] = useState("");
  const [openDoc, setOpenDoc] = useState<{ docId: string; result: OpenResult } | null>(null);
  const [page, setPage] = useState(0);
  const [impersonate, setImpersonate] = useState<string | null>(null);

  const officers = useQuery({ queryKey: ["officers"], queryFn: () => api<OfficerRow[]>("/officers") });
  const current = officers.data?.find((o) => o.officer_id === active);

  const documents = useQuery({
    queryKey: ["officer-documents", active],
    queryFn: () => api<OfficerDocument[]>(`/officers/${active}/documents`),
    enabled: !!current?.unlocked,
  });

  const unlock = useMutation({
    mutationFn: () => api(`/officers/${active}/unlock`, { method: "POST", body: JSON.stringify({ passphrase }) }),
    onSuccess: async () => {
      setPassphrase("");
      await queryClient.invalidateQueries({ queryKey: ["officers"] });
    },
  });

  const lock = useMutation({
    mutationFn: () => api(`/officers/${active}/lock`, { method: "POST" }),
    onSuccess: async () => {
      setOpenDoc(null);
      await queryClient.invalidateQueries({ queryKey: ["officers"] });
    },
  });

  const open = useMutation({
    mutationFn: (docId: string) =>
      api<OpenResult>(`/officers/${active}/documents/${docId}/open`, {
        method: "POST",
        body: JSON.stringify(impersonate ? { claim_officer_id: impersonate } : {}),
      }),
    onSuccess: (result, docId) => {
      setOpenDoc({ docId, result });
      setPage(0);
      setImpersonate(null);
    },
  });

  function selectOfficer(id: string) {
    setActive(id);
    setOpenDoc(null);
    setPassphrase("");
    open.reset();
    unlock.reset();
  }

  if (officers.isLoading) return <Loading />;
  if (officers.error) return <ErrorState error={officers.error} />;

  return (
    <div className="space-y-6 p-5 md:p-8">
      <SectionTitle eyebrow="Recipient agent" title="Officer Inbox & Viewer" />

      <div className="flex flex-wrap gap-2">
        {officers.data!.map((o) => (
          <button
            key={o.officer_id}
            onClick={() => selectOfficer(o.officer_id)}
            className={`flex items-center gap-2 border px-3 py-2 font-mono text-[11px] uppercase tracking-widest transition ${
              active === o.officer_id ? "border-signal/40 bg-signal/[0.08] text-signal" : "border-line text-slate-500 hover:text-slate-300"
            }`}
          >
            {o.unlocked ? <Unlock size={12} /> : <Lock size={12} />}
            {o.officer_id}
          </button>
        ))}
      </div>

      {current?.status !== "active" && (
        <Card className="border-warning/30 bg-warning/5 p-4 font-mono text-xs text-warning">
          {active} has status "{current?.status}" — only an enrolled, non-revoked officer can open a genuine session.
        </Card>
      )}

      {!current?.unlocked ? (
        <Card className="max-w-md p-6">
          <div className="mb-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">Unlock keystore</div>
          <div className="flex gap-2">
            <input
              type="password"
              value={passphrase}
              onChange={(e) => setPassphrase(e.target.value)}
              placeholder="Keystore passphrase"
              className="flex-1 border border-line bg-black/30 px-3 py-2 font-mono text-xs text-white outline-none focus:border-signal/40"
            />
            <Button disabled={!passphrase || unlock.isPending} onClick={() => unlock.mutate()}>
              {unlock.isPending ? "Unlocking…" : "Unlock"}
            </Button>
          </div>
          {unlock.error && <div className="mt-3"><ErrorState error={unlock.error} /></div>}
        </Card>
      ) : (
        <div className="grid gap-6 xl:grid-cols-[1fr_1.3fr]">
          <Card>
            <div className="flex items-center justify-between border-b border-line p-4">
              <div className="font-mono text-[10px] uppercase tracking-widest text-slate-400">Distributed to {active}</div>
              <Button onClick={() => lock.mutate()}>Lock session</Button>
            </div>
            {documents.isLoading && <Loading />}
            <div className="divide-y divide-line">
              {(documents.data ?? []).map((doc) => (
                <div key={doc.doc_id} className="space-y-2 p-4">
                  <div className="flex items-center gap-2 font-mono text-xs text-white"><FileText size={13} className="text-signal" /> {doc.doc_id}</div>
                  <div className="font-mono text-[9px] uppercase tracking-widest text-slate-600">
                    {doc.positions_count ?? "?"} positions // c0={doc.tardos_c0 ?? "?"} // n={doc.tardos_n ?? "?"}
                  </div>
                  <Button disabled={open.isPending} onClick={() => { setImpersonate(null); open.mutate(doc.doc_id); }}>
                    Open
                  </Button>
                </div>
              ))}
              {documents.data?.length === 0 && (
                <div className="p-8 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">
                  Nothing distributed to this officer yet
                </div>
              )}
            </div>

            <div className="border-t border-line p-4">
              <div className="mb-2 flex items-center gap-2 font-mono text-[10px] uppercase tracking-widest text-warning">
                <ShieldAlert size={13} /> Forwarding demo
              </div>
              <p className="mb-3 font-mono text-[10px] leading-5 text-slate-500">
                Present another officer's copy to this session and watch the SealedHeader mismatch get denied and
                logged as OPEN_DENIED on the ledger.
              </p>
              <div className="flex flex-wrap gap-2">
                {(documents.data ?? []).flatMap((doc) =>
                  officers.data!
                    .filter((o) => o.officer_id !== active && o.status === "active")
                    .map((o) => (
                      <Button
                        key={`${doc.doc_id}-${o.officer_id}`}
                        className="border-danger/30 bg-danger/5 text-danger hover:border-danger"
                        disabled={open.isPending}
                        onClick={() => { setImpersonate(o.officer_id); open.mutate(doc.doc_id); }}
                      >
                        Try {doc.doc_id} as {o.officer_id}
                      </Button>
                    )),
                )}
              </div>
            </div>
            {open.error && <div className="p-4"><ErrorState error={open.error} /></div>}
          </Card>

          <Card className="overflow-hidden">
            <div className="border-b border-line p-4 font-mono text-[10px] uppercase tracking-widest text-slate-400">
              {openDoc ? `Viewing ${openDoc.docId} — session ${compactId(openDoc.result.session_id, 8)}` : "No document open"}
            </div>
            {openDoc ? (
              <>
                <div className="bg-black/40 p-4">
                  <img
                    key={page}
                    src={`/api/officers/${active}/documents/${openDoc.docId}/pages/${page}`}
                    alt={`Assembled page ${page + 1}`}
                    className="mx-auto max-h-[65vh] w-auto border border-line"
                  />
                </div>
                <div className="flex items-center justify-between border-t border-line p-3">
                  <Button disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
                    <ChevronLeft size={13} className="mr-1 inline" /> Prev
                  </Button>
                  <span className="font-mono text-[10px] uppercase tracking-widest text-slate-500">
                    Page {page + 1} of {openDoc.result.page_count}
                  </span>
                  <Button disabled={page >= openDoc.result.page_count - 1} onClick={() => setPage((p) => p + 1)}>
                    Next <ChevronRight size={13} className="ml-1 inline" />
                  </Button>
                </div>
                <div className="border-t border-line p-3 font-mono text-[9px] uppercase tracking-widest text-slate-600">
                  Receipt {compactId(openDoc.result.receipt_tx_id)} finalised on ledger — assembled entirely in
                  memory, never written to disk
                </div>
              </>
            ) : (
              <div className="p-16 text-center font-mono text-[10px] uppercase tracking-widest text-slate-600">
                Open a document to assemble it in memory
              </div>
            )}
          </Card>
        </div>
      )}
    </div>
  );
}
