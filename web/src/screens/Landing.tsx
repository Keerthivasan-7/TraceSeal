import { Logo } from "../components/Logo";
import { Card } from "../components/ui";

const CONSOLES: Array<{ host: string; title: string; blurb: string }> = [
  { host: "command", title: "Command", blurb: "Document owner: release documents, investigate a leak" },
  { host: "officer-a", title: "Officer A", blurb: "Recipient workstation — holds only officer-a's keys" },
  { host: "officer-b", title: "Officer B", blurb: "Recipient workstation — holds only officer-b's keys" },
  { host: "officer-c", title: "Officer C", blurb: "Recipient workstation — holds only officer-c's keys" },
  { host: "authority", title: "Enrolment authority", blurb: "Two-person approval and CA custodian" },
  { host: "ops", title: "Operations", blurb: "Read-only ledger and system view — holds no private keys" },
];

function consoleUrl(host: string): string {
  const port = window.location.port ? `:${window.location.port}` : "";
  return `${window.location.protocol}//${host}.localhost${port}`;
}

export function Landing() {
  return (
    <div className="mx-auto flex min-h-screen max-w-3xl flex-col justify-center gap-8 p-6">
      <div className="flex items-center gap-4">
        <div className="grid h-12 w-12 place-items-center rounded-2xl border border-signal/30 bg-signal-gradient text-ink shadow-glow">
          <Logo size={24} />
        </div>
        <div>
          <div className="font-mono text-[15px] font-semibold tracking-[0.24em] text-white">TRACESEAL</div>
          <div className="mt-1 font-mono text-[10px] uppercase tracking-[0.2em] text-muted">Isolated consoles</div>
        </div>
      </div>
      <p className="font-mono text-xs leading-6 text-muted">
        Each console below is a separate browser origin backed by a separate container holding only that
        role&apos;s key material. Open them in separate windows and side by side.
      </p>
      <div className="grid gap-3 sm:grid-cols-2">
        {CONSOLES.map((c) => (
          <a key={c.host} href={consoleUrl(c.host)} className="block">
            <Card className="h-full p-4 transition hover:border-signal/40">
              <div className="font-mono text-[12px] font-semibold uppercase tracking-widest text-white">{c.title}</div>
              <div className="mt-1 font-mono text-[10px] leading-5 text-muted">{c.blurb}</div>
              <div className="mt-3 font-mono text-[10px] text-signal">{consoleUrl(c.host)}</div>
            </Card>
          </a>
        ))}
      </div>
      <p className="font-mono text-[10px] leading-5 text-muted">
        If a <code>*.localhost</code> address does not open, add <code>127.0.0.1 command.localhost
        officer-a.localhost …</code> to your hosts file.
      </p>
    </div>
  );
}
