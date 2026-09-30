/** TraceSeal's mark: a hexagonal seal (precision, tamper-evidence) around an
 * off-center set of locating rings (the forensic trace that pinpoints
 * exactly which session a leak came from) — the two halves of the name,
 * as one minimal glyph. Renders in `currentColor` so it inherits whatever
 * text color its container sets, same as the lucide icon it replaced. */
export function Logo({ size = 20, className }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 100 100" fill="none" className={className} aria-hidden="true">
      <polygon points="50,7 87,28.5 87,71.5 50,93 13,71.5 13,28.5" stroke="currentColor" strokeWidth="5.5" strokeLinejoin="round" />
      <circle cx="59" cy="59" r="24" stroke="currentColor" strokeWidth="4" opacity="0.3" />
      <circle cx="59" cy="59" r="16" stroke="currentColor" strokeWidth="4" opacity="0.6" />
      <circle cx="59" cy="59" r="8" stroke="currentColor" strokeWidth="4.5" />
      <circle cx="59" cy="59" r="3.5" fill="currentColor" />
    </svg>
  );
}
