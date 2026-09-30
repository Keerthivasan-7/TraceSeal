import { useEffect, useState } from "react";

/** Ticks up once a second while `active` is true, resets to 0 otherwise.
 * There's no real progress percentage to report for these calls (a single
 * synchronous request, no server-sent progress events) — an honest elapsed
 * counter plus an indeterminate bar tells the operator it's genuinely still
 * working without inventing a completion percentage that isn't real. */
export function useElapsedSeconds(active: boolean): number {
  const [seconds, setSeconds] = useState(0);
  useEffect(() => {
    if (!active) {
      setSeconds(0);
      return;
    }
    const start = Date.now();
    setSeconds(0);
    const id = window.setInterval(() => setSeconds(Math.floor((Date.now() - start) / 1000)), 250);
    return () => window.clearInterval(id);
  }, [active]);
  return seconds;
}
