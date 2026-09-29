"""Investigation report and its statistical-conclusion summary text
(spec Section 11 step 8: "a statistical conclusion only ... never claim
guilt or intent. Always include a limitations section.")."""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np


@dataclass(frozen=True)
class InvestigationReport:
    scores: dict[str, float]
    threshold: float
    eps1: float
    n_observed: int
    n_total_positions: int
    n_erasures: int
    # Per-position observed soft bits (nan = erasure), full document length —
    # M5's evidence bundle embeds this verbatim (spec 7.5 step 4's "extracted
    # soft bits"). Defaults to empty so M2-era callers/tests are unaffected.
    observed_bits: np.ndarray = field(default_factory=lambda: np.array([]))

    @property
    def accused_sessions(self) -> list[str]:
        return sorted(
            (sid for sid, score in self.scores.items() if score > self.threshold),
            key=lambda sid: -self.scores[sid],
        )

    @property
    def top_session(self) -> str | None:
        if not self.scores:
            return None
        return max(self.scores, key=lambda sid: self.scores[sid])

    def summary(self) -> str:
        lines = []
        top = self.top_session
        if top is not None and self.scores[top] > self.threshold:
            lines.append(
                f"Consistent with session {top}: score {self.scores[top]:.2f} against "
                f"threshold {self.threshold:.2f} (eps1={self.eps1:g}); "
                f"{self.n_observed} of {self.n_total_positions} mark positions observed "
                f"({self.n_erasures} erased)."
            )
            others = [sid for sid in self.accused_sessions if sid != top]
            if others:
                lines.append(
                    f"Additional session(s) also exceeded the threshold: {', '.join(others)}."
                )
        else:
            lines.append(
                f"No session's score exceeded the threshold {self.threshold:.2f} "
                f"(eps1={self.eps1:g}) against {self.n_observed} of "
                f"{self.n_total_positions} observed positions ({self.n_erasures} erased). "
                "Insufficient evidence for attribution."
            )
        lines.append(
            "This is a statistical conclusion from per-position pixel correlation, "
            "suitable for investigative and evidentiary review — it is not a legal "
            "determination of guilt or intent, and does not yet include cryptographic "
            "evidence-chain verification (added in Milestone M5)."
        )
        return " ".join(lines)
