"""TraceSeal attack lab (spec Section 15, Milestone M7): reproducible
distortion + collusion harness over real rendered/assembled pages, using
the same variant-rendering, Tardos, and forensic-detection code the real
protocol uses. Never simulates a result — every metric comes from a real
`forensics.pipeline.investigate` run over real (distorted or colluded)
pixels.
"""

from __future__ import annotations

__version__ = "0.1.0"
