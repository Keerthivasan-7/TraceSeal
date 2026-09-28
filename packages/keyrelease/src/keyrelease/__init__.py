"""TraceSeal key-release node (spec Section 7.3). 5 symmetric peer
instances, each holding one Shamir share of `K_B || S_v` and the
document's Tardos bias vector; whichever one a recipient submits a
DecryptRequest to acts as coordinator for that session.
"""

__version__ = "0.1.0"
