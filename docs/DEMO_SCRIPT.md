# Demo Script

The full 9-step, under-10-minute demo (`make demo`) is documented here in
**Milestone M8**, once the web UI and every service it drives exist. See
`docs/SPEC.md` Section 18 for the target script.

## M0 stand-in

There is no UI yet. `make demo-m0` is the honest, milestone-scoped
equivalent: it brings up the `tscore` container, runs the crypto unit test
suite, runs the no-egress proof, and prints a plain PASS/FAIL summary plus a
reminder of what isn't built yet. See the `Makefile` and `README.md`.
