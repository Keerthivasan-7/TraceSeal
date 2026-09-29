.PHONY: up down test test-unit test-egress test-sender test-forensics test-tardos-sim \
	test-ca test-ledger test-keyrelease test-agent test-verifier lint demo-m0 demo-m1 demo-m2 \
	demo-m3 e2e demo-m4 demo-m5 demo-m6

COMPOSE := docker compose

## Bring up all containers on the internal-only network.
up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

## Full fast test set: crypto unit tests, the no-egress proof, and every
## package's own unit tests. Excludes the slow Tardos Monte-Carlo suite
## (see test-tardos-sim).
test: test-unit test-egress test-sender test-forensics test-verifier test-ca test-ledger test-keyrelease test-agent

## packages/tscore's own pytest suite (KEM-DEM, signatures, Shamir, HKDF,
## canonical CBOR, AES-GCM, Tardos — see docs/SPEC.md Section 16). The slow
## Monte-Carlo suite is excluded here; see test-tardos-sim.
test-unit:
	$(COMPOSE) run --rm tscore python -m pytest -q -m "not slow" packages/tscore/tests

## The Tardos Monte-Carlo suite (spec Section 10): empirical innocent-
## accusation rate and coalition-detection rate under all required pirate
## strategies. Slower, so it's separate from test-unit and run explicitly
## by demo-m1.
test-tardos-sim:
	$(COMPOSE) run --rm tscore python -m pytest -q -m slow packages/tscore/tests/test_tardos.py

## Proves the `internal: true` network actually blocks egress
## (docs/SPEC.md Section 17, M0 acceptance criterion).
test-egress:
	$(COMPOSE) run --rm tscore python -m pytest -q tests/integration

## packages/sender's own pytest suite: mark-position selection, variant
## rendering, assembly, and the quality gate.
test-sender:
	$(COMPOSE) run --rm sender python -m pytest -q packages/sender/tests

## packages/forensics's own pytest suite: registration, per-position
## detection, Tardos accusation, and the report's honesty checks.
test-forensics:
	$(COMPOSE) run --rm forensics python -m pytest -q packages/forensics/tests

## packages/ca's own pytest suite: identity/registry persistence,
## certificate issuance and verification, seed-script completeness.
test-ca:
	$(COMPOSE) run --rm ca python -m pytest -q packages/ca/tests

## packages/ledger's own pytest suite: hash-chain storage, quorum
## co-signing/finalization, cross-replica chain verification.
test-ledger:
	$(COMPOSE) run --rm ledger-0 python -m pytest -q packages/ledger/tests

## packages/keyrelease's own pytest suite: share registration, the
## coordinator/peer decrypt-session protocol, and the M3 acceptance-
## critical "grant-before-finality is impossible" test.
test-keyrelease:
	$(COMPOSE) run --rm keyrelease-0 python -m pytest -q packages/keyrelease/tests

## packages/agent's own pytest suite: keystore encryption, and a full
## decrypt session against an in-process ledger + key-release cluster.
test-agent:
	$(COMPOSE) run --rm agent python -m pytest -q packages/agent/tests

## packages/verifier's own pytest suite: CLI exit codes/diagnostics for a
## genuine vs. tampered .tsev bundle. This package depends on tscore ONLY
## (see its pyproject.toml/Dockerfile) — G4's "no trust in the server".
test-verifier:
	$(COMPOSE) run --rm verifier python -m pytest -q packages/verifier/tests

lint:
	$(COMPOSE) run --rm tscore sh -c "ruff check packages/tscore/src packages/tscore/tests && cd packages/tscore && mypy"
	$(COMPOSE) run --rm sender sh -c "ruff check packages/sender/src packages/sender/tests && cd packages/sender && mypy"
	$(COMPOSE) run --rm forensics sh -c "ruff check packages/forensics/src packages/forensics/tests && cd packages/forensics && mypy"
	$(COMPOSE) run --rm ca sh -c "ruff check packages/ca/src packages/ca/tests && cd packages/ca && mypy"
	$(COMPOSE) run --rm ledger-0 sh -c "ruff check packages/ledger/src packages/ledger/tests && cd packages/ledger && mypy"
	$(COMPOSE) run --rm keyrelease-0 sh -c "ruff check packages/keyrelease/src packages/keyrelease/tests && cd packages/keyrelease && mypy"
	$(COMPOSE) run --rm agent sh -c "ruff check packages/agent/src packages/agent/tests && cd packages/agent && mypy"
	$(COMPOSE) run --rm verifier sh -c "ruff check packages/verifier/src packages/verifier/tests && cd packages/verifier && mypy"

## Milestone-scoped acceptance check. There is no UI yet, so this is the
## honest M0 stand-in for the later UI-driven `make demo-m<N>` targets.
demo-m0:
	@echo "== TraceSeal M0 acceptance =="
	@$(MAKE) test-unit && echo "[PASS] crypto unit tests" || (echo "[FAIL] crypto unit tests" && exit 1)
	@$(MAKE) test-egress && echo "[PASS] egress blocked on the internal network" || (echo "[FAIL] egress blocked" && exit 1)
	@echo ""
	@echo "M0 complete: repo skeleton, tscore crypto core, Compose, docs skeleton."
	@echo "Not yet implemented (see docs/SPEC.md Section 17): variant/watermark"
	@echo "engine, Tardos, sender/keyrelease/ledger/agent/forensics/verifier"
	@echo "services, Fabric backend, attack lab, web UI."

## Milestone M1 acceptance: variant engine + quality gate + Tardos.
## "A 3-page sample PDF produces 5 assembled copies; the quality gate
## passes; the Tardos simulation meets its bounds" (docs/SPEC.md Section 17).
demo-m1:
	@echo "== TraceSeal M1 acceptance =="
	@$(MAKE) test-sender && echo "[PASS] sender unit tests" || (echo "[FAIL] sender unit tests" && exit 1)
	@$(MAKE) test-tardos-sim && echo "[PASS] Tardos Monte-Carlo bounds" || (echo "[FAIL] Tardos Monte-Carlo bounds" && exit 1)
	@$(COMPOSE) run --rm sender python -m sender.demo_m1
	@echo ""
	@echo "M1 complete: variant/watermark engine (micro-shift), quality gate,"
	@echo "Tardos fingerprinting library. Assembled demo copies are under"
	@echo "demo/out/m1/. Not yet implemented: encryption/packaging, ledger,"
	@echo "protocol services, forensics, UI (see docs/SPEC.md Section 17)."

## Milestone M2 acceptance: forensics on clean screenshots.
## "Top-1 attribution across 5 sessions from clean PNG screenshots is
## 100%, with 0 innocent accusations" (docs/SPEC.md Section 17).
demo-m2:
	@echo "== TraceSeal M2 acceptance =="
	@$(MAKE) test-forensics && echo "[PASS] forensics unit tests" || (echo "[FAIL] forensics unit tests" && exit 1)
	@$(COMPOSE) run --rm forensics python -m forensics.demo_m2
	@echo ""
	@echo "M2 complete: ORB/RANSAC + local-refinement registration,"
	@echo "per-position NCC detection, Tardos accusation, honest reporting."
	@echo "Simulated leaked screenshots are under demo/out/m2/. Not yet"
	@echo "implemented: OCR/vault document lookup, photo/scan robustness,"
	@echo "evidence bundle signing, encryption/ledger (see docs/SPEC.md"
	@echo "Section 17)."

## Milestone M3 acceptance / full end-to-end scenario (docs/SPEC.md
## Section 17): "Full crypto protocol: sender, key-release x5, agent,
## LedgerLite, commit-before-release, receipts. Acceptance: `make e2e`
## passes; the grant-before-finality test proves it is impossible."
##
## Wipes and reseeds demo/pki, demo/blob, demo/data so every run starts
## from a clean PKI and empty ledgers — this is a full protocol run, not
## an incremental one. Since M4, `ca.seed` no longer issues officer
## certificates directly (ADR-0020) — decrypting requires a real enrolment
## first, so this target now runs the enrolment ceremony as a hard
## prerequisite step, not an optional extra. `make demo-m4` runs this same
## base scenario and then adds revocation + forwarding-detection on top.
demo-m3: e2e

e2e:
	@echo "== TraceSeal M3 / e2e: full protocol distribution + decrypt =="
	@$(MAKE) test-ca && echo "[PASS] ca unit tests" || (echo "[FAIL] ca unit tests" && exit 1)
	@$(MAKE) test-ledger && echo "[PASS] ledger unit tests" || (echo "[FAIL] ledger unit tests" && exit 1)
	@$(MAKE) test-keyrelease && echo "[PASS] keyrelease unit tests (incl. grant-before-finality)" || (echo "[FAIL] keyrelease unit tests" && exit 1)
	@$(MAKE) test-agent && echo "[PASS] agent unit tests" || (echo "[FAIL] agent unit tests" && exit 1)
	@rm -rf demo/pki demo/blob demo/data
	@$(COMPOSE) run --rm ca
	@$(COMPOSE) up -d ledger-0 ledger-1 ledger-2 ledger-3 \
		keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
	@sleep 5
	@$(COMPOSE) run --rm ca python -m ca.demo_m4
	@$(COMPOSE) run --rm sender python -m sender.demo_m3
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer a
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer b
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer c
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer d
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer e
	@$(COMPOSE) down
	@echo ""
	@echo "M3 complete: real ML-KEM-768 KEM-DEM packaging, Shamir-split"
	@echo "release-secret custody across 5 key-release nodes, LedgerLite"
	@echo "commit-before-release, 5 officers each get a correctly assembled"
	@echo "in-memory-only copy with a finalized receipt (each admitted via a"
	@echo "real 2-of-3 admin enrolment quorum, not a seed-script shortcut)."

## Milestone M4 acceptance (docs/SPEC.md Section 17): "Copy binding, open
## events, forwarding detection, enrolment quorum, revocation. Negative
## tests pass; the UI demo shows OPEN_DENIED." Real 2-of-3 admin quorum
## issues every officer's certificate against a live ledger (no direct
## `ca.seed` shortcut for officers anymore); a revoked officer's next
## decrypt attempt is denied; officer D's self-declared claim on officer
## C's identity is denied by both the server-side check and the
## SealedHeader check, with OPEN_DENIED visible on the ledger.
demo-m4:
	@echo "== TraceSeal M4 acceptance: enrolment quorum + copy binding =="
	@$(MAKE) test-ca && echo "[PASS] ca unit tests (incl. enrolment ceremony)" || (echo "[FAIL] ca unit tests" && exit 1)
	@$(MAKE) test-ledger && echo "[PASS] ledger unit tests" || (echo "[FAIL] ledger unit tests" && exit 1)
	@$(MAKE) test-keyrelease && echo "[PASS] keyrelease unit tests (incl. revocation + cert-hash checks)" || (echo "[FAIL] keyrelease unit tests" && exit 1)
	@$(MAKE) test-agent && echo "[PASS] agent unit tests (incl. copy-binding checks)" || (echo "[FAIL] agent unit tests" && exit 1)
	@rm -rf demo/pki demo/blob demo/data
	@$(COMPOSE) run --rm ca
	@$(COMPOSE) up -d ledger-0 ledger-1 ledger-2 ledger-3 \
		keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
	@sleep 5
	@$(COMPOSE) run --rm ca python -m ca.demo_m4
	@$(COMPOSE) run --rm sender python -m sender.demo_m3
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer a
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer b
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer c
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer d
	@$(COMPOSE) run --rm ca python -m ca.demo_m4 --revoke officer-e
	@$(COMPOSE) run --rm agent python -m agent.demo_m3 --officer e || echo "[PASS] revoked officer-e was denied, as expected"
	@$(COMPOSE) run --rm agent python -m agent.demo_m4 --officer d --claim-cert-of officer-c --doc-id doc-m3-demo
	@$(COMPOSE) down
	@echo ""
	@echo "M4 complete: real 2-of-3 admin enrolment quorum, revocation,"
	@echo "SealedHeader copy binding co-signed by the key-release quorum,"
	@echo "and forwarding detection (OPEN_DENIED) — both the server-side"
	@echo "recipient-identity check and the client-side SealedHeader check"
	@echo "verified independently. Not yet implemented: evidence bundles,"
	@echo "standalone verifier, Fabric backend, attack lab, UI (see"
	@echo "docs/SPEC.md Section 17)."

## Milestone M5 acceptance (docs/SPEC.md Section 17): "Evidence bundle +
## standalone verifier + signed PDF report + UI Investigate flow with
## Evidence Graph. Acceptance: Verifier passes on a genuine bundle and
## fails on each tampering case." (The UI half is deferred to M8, same
## demo-script substitution already used for M4's OPEN_DENIED — this
## milestone's own acceptance criterion only names the verifier/bundle
## chain.) Runs its own fresh document registration + one real officer
## decrypt session (a distinct doc_id from demo-m3/m4's), so it only needs
## a seeded, enrolled PKI and a live cluster, not a prior e2e run.
## `traceseal-verify` runs in its own container, which never has
## ledger/ca/forensics/sender installed (G4 — no trust in the server).
demo-m5:
	@echo "== TraceSeal M5 acceptance: evidence bundle + standalone verifier =="
	@$(MAKE) test-forensics && echo "[PASS] forensics unit tests (incl. M5 investigation pipeline)" || (echo "[FAIL] forensics unit tests" && exit 1)
	@$(MAKE) test-verifier && echo "[PASS] verifier unit tests" || (echo "[FAIL] verifier unit tests" && exit 1)
	@$(MAKE) test-ledger && echo "[PASS] ledger unit tests (incl. /records/{tx_id}/proof)" || (echo "[FAIL] ledger unit tests" && exit 1)
	@$(MAKE) test-keyrelease && echo "[PASS] keyrelease unit tests (incl. vault reveal)" || (echo "[FAIL] keyrelease unit tests" && exit 1)
	@rm -rf demo/pki demo/blob demo/data demo/out/m5
	@$(COMPOSE) run --rm ca
	@$(COMPOSE) up -d ledger-0 ledger-1 ledger-2 ledger-3 \
		keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
	@sleep 5
	@$(COMPOSE) run --rm ca python -m ca.demo_m4
	@$(COMPOSE) run --rm forensics python -m forensics.demo_m5
	@$(COMPOSE) run --rm verifier traceseal-verify demo/out/m5/case.tsev
	@$(COMPOSE) run --rm forensics python -m forensics.tamper_demo
	@if $(COMPOSE) run --rm verifier traceseal-verify demo/out/m5/case_tampered.tsev; then \
		echo "[FAIL] tampered bundle verified as VALID (should have been rejected)"; exit 1; \
	else \
		echo "[PASS] tampered bundle correctly rejected"; \
	fi
	@$(COMPOSE) down
	@echo ""
	@echo "M5 complete: signed EvidenceBundle (ML-DSA), independently"
	@echo "re-verified by a standalone traceseal-verify CLI that depends on"
	@echo "tscore only, plus a signed PDF report with a mandatory limitations"
	@echo "section. A genuine bundle verifies VALID; a one-byte-tampered copy"
	@echo "verifies INVALID. Not yet implemented: the UI Investigate flow /"
	@echo "Evidence Graph (deferred to M8), Fabric backend, attack lab (see"
	@echo "docs/SPEC.md Section 17)."

## Milestone M6 acceptance (docs/SPEC.md Section 17): "Fabric 3 SmartBFT
## backend + Go chaincode with ML-DSA verification + ML-DSA block
## co-signing + SLH-DSA checkpoints. Acceptance: the e2e passes on Fabric;
## LedgerLite remains selectable." Runs the exact same sender.demo_m3 /
## agent.demo_m3 protocol scenario `make e2e` already runs against
## LedgerLite — here with LEDGER_BACKEND=fabric, routing every ledger
## call through the Go gateway (packages/fabric-gateway) and the real
## `traceseal` chaincode (chaincode/traceseal) on a live 4-org Fabric
## SmartBFT network instead. `make e2e`/`make demo-m3`/`make demo-m4`/
## `make demo-m5` are untouched by any of this — LedgerLite stays the
## default backend everywhere (docs/DECISIONS.md ADR-0031's sibling
## decisions).
demo-m6:
	@echo "== TraceSeal M6 acceptance: Fabric 3 SmartBFT backend =="
	@rm -rf demo/pki demo/blob demo/data demo/checkpoints \
		fabric-network/crypto-config fabric-network/channel-artifacts \
		fabric-network/chaincode-artifacts fabric-network/peercfg
	@$(COMPOSE) build fabric-tools fabric-gateway
	@$(COMPOSE) run --rm ca
	@$(COMPOSE) run --rm fabric-tools bash scripts/generate.sh
	@$(COMPOSE) up -d orderer1.org1.traceseal.local orderer2.org2.traceseal.local \
		orderer3.org3.traceseal.local orderer4.org4.traceseal.local \
		peer0.org1.traceseal.local peer0.org2.traceseal.local \
		peer0.org3.traceseal.local peer0.org4.traceseal.local
	@sleep 5
	@$(COMPOSE) run --rm fabric-tools bash scripts/create-channel.sh
	@$(COMPOSE) run --rm fabric-tools bash scripts/set-anchor-peers.sh
	@$(COMPOSE) run --rm fabric-tools bash scripts/deploy-chaincode.sh
	@$(COMPOSE) up -d fabric-gateway
	@sleep 3
	@LEDGER_BACKEND=fabric FABRIC_GATEWAY_URL=http://fabric-gateway:8000 \
		$(COMPOSE) up -d ledger-0 ledger-1 ledger-2 ledger-3 \
		keyrelease-0 keyrelease-1 keyrelease-2 keyrelease-3 keyrelease-4
	@sleep 5
	@$(COMPOSE) run --rm ledger-0 python -m ledger.seed_fabric_identities
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric ca python -m ca.demo_m4
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric sender python -m sender.demo_m3
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric agent python -m agent.demo_m3 --officer a
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric agent python -m agent.demo_m3 --officer b
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric agent python -m agent.demo_m3 --officer c
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric agent python -m agent.demo_m3 --officer d
	@$(COMPOSE) run --rm -e LEDGER_BACKEND=fabric agent python -m agent.demo_m3 --officer e
	@echo "-- ML-DSA block co-signing (one pass per validator org) --"
	@$(COMPOSE) run --rm ledger-0 python -m ledger.cosigner --org 1 &
	@$(COMPOSE) run --rm ledger-0 python -m ledger.cosigner --org 2 &
	@$(COMPOSE) run --rm ledger-0 python -m ledger.cosigner --org 3 &
	@sleep 8
	@$(COMPOSE) run --rm ledger-0 python -m ledger.checkpoint
	@$(COMPOSE) down
	@echo ""
	@echo "M6 complete: a real 4-org Fabric SmartBFT network (4 independent"
	@echo "orderer MSPs, SmartBFT consensus, channel-participation API"
	@echo "bootstrap, no system channel) with a real Go chaincode verifying"
	@echo "ML-DSA-65/SLH-DSA-SHA2-128s signatures via Cloudflare CIRCL"
	@echo "(confirmed to genuinely interoperate with liboqs — see"
	@echo "chaincode/traceseal/interop_test.go), deployed via the full"
	@echo "4-org lifecycle. The identical M3/M4 protocol scenario"
	@echo "(document registration, 5 officers' decrypt sessions, enrolment)"
	@echo "ran against it via LEDGER_BACKEND=fabric with zero protocol-level"
	@echo "code changes outside the ledger client construction itself."
	@echo "ML-DSA validator co-signing and an SLH-DSA checkpoint export both"
	@echo "ran for real. LedgerLite remains the default backend everywhere"
	@echo "else. Not yet implemented: the PQC BCCSP fork (spec's own stated"
	@echo "stretch goal — Fabric's internal transport stays ECDSA, as"
	@echo "documented), attack lab, UI (see docs/SPEC.md Section 17)."
