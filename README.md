# Drift-Watch v4.0.0 — Sequential API, MCP, Policy, and Cloud Quota Drift Radar

**Zero-Dependency Python 3.10+ & Cloudflare Workers TypeScript · 33 Machine-Checked Pure-Init Lean 4 Theorems (`--trust=0`, `0 sorryAx`) · RFC 6962 + RFC 8785 Merkle Transparency · `0.0000 USD` Runtime Cost**

`Drift-Watch` (`v4.0.0`) is a dual-runtime sequential change-point detection, contractual schema/policy auditing, and cryptographic transparency engine designed for **continuous monitoring of developer APIs, Model Context Protocol (MCP) specifications, cloud free-tier quotas, and open-source grant endpoints**.

Built without third-party runtime dependencies across **Python 3.10+** (`src/drift_watch/`) and **Cloudflare Workers TypeScript + D1 SQLite** (`worker/cf_drift_watch_v4.ts`), `Drift-Watch` replaces brittle single-tick threshold checks and high-false-positive rolling z-scores with a corroborated sequential statistics pipeline, coprime Weyl phase dispersion, conditional `HTTP 304` egress reduction, and offline-verifiable Certificate Transparency receipts.

---

## Why Drift-Watch v4.0.0 Exists (Grant & Infrastructure Alignment)

Modern open-source ecosystems, autonomous agent runtimes, and public-interest developer tools depend silently on external HTTP/JSON contracts: rate-limit headers, free-tier quotas, JSON schemas, and deprecation schedules. Conventional monitors fail in three systematic ways:

1. **False-Alarm Fatigue on Transient Throttles:** Single-tick thresholds and sliding z-score windows alarm immediately on transient 1–3 tick `HTTP 429`/`503` bursts or normal diurnal traffic cycles (`40.0%` and `96.0%` false-positive rates on `DriftBench-50`).
2. **Thundering-Herd Polling & Cloud Split-Billing Cliffs:** Naive cron pollers synchronize requests at `:00` boundaries, exhaust D1 row-read quotas via full-table scans, or incur unexpected overage charges from unbundled Workers AI neuron usage and high-cardinality invocation logs/traces.
3. **Unverifiable Alert Provenance:** Ad-hoc webhook logs cannot prove *when* a breaking API mutation or quota cut was observed, or whether historical logs were silently truncated or altered.

`Drift-Watch v4.0.0` addresses all three gaps with **zero external runtime dependencies** and **`0.0000 USD` out-of-pocket cost**, aligned with:
- **Cloudflare Project Alexandria:** Edge-native Cloudflare Workers + D1 `0-SCAN` index architecture (`migrations/0001_drift_watch_v4_d1.sql`), Dec 1 Observability Split-Billing Shield (`wrangler.toml`), and deterministic `WORKERS_AI_MODE = "DETERMINISTIC_REGEX_ONLY"` zero-neuron enforcement.
- **Mozilla Fellowships Track II (Open Infrastructure & Digital Public Goods):** Transparent, offline-verifiable **RFC 6962** Merkle audit receipts and **RFC 8785** JCS canonicalization protecting public-interest APIs, research endpoints, and developer commons.
- **Agentic AI Foundation (AAIF) & OASIS SARIF v2.1.0:** Machine-actionable MCP/API contract drift rules (`DW-DRIFT-001..005`), bit-exact Python/WebCrypto parity, and machine-checked Lean 4 soundness proofs.

---

## Architecture Overview

| Layer | Python Module / Edge Artifact | Core Mathematical & Protocol Guarantee |
| :--- | :--- | :--- |
| **1. Coprime Weyl Phase Scheduler & HTTP 304** | `src/drift_watch/weyl_scheduler.py`<br>`worker/cf_drift_watch_v4.ts` | Modular Weyl sequence `(idx * 167 + 1) mod 288` (`gcd(167, 288) = 1`, Bézout inverse `119`) maps endpoints across 288 five-minute slots (`0..1435` min) with zero collisions, paired with **RFC 9110** strong `ETag` / `If-None-Match` `HTTP 304` short-circuiting and unsolicited-304 anomaly rejection. |
| **2. Clause-Scoped Policy & Schema Extractor** | `src/drift_watch/weyl_scheduler.py` | Deterministic zero-LLM extractor (`WORKERS_AI_MODE = "DETERMINISTIC_REGEX_ONLY"`) scoping quota caps to `FREE_SCOPE`, `CREDIT_SCOPE`, `PAID_SCOPE`, and `GENERAL_SCOPE` with negation-window guards (`no`, `not`, `never`, `without`, `zero`) and directional tightening checks (`DW-DRIFT-001..005`). |
| **3. Corroborated Sequential Detection** | `src/drift_watch/sequential_cusum.py`<br>`worker/cf_drift_watch_v4.ts` | Integer basis-point **Lorden (1971) / Moustakides (1986)** two-sided CUSUM corroborated with **Page (1954)** cumulative deviation (signed `trunc_div` matching JS `Math.trunc`), **Ville (1939)** anytime-valid non-negative supermartingale e-process (`2 / alpha` stopping threshold), and `corroboration_window` transient `429/502/503/504` burst quarantine. |
| **4. V8-Exact RFC 8785 JCS & RFC 6962 Merkle Log** | `src/drift_watch/merkle_transparency.py`<br>`worker/cf_drift_watch_v4.ts` | ECMA-262 / V8-exact **RFC 8785** JCS canonicalization (`-0.0 -> "0"`, UTF-16 code-unit key order, lone surrogate and non-finite float rejection) feeding an `O(log N)` binary-carry frontier **RFC 6962** Merkle accumulator (`0x00` leaf / `0x01` node domain separation) with offline `verify_inclusion_proof` and `verify_consistency_proof`. |
| **5. D1 `0-SCAN` Edge Runtime & Scale-to-Zero Mirror** | `migrations/0001_drift_watch_v4_d1.sql`<br>`server/drift_watch_edge_mirror.py` | Disjoint `UNION ALL` range seeks over `idx_dw_targets_cold_start` (partial) and `idx_dw_targets_active_due` (covering) verified via `EXPLAIN QUERY PLAN` with zero full-table scans, Strict-CSP3 headers, and `127.0.0.1` default host binding. |
| **6. Pure-Init Lean 4 Formal Soundness Kernel** | `formal/DriftWatchV4Formal.lean`<br>`formal/DriftWatchStreamSoundness.lean` | **33 machine-checked theorems** (`T01..T18` + `S01..S15`) compiled with `lean --trust=0 -DwarningAsError=true` using zero external libraries (`Init` only) and `0 sorryAx`. |

---

## Empirical Results (`DriftBench-50` Comparative Benchmark)

`bench/driftbench_50/run_driftbench_50.py` evaluates **50 deterministic endpoint traces x 360 ticks (`18,000` total observations, seed `20261127`)** spanning:
- **25 Persistent Drift Scenarios (onset `t = 120`):** `API_MCP_SCHEMA_BREAK` (5), `RATELIMIT_HEADER_CUT` (5), `PERSISTENT_STATUS_CLIFF` (5), `LATENCY_TAIL_SHIFT` (5), and `SILENT_POLICY_CONTRACT_DRIFT` (5).
- **25 Benign Null-Hypothesis Scenarios:** `BENIGN_STATIONARY_304` (8), `BENIGN_DIURNAL_AND_EXPANSION` (7, including negated assurances and free-tier quota expansions), and `BENIGN_TRANSIENT_3TICK_429_BURST` (10, each containing two 3-tick `HTTP 429` spikes).

Exact measured metrics from `bench/driftbench_50/results.json` and `bench/driftbench_50/SUMMARY.md`:

| Detector | TP / 25 | FP / 25 | TN / 25 | FN / 25 | TPR (95% Wilson CI) | FPR (95% Wilson CI) | F1 | Mean Delay ARL1 (ticks) | p50 Latency (us) | p95 Latency (us) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Static Single-Tick (`\|x\| >= 2200` bps or `429`/`503`) | 25 | 10 | 15 | 0 | 1.0000 (`0.8668..1.0000`) | 0.4000 (`0.2340..0.5926`) | 0.8333 | 1.44 | 0.87 | 1.60 |
| Rolling Z-Score (`W = 24`, `\|z\| >= 3.0`) | 25 | 24 | 1 | 0 | 1.0000 (`0.8668..1.0000`) | 0.9600 (`0.8046..0.9929`) | 0.6757 | 1.00 | 6.74 | 10.19 |
| **Drift-Watch v4.0.0** | **25** | **0** | **25** | **0** | **1.0000** (`0.8668..1.0000`) | **0.0000** (`0.0000..0.1332`) | **1.0000** | **3.04** | **17.94** | **89.67** |

### Operational, Bandwidth, & Cryptographic Measurements (`DriftBench-50`)

- **Pre-Onset False Alarms:** `0` (`Drift-Watch v4.0.0`) vs `14` (`Rolling Z-Score`).
- **RFC 9110 Conditional `HTTP 304` Egress Reduction:** **`78.15%`** (`78.1454%` exact; `16,522,080` actual wire bytes vs `75,600,000` unconditional baseline bytes; `14,696` `HTTP 304` hits across `18,000` polls).
- **Coprime Weyl Phase Dispersion (`gcd(167, 288) = 1`, inverse `119`):** `50/50` unique phase slots (`0` collisions, `2..3` endpoints per UTC hour, circular inter-endpoint gap `25..35` minutes).
- **RFC 6962 Transparency Receipts:** **`847/847`** inclusion and consistency proofs verified offline against root `64523fb5a8f64d47aff0fe9994f387766d75cc608b0777c535b6634caae46118`.
- **Cloud & AI Neuron Overages:** `0.0000 USD` (`WORKERS_AI_MODE = DETERMINISTIC_REGEX_ONLY`).

Reproduce `DriftBench-50` locally:

```bash
PYTHONPATH=src python3 bench/driftbench_50/run_driftbench_50.py
```

---

## Machine-Checked Pure-Init Lean 4 Formal Soundness (`33/33` Theorems, `0 sorryAx`)

Both formal modules compile standalone against Lean 4 `Init` only (zero Mathlib dependency) with `lean --trust=0 -DwarningAsError=true`.

### Part 1: `formal/DriftWatchV4Formal.lean` (`T01..T18`)

| ID | Theorem | Verified Property |
| :--- | :--- | :--- |
| `T01` | `T01_bezout_coprime_167_288` | `(167 * 119) % 288 = 1` exact Bézout modular inverse witness. |
| `T02` | `T02_general_coprime_weyl_injective` | General coprime `(step * inv) % m = 1` implies collision-free injectivity of `weylSlotGen`. |
| `T03` | `T03_weyl_slot_288_collision_free` | Instantiated 288-slot collision-free bijection for `(167, 288, 1)`. |
| `T04` | `T04_weyl_offset_1440_collision_free` | Instantiated 1440-minute slot collision-free injectivity. |
| `T05` | `T05_weyl_offset_in_day_and_5min_aligned` | Every offset satisfies `< 1440` and `% 5 = 0`. |
| `T06` | `T06_driftbench50_hourly_minimax_dispersion` | Every UTC hour `0..23` in `DriftBench-50` receives strictly `2` or `3` endpoints. |
| `T07` | `T07_http304_egress_strictly_bounded_and_saved` | Conditional `HTTP 304` actual egress `<= fullBytes` and `actual + saved = fullBytes`. |
| `T08` | `T08_cusum_nonneg_invariant` | Two-sided CUSUM scores remain non-negative (`>= 0`) for any finite trace. |
| `T09` | `T09_cusum_deadband_exact_zero` | Observations in `[mu0 - k, mu0 + k]` keep both CUSUM accumulators identically `0`. |
| `T10` | `T10_cusum_state_monotone_in_initial_score` | CUSUM state propagation is monotone in initial score `s1 <= s2`. |
| `T11` | `T11_cusum_threshold_alarm_antitone` | Lowering alarm threshold `h1 <= h2` preserves alarm firing. |
| `T12` | `T12_cusum_sustained_shift_linear_growth` | Sustained shifts `>= mu0 + k + d` (`d >= 1`) grow CUSUM score linearly (`>= s + len * d`). |
| `T13` | `T13_corroboration_window_blocks_transient_429_burst` | Bursts `< window` are suppressed (`false`) while cliffs `>= window` trigger (`true`). |
| `T14` | `T14_doob_optional_stopping_tree` | Discrete Doob optional stopping bound `expectedStoppedWealth t <= probMass t * rootWealth t`. |
| `T15` | `T15_markov_stopped_wealth_domination` | Markov domination `M * alarmMass M t <= expectedStoppedWealth t`. |
| `T16` | `T16_ville_one_sided_anytime_false_alarm_bound` | Ville (1939) anytime-valid bound `M * alarmMass M t <= probMass t * rootWealth t`. |
| `T17` | `T17_ville_two_sided_union_false_alarm_bound` | Two-sided union bound `M * alarmUnion <= 2 * (P * W0)`. |
| `T18` | `T18_rfc6962_leaf_node_domain_disjoint` | RFC 6962 `0x00` leaf and `0x01` node prefixes are disjoint and collision-free under injective compression. |

### Part 2: `formal/DriftWatchStreamSoundness.lean` (`S01..S15`)

| ID | Theorem | Verified Property |
| :--- | :--- | :--- |
| `S01` | `S01_unscoped_setdiff_blind_to_tier_swap` | Demonstrates unscoped bag-of-numbers blindness on tier swaps vs clause-scoped detection. |
| `S02` | `S02_directional_quota_lattice_asymmetry` | Quota expansions never trigger tightening while contractions strictly do. |
| `S03` | `S03_negation_window_blocks_assurance_false_positive` | Negated policy clauses (`hasNegationWindow = true`) suppress false alarms. |
| `S04` | `S04_dual_anchor_catches_gradual_erosion` | Comparing against initial baseline anchor catches multi-step `< 10%` creeping quota erosion. |
| `S05` | `S05_sliding_window_sum_exact_conservation` | Single-step sliding window enter/exit conservation identity. |
| `S06` | `S06_sliding_window_multi_step_telescope` | Inductive multi-step sliding window telescoping sum conservation. |
| `S07` | `S07_adaptive_spectral_order_bounds_and_antitonicity` | Spectral order bounds `1000 <= adaptiveOrderQBps <= 20000` and antitonicity. |
| `S08` | `S08_centered_perturbation_zero_sum` | Centered perturbation residuals sum identically to `0`. |
| `S09` | `S09_martingale_mmd_incremental_bilinear_identity` | Incremental bilinear cross-pair update identity for streaming MMD. |
| `S10` | `S10_martingale_mmd_inductive_prefix_sum` | Online `foldr` accumulator equals quadratic `streamCrossPairs` plus running prefix sum. |
| `S11` | `S11_martingale_mmd_exchangeable_antisymmetry` | Exchangeable antisymmetry cancellation under identical pre/post distributions. |
| `S12` | `S12_hinge_alert_budget_subadditivity` | Subadditivity of alert hinge budget under combined event streams. |
| `S13` | `S13_byzantine_quorum_intersection_safety` | For `3 * f + 1 <= n`, corroboration quorum satisfies `>= 3` and `f + 1 + n <= 2 * quorum`. |
| `S14` | `S14_drift_gate_fail_closed_and_bounded` | Release gate fails closed (`-26000`) when quorum or clause-scoping fails, and is bounded in `[4000, 9200]`. |
| `S15` | `S15_drift_gate_discrete_supermodularity` | Discrete mixed second differences equal `+2`, proving supermodularity across F1, AUROC, and throughput. |

Verify both Lean 4 modules directly:

```bash
lean --trust=0 -DwarningAsError=true formal/DriftWatchV4Formal.lean
lean --trust=0 -DwarningAsError=true formal/DriftWatchStreamSoundness.lean
```

---

## SARIF v2.1.0 Rules & CLI Usage

`Drift-Watch` emits deterministic OASIS SARIF v2.1.0 reports (`DW-DRIFT-001..005`) sealed with RFC 6962 transparency receipts:

| Rule ID | Name | Level | Trigger |
| :--- | :--- | :--- | :--- |
| `DW-DRIFT-001` | `ApiOrMcpSchemaBreakingDrift` | `error` | API or MCP JSON contract field removal or type mutation |
| `DW-DRIFT-002` | `QuotaOrRateLimitTightening` | `error` | Clause-scoped free-tier quota cut or IETF `RateLimit` header tightening |
| `DW-DRIFT-003` | `SequentialStatisticalDrift` | `warning` | Corroborated CUSUM + Page-Hinkley / Ville e-process latency or residual shift |
| `DW-DRIFT-004` | `ClauseScopedPolicyRestriction` | `error` | Non-negated billing wall or commercial restriction added |
| `DW-DRIFT-005` | `EndpointDeprecationOrPersistentCliff` | `error` | Corroborated `HTTP 410 Gone` or persistent `429`/`503` outage cliff |

### Quickstart

```bash
# 1. Install editable Python package (zero third-party runtime dependencies)
python3 -m pip install -e .

# 2. Run full unit + Python <-> Node.js WebCrypto cross-runtime parity suite
python3 -W error::DeprecationWarning -m unittest discover -s tests -v

# 3. Scan an endpoint trace, emit SARIF v2.1.0 + RFC 6962 receipt, and verify offline
drift-watch scan trace.json --sarif-out drift.sarif.json --receipt-out receipt.json --fail-on-drift
drift-watch verify-receipt receipt.json

# 4. Run DriftBench-50 comparative evaluation
drift-watch benchmark --ticks 360 --json-out bench_results.json
```

---

## Cloudflare Workers Edge & Scale-to-Zero WSGI Mirror

### 1. Edge Mirror (`server/drift_watch_edge_mirror.py`, `Dockerfile`)

Initializes an in-memory SQLite mirror from `migrations/0001_drift_watch_v4_d1.sql`, audits `COLD_START_HEAL_SQL` from `worker/cf_drift_watch_v4.ts` via `EXPLAIN QUERY PLAN` for zero full-table scans, validates the Dec 1 Observability Split-Billing Shield in `wrangler.toml`, and serves `GET`/`HEAD` routes with Strict-CSP3 headers (`127.0.0.1` default bare-host bind):

| Path | Methods | Description |
| :--- | :--- | :--- |
| `/` | `GET`, `HEAD` | Strict-CSP3 HTML overview (`?format=json` returns JSON health payload) |
| `/health`, `/healthz` | `GET`, `HEAD` | Active/core target counts, Weyl uniqueness, `0-SCAN` SQLite audit, and `wrangler.toml` shield status |
| `/telemetry/24h` | `GET`, `HEAD` | Hourly poll / `HTTP 304` / quarantine / drift rollup (`dw_poll_hourly_rollup`) |

```bash
python3 server/drift_watch_edge_mirror.py           # Print JSON health + 0-SCAN audit
python3 server/drift_watch_edge_mirror.py --serve   # Start local WSGI server on 127.0.0.1:8080
```

### 2. Ephemeral Cloudflare Workers + D1 Deployment (`scripts/deploy_cloudflare.py`)

`scripts/deploy_cloudflare.py` injects the live D1 UUID into a temporary Wrangler config at deploy time so tracked `wrangler.toml` never stores deployment identifiers:

```bash
python3 scripts/deploy_cloudflare.py --dry-run --outdir /tmp/dw_v4_dist
python3 scripts/deploy_cloudflare.py --db-uuid <YOUR_D1_DATABASE_UUID>
```

---

## Open-Source Verification Commons (5-Repository Suite)

`Drift-Watch` is part of an integrated, zero-dependency, Lean 4-verified open-source verification commons:

| Repository | Role in the Commons | Link |
| :--- | :--- | :--- |
| **ProofGate** (`v2.0.0`) | Six-layer formal verification gate & multi-step DIFC trajectory security for autonomous AI agents | [github.com/alpalbayrak91-boop/proofgate](https://github.com/alpalbayrak91-boop/proofgate) |
| **WheelCap** (`v2.0.0`) | Differential source-to-wheel capability gate, constant-folding reflection audit, PEP 770 / CycloneDX 1.6 / SLSA v1.0 | [github.com/alpalbayrak91-boop/wheelcap](https://github.com/alpalbayrak91-boop/wheelcap) |
| **Temporal-GABA-Memory** (`v1.0.0`) | Bi-temporal belief revision, cellular-sheaf consistency, negative-knowledge tracking, and Vendi diversity scoring | [github.com/alpalbayrak91-boop/temporal-gaba-memory](https://github.com/alpalbayrak91-boop/temporal-gaba-memory) |
| **LeakSpec** (`v2.7.0`) | 5-layer causal, Kramers–Kronig spectral, SimHash64/MinHash-LSH contamination, and SARIF v2.1.0 leakage auditor | [github.com/alpalbayrak91-boop/leakspec-cli](https://github.com/alpalbayrak91-boop/leakspec-cli) |
| **Drift-Watch** (`v4.0.0`) | Sequential API, MCP, policy, and cloud quota drift radar with coprime Weyl HTTP 304 & RFC 6962 receipts | [github.com/alpalbayrak91-boop/drift-watch](https://github.com/alpalbayrak91-boop/drift-watch) |

---

## References

1. **Page, E. S.** (1954). Continuous Inspection Schemes. *Biometrika*, 41(1/2), 100–115.
2. **Lorden, G.** (1971). Procedures for Reacting to a Change in Distribution. *Annals of Mathematical Statistics*, 42(6), 1897–1908.
3. **Moustakides, G. V.** (1986). Optimal Stopping Times for Detecting Changes in Distributions. *Annals of Statistics*, 14(4), 1379–1387.
4. **Ville, J.** (1939). *Étude critique de la notion de collectif*. Monographies des Probabilités, Gauthier-Villars, Paris.
5. **Weyl, H.** (1916). Über die Gleichverteilung von Zahlen mod. Eins. *Mathematische Annalen*, 77(3), 313–352.
6. **Wilson, E. B.** (1927). Probable Inference, the Law of Succession, and Statistical Inference. *Journal of the American Statistical Association*, 22(158), 209–212.
7. **Laurie, B., Langley, A., & Kasper, E.** (2013). *Certificate Transparency* (IETF RFC 6962, Section 2.1).
8. **Rundgren, A., Jordan, B., & Erdtman, S.** (2020). *JSON Canonicalization Scheme (JCS)* (IETF RFC 8785).
9. **Fielding, R., Nottingham, M., & Reschke, J.** (2022). *HTTP Semantics* (IETF RFC 9110, Sections 8.8.3 & 13.1.2).

---

## Citation & License

- **Author:** Alp Albayrak ([ORCID: 0009-0008-9737-4477](https://orcid.org/0009-0008-9737-4477))
- **Citation Metadata:** [`CITATION.cff`](CITATION.cff) · [`Zenodo JSON`](.zenodo.json)
- **License:** [MIT License](LICENSE). All monetary units are expressed strictly in `USD`.
