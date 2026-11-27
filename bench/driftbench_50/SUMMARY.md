# DriftBench-50 Comparative Empirical Report (v4.0.0)

Deterministic 50-endpoint x 360-tick (`18,000` observations) evaluation comparing:
1. **Static Single-Tick Threshold** (`|x_t| >= 2,200 bps` or raw `429`/`503`),
2. **Rolling Z-Score Window** (`W = 24`, `|z_t| >= 3.0`),
3. **Drift-Watch v4.0.0** (Corroborated Lorden/Moustakides Two-Sided CUSUM + Page-Hinkley + Ville E-Process + Coprime Weyl HTTP 304 + RFC 6962 JCS Receipts).

## 1. Detector Accuracy, Wilson 95% CIs, Detection Delay (ARL1), & Per-Tick Latency

| Detector | TP / 25 | FP / 25 | TPR (95% Wilson CI) | FPR (95% Wilson CI) | F1 | Mean Delay ARL1 (ticks) | p50 Latency (us) | p95 Latency (us) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Static Single-Tick | 25 | 10 | 1.0000 (0.8668..1.0000) | 0.4000 (0.2340..0.5926) | 0.8333 | 1.44 | 0.87 | 1.60 |
| Rolling Z-Score (W=24) | 25 | 24 | 1.0000 (0.8668..1.0000) | 0.9600 (0.8046..0.9929) | 0.6757 | 1 | 6.74 | 10.19 |
| **Drift-Watch v4.0.0** | **25** | **0** | **1.0000** (0.8668..1.0000) | **0.0000** (0.0000..0.1332) | **1.0000** | **3.04** | **17.94** | **89.67** |

## 2. Bandwidth Efficiency, Weyl Phase Dispersion, & RFC 6962 Transparency

- **RFC 9110 Conditional HTTP 304 Egress Reduction**: `78.15%` (`16,522,080` wire bytes vs `75,600,000` unconditional bytes across `18,000` polls).
- **Coprime Weyl Dispersion (`gcd(167, 288) = 1`)**: `50/50` unique phase slots (`0` collisions; `2..3` endpoints per UTC hour).
- **RFC 6962 Certificate Transparency Receipts**: `847/847` inclusion + consistency proofs verified offline (`merkle_root_sha256 = 64523fb5a8f64d47aff0fe9994f387766d75cc608b0777c535b6634caae46118`).
- **Out-of-Pocket Cloud & AI Neuron Cost**: `0.0000 USD` (`WORKERS_AI_MODE = DETERMINISTIC_REGEX_ONLY`).

## 3. Reproducibility Command

```bash
PYTHONPATH=src python3 bench/driftbench_50/run_driftbench_50.py
```
