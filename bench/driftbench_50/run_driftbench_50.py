#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""DriftBench-50: Deterministic 50-Trace Multi-Endpoint Drift Detection Benchmark.

Evaluates 50 realistic multi-endpoint traces (360 ticks each = 18,000 observations):
- 25 Persistent Drift Scenarios (onset t = 120):
    1. API / MCP JSON schema breaking mutation (5 traces)
    2. IETF RateLimit header envelope cap tightening (5 traces)
    3. Persistent HTTP 410 Gone / sustained HTTP 429 cliff (5 traces)
    4. Sustained latency-tail / throughput shift & creeping erosion (5 traces)
    5. Silent HTTP 200 clause-scoped policy / billing-wall drift (5 traces)
- 25 Benign Null-Hypothesis Scenarios:
    6. Stationary conditional HTTP 304 traffic (8 traces)
    7. Diurnal sinusoidal traffic + negated assurance + quota expansion (7 traces)
    8. Transient 3-tick HTTP 429 bursts with clean recovery (10 traces)

Compares:
  1. Static Single-Tick Threshold Baseline
  2. Rolling Z-Score Window Baseline (W = 24, z >= 3.0)
  3. Drift-Watch v4.0.0 (Corroborated Lorden/Moustakides CUSUM + Page-Hinkley + Ville E-Process + Weyl HTTP 304)
"""

from __future__ import annotations

import json
import math
import pathlib
import random
import statistics
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from drift_watch import (  # noqa: E402
    CorroboratedDriftMonitor,
    Rfc6962MerkleAccumulator,
    RollingZScoreBaseline,
    StaticThresholdBaseline,
    WeylPhaseScheduler,
    __version__,
    evaluate_contract_drift,
    extract_clause_scoped_contract,
    verify_transparency_receipt,
)

MASTER_SEED = 20261127
CHANGE_ONSET_TICK = 120


def wilson_ci_95(successes: int, total: int, z: float = 1.959963984540054) -> Tuple[float, float]:
    """Exact Wilson (1927) 95% binomial score confidence interval."""
    if total <= 0:
        return (0.0, 0.0)
    p = float(successes) / float(total)
    n = float(total)
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z / denom) * math.sqrt((p * (1.0 - p)) / n + z2 / (4.0 * n * n))
    return (round(max(0.0, center - half), 6), round(min(1.0, center + half), 6))


def _pct_us(samples_ns: Sequence[int], q: float) -> float:
    if not samples_ns:
        return 0.0
    ordered = sorted(samples_ns)
    idx = min(len(ordered) - 1, max(0, int(round(q * (len(ordered) - 1)))))
    return round(ordered[idx] / 1_000.0, 3)


def build_50_scenarios() -> List[Dict[str, Any]]:
    """Construct 25 persistent drift scenarios and 25 benign diurnal / 3-tick 429 scenarios."""
    scheduler = WeylPhaseScheduler()
    scenarios: List[Dict[str, Any]] = []

    drift_classes = [
        ("API_MCP_SCHEMA_BREAK", True),
        ("RATELIMIT_HEADER_CUT", True),
        ("PERSISTENT_STATUS_CLIFF", True),
        ("LATENCY_TAIL_SHIFT", True),
        ("SILENT_POLICY_CONTRACT_DRIFT", True),
    ]
    for c_idx, (cname, is_drift) in enumerate(drift_classes):
        for k in range(5):
            idx = c_idx * 5 + k
            scenarios.append(
                {
                    "index": idx,
                    "endpoint_id": f"W{idx + 1:02d}",
                    "scenario_class": cname,
                    "has_persistent_drift": is_drift,
                    "period_min": 15,
                    "weyl_slot": scheduler.slot_for(idx),
                    "weyl_offset_min": scheduler.minute_offset_for(idx),
                }
            )

    benign_specs = (
        [("BENIGN_STATIONARY_304", False)] * 8
        + [("BENIGN_DIURNAL_AND_EXPANSION", False)] * 7
        + [("BENIGN_TRANSIENT_3TICK_429_BURST", False)] * 10
    )
    for b_idx, (bname, is_drift) in enumerate(benign_specs):
        idx = 25 + b_idx
        scenarios.append(
            {
                "index": idx,
                "endpoint_id": f"W{idx + 1:02d}",
                "scenario_class": bname,
                "has_persistent_drift": is_drift,
                "period_min": 15,
                "weyl_slot": scheduler.slot_for(idx),
                "weyl_offset_min": scheduler.minute_offset_for(idx),
            }
        )
    return scenarios


def _compute_detector_summary(
    tp: int,
    fp: int,
    tn: int,
    fn: int,
    pre_onset_fa: int,
    delays: Sequence[int],
    latencies_ns: Sequence[int],
) -> Dict[str, Any]:
    pos_total = tp + fn
    neg_total = tn + fp
    tpr = float(tp) / float(pos_total) if pos_total else 0.0
    fpr = float(fp) / float(neg_total) if neg_total else 0.0
    prec = float(tp) / float(tp + fp) if (tp + fp) else 0.0
    f1 = (2.0 * prec * tpr / (prec + tpr)) if (prec + tpr) > 0.0 else 0.0
    return {
        "TP": tp,
        "FP": fp,
        "TN": tn,
        "FN": fn,
        "pre_onset_false_alarms": pre_onset_fa,
        "tpr": round(tpr, 6),
        "tpr_wilson_95_ci": list(wilson_ci_95(tp, pos_total)),
        "fpr": round(fpr, 6),
        "fpr_wilson_95_ci": list(wilson_ci_95(fp, neg_total)),
        "precision": round(prec, 6),
        "f1": round(f1, 6),
        "arl1_mean_delay_ticks": round(statistics.mean(delays), 3) if delays else None,
        "arl1_median_delay_ticks": round(float(statistics.median(delays)), 3) if delays else None,
        "arl1_max_delay_ticks": int(max(delays)) if delays else None,
        "tick_latency_mean_us": round((sum(latencies_ns) / float(len(latencies_ns))) / 1_000.0, 3)
        if latencies_ns
        else 0.0,
        "tick_latency_p50_us": _pct_us(latencies_ns, 0.50),
        "tick_latency_p95_us": _pct_us(latencies_ns, 0.95),
    }


def _render_summary_markdown(res: Dict[str, Any]) -> str:
    d_stat = res["detectors"]["static_single_tick"]
    d_roll = res["detectors"]["rolling_zscore"]
    d_dw4 = res["detectors"]["drift_watch_v4"]
    weyl = res["weyl_dispersion_audit"]

    lines = [
        "# DriftBench-50 Comparative Empirical Report (v4.0.0)",
        "",
        "Deterministic 50-endpoint x 360-tick (`18,000` observations) evaluation comparing:",
        "1. **Static Single-Tick Threshold** (`|x_t| >= 2,200 bps` or raw `429`/`503`),",
        "2. **Rolling Z-Score Window** (`W = 24`, `|z_t| >= 3.0`),",
        "3. **Drift-Watch v4.0.0** (Corroborated Lorden/Moustakides Two-Sided CUSUM + Page-Hinkley + Ville E-Process + Coprime Weyl HTTP 304 + RFC 6962 JCS Receipts).",
        "",
        "## 1. Detector Accuracy, Wilson 95% CIs, Detection Delay (ARL1), & Per-Tick Latency",
        "",
        "| Detector | TP / 25 | FP / 25 | TPR (95% Wilson CI) | FPR (95% Wilson CI) | F1 | Mean Delay ARL1 (ticks) | p50 Latency (us) | p95 Latency (us) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        (
            f"| Static Single-Tick | {d_stat['TP']} | {d_stat['FP']} | "
            f"{d_stat['tpr']:.4f} ({d_stat['tpr_wilson_95_ci'][0]:.4f}..{d_stat['tpr_wilson_95_ci'][1]:.4f}) | "
            f"{d_stat['fpr']:.4f} ({d_stat['fpr_wilson_95_ci'][0]:.4f}..{d_stat['fpr_wilson_95_ci'][1]:.4f}) | "
            f"{d_stat['f1']:.4f} | {d_stat['arl1_mean_delay_ticks']} | "
            f"{d_stat['tick_latency_p50_us']:.2f} | {d_stat['tick_latency_p95_us']:.2f} |"
        ),
        (
            f"| Rolling Z-Score (W=24) | {d_roll['TP']} | {d_roll['FP']} | "
            f"{d_roll['tpr']:.4f} ({d_roll['tpr_wilson_95_ci'][0]:.4f}..{d_roll['tpr_wilson_95_ci'][1]:.4f}) | "
            f"{d_roll['fpr']:.4f} ({d_roll['fpr_wilson_95_ci'][0]:.4f}..{d_roll['fpr_wilson_95_ci'][1]:.4f}) | "
            f"{d_roll['f1']:.4f} | {d_roll['arl1_mean_delay_ticks']} | "
            f"{d_roll['tick_latency_p50_us']:.2f} | {d_roll['tick_latency_p95_us']:.2f} |"
        ),
        (
            f"| **Drift-Watch v4.0.0** | **{d_dw4['TP']}** | **{d_dw4['FP']}** | "
            f"**{d_dw4['tpr']:.4f}** ({d_dw4['tpr_wilson_95_ci'][0]:.4f}..{d_dw4['tpr_wilson_95_ci'][1]:.4f}) | "
            f"**{d_dw4['fpr']:.4f}** ({d_dw4['fpr_wilson_95_ci'][0]:.4f}..{d_dw4['fpr_wilson_95_ci'][1]:.4f}) | "
            f"**{d_dw4['f1']:.4f}** | **{d_dw4['arl1_mean_delay_ticks']}** | "
            f"**{d_dw4['tick_latency_p50_us']:.2f}** | **{d_dw4['tick_latency_p95_us']:.2f}** |"
        ),
        "",
        "## 2. Bandwidth Efficiency, Weyl Phase Dispersion, & RFC 6962 Transparency",
        "",
        f"- **RFC 9110 Conditional HTTP 304 Egress Reduction**: `{res['http_304_egress_reduction_pct']:.2f}%` "
        f"(`{res['actual_wire_bytes']:,}` wire bytes vs `{res['unconditional_baseline_bytes']:,}` unconditional bytes across `{res['total_ticks_evaluated']:,}` polls).",
        f"- **Coprime Weyl Dispersion (`gcd(167, 288) = 1`)**: `{weyl['unique_slots']}/50` unique phase slots "
        f"(`{weyl['collision_count']}` collisions; `{weyl['hourly_min_endpoints']}..{weyl['hourly_max_endpoints']}` endpoints per UTC hour).",
        f"- **RFC 6962 Certificate Transparency Receipts**: `{res['verified_merkle_receipts']}/{res['merkle_tree_size']}` "
        f"inclusion + consistency proofs verified offline (`merkle_root_sha256 = {res['merkle_root_sha256']}`).",
        "- **Out-of-Pocket Cloud & AI Neuron Cost**: `0.0000 USD` (`WORKERS_AI_MODE = DETERMINISTIC_REGEX_ONLY`).",
        "",
        "## 3. Reproducibility Command",
        "",
        "```bash",
        "PYTHONPATH=src python3 bench/driftbench_50/run_driftbench_50.py",
        "```",
        "",
    ]
    return "\n".join(lines)


def run_driftbench_50(
    ticks_per_trace: int = 360,
    seed: int = MASTER_SEED,
    write_outputs: bool = True,
) -> Dict[str, Any]:
    rng = random.Random(seed)
    scenarios = build_50_scenarios()
    scheduler = WeylPhaseScheduler()
    weyl_audit = scheduler.dispersion_audit(len(scenarios))
    merkle_acc = Rfc6962MerkleAccumulator()

    counts = {
        "static_single_tick": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "pre_fa": 0, "delays": [], "lat_ns": []},
        "rolling_zscore": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "pre_fa": 0, "delays": [], "lat_ns": []},
        "drift_watch_v4": {"tp": 0, "fp": 0, "tn": 0, "fn": 0, "pre_fa": 0, "delays": [], "lat_ns": []},
    }

    total_ticks = 0
    total_304_hits = 0
    actual_wire_bytes = 0
    unconditional_bytes = 0
    verified_receipts = 0
    by_class: Dict[str, Dict[str, int]] = {}

    for sc in scenarios:
        ep_id = sc["endpoint_id"]
        sclass = sc["scenario_class"]
        is_drift = bool(sc["has_persistent_drift"])
        by_class.setdefault(sclass, {"traces": 0, "static_alarms": 0, "zscore_alarms": 0, "dw4_alarms": 0})
        by_class[sclass]["traces"] += 1

        det_static = StaticThresholdBaseline(threshold_bps=2_200)
        det_zscore = RollingZScoreBaseline(window_size=24, z_thresh=3.0)
        det_dw4 = CorroboratedDriftMonitor(
            ep_id,
            merkle_accumulator=merkle_acc,
            corroboration_window=4,
            structural_corroboration_ticks=2,
        )

        base_etag = f'"{ep_id}-v1"'
        drift_etag = f'"{ep_id}-v2"'
        base_body = "Free tier includes 10,000 requests/day. No credit card required for developer access."
        base_headers = {"RateLimit-Limit": "1000"}
        base_schema = {"id": "string", "quota_remaining": "integer", "items": "array"}
        base_contract = extract_clause_scoped_contract(
            base_body, headers=base_headers, json_schema_fields=base_schema
        )

        stat_pre_fa = z_pre_fa = dw4_pre_fa = False
        stat_det_delay: Optional[int] = None
        z_det_delay: Optional[int] = None
        dw4_det_delay: Optional[int] = None
        stat_any_fa = z_any_fa = dw4_any_fa = False

        for t in range(ticks_per_trace):
            total_ticks += 1
            epoch_min = 29_932_000 + t * sc["period_min"] + sc["weyl_offset_min"]
            jitter = max(-950, min(950, int(round(rng.gauss(0.0, 380.0)))))

            http_status = 304 if (t > 0 and rng.random() < 0.88) else 200
            etag = base_etag
            body = base_body
            headers = dict(base_headers)
            schema = dict(base_schema)
            x_bps = jitter

            if sclass == "BENIGN_DIURNAL_AND_EXPANSION":
                diurnal = int(round(520.0 * math.sin(2.0 * math.pi * float(t) / 96.0)))
                x_bps = diurnal + int(round(0.65 * jitter))
                if t >= 150:
                    if t in (150, 151):
                        http_status = 200
                    etag = f'"{ep_id}-expanded"'
                    body = "Free tier expanded to 25,000 requests/day. No credit card required."
                    headers = {"RateLimit-Limit": "2500"}
            elif sclass == "BENIGN_TRANSIENT_3TICK_429_BURST":
                if t in (90, 91, 92, 210, 211, 212):
                    http_status = 429
                    etag = ""
                    x_bps = 14_000

            elif is_drift and t >= CHANGE_ONSET_TICK:
                if sclass == "API_MCP_SCHEMA_BREAK":
                    if t in (CHANGE_ONSET_TICK, CHANGE_ONSET_TICK + 1, CHANGE_ONSET_TICK + 2):
                        http_status = 200
                    etag = drift_etag
                    schema = {"id": "string", "quota_remaining": "string"}
                elif sclass == "RATELIMIT_HEADER_CUT":
                    if t in (CHANGE_ONSET_TICK, CHANGE_ONSET_TICK + 1, CHANGE_ONSET_TICK + 2):
                        http_status = 200
                    etag = drift_etag
                    headers = {"RateLimit-Limit": "150"}
                    x_bps = -1_400 + jitter
                elif sclass == "PERSISTENT_STATUS_CLIFF":
                    http_status = 410 if (sc["index"] % 2 == 0) else 429
                    etag = ""
                    x_bps = 9_500 + jitter
                elif sclass == "LATENCY_TAIL_SHIFT":
                    if sc["index"] % 2 == 0:
                        x_bps = 2_450 + jitter
                    else:
                        x_bps = min(2_750, 1_350 + (t - CHANGE_ONSET_TICK + 1) * 140) + jitter
                elif sclass == "SILENT_POLICY_CONTRACT_DRIFT":
                    if t in (CHANGE_ONSET_TICK, CHANGE_ONSET_TICK + 1, CHANGE_ONSET_TICK + 2):
                        http_status = 200
                    etag = drift_etag
                    body = "Free tier reduced to 1,000 requests/day. Credit card required for API access."

            wire_b = 180 if http_status == 304 else 4_200
            full_b = 4_200

            contract_changed = False
            if http_status == 200:
                curr_c = extract_clause_scoped_contract(body, headers=headers, json_schema_fields=schema)
                contract_changed = evaluate_contract_drift(base_contract, curr_c)["adverse_contract_drift"]

            ts0 = time.perf_counter_ns()
            s_alarm = det_static.update(x_bps, http_status=http_status, contract_changed=contract_changed)
            ts1 = time.perf_counter_ns()
            counts["static_single_tick"]["lat_ns"].append(ts1 - ts0)

            tz0 = time.perf_counter_ns()
            z_alarm = det_zscore.update(x_bps, contract_changed=contract_changed)
            tz1 = time.perf_counter_ns()
            counts["rolling_zscore"]["lat_ns"].append(tz1 - tz0)

            td0 = time.perf_counter_ns()
            dw4_out = det_dw4.observe_tick(
                epoch_min=epoch_min,
                http_status=http_status,
                residual_bps=x_bps,
                etag=etag,
                wire_bytes=wire_b,
                full_representation_bytes=full_b,
                body_text=body if http_status == 200 else "",
                headers=headers if http_status == 200 else None,
                json_schema_fields=schema if http_status == 200 else None,
            )
            td1 = time.perf_counter_ns()
            counts["drift_watch_v4"]["lat_ns"].append(td1 - td0)

            if dw4_out["receipt"] is not None:
                ver = verify_transparency_receipt(dw4_out["receipt"])
                if not ver["verified"]:
                    raise RuntimeError(f"Merkle receipt verification failed: {ver}")
                verified_receipts += 1

            dw4_alarm = bool(dw4_out["alarm"])

            if not is_drift:
                stat_any_fa = stat_any_fa or s_alarm
                z_any_fa = z_any_fa or z_alarm
                dw4_any_fa = dw4_any_fa or dw4_alarm
            else:
                if t < CHANGE_ONSET_TICK:
                    stat_pre_fa = stat_pre_fa or s_alarm
                    z_pre_fa = z_pre_fa or z_alarm
                    dw4_pre_fa = dw4_pre_fa or dw4_alarm
                else:
                    if s_alarm and stat_det_delay is None:
                        stat_det_delay = t - CHANGE_ONSET_TICK + 1
                    if z_alarm and z_det_delay is None:
                        z_det_delay = t - CHANGE_ONSET_TICK + 1
                    if dw4_alarm and dw4_det_delay is None:
                        dw4_det_delay = t - CHANGE_ONSET_TICK + 1

        total_304_hits += det_dw4.poll_sm.http_304_hits
        actual_wire_bytes += det_dw4.poll_sm.actual_egress_bytes
        unconditional_bytes += det_dw4.poll_sm.unconditional_egress_bytes

        if not is_drift:
            counts["static_single_tick"]["fp" if stat_any_fa else "tn"] += 1
            counts["rolling_zscore"]["fp" if z_any_fa else "tn"] += 1
            counts["drift_watch_v4"]["fp" if dw4_any_fa else "tn"] += 1
            by_class[sclass]["static_alarms"] += int(stat_any_fa)
            by_class[sclass]["zscore_alarms"] += int(z_any_fa)
            by_class[sclass]["dw4_alarms"] += int(dw4_any_fa)
        else:
            counts["static_single_tick"]["pre_fa"] += int(stat_pre_fa)
            counts["rolling_zscore"]["pre_fa"] += int(z_pre_fa)
            counts["drift_watch_v4"]["pre_fa"] += int(dw4_pre_fa)

            for key, delay_opt in (
                ("static_single_tick", stat_det_delay),
                ("rolling_zscore", z_det_delay),
                ("drift_watch_v4", dw4_det_delay),
            ):
                if delay_opt is not None:
                    counts[key]["tp"] += 1
                    counts[key]["delays"].append(delay_opt)
                else:
                    counts[key]["fn"] += 1

            by_class[sclass]["static_alarms"] += int(stat_det_delay is not None)
            by_class[sclass]["zscore_alarms"] += int(z_det_delay is not None)
            by_class[sclass]["dw4_alarms"] += int(dw4_det_delay is not None)

    egress_saved = unconditional_bytes - actual_wire_bytes
    egress_reduction_pct = round(100.0 * float(egress_saved) / float(unconditional_bytes), 4)

    detectors_report = {
        name: _compute_detector_summary(
            tp=c["tp"],
            fp=c["fp"],
            tn=c["tn"],
            fn=c["fn"],
            pre_onset_fa=c["pre_fa"],
            delays=c["delays"],
            latencies_ns=c["lat_ns"],
        )
        for name, c in counts.items()
    }

    results: Dict[str, Any] = {
        "schema": "driftbench-50-v4",
        "version": __version__,
        "seed": seed,
        "total_traces": len(scenarios),
        "persistent_drift_traces": 25,
        "benign_null_traces": 25,
        "ticks_per_trace": ticks_per_trace,
        "total_ticks_evaluated": total_ticks,
        "change_onset_tick": CHANGE_ONSET_TICK,
        "http_304_hits": total_304_hits,
        "actual_wire_bytes": actual_wire_bytes,
        "unconditional_baseline_bytes": unconditional_bytes,
        "http_304_egress_reduction_pct": egress_reduction_pct,
        "weyl_dispersion_audit": weyl_audit,
        "merkle_tree_size": merkle_acc.size,
        "verified_merkle_receipts": verified_receipts,
        "merkle_root_sha256": merkle_acc.root_hash().hex(),
        "out_of_pocket_cost_usd": "0.0000 USD",
        "detectors": detectors_report,
        "by_scenario_class": by_class,
    }

    if write_outputs:
        out_dir = REPO_ROOT / "bench" / "driftbench_50"
        out_dir.mkdir(parents=True, exist_ok=True)
        json_text = json.dumps(results, indent=2, ensure_ascii=True) + "\n"
        md_text = _render_summary_markdown(results)
        if chr(36) in json_text or chr(36) in md_text:
            raise RuntimeError("Unexpected ASCII-36 byte in DriftBench-50 output")
        (out_dir / "results.json").write_text(json_text, encoding="utf-8")
        (out_dir / "SUMMARY.md").write_text(md_text, encoding="utf-8")

    return results


if __name__ == "__main__":
    summary = run_driftbench_50(write_outputs=True)
    print(
        json.dumps(
            {
                "version": summary["version"],
                "detectors": summary["detectors"],
                "http_304_egress_reduction_pct": summary["http_304_egress_reduction_pct"],
                "merkle_tree_size": summary["merkle_tree_size"],
                "verified_merkle_receipts": summary["verified_merkle_receipts"],
                "merkle_root_sha256": summary["merkle_root_sha256"],
            },
            indent=2,
            ensure_ascii=True,
        )
    )
