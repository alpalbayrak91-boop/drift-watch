# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Command-line interface and OASIS SARIF v2.1.0 emitter for Drift-Watch v4.0.0."""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from typing import Any, Dict, List, Mapping, Optional, Sequence

from .merkle_transparency import Rfc6962MerkleAccumulator, verify_transparency_receipt
from .sequential_cusum import CorroboratedDriftMonitor

SARIF_RULES: Dict[str, Dict[str, str]] = {
    "DW-DRIFT-001": {
        "name": "ApiOrMcpSchemaBreakingDrift",
        "short": "Breaking API or MCP JSON contract field removal or type mutation.",
        "level": "error",
    },
    "DW-DRIFT-002": {
        "name": "QuotaOrRateLimitTightening",
        "short": "Directional free-tier quota cap or IETF RateLimit header tightening.",
        "level": "error",
    },
    "DW-DRIFT-003": {
        "name": "SequentialStatisticalDrift",
        "short": "Corroborated CUSUM + Page-Hinkley / Ville e-process latency or throughput shift.",
        "level": "warning",
    },
    "DW-DRIFT-004": {
        "name": "ClauseScopedPolicyRestriction",
        "short": "Clause-scoped billing wall or commercial/license policy restriction added.",
        "level": "error",
    },
    "DW-DRIFT-005": {
        "name": "EndpointDeprecationOrPersistentCliff",
        "short": "Corroborated HTTP 410 Gone deprecation notice or persistent HTTP 429/503 outage cliff.",
        "level": "error",
    },
}


def _require_strict_int_field(val: Any, field_name: str) -> int:
    if isinstance(val, bool) or not isinstance(val, int):
        raise ValueError(f"STRICT_INT_REQUIRED:{field_name}")
    return val


def _require_str_field(val: Any, field_name: str) -> str:
    if not isinstance(val, str):
        raise ValueError(f"STRICT_STR_REQUIRED:{field_name}")
    return val


def _require_optional_mapping(val: Any, field_name: str) -> Mapping[str, Any] | None:
    if val is None:
        return None
    if not isinstance(val, Mapping):
        raise ValueError(f"STRICT_MAPPING_REQUIRED:{field_name}")
    return val


def build_sarif_v210_report(alerts: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    """Emit a deterministic OASIS SARIF v2.1.0 document for DW-DRIFT-001..005 findings."""
    rules_list: List[Dict[str, Any]] = []
    for rule_id, meta in sorted(SARIF_RULES.items()):
        rules_list.append(
            {
                "id": rule_id,
                "name": meta["name"],
                "shortDescription": {"text": meta["short"]},
                "defaultConfiguration": {"level": meta["level"]},
            }
        )

    results_list: List[Dict[str, Any]] = []
    for alert in alerts:
        raw_ep = alert.get("endpoint_id", "unknown-endpoint")
        ep_id = _require_str_field(raw_ep, "endpoint_id")
        epoch_min = _require_strict_int_field(alert.get("epoch_min", 0), "epoch_min")
        reasons = [str(r) for r in (alert.get("reasons") or [])]
        rcpt = alert.get("receipt") or {}
        root_hex = str(rcpt.get("merkle_root_sha256", ""))
        for r_id in alert.get("rule_ids") or ["DW-DRIFT-003"]:
            rule_key = str(r_id) if str(r_id) in SARIF_RULES else "DW-DRIFT-003"
            results_list.append(
                {
                    "ruleId": rule_key,
                    "level": SARIF_RULES[rule_key]["level"],
                    "message": {
                        "text": f"[{ep_id} @ min {epoch_min}] " + "; ".join(reasons),
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f"endpoints/{ep_id}"},
                                "region": {"startLine": max(1, epoch_min)},
                            }
                        }
                    ],
                    "properties": {
                        "endpoint_id": ep_id,
                        "epoch_min": epoch_min,
                        "merkle_root_sha256": root_hex,
                    },
                }
            )

    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Drift-Watch",
                        "semanticVersion": "4.0.0",
                        "informationUri": "https://github.com/alpalbayrak91-boop/drift-watch",
                        "rules": rules_list,
                    }
                },
                "results": results_list,
            }
        ],
    }


def scan_trace_document(doc: Mapping[str, Any]) -> Dict[str, Any]:
    """Replay a JSON endpoint trace document through CorroboratedDriftMonitor."""
    endpoints = doc.get("endpoints")
    if not isinstance(endpoints, list) or not endpoints:
        raise ValueError("TRACE_DOCUMENT_REQUIRES_NONEMPTY_ENDPOINTS_LIST")

    acc = Rfc6962MerkleAccumulator()
    alerts: List[Dict[str, Any]] = []
    receipts: List[Dict[str, Any]] = []

    for ep in endpoints:
        if not isinstance(ep, Mapping):
            raise ValueError("INVALID_ENDPOINT_ENTRY")
        raw_ep_id = ep.get("endpoint_id")
        ep_id = _require_str_field(raw_ep_id, "endpoint_id")
        if not ep_id.strip():
            raise ValueError("EMPTY_ENDPOINT_ID")
        corr_win = _require_strict_int_field(ep.get("corroboration_window", 4), "corroboration_window")
        mon = CorroboratedDriftMonitor(ep_id, merkle_accumulator=acc, corroboration_window=corr_win)
        ticks = ep.get("ticks")
        if not isinstance(ticks, list):
            raise ValueError(f"TICKS_LIST_REQUIRED:{ep_id}")
        for idx, tick in enumerate(ticks):
            if not isinstance(tick, Mapping):
                raise ValueError("INVALID_TICK_OBJECT")
            out = mon.observe_tick(
                epoch_min=_require_strict_int_field(tick.get("epoch_min", idx * 5), "epoch_min"),
                http_status=_require_strict_int_field(tick.get("http_status", 200), "http_status"),
                residual_bps=_require_strict_int_field(tick.get("residual_bps", 0), "residual_bps"),
                etag=_require_str_field(tick.get("etag", ""), "etag"),
                wire_bytes=_require_strict_int_field(tick.get("wire_bytes", 256), "wire_bytes"),
                full_representation_bytes=_require_strict_int_field(
                    tick.get("full_representation_bytes", 4096), "full_representation_bytes"
                ),
                body_text=_require_str_field(tick.get("body_text", ""), "body_text"),
                headers=_require_optional_mapping(tick.get("headers"), "headers"),
                json_schema_fields=_require_optional_mapping(
                    tick.get("json_schema_fields"), "json_schema_fields"
                ),
            )
            if out["alarm"]:
                alerts.append(out)
                if out["receipt"] is not None:
                    receipts.append(out["receipt"])

    sarif = build_sarif_v210_report(alerts)
    return {
        "version": "4.0.0",
        "endpoints_scanned": len(endpoints),
        "alerts_count": len(alerts),
        "merkle_tree_size": acc.size,
        "merkle_root_sha256": acc.root_hash().hex(),
        "alerts": alerts,
        "receipts": receipts,
        "sarif": sarif,
    }


def _cmd_scan(args: argparse.Namespace) -> int:
    src_path = pathlib.Path(args.input)
    if not src_path.is_file():
        sys.stderr.write(f"Input trace file not found: {src_path}\n")
        return 2
    try:
        doc = json.loads(src_path.read_text(encoding="utf-8"))
        report = scan_trace_document(doc)
    except Exception as exc:
        sys.stderr.write(f"Scan error: {exc}\n")
        return 2

    if args.sarif_out:
        pathlib.Path(args.sarif_out).write_text(
            json.dumps(report["sarif"], indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    if args.receipt_out and report["receipts"]:
        pathlib.Path(args.receipt_out).write_text(
            json.dumps(report["receipts"][-1], indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    summary = {
        "version": report["version"],
        "endpoints_scanned": report["endpoints_scanned"],
        "alerts_count": report["alerts_count"],
        "merkle_tree_size": report["merkle_tree_size"],
        "merkle_root_sha256": report["merkle_root_sha256"],
    }
    sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=True) + "\n")
    return 1 if report["alerts_count"] > 0 and args.fail_on_drift else 0


def _cmd_verify_receipt(args: argparse.Namespace) -> int:
    rcpt_path = pathlib.Path(args.receipt)
    if not rcpt_path.is_file():
        sys.stderr.write(f"Receipt file not found: {rcpt_path}\n")
        return 2
    try:
        rcpt = json.loads(rcpt_path.read_text(encoding="utf-8"))
    except Exception as exc:
        sys.stderr.write(f"Invalid receipt JSON: {exc}\n")
        return 2

    ver = verify_transparency_receipt(
        rcpt,
        expected_root_hex=args.expected_root,
        expected_tree_size=args.expected_tree_size,
    )
    sys.stdout.write(json.dumps(ver, indent=2, ensure_ascii=True) + "\n")
    return 0 if ver["verified"] else 2


def _cmd_benchmark(args: argparse.Namespace) -> int:
    repo_root = pathlib.Path(__file__).resolve().parents[2]
    bench_script = repo_root / "bench" / "driftbench_50" / "run_driftbench_50.py"
    if not bench_script.is_file():
        sys.stderr.write("Benchmark runner bench/driftbench_50/run_driftbench_50.py not found.\n")
        return 2
    import importlib.util

    spec = importlib.util.spec_from_file_location("run_driftbench_50", bench_script)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    results = mod.run_driftbench_50(
        ticks_per_trace=args.ticks,
        write_outputs=bool(args.write),
    )
    if args.json_out:
        pathlib.Path(args.json_out).write_text(
            json.dumps(results, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    sys.stdout.write(
        json.dumps(
            {
                "version": results["version"],
                "total_traces": results["total_traces"],
                "detectors": results["detectors"],
                "http_304_egress_reduction_pct": results["http_304_egress_reduction_pct"],
                "merkle_root_sha256": results["merkle_root_sha256"],
            },
            indent=2,
            ensure_ascii=True,
        )
        + "\n"
    )
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="drift-watch",
        description="Drift-Watch v4.0.0: Sequential API/Quota Drift Radar & RFC 6962 Transparency Verifier",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan an endpoint telemetry trace and emit SARIF v2.1.0 + RFC 6962 receipts")
    p_scan.add_argument("input", help="Path to JSON trace file")
    p_scan.add_argument("--sarif-out", default=None, help="Output path for SARIF v2.1.0 JSON report")
    p_scan.add_argument("--receipt-out", default=None, help="Output path for latest RFC 6962 transparency receipt")
    p_scan.add_argument("--fail-on-drift", action="store_true", help="Exit with code 1 when drift alerts are found")
    p_scan.set_defaults(func=_cmd_scan)

    p_bench = sub.add_parser("benchmark", help="Run the 50-trace DriftBench-50 comparative evaluation")
    p_bench.add_argument("--ticks", type=int, default=360, help="Ticks per endpoint trace (default: 360)")
    p_bench.add_argument("--write", action="store_true", help="Write results.json and SUMMARY.md into bench/driftbench_50")
    p_bench.add_argument("--json-out", default=None, help="Optional path to write full JSON benchmark results")
    p_bench.set_defaults(func=_cmd_benchmark)

    p_ver = sub.add_parser("verify-receipt", help="Offline verify an RFC 6962 + RFC 8785 JCS transparency receipt")
    p_ver.add_argument("receipt", help="Path to receipt JSON file")
    p_ver.add_argument("--expected-root", default=None, help="Optional expected 64-hex SHA-256 Merkle root")
    p_ver.add_argument("--expected-tree-size", type=int, default=None, help="Optional expected Merkle tree size")
    p_ver.set_defaults(func=_cmd_verify_receipt)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
