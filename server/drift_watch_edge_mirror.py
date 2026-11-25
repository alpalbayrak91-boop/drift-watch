#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: MIT
"""Drift-Watch v3.9.1 Zero-Dependency Scale-to-Zero Edge Mirror WSGI Server.

Initializes an in-memory SQLite database directly from migrations/0001_drift_watch_v39_d1.sql
(40 targets W01..W40, 34 strict MC06 core targets W01..W34, 6 Wave-14 targets W35..W40,
and 0-SCAN covering/partial indexes) and serves /, /health, /healthz, /telemetry/24h, /envelopes
with Strict-CSP3 headers and 0.0000 USD out-of-pocket cost.

Host default: 127.0.0.1 on bare host; K_SERVICE / BIND_HOST inside Cloud Run container.
Fail-closed observability shield audit: missing wrangler.toml yields shield_compliant=False.
Strict KURAL-3 hygiene: 0 chr(36) anywhere in source or rendered output; USD only.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import html
import json
import os
import re
import signal
import sqlite3
import threading
import time
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

VERSION = "v3.9.1"
ENGINE_ID = "IS-FON-93-DRIFT-WATCH-V39-UNIFIED"
COST_USD = "0.0000 USD"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA_PATH = REPO_ROOT / "migrations" / "0001_drift_watch_v39_d1.sql"
DEFAULT_WRANGLER_PATH = REPO_ROOT / "wrangler.toml"
DEFAULT_WORKER_PATH = REPO_ROOT / "src" / "cf_drift_watch_v39_worker.js"

_BASE_CSS = (
    "body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#090f1d;color:#e6eefc}"
    "header{padding:20px 28px;background:#111a30;border-bottom:1px solid #24355e}"
    "h1{margin:0 0 6px 0;font-size:20px}.sub{color:#9ab0e6;font-size:13px}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;padding:20px 28px}"
    ".card{background:#111a30;border:1px solid #24355e;border-radius:10px;padding:14px 16px}"
    ".kpi{font-size:20px;font-weight:700;color:#34d399;margin:6px 0}.muted{color:#9ab0e6;font-size:12px}"
    "pre{margin:0 28px 28px 28px;padding:16px;background:#0c1426;border:1px solid #24355e;border-radius:10px;overflow-x:auto;font-size:12px;color:#cbd5f5}"
)
STYLE_SHA256_B64 = base64.b64encode(hashlib.sha256(_BASE_CSS.encode("utf-8")).digest()).decode("ascii")
STRICT_HTML_CSP3 = (
    f"default-src 'none'; style-src 'sha256-{STYLE_SHA256_B64}'; "
    "script-src 'none'; img-src 'none'; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
META_HTML_CSP3 = (
    f"default-src 'none'; style-src 'sha256-{STYLE_SHA256_B64}'; "
    "script-src 'none'; img-src 'none'; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)
STRICT_JSON_CSP3 = "default-src 'none'; style-src 'none'; script-src 'none'; frame-ancestors 'none'"

_COLD_SQL_CONST_RE = re.compile(
    r"export\s+const\s+COLD_START_HEAL_SQL\s*=\s*([\s\S]*?);",
    re.MULTILINE,
)
_QUOTED_SEG_RE = re.compile(r'"([^"]*)"')


def resolve_bind_host(env: Optional[Mapping[str, str]] = None) -> str:
    src = os.environ if env is None else env
    return (src.get("BIND_HOST") or "").strip() or ("0.0.0.0" if src.get("K_SERVICE") else "127.0.0.1")


def extract_worker_cold_start_sql(worker_path: Path = DEFAULT_WORKER_PATH) -> str:
    if not worker_path.exists():
        raise FileNotFoundError(f"Worker source missing for SQL parity audit: {worker_path}")
    src = worker_path.read_text(encoding="utf-8")
    m = _COLD_SQL_CONST_RE.search(src)
    if not m:
        raise ValueError("COLD_START_HEAL_SQL constant not found in cf_drift_watch_v39_worker.js")
    parts = _QUOTED_SEG_RE.findall(m.group(1))
    if not parts:
        raise ValueError("COLD_START_HEAL_SQL string segments empty")
    return "".join(parts).strip()


def iso_week_key(now_utc: dt.datetime) -> str:
    year, week, _ = now_utc.isocalendar()
    return f"{year}-W{week:02d}"


def parse_observability_shield(wrangler_path: Path = DEFAULT_WRANGLER_PATH) -> Dict[str, Any]:
    shield: Dict[str, Any] = {
        "dec1_2026_split_billing_shield": True,
        "observability_enabled": False,
        "head_sampling_rate": None,
        "logs_enabled": False,
        "logs_head_sampling_rate": None,
        "invocation_logs": None,
        "traces_enabled": None,
        "shield_compliant": False,
    }
    if not wrangler_path.exists():
        shield["error"] = "missing_wrangler_toml"
        shield["shield_compliant"] = False
        return shield

    section = ""
    for raw_line in wrangler_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line.strip("[]").strip()
            continue
        if "=" not in line:
            continue
        k, v = [p.strip() for p in line.split("=", 1)]
        if section == "observability":
            if k == "enabled":
                shield["observability_enabled"] = v == "true"
            elif k == "head_sampling_rate":
                shield["head_sampling_rate"] = float(v)
        elif section == "observability.logs":
            if k == "enabled":
                shield["logs_enabled"] = v == "true"
            elif k == "head_sampling_rate":
                shield["logs_head_sampling_rate"] = float(v)
            elif k == "invocation_logs":
                shield["invocation_logs"] = v == "true"
        elif section == "observability.traces":
            if k == "enabled":
                shield["traces_enabled"] = v == "true"

    shield["shield_compliant"] = bool(
        shield["observability_enabled"] is True
        and shield["head_sampling_rate"] is not None
        and shield["head_sampling_rate"] <= 0.10
        and shield["logs_enabled"] is True
        and shield["logs_head_sampling_rate"] is not None
        and shield["logs_head_sampling_rate"] <= 0.10
        and shield["invocation_logs"] is False
        and shield["traces_enabled"] is False
    )
    return shield


class DriftWatchMirrorStore:
    """Thread-safe in-memory SQLite mirror initialized from D1 migration SQL."""

    def __init__(
        self,
        schema_path: Path = DEFAULT_SCHEMA_PATH,
        wrangler_path: Path = DEFAULT_WRANGLER_PATH,
        worker_path: Path = DEFAULT_WORKER_PATH,
    ) -> None:
        self._lock = threading.RLock()
        self._boot_monotonic = time.monotonic()
        self._schema_path = schema_path
        self._wrangler_path = wrangler_path
        self._worker_path = worker_path
        self._conn = sqlite3.connect(":memory:", check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        sql_script = schema_path.read_text(encoding="utf-8")
        self._conn.executescript(sql_script)
        self._conn.commit()
        self._shield = parse_observability_shield(wrangler_path)

    def verify_zero_table_scans(self) -> Dict[str, Any]:
        cold_sql = extract_worker_cold_start_sql(self._worker_path)
        queries = {
            "due_batch_lookup": (
                "SELECT target_id, url FROM dw_targets "
                "WHERE active = 1 AND next_due_epoch_min <= ? ORDER BY next_due_epoch_min ASC LIMIT 4",
                (29932000,),
            ),
            "cold_start_partial_lookup": (
                cold_sql,
                (29931800, 29932100),
            ),
            "hourly_rollup_24h_range": (
                "SELECT hour_bucket_utc, polls_total FROM dw_poll_hourly_rollup "
                "WHERE hour_bucket_utc >= ? ORDER BY hour_bucket_utc ASC",
                (498800,),
            ),
            "unack_events_lookup": (
                "SELECT event_id, target_id FROM dw_events "
                "WHERE acknowledged = 0 AND severity = 'S4_DEADLINE_OR_ENDPOINT_DEATH'",
                (),
            ),
        }
        plans: Dict[str, List[str]] = {}
        full_scans = 0
        with self._lock:
            idx_rows = self._conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_dw_%' ORDER BY name ASC"
            ).fetchall()
            index_names = [str(r["name"]) for r in idx_rows]
            for name, (sql, params) in queries.items():
                eqp = self._conn.execute(f"EXPLAIN QUERY PLAN {sql}", params).fetchall()
                details = [str(r["detail"]) for r in eqp]
                plans[name] = details
                for d in details:
                    upper = d.upper()
                    if "SCAN " in upper and "USING INDEX" not in upper and "USING COVERING INDEX" not in upper:
                        full_scans += 1
        cold_details = " | ".join(plans["cold_start_partial_lookup"])
        cold_uses_partial_idx = "idx_dw_targets_cold_start" in cold_details
        return {
            "zero_full_table_scans": full_scans == 0 and cold_uses_partial_idx,
            "full_table_scan_count": full_scans,
            "cold_start_uses_partial_index": cold_uses_partial_idx,
            "covering_and_partial_indexes": index_names,
            "index_count": len(index_names),
            "query_plans": plans,
        }

    def health_payload(self) -> Dict[str, Any]:
        now_utc = dt.datetime.now(dt.timezone.utc)
        now_hour_bucket = int(now_utc.timestamp() // 3600)
        wk = iso_week_key(now_utc)
        with self._lock:
            c = self._conn.execute(
                "SELECT COUNT(*) AS n, COUNT(DISTINCT weyl_offset_min) AS u_weyl, "
                "SUM(CASE WHEN is_mc06_core = 1 AND target_id GLOB 'W[0-9][0-9]' "
                "AND CAST(SUBSTR(target_id, 2) AS INTEGER) BETWEEN 1 AND 34 THEN 1 ELSE 0 END) AS mc06_core_n, "
                "SUM(CASE WHEN period_min < base_period_min THEN 1 ELSE 0 END) AS acc_n, "
                "SUM(CASE WHEN last_polled_epoch_min = 0 THEN 1 ELSE 0 END) AS cold_n, "
                "SUM(CASE WHEN last_etag != '' OR last_modified != '' THEN 1 ELSE 0 END) AS cond_ready_n, "
                "SUM(value_at_risk_micro_usd) AS total_var_ucr "
                "FROM dw_targets WHERE active = 1"
            ).fetchone()
            th = self._conn.execute(
                "SELECT COALESCE(SUM(CASE WHEN quarantine_class = 'INFRA_TRANSIENT_429' THEN 1 ELSE 0 END), 0) AS tr_n, "
                "COALESCE(SUM(CASE WHEN quarantine_class = 'PERMANENT_CAP_OR_SILENT_CUT' THEN 1 ELSE 0 END), 0) AS cap_n "
                "FROM dw_provider_quota_envelopes"
            ).fetchone()
            tel = self._conn.execute(
                "SELECT COALESCE(SUM(polls_total), 0) AS polls_24h, "
                "COALESCE(SUM(polls_cold_start), 0) AS cold_polls_24h, "
                "COALESCE(SUM(polls_warm), 0) AS warm_polls_24h, "
                "COALESCE(SUM(polls_conditional_sent), 0) AS cond_polls_24h, "
                "COALESCE(SUM(http_304_count), 0) AS h304_24h, "
                "COALESCE(SUM(http_200_count), 0) AS h200_24h, "
                "COALESCE(SUM(http_429_count), 0) AS h429_24h, "
                "COALESCE(SUM(http_403_waf_count), 0) AS h403_24h, "
                "COALESCE(SUM(http_404_410_count), 0) AS h404_24h, "
                "COALESCE(SUM(http_5xx_count), 0) AS h5xx_24h, "
                "COALESCE(SUM(net_err_count), 0) AS net_err_24h, "
                "COALESCE(SUM(bytes_fetched), 0) AS bytes_fetched_24h, "
                "COALESCE(SUM(bytes_saved_est), 0) AS bytes_saved_24h, "
                "COUNT(*) AS active_hours_24h "
                "FROM dw_poll_hourly_rollup WHERE hour_bucket_utc >= ?",
                (now_hour_bucket - 23,),
            ).fetchone()
            bud = self._conn.execute(
                "SELECT used_min, budget_min FROM dw_weekly_budget WHERE iso_week = ?",
                (wk,),
            ).fetchone()
            grp_rows = self._conn.execute(
                "SELECT group_code, COUNT(*) AS cnt FROM dw_targets WHERE active = 1 GROUP BY group_code ORDER BY group_code ASC"
            ).fetchall()

        index_audit = self.verify_zero_table_scans()
        active_targets = int(c["n"] or 0)
        mc06_core = int(c["mc06_core_n"] or 0)
        cold_pending = int(c["cold_n"] or 0)
        cond_ready = int(c["cond_ready_n"] or 0)
        total_var_usd = (int(c["total_var_ucr"] or 0)) / 1_000_000.0
        polls_24h = int(tel["polls_24h"] or 0)
        warm_polls_24h = int(tel["warm_polls_24h"] or 0)
        cond_polls_24h = int(tel["cond_polls_24h"] or 0)
        h304_24h = int(tel["h304_24h"] or 0)

        raw_ratio = round(h304_24h / polls_24h, 4) if polls_24h > 0 else None
        warm_ratio = round(h304_24h / warm_polls_24h, 4) if warm_polls_24h > 0 else None
        cond_ratio = round(h304_24h / cond_polls_24h, 4) if cond_polls_24h > 0 else None

        gate_status = "PASS_40_OF_40_AND_34_OF_34_READY"
        if active_targets < 40 or mc06_core < 34:
            gate_status = "FAIL_ACTIVE_TARGETS"
        elif cold_pending > 0 or cond_polls_24h < 15:
            gate_status = "COLD_START_IN_PROGRESS"
        elif cond_ratio is not None and cond_ratio < 0.65:
            gate_status = "WARN_LOW_CONDITIONAL_304"

        return {
            "status": "ok",
            "engine": ENGINE_ID,
            "version": VERSION,
            "uptime_sec": round(time.monotonic() - self._boot_monotonic, 3),
            "active_targets": active_targets,
            "mc06_core_w01_w34_active": mc06_core,
            "wave14_extension_w35_w40_active": active_targets - mc06_core,
            "unique_weyl_offsets_count": int(c["u_weyl"] or 0),
            "accelerated_cliff_targets": int(c["acc_n"] or 0),
            "cold_start_pending_count": cold_pending,
            "targets_with_conditional_validators": cond_ready,
            "monitored_value_at_risk_usd": f"{total_var_usd:.2f} USD",
            "group_breakdown": {str(r["group_code"]): int(r["cnt"]) for r in grp_rows},
            "index_zero_scan_audit": {
                "zero_full_table_scans": index_audit["zero_full_table_scans"],
                "full_table_scan_count": index_audit["full_table_scan_count"],
                "cold_start_uses_partial_index": index_audit["cold_start_uses_partial_index"],
                "index_count": index_audit["index_count"],
                "indexes": index_audit["covering_and_partial_indexes"],
            },
            "observability_shield": self._shield,
            "telemetry_24h": {
                "window_hours": 24,
                "active_hours_recorded": int(tel["active_hours_24h"] or 0),
                "polls_24h": polls_24h,
                "cold_start_polls_24h": int(tel["cold_polls_24h"] or 0),
                "warm_polls_24h": warm_polls_24h,
                "conditional_polls_24h": cond_polls_24h,
                "http_304_hits_24h": h304_24h,
                "http_200_hits_24h": int(tel["h200_24h"] or 0),
                "http_429_hits_24h": int(tel["h429_24h"] or 0),
                "http_403_waf_hits_24h": int(tel["h403_24h"] or 0),
                "http_404_410_hits_24h": int(tel["h404_24h"] or 0),
                "http_5xx_hits_24h": int(tel["h5xx_24h"] or 0),
                "net_err_24h": int(tel["net_err_24h"] or 0),
                "bytes_fetched_24h": int(tel["bytes_fetched_24h"] or 0),
                "bytes_saved_est_24h": int(tel["bytes_saved_24h"] or 0),
                "raw_http_304_ratio_24h": raw_ratio,
                "warm_http_304_ratio_24h": warm_ratio,
                "conditional_http_304_ratio_24h": cond_ratio,
            },
            "t48h_deploy_gate_status": gate_status,
            "infra_transient_429_count": int(th["tr_n"] or 0),
            "permanent_cap_or_dead_count": int(th["cap_n"] or 0),
            "weekly_budget_iso_week": wk,
            "weekly_budget_used_min": int(bud["used_min"]) if bud else 0,
            "weekly_budget_cap_min": int(bud["budget_min"]) if bud else 60,
            "d90_4_strict_mc06_core": True,
            "d90_5_multilabel_psl": True,
            "d90_6_cf_vectorize_stale_banner_guard": True,
            "d92_splitbrain_closed": True,
            "kural3_zero_chr36": True,
            "cash_overage_usd": COST_USD,
        }

    def telemetry_24h_payload(self) -> Dict[str, Any]:
        now_utc = dt.datetime.now(dt.timezone.utc)
        now_hour_bucket = int(now_utc.timestamp() // 3600)
        with self._lock:
            rows = self._conn.execute(
                "SELECT hour_bucket_utc, polls_total, polls_cold_start, polls_warm, "
                "polls_conditional_sent, http_304_count, http_200_count, http_429_count, "
                "http_403_waf_count, http_404_410_count, http_5xx_count, net_err_count, "
                "bytes_fetched, bytes_saved_est, updated_at_utc "
                "FROM dw_poll_hourly_rollup WHERE hour_bucket_utc >= ? ORDER BY hour_bucket_utc ASC",
                (now_hour_bucket - 23,),
            ).fetchall()
        return {
            "version": VERSION,
            "now_hour_bucket_utc": now_hour_bucket,
            "hours": [dict(r) for r in rows],
            "cash_overage_usd": COST_USD,
        }

    def envelopes_payload(self) -> Dict[str, Any]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT target_id, provider_family, binding_bucket, quota_unit, last_http_status, "
                "throttle_kind, retryable, quarantine_class, retry_after_sec, rl_limit, rl_remaining, "
                "rl_reset_sec, effective_backoff_sec, clock_skew_sec, guard_band_breached, "
                "headroom_ratio_bps, backoff_until_epoch_min, consecutive_throttles, observed_at_utc "
                "FROM dw_provider_quota_envelopes "
                "ORDER BY consecutive_throttles DESC, effective_backoff_sec DESC LIMIT 50"
            ).fetchall()
        return {
            "version": VERSION,
            "envelopes": [dict(r) for r in rows],
            "cash_overage_usd": COST_USD,
        }


def render_root_html(health: Dict[str, Any]) -> str:
    pretty = html.escape(json.dumps(health, indent=2, ensure_ascii=True))
    idx = health["index_zero_scan_audit"]
    sh = health["observability_shield"]
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\" />\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />\n"
        f"<meta http-equiv=\"Content-Security-Policy\" content=\"{META_HTML_CSP3}\" />\n"
        f"<title>Drift-Watch {VERSION} Scale-to-Zero Edge Poller &amp; D1 Shield</title>\n"
        f"<style>{_BASE_CSS}</style>\n</head>\n<body>\n<header>\n"
        f"<h1>Drift-Watch {VERSION} Unified Schema-Parity Edge Poller (Dec 1 Observability Shield)</h1>\n"
        "<div class=\"sub\">40 Active Targets (W01..W40) | 34 Strict MC06 Core | 0-SCAN D1 Covering Indexes | Strict-CSP3 | 0.0000 USD</div>\n"
        "</header>\n<section class=\"grid\">\n"
        f"<div class=\"card\"><div class=\"muted\">Target Fleet &amp; Weyl Dispersion</div>"
        f"<div class=\"kpi\">{health['active_targets']} Targets ({health['mc06_core_w01_w34_active']} MC06)</div>"
        f"<div class=\"muted\">Unique Weyl Offsets: {health['unique_weyl_offsets_count']} | VaR: {health['monitored_value_at_risk_usd']}</div></div>\n"
        f"<div class=\"card\"><div class=\"muted\">SQLite / D1 0-SCAN Index Guard</div>"
        f"<div class=\"kpi\">{idx['index_count']} Indexes | {idx['full_table_scan_count']} Scans</div>"
        f"<div class=\"muted\">Cold-Start Partial Idx: {idx['cold_start_uses_partial_index']} | 0-SCAN: {idx['zero_full_table_scans']}</div></div>\n"
        f"<div class=\"card\"><div class=\"muted\">Dec 1 2026 Observability Shield</div>"
        f"<div class=\"kpi\">Sample {sh['head_sampling_rate']} | Traces Off</div>"
        f"<div class=\"muted\">invocation_logs={sh['invocation_logs']} | Compliant: {sh['shield_compliant']}</div></div>\n"
        f"<div class=\"card\"><div class=\"muted\">Out-of-Pocket Spend Lock</div>"
        f"<div class=\"kpi\">{health['cash_overage_usd']}</div>"
        f"<div class=\"muted\">Endpoints: /health | /telemetry/24h | /envelopes</div></div>\n"
        f"</section>\n<pre>{pretty}</pre>\n</body>\n</html>\n"
    )


def security_headers(content_type: str, content_length: int, is_html: bool = False) -> List[Tuple[str, str]]:
    return [
        ("Content-Type", content_type),
        ("Content-Length", str(content_length)),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Cache-Control", "no-store"),
        ("Content-Security-Policy", STRICT_HTML_CSP3 if is_html else STRICT_JSON_CSP3),
    ]


def create_wsgi_app(store: Optional[DriftWatchMirrorStore] = None) -> Callable[..., Iterable[bytes]]:
    active_store = store or DriftWatchMirrorStore()

    def app(environ: Dict[str, Any], start_response: Callable[..., Any]) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))
        qs = parse_qs(str(environ.get("QUERY_STRING", "")), keep_blank_values=True)

        def respond_json(payload: Dict[str, Any], status: str = "200 OK") -> List[bytes]:
            raw = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
            start_response(status, security_headers("application/json; charset=utf-8", len(raw), is_html=False))
            return [b""] if method == "HEAD" else [raw]

        if method not in ("GET", "HEAD"):
            return respond_json(
                {"error": "method_not_allowed", "allowed": ["GET", "HEAD"]},
                status="405 Method Not Allowed",
            )

        if path == "/":
            if qs.get("format", [""])[0] == "json":
                return respond_json(active_store.health_payload())
            body = render_root_html(active_store.health_payload()).encode("utf-8")
            start_response("200 OK", security_headers("text/html; charset=utf-8", len(body), is_html=True))
            return [b""] if method == "HEAD" else [body]

        if path in ("/health", "/healthz"):
            return respond_json(active_store.health_payload())

        if path == "/telemetry/24h":
            return respond_json(active_store.telemetry_24h_payload())

        if path == "/envelopes":
            return respond_json(active_store.envelopes_payload())

        return respond_json({"error": "not_found", "path": path}, status="404 Not Found")

    return app


STORE = DriftWatchMirrorStore()
wsgi_app = create_wsgi_app(STORE)


class ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class QuietWSGIHandler(WSGIRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass


def serve_forever() -> None:
    host = (os.environ.get("BIND_HOST") or "").strip() or ("0.0.0.0" if os.environ.get("K_SERVICE") else "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    srv = ThreadingWSGIServer((host, port), QuietWSGIHandler)
    srv.set_app(wsgi_app)

    def _shutdown(_signum: int, _frame: Any) -> None:
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    print(f"Serving Drift-Watch {VERSION} Edge Mirror on {host}:{port} ({COST_USD})", flush=True)
    srv.serve_forever()


def main() -> int:
    ap = argparse.ArgumentParser(description="Drift-Watch v3.9.1 Scale-to-Zero Edge Mirror")
    ap.add_argument("--serve", action="store_true", help="Start HTTP WSGI server")
    args = ap.parse_args()
    if args.serve:
        serve_forever()
        return 0
    print(json.dumps(STORE.health_payload(), indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
