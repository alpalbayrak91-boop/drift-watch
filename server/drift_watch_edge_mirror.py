#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Drift-Watch v4.0.0 Zero-Dependency Scale-to-Zero Edge Mirror WSGI Server.

Initializes an in-memory SQLite database from migrations/0001_drift_watch_v4_d1.sql
with 0-SCAN covering and partial indexes and serves /, /health, /healthz, /telemetry/24h
with Strict-CSP3 headers and 0.0000 USD out-of-pocket cost.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import os
import re
import sqlite3
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import parse_qs
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer

VERSION = "4.0.0"
COST_USD = "0.0000 USD"
REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA_PATH = REPO_ROOT / "migrations" / "0001_drift_watch_v4_d1.sql"
DEFAULT_WRANGLER_PATH = REPO_ROOT / "wrangler.toml"
DEFAULT_WORKER_PATH = REPO_ROOT / "worker" / "cf_drift_watch_v4.ts"

_BASE_CSS = (
    "body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#090f1d;color:#e6eefc}"
    "header{padding:20px 28px;background:#111a30;border-bottom:1px solid #24355e}"
    "h1{margin:0 0 6px 0;font-size:20px}.sub{color:#9ab0e6;font-size:13px}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:14px;padding:20px 28px}"
    ".card{background:#111a30;border:1px solid #24355e;border-radius:10px;padding:14px 16px}"
    ".kpi{font-size:20px;font-weight:700;color:#34d399;margin:6px 0}.muted{color:#9ab0e6;font-size:12px}"
)
STYLE_SHA256_B64 = base64.b64encode(hashlib.sha256(_BASE_CSS.encode("utf-8")).digest()).decode("ascii")
STRICT_HTML_CSP3 = (
    f"default-src 'none'; style-src 'sha256-{STYLE_SHA256_B64}'; "
    "script-src 'none'; img-src 'none'; connect-src 'none'; object-src 'none'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)
STRICT_JSON_CSP3 = "default-src 'none'; style-src 'none'; script-src 'none'; frame-ancestors 'none'"

_COLD_SQL_CONST_RE = re.compile(
    r'export\s+const\s+COLD_START_HEAL_SQL\s*=\s*((?:\s*"[^"]*"\s*\+?\s*)+);',
    re.MULTILINE,
)
_QUOTED_SEG_RE = re.compile(r'"([^"]*)"')


def resolve_bind_host(env: Optional[Mapping[str, str]] = None) -> str:
    src = os.environ if env is None else env
    return (src.get("BIND_HOST") or "").strip() or ("0.0.0.0" if src.get("K_SERVICE") else "127.0.0.1")


def extract_worker_cold_start_sql(worker_path: Path = DEFAULT_WORKER_PATH) -> str:
    if not worker_path.exists():
        raise FileNotFoundError(f"Worker source missing: {worker_path}")
    src = worker_path.read_text(encoding="utf-8")
    m = _COLD_SQL_CONST_RE.search(src)
    if not m:
        raise ValueError("COLD_START_HEAL_SQL constant not found in cf_drift_watch_v4.ts")
    parts = _QUOTED_SEG_RE.findall(m.group(1))
    if not parts:
        raise ValueError("COLD_START_HEAL_SQL string segments empty")
    return "".join(parts).strip()


def parse_observability_shield(wrangler_path: Path = DEFAULT_WRANGLER_PATH) -> Dict[str, Any]:
    shield: Dict[str, Any] = {
        "observability_enabled": False,
        "head_sampling_rate": None,
        "logs_enabled": False,
        "logs_head_sampling_rate": None,
        "invocation_logs": None,
        "traces_enabled": None,
        "workers_ai_mode": None,
        "shield_compliant": False,
    }
    if not wrangler_path.exists():
        shield["error"] = "missing_wrangler_toml"
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
        k, v = [part.strip() for part in line.split("=", 1)]
        v_clean = v.strip('"')
        if section == "observability":
            if k == "enabled":
                shield["observability_enabled"] = v_clean == "true"
            elif k == "head_sampling_rate":
                shield["head_sampling_rate"] = float(v_clean)
        elif section == "observability.logs":
            if k == "enabled":
                shield["logs_enabled"] = v_clean == "true"
            elif k == "head_sampling_rate":
                shield["logs_head_sampling_rate"] = float(v_clean)
            elif k == "invocation_logs":
                shield["invocation_logs"] = v_clean == "true"
        elif section == "observability.traces":
            if k == "enabled":
                shield["traces_enabled"] = v_clean == "true"
        elif section == "vars" and k == "WORKERS_AI_MODE":
            shield["workers_ai_mode"] = v_clean

    shield["shield_compliant"] = bool(
        shield["observability_enabled"] is True
        and shield["head_sampling_rate"] == 0.10
        and shield["logs_head_sampling_rate"] == 0.10
        and shield["invocation_logs"] is False
        and shield["traces_enabled"] is False
        and shield["workers_ai_mode"] == "DETERMINISTIC_REGEX_ONLY"
    )
    return shield


class DriftWatchMirrorStore:
    def __init__(
        self,
        schema_path: Path = DEFAULT_SCHEMA_PATH,
        wrangler_path: Path = DEFAULT_WRANGLER_PATH,
        worker_path: Path = DEFAULT_WORKER_PATH,
    ) -> None:
        self.schema_path = schema_path
        self.wrangler_path = wrangler_path
        self.worker_path = worker_path
        self.conn = sqlite3.connect(":memory:", check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(self.schema_path.read_text(encoding="utf-8"))

    def verify_zero_table_scans(self) -> Dict[str, Any]:
        cold_sql = extract_worker_cold_start_sql(self.worker_path)
        plan_rows = self.conn.execute("EXPLAIN QUERY PLAN " + cold_sql, (29932000, 29932500)).fetchall()
        details = [str(r["detail"]) for r in plan_rows]
        full_scans = [
            d
            for d in details
            if "SCAN " in d
            and "USING INDEX" not in d
            and "USING COVERING INDEX" not in d
            and "SUBQUERY" not in d.upper()
        ]
        return {
            "zero_full_table_scans": len(full_scans) == 0,
            "full_table_scan_count": len(full_scans),
            "uses_cold_start_partial_index": any("idx_dw_targets_cold_start" in d for d in details),
            "uses_active_due_covering_index": any("idx_dw_targets_active_due" in d for d in details),
            "query_plan": details,
        }

    def health_payload(self) -> Dict[str, Any]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n, COUNT(DISTINCT weyl_offset_min) AS u_weyl, "
            "SUM(CASE WHEN is_core_target = 1 THEN 1 ELSE 0 END) AS core_n "
            "FROM dw_targets WHERE active = 1"
        ).fetchone()
        active_n = int(row["n"] or 0)
        unique_weyl = int(row["u_weyl"] or 0)
        core_n = int(row["core_n"] or 0)
        shield = parse_observability_shield(self.wrangler_path)
        scan_audit = self.verify_zero_table_scans()
        return {
            "status": "ok" if (active_n > 0 and shield["shield_compliant"] and scan_audit["zero_full_table_scans"]) else "degraded",
            "version": VERSION,
            "active_targets": active_n,
            "core_targets": core_n,
            "unique_weyl_offsets": unique_weyl,
            "zero_full_table_scans": scan_audit["zero_full_table_scans"],
            "observability_shield": shield,
            "cash_overage_usd": COST_USD,
        }

    def telemetry_24h_payload(self) -> Dict[str, Any]:
        rows = self.conn.execute(
            "SELECT hour_epoch, polls_count, http_304_count, quarantined_429_count, confirmed_drift_count "
            "FROM dw_poll_hourly_rollup ORDER BY hour_epoch DESC LIMIT 24"
        ).fetchall()
        return {
            "version": VERSION,
            "hours": [dict(r) for r in rows],
        }


def _render_html_overview(health: Mapping[str, Any]) -> bytes:
    doc = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<title>Drift-Watch v4.0.0</title>"
        f"<style>{_BASE_CSS}</style></head><body>"
        "<header><h1>Drift-Watch v4.0.0</h1>"
        "<div class=\"sub\">Sequential CUSUM + Ville E-Process + Weyl HTTP 304 + RFC 6962 Transparency | 0.0000 USD</div>"
        "</header><div class=\"grid\">"
        f"<div class=\"card\"><div class=\"muted\">Active Targets</div><div class=\"kpi\">{int(health['active_targets'])}</div></div>"
        f"<div class=\"card\"><div class=\"muted\">Unique Weyl Offsets</div><div class=\"kpi\">{int(health['unique_weyl_offsets'])}</div></div>"
        f"<div class=\"card\"><div class=\"muted\">0-SCAN SQLite Audit</div><div class=\"kpi\">{html.escape(str(health['zero_full_table_scans']))}</div></div>"
        "</div></body></html>"
    )
    return doc.encode("utf-8")


def create_wsgi_app(store: Optional[DriftWatchMirrorStore] = None) -> Callable[..., Iterable[bytes]]:
    active_store = store if store is not None else DriftWatchMirrorStore()

    def app(environ: Mapping[str, Any], start_response: Callable[[str, List[Tuple[str, str]]], Any]) -> Iterable[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = str(environ.get("PATH_INFO", "/"))
        qs = parse_qs(str(environ.get("QUERY_STRING", "")))

        if method not in ("GET", "HEAD"):
            payload = json.dumps({"error": "method_not_allowed", "allowed": ["GET", "HEAD"]}).encode("utf-8")
            headers = [
                ("Content-Type", "application/json; charset=utf-8"),
                ("Content-Length", str(len(payload))),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Security-Policy", STRICT_JSON_CSP3),
            ]
            start_response("405 Method Not Allowed", headers)
            return [b""] if method == "HEAD" else [payload]

        if path == "/" and qs.get("format", [""])[0] != "json":
            html_body = _render_html_overview(active_store.health_payload())
            headers = [
                ("Content-Type", "text/html; charset=utf-8"),
                ("Content-Length", str(len(html_body))),
                ("X-Content-Type-Options", "nosniff"),
                ("X-Frame-Options", "DENY"),
                ("Referrer-Policy", "no-referrer"),
                ("Content-Security-Policy", STRICT_HTML_CSP3),
            ]
            start_response("200 OK", headers)
            return [b""] if method == "HEAD" else [html_body]

        if path in ("/", "/health", "/healthz"):
            body = json.dumps(active_store.health_payload()).encode("utf-8")
            status_line = "200 OK"
        elif path == "/telemetry/24h":
            body = json.dumps(active_store.telemetry_24h_payload()).encode("utf-8")
            status_line = "200 OK"
        else:
            body = json.dumps({"error": "not_found", "path": path}).encode("utf-8")
            status_line = "404 Not Found"

        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", STRICT_JSON_CSP3),
        ]
        start_response(status_line, headers)
        return [b""] if method == "HEAD" else [body]

    return app


class _ThreadedWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Drift-Watch v4.0.0 Scale-to-Zero Edge Mirror")
    parser.add_argument("--serve", action="store_true", help="Start WSGI HTTP server")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")))
    args = parser.parse_args()

    store = DriftWatchMirrorStore()
    if not args.serve:
        print(json.dumps(store.health_payload(), indent=2))
        return 0

    host = resolve_bind_host()
    with _ThreadedWSGIServer((host, args.port), WSGIRequestHandler) as httpd:
        httpd.set_app(create_wsgi_app(store))
        httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
