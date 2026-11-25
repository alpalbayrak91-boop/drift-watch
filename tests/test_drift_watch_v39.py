# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: MIT
"""Pytest verification suite for Drift-Watch v3.9.1 Worker, D1 SQLite Schema,
Dec 1 2026 Observability Shield, Ephemeral Deploy Config, and Scale-to-Zero WSGI Mirror.

Strict KURAL-3 hygiene: 0 chr(36) across every file in the repository; USD only.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch
from wsgiref.validate import validator

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts import deploy_cloudflare  # noqa: E402
from server import drift_watch_edge_mirror as mirror  # noqa: E402

EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".wrangler", "dist"}

DISALLOWED_TOKEN_SHA256 = {
    "8386820647851c3128f6196b45bc29e834406c086104789268b07b8a39140113",
    "b0920c5c79e69be71240a764c4514275b563720c2c9d7546958e0792154be8da",
    "a83f0eb447206ef51a485f678fd0103a8f5e0c259373f94f05c845172bc30464",
    "9a0a82f0f15a62f8c709704c2a2c4452225368d2187368e4d70811675b6f8198",
}


def _iter_repo_files() -> List[Path]:
    files: List[Path] = []
    for p in sorted(REPO_ROOT.rglob("*")):
        if any(part in EXCLUDED_DIRS for part in p.parts):
            continue
        if p.is_file():
            files.append(p)
    return files


def _wsgi_request(
    app: Any,
    path: str,
    query: str = "",
    method: str = "GET",
) -> Tuple[str, Dict[str, str], bytes]:
    status_holder: List[str] = []
    headers_holder: Dict[str, str] = {}

    def _start_response(status: str, headers: List[Tuple[str, str]], _exc_info: Any = None) -> None:
        status_holder.append(status)
        headers_holder.clear()
        for k, v in headers:
            headers_holder[k] = v

    environ = {
        "REQUEST_METHOD": method,
        "SCRIPT_NAME": "",
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": "8080",
        "SERVER_PROTOCOL": "HTTP/1.1",
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
        "wsgi.errors": sys.stderr,
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    resp = app(environ, _start_response)
    try:
        body = b"".join(resp)
    finally:
        if hasattr(resp, "close"):
            resp.close()
    return status_holder[0], headers_holder, body


def test_01_kural3_zero_chr36_across_all_repo_files() -> None:
    repo_files = _iter_repo_files()
    assert len(repo_files) >= 12
    for fp in repo_files:
        text = fp.read_text(encoding="utf-8")
        assert chr(36) not in text, f"ASCII-36 violation in {fp.relative_to(REPO_ROOT)}"


def test_02_kural7_kural8_clean_host_bind_and_opsec() -> None:
    assert mirror.resolve_bind_host({}) == "127.0.0.1"
    assert mirror.resolve_bind_host({"BIND_HOST": ""}) == "127.0.0.1"
    assert mirror.resolve_bind_host({"BIND_HOST": "   "}) == "127.0.0.1"
    assert mirror.resolve_bind_host({"DEPLOY_TARGET": "cloud_run"}) == "127.0.0.1"
    assert mirror.resolve_bind_host({"K_SERVICE": "alplab-drift-watch-v39"}) == "0.0.0.0"
    assert mirror.resolve_bind_host({"K_SERVICE": "alplab-drift-watch-v39", "BIND_HOST": "127.0.0.1"}) == "127.0.0.1"
    assert mirror.resolve_bind_host({"BIND_HOST": "0.0.0.0"}) == "0.0.0.0"

    dockerfile_txt = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "BIND_HOST=0.0.0.0" in dockerfile_txt

    home_prefix = "/" + "home/"
    gmail_suffix = "@" + "gmail.com"
    secret_re = re.compile(r"\b(?:gh[op]_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,})\b")
    cf_tok = "CLOUDFLARE_API_TOKEN" + "="
    for fp in _iter_repo_files():
        txt = fp.read_text(encoding="utf-8")
        low = txt.lower()
        assert home_prefix not in low, f"Internal path leak in {fp.relative_to(REPO_ROOT)}"
        assert gmail_suffix not in low, f"Personal email leak in {fp.relative_to(REPO_ROOT)}"
        assert secret_re.search(txt) is None, f"Secret token leak in {fp.relative_to(REPO_ROOT)}"
        assert cf_tok not in txt, f"Env token leak in {fp.relative_to(REPO_ROOT)}"
        words = [w.strip(".,:;()[]{}'\"<>/-") for w in low.split()]
        for w in words:
            if w:
                digest = hashlib.sha256(w.encode("utf-8")).hexdigest()
                assert digest not in DISALLOWED_TOKEN_SHA256, f"Disallowed token in {fp.relative_to(REPO_ROOT)}"


def test_03_node_syntax_and_worker_fetch_hardening() -> None:
    worker_js = REPO_ROOT / "src" / "cf_drift_watch_v39_worker.js"
    assert worker_js.exists()
    chk = subprocess.run(
        ["node", "--check", str(worker_js)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert chk.returncode == 0, f"node --check failed: {chk.stderr}"

    esm_probe = (
        "import worker, { COLD_START_HEAL_SQL } from './src/cf_drift_watch_v39_worker.js';\n"
        "const mockDb = {\n"
        "  prepare(sql) {\n"
        "    const stmt = {\n"
        "      bind() { return stmt; },\n"
        "      async first() {\n"
        "        if (sql.includes('FROM dw_targets')) return { n: 40, u_weyl: 40, mc06_core_n: 34, acc_n: 0, cold_n: 0, cond_ready_n: 40 };\n"
        "        if (sql.includes('FROM dw_provider_quota_envelopes')) return { tr_n: 0, cap_n: 0 };\n"
        "        if (sql.includes('FROM dw_poll_hourly_rollup')) return { polls_24h: 40, warm_polls_24h: 40, cond_polls_24h: 40, h304_24h: 32, active_hours_24h: 6 };\n"
        "        return { used_min: 0, budget_min: 60 };\n"
        "      },\n"
        "      async all() { return { results: [] }; }\n"
        "    };\n"
        "    return stmt;\n"
        "  }\n"
        "};\n"
        "const env = { DRIFT_DB: mockDb };\n"
        "const rRoot = await worker.fetch(new Request('https://example.workers.dev/'), env);\n"
        "const tRoot = await rRoot.text();\n"
        "const rHead = await worker.fetch(new Request('https://example.workers.dev/health', { method: 'HEAD' }), env);\n"
        "const tHead = await rHead.text();\n"
        "const rHz = await worker.fetch(new Request('https://example.workers.dev/healthz'), env);\n"
        "const jHz = await rHz.json();\n"
        "const r405 = await worker.fetch(new Request('https://example.workers.dev/health', { method: 'POST' }), env);\n"
        "const r404 = await worker.fetch(new Request('https://example.workers.dev/unknown-route'), env);\n"
        "const j404 = await r404.json();\n"
        "console.log(JSON.stringify({\n"
        "  hasIdx: COLD_START_HEAL_SQL.includes('idx_dw_targets_cold_start'),\n"
        "  rootStatus: rRoot.status,\n"
        "  rootText: tRoot,\n"
        "  rootNosniff: rRoot.headers.get('x-content-type-options'),\n"
        "  rootCsp: rRoot.headers.get('content-security-policy'),\n"
        "  headStatus: rHead.status,\n"
        "  headEmpty: tHead === '',\n"
        "  headLen: Number(rHead.headers.get('content-length')),\n"
        "  hzStatus: rHz.status,\n"
        "  hzGate: jHz.t48h_deploy_gate_status,\n"
        "  s405: r405.status,\n"
        "  s404: r404.status,\n"
        "  err404: j404.error\n"
        "}));\n"
    )
    run_esm = subprocess.run(
        ["node", "--input-type=module", "-e", esm_probe],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert run_esm.returncode == 0, f"Worker ESM probe failed: {run_esm.stderr}"
    out = json.loads(run_esm.stdout.strip())
    assert out["hasIdx"] is True
    assert out["rootStatus"] == 200
    assert "KONU-5" not in out["rootText"]
    assert out["rootNosniff"] == "nosniff"
    assert "default-src 'none'" in out["rootCsp"]
    assert "frame-ancestors 'none'" in out["rootCsp"]
    assert out["headStatus"] == 200 and out["headEmpty"] is True and out["headLen"] > 0
    assert out["hzStatus"] == 200 and out["hzGate"] == "PASS_40_OF_40_AND_34_OF_34_READY"
    assert out["s405"] == 405
    assert out["s404"] == 404 and out["err404"] == "not_found"


def test_04_sqlite_d1_schema_idempotent_redeploy_preserves_live_state() -> None:
    sql_path = REPO_ROOT / "migrations" / "0001_drift_watch_v39_d1.sql"
    sql_txt = sql_path.read_text(encoding="utf-8")
    assert "INSERT OR REPLACE INTO dw_targets" not in sql_txt
    assert sql_txt.count("INSERT OR IGNORE INTO dw_targets") == 40

    conn = sqlite3.connect(":memory:")
    conn.executescript(sql_txt)
    conn.execute(
        "UPDATE dw_targets SET last_polled_epoch_min = 29932555, last_etag = 'etag-live-w01', "
        "last_canon_sha256 = 'deadbeefcafe1234', alpha_milli = 2750 WHERE target_id = 'W01'"
    )
    conn.commit()
    # Re-apply migration SQL (simulating idempotent redeploy)
    conn.executescript(sql_txt)
    row = conn.execute(
        "SELECT last_polled_epoch_min, last_etag, last_canon_sha256, alpha_milli FROM dw_targets WHERE target_id = 'W01'"
    ).fetchone()
    assert row == (29932555, "etag-live-w01", "deadbeefcafe1234", 2750)

    store = mirror.DriftWatchMirrorStore()
    health = store.health_payload()
    assert health["status"] == "ok"
    assert health["version"] == "v3.9.1"
    assert health["active_targets"] == 40
    assert health["mc06_core_w01_w34_active"] == 34
    assert health["wave14_extension_w35_w40_active"] == 6
    assert health["unique_weyl_offsets_count"] == 40
    assert health["cash_overage_usd"] == "0.0000 USD"


def test_05_explain_query_plan_exact_worker_coldres_uses_partial_index() -> None:
    cold_sql = mirror.extract_worker_cold_start_sql()
    assert "idx_dw_targets_cold_start" in cold_sql
    assert "UNION ALL" in cold_sql

    store = mirror.DriftWatchMirrorStore()
    audit = store.verify_zero_table_scans()
    assert audit["zero_full_table_scans"] is True, f"Scan or partial-index miss: {audit}"
    assert audit["full_table_scan_count"] == 0
    assert audit["cold_start_uses_partial_index"] is True
    cold_plan_str = " | ".join(audit["query_plans"]["cold_start_partial_lookup"])
    assert "idx_dw_targets_cold_start" in cold_plan_str
    assert "idx_dw_targets_active_due" not in cold_plan_str

    # Verify 0 rows returned once all 40 targets have last_polled_epoch_min > 0
    conn = sqlite3.connect(":memory:")
    conn.executescript((REPO_ROOT / "migrations" / "0001_drift_watch_v39_d1.sql").read_text(encoding="utf-8"))
    conn.execute("UPDATE dw_targets SET last_polled_epoch_min = 29932000")
    warm_rows = conn.execute(cold_sql, (29931940, 29932240)).fetchall()
    assert warm_rows == []


def test_06_dec1_2026_observability_shield_fail_closed_and_clean_wrangler(tmp_path: Path) -> None:
    wrangler_path = REPO_ROOT / "wrangler.toml"
    before_bytes = wrangler_path.read_bytes()
    assert 'database_id = "00000000-0000-0000-0000-000000000000"' in before_bytes.decode("utf-8")

    shield = mirror.parse_observability_shield(wrangler_path)
    assert shield["shield_compliant"] is True
    assert shield["head_sampling_rate"] == 0.10
    assert shield["logs_head_sampling_rate"] == 0.10
    assert shield["invocation_logs"] is False
    assert shield["traces_enabled"] is False

    # Missing wrangler.toml MUST fail closed
    missing_shield = mirror.parse_observability_shield(tmp_path / "nonexistent_wrangler.toml")
    assert missing_shield["shield_compliant"] is False
    assert missing_shield["error"] == "missing_wrangler_toml"

    # Ephemeral deploy config must never mutate tracked wrangler.toml and must clean up temp file
    test_uuid = "12345678-1234-4321-8765-123456789abc"
    seen_configs: List[Path] = []

    def _fake_run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        if "--config" in cmd:
            cfg = Path(cmd[cmd.index("--config") + 1])
            assert cfg.exists()
            assert cfg != wrangler_path
            assert f'database_id = "{test_uuid}"' in cfg.read_text(encoding="utf-8")
            seen_configs.append(cfg)
        return subprocess.CompletedProcess(cmd, 0, stdout="ok\n", stderr="")

    with patch.object(deploy_cloudflare, "run_cmd", side_effect=_fake_run_cmd):
        deploy_cloudflare.deploy_with_ephemeral_config(test_uuid, src_toml=wrangler_path)

    assert len(seen_configs) == 2
    for cfg in seen_configs:
        assert not cfg.exists(), f"Ephemeral config leaked on disk: {cfg}"
    assert wrangler_path.read_bytes() == before_bytes


def test_07_wsgi_endpoints_pep3333_strict_csp3_and_head_405_404() -> None:
    store = mirror.DriftWatchMirrorStore()
    validated_app = validator(mirror.create_wsgi_app(store))

    for route in ("/", "/health", "/healthz", "/telemetry/24h", "/envelopes"):
        st, hdrs, body = _wsgi_request(validated_app, route, method="GET")
        assert st == "200 OK", f"Route {route} returned {st}"
        assert hdrs["X-Content-Type-Options"] == "nosniff"
        assert hdrs["X-Frame-Options"] == "DENY"
        assert hdrs["Referrer-Policy"] == "no-referrer"
        assert "default-src 'none'" in hdrs["Content-Security-Policy"]
        assert "frame-ancestors 'none'" in hdrs["Content-Security-Policy"]
        assert int(hdrs["Content-Length"]) == len(body)
        assert chr(36).encode("ascii") not in body

        st_h, hdrs_h, body_h = _wsgi_request(validated_app, route, method="HEAD")
        assert st_h == "200 OK"
        assert body_h == b""
        assert int(hdrs_h["Content-Length"]) > 0

        if route == "/":
            html_str = body.decode("utf-8")
            assert f"'sha256-{mirror.STYLE_SHA256_B64}'" in hdrs["Content-Security-Policy"]
            assert "<script" not in html_str.lower()
            assert "0.0000 USD" in html_str
        else:
            parsed = json.loads(body.decode("utf-8"))
            assert parsed["version"] == "v3.9.1"

    st_j, _, body_j = _wsgi_request(validated_app, "/", query="format=json", method="GET")
    assert st_j == "200 OK"
    assert json.loads(body_j.decode("utf-8"))["active_targets"] == 40

    st_405, _, body_405 = _wsgi_request(validated_app, "/health", method="POST")
    assert st_405 == "405 Method Not Allowed"
    assert json.loads(body_405.decode("utf-8"))["error"] == "method_not_allowed"

    st_404, _, body_404 = _wsgi_request(validated_app, "/unknown", method="GET")
    assert st_404 == "404 Not Found"
    assert json.loads(body_404.decode("utf-8"))["error"] == "not_found"
