# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: MIT
"""Pytest verification suite for Drift-Watch v3.9.0 Worker, D1 SQLite Schema,
Dec 1 2026 Observability Shield, and Scale-to-Zero Python 3.12 WSGI Edge Mirror.

Strict KURAL-3 hygiene: 0 chr(36) across every file in the repository; USD only.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple
from wsgiref.validate import validator

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from server import drift_watch_edge_mirror as mirror  # noqa: E402

EXCLUDED_DIRS = {".git", "node_modules", "__pycache__", ".pytest_cache", ".wrangler", "dist"}

# SHA-256 digests of disallowed non-fleet / quarantined account tokens (keeps plaintext out of public repo)
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
    assert len(repo_files) >= 9
    for fp in repo_files:
        text = fp.read_text(encoding="utf-8")
        assert chr(36) not in text, f"ASCII-36 violation in {fp.relative_to(REPO_ROOT)}"


def test_02_kural7_kural8_clean_host_bind_and_opsec() -> None:
    py_mirror = (REPO_ROOT / "server" / "drift_watch_edge_mirror.py").read_text(encoding="utf-8")
    assert '"127.0.0.1"' in py_mirror
    assert "0.0.0.0" not in py_mirror

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


def test_03_node_syntax_check_cloudflare_worker() -> None:
    worker_js = REPO_ROOT / "src" / "cf_drift_watch_v39_worker.js"
    assert worker_js.exists()
    proc = subprocess.run(
        ["node", "--check", str(worker_js)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, f"node --check failed: {proc.stderr}"


def test_04_sqlite_d1_schema_40_targets_34_mc06_and_unique_weyl() -> None:
    store = mirror.DriftWatchMirrorStore()
    health = store.health_payload()
    assert health["status"] == "ok"
    assert health["version"] == "v3.9.0"
    assert health["active_targets"] == 40
    assert health["mc06_core_w01_w34_active"] == 34
    assert health["wave14_extension_w35_w40_active"] == 6
    assert health["unique_weyl_offsets_count"] == 40
    assert health["cold_start_pending_count"] == 40
    assert health["cash_overage_usd"] == "0.0000 USD"
    assert health["kural3_zero_chr36"] is True


def test_05_explain_query_plan_zero_full_table_scans() -> None:
    store = mirror.DriftWatchMirrorStore()
    audit = store.verify_zero_table_scans()
    assert audit["zero_full_table_scans"] is True, f"Full table scan detected: {audit}"
    assert audit["full_table_scan_count"] == 0
    assert audit["index_count"] == 5
    assert "idx_dw_targets_active_due" in audit["covering_and_partial_indexes"]
    assert "idx_dw_targets_cold_start" in audit["covering_and_partial_indexes"]


def test_06_dec1_2026_observability_shield_wrangler_config() -> None:
    wrangler_txt = (REPO_ROOT / "wrangler.toml").read_text(encoding="utf-8")
    assert 'main = "src/cf_drift_watch_v39_worker.js"' in wrangler_txt
    shield = mirror.parse_observability_shield(REPO_ROOT / "wrangler.toml")
    assert shield["shield_compliant"] is True
    assert shield["head_sampling_rate"] == 0.10
    assert shield["logs_head_sampling_rate"] == 0.10
    assert shield["invocation_logs"] is False
    assert shield["traces_enabled"] is False


def test_07_wsgi_endpoints_pep3333_strict_csp3_and_head_405_404() -> None:
    store = mirror.DriftWatchMirrorStore()
    validated_app = validator(mirror.create_wsgi_app(store))

    for route in ("/", "/health", "/telemetry/24h", "/envelopes"):
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
            assert parsed["version"] == "v3.9.0"

    st_j, _, body_j = _wsgi_request(validated_app, "/", query="format=json", method="GET")
    assert st_j == "200 OK"
    assert json.loads(body_j.decode("utf-8"))["active_targets"] == 40

    st_405, _, body_405 = _wsgi_request(validated_app, "/health", method="POST")
    assert st_405 == "405 Method Not Allowed"
    assert json.loads(body_405.decode("utf-8"))["error"] == "method_not_allowed"

    st_404, _, body_404 = _wsgi_request(validated_app, "/missing", method="GET")
    assert st_404 == "404 Not Found"
    assert json.loads(body_404.decode("utf-8"))["error"] == "not_found"
