#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 AlpLab Research
# SPDX-License-Identifier: MIT
"""Zero-ASCII-36 Cloudflare Worker + D1 deployment orchestrator for Drift-Watch v3.9.0.

Verifies Wrangler authentication, resolves or provisions D1 database
alplab-drift-watch-v39-db, patches database_id in wrangler.toml, executes
migrations/0001_drift_watch_v39_d1.sql remotely, and deploys the Worker
with Dec 1 2026 Observability Free-Tier Shield (0.0000 USD out-of-pocket).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
WRANGLER_TOML = REPO_ROOT / "wrangler.toml"
MIGRATION_SQL = REPO_ROOT / "migrations" / "0001_drift_watch_v39_d1.sql"
DB_NAME = "alplab-drift-watch-v39-db"
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    proc = subprocess.run(
        cmd,
        cwd=str(REPO_ROOT),
        text=True,
        capture_output=True,
        check=False,
    )
    if check and proc.returncode != 0:
        sys.stderr.write(f"Command failed ({proc.returncode}): {' '.join(cmd)}\n")
        if proc.stdout:
            sys.stderr.write(proc.stdout + "\n")
        if proc.stderr:
            sys.stderr.write(proc.stderr + "\n")
        raise SystemExit(proc.returncode)
    return proc


def resolve_or_create_d1() -> str:
    listed = run_cmd(["npx", "--yes", "wrangler", "d1", "list", "--json"], check=True)
    rows = json.loads(listed.stdout or "[]")
    for item in rows:
        if isinstance(item, dict) and item.get("name") == DB_NAME:
            uid = str(item.get("uuid") or "")
            if UUID_RE.fullmatch(uid):
                return uid

    created = run_cmd(["npx", "--yes", "wrangler", "d1", "create", DB_NAME], check=True)
    combined = (created.stdout or "") + "\n" + (created.stderr or "")
    for match in UUID_RE.findall(combined):
        if match != "00000000-0000-0000-0000-000000000000":
            return match
    raise RuntimeError("Could not extract D1 database UUID from wrangler d1 create output.")


def patch_wrangler_database_id(db_uuid: str) -> None:
    src = WRANGLER_TOML.read_text(encoding="utf-8")
    lines = src.splitlines()
    updated: List[str] = []
    replaced = False
    for line in lines:
        if line.strip().startswith("database_id") and not replaced:
            updated.append(f'database_id = "{db_uuid}"')
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        raise RuntimeError("database_id field not found in wrangler.toml")
    WRANGLER_TOML.write_text("\n".join(updated) + "\n", encoding="utf-8")


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Deploy Drift-Watch v3.9.0 to Cloudflare Workers + D1 (0.0000 USD).")
    ap.add_argument("--dry-run", action="store_true", help="Bundle and validate Worker without remote mutation.")
    ap.add_argument("--outdir", default="/tmp/dw_v39_dist", help="Output directory for --dry-run bundle.")
    args = ap.parse_args(argv)

    if args.dry_run:
        res = run_cmd(["npx", "--yes", "wrangler", "deploy", "--dry-run", "--outdir", args.outdir], check=True)
        sys.stdout.write(res.stdout)
        return 0

    run_cmd(["npx", "--yes", "wrangler", "whoami"], check=True)
    db_uuid = resolve_or_create_d1()
    patch_wrangler_database_id(db_uuid)
    run_cmd(
        [
            "npx",
            "--yes",
            "wrangler",
            "d1",
            "execute",
            DB_NAME,
            "--remote",
            "--file",
            str(MIGRATION_SQL),
        ],
        check=True,
    )
    dep = run_cmd(["npx", "--yes", "wrangler", "deploy"], check=True)
    sys.stdout.write(dep.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
