#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Ephemeral Cloudflare Worker + D1 deployment orchestrator for Drift-Watch v4.0.0.

Generates an ephemeral Wrangler configuration with the live D1 database UUID
so tracked wrangler.toml never stores live deployment identifiers or secrets.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List, Optional

REPO_ROOT = Path(__file__).resolve().parent.parent
WRANGLER_TOML = REPO_ROOT / "wrangler.toml"
MIGRATION_SQL = REPO_ROOT / "migrations" / "0001_drift_watch_v4_d1.sql"
DB_NAME = "drift-watch-v4-db"
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
        raise SystemExit(proc.returncode)
    return proc


def render_ephemeral_wrangler_toml(src_toml: Path, db_uuid: str) -> str:
    if not UUID_RE.fullmatch(db_uuid):
        raise ValueError(f"Invalid D1 UUID: {db_uuid}")
    lines = src_toml.read_text(encoding="utf-8").splitlines()
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
    return "\n".join(updated) + "\n"


def deploy_with_ephemeral_config(db_uuid: str, src_toml: Path = WRANGLER_TOML) -> subprocess.CompletedProcess[str]:
    rendered = render_ephemeral_wrangler_toml(src_toml, db_uuid)
    tmp_path: Optional[Path] = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(src_toml.parent),
            prefix=".wrangler.deploy.",
            suffix=".toml",
            delete=False,
        ) as fh:
            fh.write(rendered)
            tmp_path = Path(fh.name)

        run_cmd(
            [
                "npx",
                "--yes",
                "wrangler",
                "d1",
                "execute",
                DB_NAME,
                "--config",
                str(tmp_path),
                "--remote",
                "--file",
                str(MIGRATION_SQL),
            ],
            check=True,
        )
        return run_cmd(["npx", "--yes", "wrangler", "deploy", "--config", str(tmp_path)], check=True)
    finally:
        if tmp_path is not None:
            tmp_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Deploy Drift-Watch v4.0.0 to Cloudflare Workers + D1")
    parser.add_argument("--dry-run", action="store_true", help="Validate config and stage bundle without network calls")
    parser.add_argument("--outdir", default=None, help="Optional output directory for dry-run verification")
    parser.add_argument("--db-uuid", default="11111111-2222-4333-8444-555555555555", help="D1 database UUID")
    args = parser.parse_args()

    rendered = render_ephemeral_wrangler_toml(WRANGLER_TOML, args.db_uuid)
    if args.dry_run:
        if args.outdir:
            out = Path(args.outdir)
            out.mkdir(parents=True, exist_ok=True)
            (out / "wrangler.generated.toml").write_text(rendered, encoding="utf-8")
            shutil.copy2(REPO_ROOT / "worker" / "cf_drift_watch_v4.ts", out / "cf_drift_watch_v4.ts")
        print(json.dumps({"dry_run": True, "db_name": DB_NAME, "status": "validated"}))
        return 0

    deploy_with_ephemeral_config(args.db_uuid)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
