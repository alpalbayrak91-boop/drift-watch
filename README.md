# Drift-Watch v3.9.1

Zero-cash policy, grant, and cloud free-tier quota drift radar powered by Cloudflare Workers + D1 SQLite and a zero-dependency Python 3.12 WSGI scale-to-zero edge mirror (`0.0000 USD` out-of-pocket).

## Architecture Highlights

- **40 Seeded Endpoints (`W01..W40`)**:
  - `34` strict `MC06` core grant, API, and cloud free-tier pricing/changelog targets (`W01..W34`, `is_mc06_core = 1`).
  - `6` `Wave-14` rolling grant, prize, and API deprecation targets (`W35..W40`, `is_mc06_core = 0`).
  - `40` unique modular Weyl phase offsets (`0..1439` minutes) preventing synchronized burst polling.
- **Idempotent & 0-SCAN SQLite / Cloudflare D1 Schema (`migrations/0001_drift_watch_v39_d1.sql`)**:
  - Idempotent `INSERT OR IGNORE` seeding preserves live `last_polled_epoch_min`, `last_etag`, `last_canon_sha256`, and EWMA state across redeployments.
  - Covering index `idx_dw_targets_active_due` (`active, next_due_epoch_min, target_id`) guarantees zero full-table scans under the Cloudflare D1 `5,000,000` row-read/day Free Tier ceiling.
  - Partial index `idx_dw_targets_cold_start` (`WHERE active = 1 AND last_polled_epoch_min = 0`) paired with disjoint `UNION ALL` range seeks reads zero rows once initial cold-start polling completes.
  - Integer-keyed hourly rollup table `dw_poll_hourly_rollup` (`168`-hour sliding retention) tracks conditional `If-None-Match` / `If-Modified-Since` `HTTP 304` efficiency.
- **Dec 1, 2026 Cloudflare Observability Split-Billing Shield (`wrangler.toml`)**:
  - Pre-hardened against unbundled invocation log and trace overages (fail-closed verification):
    - `head_sampling_rate = 0.10`
    - `invocation_logs = false`
    - `[observability.traces] enabled = false`
- **Hardened Worker & Scale-to-Zero Python 3.12 Edge Mirror (`src/cf_drift_watch_v39_worker.js`, `server/drift_watch_edge_mirror.py`, `Dockerfile`)**:
  - Enforces `GET` / `HEAD` (`405` on unsupported methods), JSON `404` on unknown routes, Strict-CSP3 headers, and `X-Content-Type-Options: nosniff`.
  - Defaults to `127.0.0.1` on bare host (`K_SERVICE` / `BIND_HOST` inside Cloud Run container with `PORT` env var).

## Endpoints

| Path | Method | Description |
| --- | --- | --- |
| `/` | `GET`, `HEAD` | Strict-CSP3 status overview (`?format=json` returns JSON on WSGI mirror) |
| `/health`, `/healthz` | `GET`, `HEAD` | Target counts, MC06 core verification, 0-SCAN index audit, 24h HTTP 304 ratios, and Dec 1 Observability Shield state |
| `/telemetry/24h` | `GET`, `HEAD` | Hourly rollup window (`dw_poll_hourly_rollup`, last 24 hours) |
| `/envelopes` | `GET`, `HEAD` | Normalized provider rate-limit and quarantine envelopes (`dw_provider_quota_envelopes`) |

## Quick Verification

```bash
node --check src/cf_drift_watch_v39_worker.js
pytest -v tests/test_drift_watch_v39.py
python3 scripts/deploy_cloudflare.py --dry-run --outdir /tmp/dw_v39_dist
```

## Deployment

### Cloudflare Workers + D1 (Free Tier, Clean Config)

`scripts/deploy_cloudflare.py` generates an ephemeral Wrangler config during deployment so tracked `wrangler.toml` never stores live D1 UUIDs:

```bash
python3 scripts/deploy_cloudflare.py
```

### Scale-to-Zero Container (`Dockerfile`)

```bash
docker build -t drift-watch-v39 .
docker run --rm -p 127.0.0.1:8080:8080 drift-watch-v39
```

## License

MIT License. Copyright (c) 2026 AlpLab Research. All monetary units are expressed strictly in `USD`.
