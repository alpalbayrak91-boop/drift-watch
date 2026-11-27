-- SPDX-FileCopyrightText: 2026 Alp Albayrak
-- SPDX-License-Identifier: MIT
-- Drift-Watch v4.0.0 Cloudflare D1 / SQLite 0-SCAN Schema
-- Covering index idx_dw_targets_active_due + partial index idx_dw_targets_cold_start
-- paired with disjoint UNION ALL seeks guarantee zero full-table scans.

CREATE TABLE IF NOT EXISTS dw_targets (
  target_id TEXT PRIMARY KEY,
  entity_key TEXT NOT NULL,
  category TEXT NOT NULL,
  is_core_target INTEGER NOT NULL DEFAULT 1 CHECK (is_core_target IN (0, 1)),
  url TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
  period_min INTEGER NOT NULL CHECK (period_min > 0),
  weyl_offset_min INTEGER NOT NULL CHECK (weyl_offset_min >= 0 AND weyl_offset_min < 1440),
  last_polled_epoch_min INTEGER NOT NULL DEFAULT 0,
  next_due_epoch_min INTEGER NOT NULL DEFAULT 0,
  last_etag TEXT NOT NULL DEFAULT '',
  last_canon_sha256 TEXT NOT NULL DEFAULT '',
  cusum_pos_bps INTEGER NOT NULL DEFAULT 0,
  cusum_neg_bps INTEGER NOT NULL DEFAULT 0,
  transient_429_streak INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_dw_targets_active_due
  ON dw_targets (active, next_due_epoch_min, target_id);

CREATE INDEX IF NOT EXISTS idx_dw_targets_cold_start
  ON dw_targets (active, next_due_epoch_min, target_id)
  WHERE active = 1 AND last_polled_epoch_min = 0;

CREATE TABLE IF NOT EXISTS dw_poll_hourly_rollup (
  hour_epoch INTEGER PRIMARY KEY,
  polls_count INTEGER NOT NULL DEFAULT 0,
  http_304_count INTEGER NOT NULL DEFAULT 0,
  quarantined_429_count INTEGER NOT NULL DEFAULT 0,
  confirmed_drift_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS dw_merkle_receipts (
  leaf_index INTEGER PRIMARY KEY,
  target_id TEXT NOT NULL,
  epoch_min INTEGER NOT NULL,
  rule_id TEXT NOT NULL,
  leaf_hash_sha256 TEXT NOT NULL,
  merkle_root_sha256 TEXT NOT NULL,
  jcs_payload TEXT NOT NULL
);

INSERT OR IGNORE INTO dw_targets (target_id, entity_key, category, is_core_target, url, period_min, weyl_offset_min, next_due_epoch_min) VALUES
  ('W01', 'cloudflare_workers_pricing', 'CLOUD_QUOTA', 1, 'https://developers.cloudflare.com/workers/platform/pricing/', 360, 5, 29932005),
  ('W02', 'cloudflare_d1_limits', 'CLOUD_QUOTA', 1, 'https://developers.cloudflare.com/d1/platform/pricing/', 360, 840, 29932840),
  ('W03', 'cloudflare_r2_pricing', 'CLOUD_QUOTA', 1, 'https://developers.cloudflare.com/r2/pricing/', 480, 235, 29932235),
  ('W04', 'cloudflare_workers_ai_pricing', 'CLOUD_QUOTA', 1, 'https://developers.cloudflare.com/workers-ai/platform/pricing/', 300, 1070, 29933070),
  ('W05', 'cloudflare_observability_pricing', 'CLOUD_QUOTA', 1, 'https://developers.cloudflare.com/observability/pricing/', 360, 465, 29932465),
  ('W06', 'cloudflare_workflows_pricing', 'CLOUD_QUOTA', 1, 'https://developers.cloudflare.com/workflows/reference/pricing/', 720, 1300, 29933300),
  ('W07', 'cloudflare_project_alexandria', 'OSS_GRANT', 1, 'https://www.cloudflare.com/lp/project-alexandria/', 720, 695, 29932695),
  ('W08', 'mozilla_fellowships_program', 'OSS_GRANT', 1, 'https://www.mozillafoundation.org/en/what-we-do/grantmaking/fellowship/', 360, 90, 29932090),
  ('W09', 'nlnet_ngi_zero_commons', 'OSS_GRANT', 1, 'https://nlnet.nl/commonsfund/', 720, 925, 29932925),
  ('W10', 'github_rest_ratelimit_docs', 'API_CONTRACT', 1, 'https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api', 360, 320, 29932320),
  ('W11', 'pypi_json_api_warehouse', 'API_CONTRACT', 1, 'https://docs.pypi.org/api/json/', 720, 1155, 29933155),
  ('W12', 'openalex_api_rate_limits', 'API_CONTRACT', 1, 'https://help.openalex.org/api/authentication/', 720, 550, 29932550),
  ('W13', 'sigstore_rekor_transparency', 'TRANSPARENCY', 1, 'https://www.sigstore.dev/', 720, 1385, 29933385),
  ('W14', 'ietf_rfc6962_spec', 'TRANSPARENCY', 1, 'https://www.rfc-editor.org/info/rfc6962/', 1440, 780, 29932780),
  ('W15', 'ietf_rfc8785_jcs_spec', 'TRANSPARENCY', 1, 'https://www.rfc-editor.org/info/rfc8785/', 1440, 175, 29932175),
  ('W16', 'mcp_specification_schema', 'MCP_SCHEMA', 0, 'https://modelcontextprotocol.io/specification', 360, 1010, 29933010),
  ('W17', 'bluesky_atproto_ratelimits', 'API_CONTRACT', 0, 'https://docs.bsky.app/docs/advanced-guides/rate-limits', 720, 405, 29932405),
  ('W18', 'crossref_rest_api_politeness', 'API_CONTRACT', 0, 'https://www.crossref.org/documentation/retrieve-metadata/rest-api/', 720, 1240, 29933240),
  ('W19', 'europepmc_rest_service', 'API_CONTRACT', 0, 'https://europepmc.org/RestfulWebService', 720, 635, 29932635),
  ('W20', 'arxiv_api_user_manual', 'API_CONTRACT', 0, 'https://info.arxiv.org/help/api/user-manual.html', 720, 30, 29932030);
