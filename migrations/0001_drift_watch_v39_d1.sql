-- IS-FON-93 / Drift-Watch v3.9.1 Cloudflare D1 SQLite Schema (Zero-Cash Free Tier, 40 Targets W01..W40)
-- Closes DEADEND-K5-DRIFTV38-D1-SCHEMA-WORKER-SPLITBRAIN-20261124, DEADEND-K5-B77554C6, D90-4..D90-6:
--   1) Unified column name last_polled_epoch_min + partial index idx_dw_targets_cold_start (0-SCAN).
--   2) Unified rollup table dw_poll_hourly_rollup (hour_bucket_utc PK, 0-SCAN range read, 168h GC).
--   3) Explicit is_mc06_core (0/1) column eliminating lexical target_id <= 'W34' spoof (D90-4).
--   4) 40 targets seeded (W01..W34 is_mc06_core=1, W35..W40 is_mc06_core=0), 40 unique Weyl offsets.
-- Strict KURAL-3 hygiene: 0 chr(36) anywhere in file; USD only.

CREATE TABLE IF NOT EXISTS dw_targets (
  target_id TEXT PRIMARY KEY,
  entity_key TEXT NOT NULL,
  group_code TEXT NOT NULL,
  is_mc06_core INTEGER NOT NULL DEFAULT 0 CHECK (is_mc06_core IN (0, 1)),
  url TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'html',
  value_at_risk_micro_usd INTEGER NOT NULL,
  action_cost_min INTEGER NOT NULL,
  alpha_milli INTEGER NOT NULL CHECK (alpha_milli >= 350),
  beta_days_milli INTEGER NOT NULL CHECK (beta_days_milli >= 7000),
  mu_milli INTEGER NOT NULL,
  external_cliff_utc TEXT,
  internal_gate_utc TEXT,
  peak_utc_start INTEGER NOT NULL DEFAULT 14 CHECK (peak_utc_start >= 0 AND peak_utc_start <= 23),
  peak_utc_end INTEGER NOT NULL DEFAULT 22 CHECK (peak_utc_end >= 1 AND peak_utc_end <= 24),
  bayes_polls_day_milli INTEGER NOT NULL,
  base_period_min INTEGER NOT NULL CHECK (base_period_min >= 120 AND base_period_min <= 2880),
  period_min INTEGER NOT NULL CHECK (period_min >= 120 AND period_min <= 2880),
  weyl_offset_min INTEGER NOT NULL UNIQUE CHECK (weyl_offset_min >= 0 AND weyl_offset_min < 1440),
  nhpp_mult_milli INTEGER NOT NULL DEFAULT 1000,
  lambda_ucb90_milli INTEGER NOT NULL DEFAULT 50,
  next_due_epoch_min INTEGER NOT NULL,
  last_polled_epoch_min INTEGER NOT NULL DEFAULT 0,
  last_etag TEXT NOT NULL DEFAULT '',
  last_modified TEXT NOT NULL DEFAULT '',
  last_canon_sha256 TEXT NOT NULL DEFAULT '',
  last_signals_json TEXT NOT NULL DEFAULT '{}',
  last_body_bytes INTEGER NOT NULL DEFAULT 0 CHECK (last_body_bytes >= 0),
  last_http_status INTEGER NOT NULL DEFAULT 0,
  consecutive_429_count INTEGER NOT NULL DEFAULT 0,
  consecutive_dead_count INTEGER NOT NULL DEFAULT 0,
  consecutive_net_err_count INTEGER NOT NULL DEFAULT 0,
  last_alert_sig TEXT NOT NULL DEFAULT '',
  last_alert_epoch_min INTEGER NOT NULL DEFAULT 0,
  active INTEGER NOT NULL DEFAULT 1,
  updated_at_utc TEXT NOT NULL
);

-- R108 Covering Index: guarantees 0 full-table SCAN under D1 5M row-read/day Free cap
CREATE INDEX IF NOT EXISTS idx_dw_targets_active_due
  ON dw_targets(active, next_due_epoch_min, target_id);

-- D92-1 Partial Index: 0-SCAN cold-start self-heal (reads 0 rows once all 40 targets polled)
CREATE INDEX IF NOT EXISTS idx_dw_targets_cold_start
  ON dw_targets(next_due_epoch_min, target_id)
  WHERE active = 1 AND last_polled_epoch_min = 0;

-- D92-2 Canonical Hourly Poll & HTTP 304 Rollup Table (max 168 rows = 7 days, INTEGER PK = 0-SCAN)
CREATE TABLE IF NOT EXISTS dw_poll_hourly_rollup (
  hour_bucket_utc INTEGER PRIMARY KEY,
  polls_total INTEGER NOT NULL DEFAULT 0 CHECK (polls_total >= 0),
  polls_cold_start INTEGER NOT NULL DEFAULT 0 CHECK (polls_cold_start >= 0),
  polls_warm INTEGER NOT NULL DEFAULT 0 CHECK (polls_warm >= 0),
  polls_conditional_sent INTEGER NOT NULL DEFAULT 0 CHECK (polls_conditional_sent >= 0),
  http_304_count INTEGER NOT NULL DEFAULT 0 CHECK (http_304_count >= 0),
  http_200_count INTEGER NOT NULL DEFAULT 0 CHECK (http_200_count >= 0),
  http_403_waf_count INTEGER NOT NULL DEFAULT 0 CHECK (http_403_waf_count >= 0),
  http_404_410_count INTEGER NOT NULL DEFAULT 0 CHECK (http_404_410_count >= 0),
  http_429_count INTEGER NOT NULL DEFAULT 0 CHECK (http_429_count >= 0),
  http_5xx_count INTEGER NOT NULL DEFAULT 0 CHECK (http_5xx_count >= 0),
  net_err_count INTEGER NOT NULL DEFAULT 0 CHECK (net_err_count >= 0),
  bytes_fetched INTEGER NOT NULL DEFAULT 0 CHECK (bytes_fetched >= 0),
  bytes_saved_est INTEGER NOT NULL DEFAULT 0 CHECK (bytes_saved_est >= 0),
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dw_events (
  event_id INTEGER PRIMARY KEY AUTOINCREMENT,
  target_id TEXT NOT NULL,
  detected_at_utc TEXT NOT NULL,
  severity TEXT NOT NULL,
  quarantine_class TEXT NOT NULL DEFAULT 'NOISY_DRIFT_QUARANTINE',
  rule_refs TEXT NOT NULL,
  reasons TEXT NOT NULL,
  zcl_admitted INTEGER NOT NULL DEFAULT 0,
  zcl_density_milli INTEGER NOT NULL DEFAULT 0,
  acknowledged INTEGER NOT NULL DEFAULT 0,
  FOREIGN KEY(target_id) REFERENCES dw_targets(target_id)
);

CREATE INDEX IF NOT EXISTS idx_dw_events_unack_sev
  ON dw_events(acknowledged, severity, quarantine_class, detected_at_utc);

CREATE TABLE IF NOT EXISTS dw_weekly_budget (
  iso_week TEXT PRIMARY KEY,
  budget_min INTEGER NOT NULL DEFAULT 60,
  used_min INTEGER NOT NULL DEFAULT 0,
  updated_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dw_provider_quota_envelopes (
  target_id TEXT PRIMARY KEY,
  provider_family TEXT NOT NULL DEFAULT 'unknown',
  binding_bucket TEXT NOT NULL DEFAULT 'default',
  quota_unit TEXT NOT NULL DEFAULT 'requests',
  last_http_status INTEGER NOT NULL DEFAULT 0,
  throttle_kind TEXT NOT NULL DEFAULT 'none',
  retryable INTEGER NOT NULL DEFAULT 1,
  quarantine_class TEXT NOT NULL DEFAULT 'CLEAN_PASS',
  retry_after_sec INTEGER NOT NULL DEFAULT 0 CHECK (retry_after_sec >= 0),
  rl_limit INTEGER,
  rl_remaining INTEGER,
  rl_reset_sec INTEGER NOT NULL DEFAULT 0 CHECK (rl_reset_sec >= 0),
  effective_backoff_sec INTEGER NOT NULL DEFAULT 0 CHECK (effective_backoff_sec >= 0),
  clock_skew_sec INTEGER NOT NULL DEFAULT 0,
  guard_band_breached INTEGER NOT NULL DEFAULT 0,
  headroom_ratio_bps INTEGER,
  backoff_until_epoch_min INTEGER NOT NULL DEFAULT 0,
  consecutive_throttles INTEGER NOT NULL DEFAULT 0,
  observed_at_utc TEXT NOT NULL,
  FOREIGN KEY(target_id) REFERENCES dw_targets(target_id)
);

CREATE INDEX IF NOT EXISTS idx_dw_envelopes_quarantine_guard
  ON dw_provider_quota_envelopes(quarantine_class, guard_band_breached, retryable, effective_backoff_sec);

CREATE INDEX IF NOT EXISTS idx_dw_envelopes_throttled
  ON dw_provider_quota_envelopes(consecutive_throttles, backoff_until_epoch_min);

-- Seed W01..W40 (MC06 W01..W34 is_mc06_core=1; Wave-14 W35..W40 is_mc06_core=0; Nov 29 T-48h anchor)
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W01', 'entity:nlnet_codesupply', 'GRANT', 1, 'https://nlnet.nl/codesupply/', 'html', 19440000000, 20, 1400, 30000, 250, '2027-01-03', '2026-11-25', 8, 16, 6025, 210, 210, 145, 1214, 98, 29931850, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W02', 'entity:nlnet_restack', 'GRANT', 1, 'https://nlnet.nl/restack/', 'html', 19440000000, 20, 1400, 30000, 250, '2027-01-03', '2026-11-25', 8, 16, 6025, 210, 210, 55, 1214, 98, 29931855, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W03', 'entity:nlnet_commons', 'GRANT', 1, 'https://nlnet.nl/commonsfund/', 'html', 300000000, 5, 500, 60000, 50, NULL, NULL, 8, 16, 500, 2880, 2880, 15, 1200, 22, 29932010, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W04', 'entity:anthropic_erap', 'GRANT', 1, 'https://support.claude.com/en/articles/9125743-what-is-the-external-researcher-access-program', 'html', 1000000000, 15, 1300, 30000, 350, '2026-12-07', '2026-12-05', 14, 22, 2434, 660, 660, 410, 1850, 93, 29931910, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W05', 'entity:openai_codex_oss', 'GRANT', 1, 'https://openai.com/form/codex-open-source-fund/', 'html', 2500000000, 15, 1100, 30000, 220, NULL, '2026-11-25', 14, 22, 1821, 695, 695, 215, 1200, 82, 29931875, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W06', 'entity:ai_for_math_fund', 'GRANT', 1, 'https://www.renaissancephilanthropy.org/ai-for-math-fund', 'html', 10000000000, 20, 1000, 30000, 180, NULL, '2026-11-30', 14, 22, 3176, 400, 400, 280, 1200, 76, 29931870, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W07', 'entity:cf_startups', 'GRANT', 1, 'https://www.cloudflare.com/startups/', 'html', 1200000000, 10, 1200, 30000, 200, NULL, '2027-02-03', 14, 22, 1243, 1015, 1015, 590, 1200, 87, 29931890, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W08', 'entity:cf_alexandria', 'GRANT', 1, 'https://www.cloudflare.com/lp/project-alexandria/', 'html', 1200000000, 10, 800, 30000, 120, NULL, '2026-11-25', 14, 22, 824, 1535, 1535, 680, 1200, 64, 29931895, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W09', 'entity:eu_cascade_edito2', 'GRANT', 1, 'https://cascadefunding.eu/open-call/edito-oc2-integration-of-innovative-ocean-solutions-into-edito/', 'html', 500000000, 10, 500, 60000, 80, '2027-01-28', NULL, 8, 16, 500, 2880, 2880, 905, 1200, 22, 29931960, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W10', 'entity:gcp_free_trial', 'GRANT', 1, 'https://cloud.google.com/free', 'html', 300000000, 15, 900, 30000, 300, '2027-02-03', '2027-01-20', 14, 22, 682, 1855, 1855, 990, 1200, 70, 29932015, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W11', 'entity:cf_workers_ai', 'INFRA', 1, 'https://developers.cloudflare.com/workers-ai/platform/pricing/', 'html', 1800000000, 10, 1800, 30000, 500, '2026-12-01', '2026-11-30', 14, 22, 5942, 300, 300, 200, 2731, 119, 29931880, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W12', 'entity:cf_observability', 'INFRA', 1, 'https://developers.cloudflare.com/observability/pricing/', 'html', 1200000000, 10, 1700, 30000, 480, '2026-12-01', '2026-11-30', 14, 22, 4650, 380, 380, 25, 2731, 114, 29931900, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W13', 'entity:cf_d1_changelog', 'INFRA', 1, 'https://developers.cloudflare.com/changelog/post/2026-09-01-d1-free-tier-limit-enforcement/', 'html', 900000000, 8, 1100, 30000, 250, '2026-12-01', '2026-11-30', 14, 22, 2461, 720, 720, 5, 2731, 82, 29931925, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W14', 'entity:cf_workflows', 'INFRA', 1, 'https://developers.cloudflare.com/workflows/reference/pricing/', 'html', 600000000, 8, 900, 30000, 200, '2026-12-01', '2026-11-30', 14, 22, 1664, 1065, 1065, 335, 2731, 70, 29931940, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W15', 'entity:sambanova_limits', 'INFRA', 1, 'https://docs.sambanova.ai/', 'html', 960000000, 8, 1600, 30000, 450, '2026-12-01', '2026-11-30', 14, 22, 3935, 450, 450, 225, 2731, 109, 29931920, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W16', 'entity:nvidia_nim_docs', 'INFRA', 1, 'https://docs.api.nvidia.com/nim/', 'html', 1440000000, 10, 1500, 30000, 420, '2026-12-01', '2026-11-30', 14, 22, 4542, 390, 390, 165, 2731, 104, 29931885, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W17', 'entity:openalex_auth', 'INFRA', 1, 'https://help.openalex.org/api/authentication/', 'html', 600000000, 8, 1200, 30000, 220, NULL, NULL, 14, 22, 922, 1370, 1370, 1405, 1200, 87, 29931945, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W18', 'entity:unpaywall_api', 'INFRA', 1, 'https://unpaywall.org/products/api', 'html', 360000000, 6, 800, 30000, 180, NULL, NULL, 14, 22, 553, 2285, 2285, 1120, 1200, 64, 29931990, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W19', 'entity:jina_reader', 'INFRA', 1, 'https://jina.ai/reader/', 'html', 540000000, 8, 1100, 30000, 280, NULL, NULL, 8, 16, 955, 1325, 1325, 520, 1200, 82, 29931950, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W20', 'entity:firecrawl_pricing', 'INFRA', 1, 'https://www.firecrawl.dev/pricing', 'html', 720000000, 8, 1200, 30000, 250, NULL, NULL, 14, 22, 1077, 1175, 1175, 180, 1200, 87, 29931930, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W21', 'entity:beehiiv_pricing', 'INFRA', 1, 'https://www.beehiiv.com/blog/beehiiv-pricing-2026', 'html', 480000000, 6, 800, 30000, 150, NULL, NULL, 14, 22, 583, 2170, 2170, 230, 1200, 64, 29931965, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W22', 'entity:ipinfo_lite', 'INFRA', 1, 'https://ipinfo.io/lite', 'html', 300000000, 5, 700, 30000, 120, NULL, NULL, 14, 22, 500, 2880, 2880, 355, 1200, 58, 29932020, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W23', 'entity:frankfurter_v2', 'INFRA', 1, 'https://frankfurter.dev/', 'html', 240000000, 5, 600, 30000, 100, NULL, NULL, 8, 16, 500, 2880, 2880, 1250, 1200, 51, 29932025, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W24', 'entity:sigstore_public', 'INFRA', 1, 'https://www.sigstore.dev/', 'html', 480000000, 8, 700, 30000, 120, NULL, '2026-11-25', 14, 22, 500, 2555, 2555, 695, 1200, 58, 29931970, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W25', 'entity:openfreemap_tiles', 'S14_GEO', 1, 'https://openfreemap.org/', 'html', 360000000, 6, 800, 30000, 180, NULL, NULL, 8, 16, 553, 2285, 2285, 575, 1200, 64, 29931995, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W26', 'entity:tomtom_dev_maps', 'S14_GEO', 1, 'https://developer.tomtom.com/pricing', 'html', 480000000, 6, 1000, 30000, 220, NULL, NULL, 8, 16, 769, 1645, 1645, 105, 1200, 76, 29931975, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W27', 'entity:locationiq_geocoding', 'S14_GEO', 1, 'https://locationiq.com/pricing', 'html', 540000000, 6, 1100, 30000, 240, NULL, NULL, 14, 22, 884, 1430, 1430, 305, 1200, 82, 29931955, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W28', 'entity:copernicus_cdse_eo', 'S14_EO', 1, 'https://dataspace.copernicus.eu/', 'html', 720000000, 10, 900, 30000, 200, NULL, NULL, 8, 16, 863, 1465, 1465, 1200, 1200, 70, 29931935, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W29', 'entity:weatherapi_free_comm', 'S14_EO', 1, 'https://www.weatherapi.com/pricing.aspx', 'html', 240000000, 5, 900, 30000, 180, NULL, NULL, 8, 16, 500, 2675, 2675, 150, 1200, 70, 29932030, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W30', 'entity:emqx_cloud_serverless', 'S14_IOT', 1, 'https://www.emqx.com/en/pricing', 'html', 360000000, 8, 1000, 30000, 220, NULL, NULL, 8, 16, 666, 1900, 1900, 435, 1200, 76, 29932000, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W31', 'entity:thingsboard_cloud_free', 'S14_IOT', 1, 'https://thingsboard.io/pricing/', 'html', 480000000, 10, 1200, 30000, 300, NULL, NULL, 8, 16, 963, 1315, 1315, 1065, 1200, 87, 29931980, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W32', 'entity:penpot_cloud_oss', 'S14_DESIGN', 1, 'https://penpot.app/', 'html', 360000000, 6, 700, 30000, 140, NULL, NULL, 8, 16, 500, 2730, 2730, 1045, 1200, 58, 29932005, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W33', 'entity:bluesky_atproto_api', 'S14_COMM', 1, 'https://docs.bsky.app/docs/advanced-guides/rate-limits', 'html', 240000000, 6, 1100, 30000, 250, NULL, NULL, 14, 22, 601, 2105, 2105, 780, 1200, 82, 29932035, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W34', 'entity:zulip_cloud_oss', 'S14_COMM', 1, 'https://zulip.com/for/open-source/', 'html', 480000000, 12, 800, 30000, 160, NULL, '2026-11-25', 14, 22, 602, 2100, 2100, 1330, 1200, 64, 29931985, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W35', 'entity:lightcone_commons_r3', 'W14_GRANT', 0, 'https://www.lesswrong.com/posts/3ASLq8ePNqkbeGqdj/lightcone-commons-round-1-complete-round-2-underway', 'html', 18000000000, 20, 1200, 30000, 280, '2027-01-01', '2026-12-20', 14, 22, 5814, 220, 220, 120, 1218, 87, 29931860, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W36', 'entity:clr_fund_rolling', 'W14_GRANT', 0, 'https://longtermrisk.org/grantmaking/', 'html', 15000000000, 18, 900, 30000, 180, NULL, '2026-12-15', 14, 22, 3735, 340, 340, 220, 1200, 70, 29931865, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W37', 'entity:aipho_2027_kaggle', 'W14_PRIZE', 0, 'https://aipho.org/', 'html', 25000000000, 15, 800, 45000, 140, '2027-04-01', '2026-12-10', 14, 22, 3318, 380, 380, 380, 1200, 43, 29931845, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W38', 'entity:mathlib_d4_roadmap', 'W14_STRAT', 0, 'https://mathlib-initiative.org/roadmap/', 'html', 1200000000, 12, 800, 30000, 150, NULL, '2026-12-01', 14, 22, 921, 1370, 1370, 860, 1200, 64, 29931905, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W39', 'entity:groq_free_limits', 'W14_API', 0, 'https://console.groq.com/docs/rate-limits', 'html', 1100000000, 8, 1500, 30000, 420, '2026-12-01', '2026-11-30', 14, 22, 3970, 445, 445, 75, 2731, 104, 29931915, '2026-11-24T12:30:00Z');
INSERT OR IGNORE INTO dw_targets (target_id, entity_key, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, external_cliff_utc, internal_gate_utc, peak_utc_start, peak_utc_end, bayes_polls_day_milli, base_period_min, period_min, weyl_offset_min, nhpp_mult_milli, lambda_ucb90_milli, next_due_epoch_min, updated_at_utc) VALUES ('W40', 'entity:aistudio_free_limits', 'W14_API', 0, 'https://ai.google.dev/gemini-api/docs/deprecations', 'html', 900000000, 8, 1400, 30000, 380, '2026-12-01', '2026-11-30', 14, 22, 3327, 535, 535, 45, 2731, 98, 29932040, '2026-11-24T12:30:00Z');
