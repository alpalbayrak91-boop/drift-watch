// IS-FON-93 / KONU-5-FIRSAT-KOTA-RADARI (2026-11-24)
// Drift-Watch v3.9.0 Cloudflare Worker (Zero-Cash Free Tier, 40 Targets: 34 MC06 Core + 6 Wave-14)
// Full disk closure of DEADEND-K5-DRIFTV38-D1-SCHEMA-WORKER-SPLITBRAIN-20261124, DEADEND-K5-B77554C6, D90-4..D90-6:
//   - D92-1: Unified last_polled_epoch_min + partial index idx_dw_targets_cold_start (0-SCAN).
//   - D92-2: Unified dw_poll_hourly_rollup (hour_bucket_utc, polls_total, polls_cold_start, polls_warm,
//            polls_conditional_sent, http_304_count..net_err_count, bytes_fetched, bytes_saved_est).
//   - V38-F2b: Cold-start network error (!t.last_canon_sha256) retries at nowEpochMin + waitMin (no 48h stall).
//   - V38-F3: RFC 9110 Sec 13.1.3 stale ETag/Last-Modified clearing on HTTP 200 OK when header omitted.
//   - V38-F4: True elapsed dtDays = (nowEpochMin - t.last_polled_epoch_min) / 1440.0; skips cold-start EWMA.
//   - D90-4: Explicit is_mc06_core = 1 + strict W01..W34 guard (blocks W100 / CF01 lexical spoof).
//   - D90-5: Multi-label Public Suffix List (gov.tr, edu.tr, co.uk, europa.eu, etc.) for registrableDomain().
//   - D90-6: Scoped stale Vectorize paid-plan side-note filter on Cloudflare Workers pricing (agentdeals PR #3560).
// Strict KURAL-3 hygiene: 0 chr(36) anywhere in source; USD only; ZERO-FLASH-18 compliant.

const SEV_ORDER = {
  S0_NOOP: 0,
  S1_INFO_NEW_CALL: 1,
  S2_LIMIT_TIGHTENING: 2,
  S3_CARD_WALL_OR_LICENSE_DRIFT: 3,
  S4_DEADLINE_OR_ENDPOINT_DEATH: 4,
};

const SEV_ZCL_WEIGHT = {
  S0_NOOP: 0.0,
  S1_INFO_NEW_CALL: 0.15,
  S2_LIMIT_TIGHTENING: 0.40,
  S3_CARD_WALL_OR_LICENSE_DRIFT: 0.85,
  S4_DEADLINE_OR_ENDPOINT_DEATH: 1.00,
};

const MAX_BACKOFF_SEC = 86400;
const DEAD_REALERT_COOLDOWN_MIN = 10080;
const MIN_VALID_EPOCH_MIN = 29000000;
const DEFAULT_GUARD_BAND_EPS = 0.08;
const DEFAULT_EWMA_GAMMA = 0.92;
const DEFAULT_LAGRANGE_NU_REF = 16.2744;
const DEFAULT_T24H_MAX_PERIOD_MIN = 240;
const DEFAULT_ZCL_CLIFF_RESERVE_MIN = 20;
const DEFAULT_FETCH_TIMEOUT_MS = 8000;
const DEFAULT_TELEMETRY_RETENTION_HOURS = 168;
const Z90_QUANTILE = 1.2815515655446004;

const MULTI_LABEL_PUBLIC_SUFFIXES = new Set([
  "gov.tr", "edu.tr", "com.tr", "org.tr", "net.tr", "bel.tr", "k12.tr", "pol.tr", "mil.tr",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
  "com.au", "edu.au", "gov.au", "org.au", "net.au",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "co.kr", "go.kr", "or.kr", "ac.kr",
  "com.br", "gov.br", "org.br", "edu.br",
  "co.in", "gov.in", "ac.in", "org.in",
  "europa.eu",
]);

const RELEVANCE_KEYWORDS = [
  "grant", "grants", "call", "funding", "fellowship", "research", "credit",
  "credits", "pricing", "free tier", "quota", "neuron", "limit", "deprecated",
  "sunset", "closed", "restack", "codesupply", "erap", "external researcher",
  "open source", "oss", "math", "startup", "observability", "workers ai",
  "api", "billing", "non-commercial", "cc-by-nc", "genai", "bsl", "pay-per-use",
];

const SPEND_CAP_ERROR_CODES = new Set([
  "enforced_spend_limit_reached",
  "insufficient_quota",
  "credit_balance_exhausted",
  "billing_hard_limit_reached",
  "monthly_spend_limit_reached",
  "service_tier_capacity_exceeded",
  "payment_required",
  "spend_limit_exceeded",
  "free_tier_removed",
  "1300",
]);

const WAF_CHALLENGE_MARKERS = [
  "just a moment",
  "cf-browser-verification",
  "attention required",
  "cloudflare ray id",
  "access denied",
  "enable javascript and cookies",
  "bot protection",
  "captcha",
];

const RETIREMENT_PATH_MARKERS = [
  "/sunset",
  "/retired",
  "/deprecation",
  "/deprecated",
  "/decommissioned",
  "/discontinued",
  "/archive/closed",
  "/closed-programs",
];

const NONCOMM_RX = [
  /\bcc[- ]?by[- ]?nc\b/gi,
  /\bnon[- ]?commercial\b/gi,
  /\bticari\s+disi\b/gi,
  /\bpersonal\s+use\s+only\b/gi,
  /\bacademic\s+use\s+only\b/gi,
  /\bnot\s+for\s+commercial\s+use\b/gi,
];

const CARD_WALL_RX = [
  /\bcredit\s+card\s+required\b/gi,
  /\bpayment\s+method\s+required\b/gi,
  /\brequires\s+(?:a\s+)?(?:pro|paid)\s+plan\b/gi,
  /\bpro\s+subscription\s+required\b/gi,
  /\bupgrade\s+to\s+pro\b/gi,
  /\bcloud\s+billing\s+required\b/gi,
  /\bbilling\s+account\s+required\b/gi,
  /\bpay[- ]?per[- ]?use\b/gi,
  /\bstripe\s+connect\s+required\b/gi,
  /\bdonation[- ]?only\b/gi,
  /\bonly\s+available\s+on\s+the\s+workers\s+paid\s+plan\b/gi,
];

const CF_WORKERS_STALE_VECTORIZE_RX = /vectorize\s+is\s+currently\s+only\s+available\s+on\s+the\s+workers\s+paid\s+plan/gi;

const LICENSE_IP_RX = [
  /\b(?:bsl\s*1\.1|business\s+source\s+license|sspl|source[- ]?available)\b/gi,
  /\bpublicly\s+accessible\s+(?:documents?|designs?|cad)\b/gi,
  /\ball\s+(?:documents?|designs?|files?)\s+are\s+public\b/gi,
  /\bbulk\s+geocoding\s+(?:is\s+)?prohibited\b/gi,
];

const DEATH_RX = [
  /\b410\s+gone\b/gi,
  /\bpermanently\s+closed\b/gi,
  /\bno\s+longer\s+accepting\b/gi,
  /\bno\s+longer\s+available\b/gi,
  /\b(?:endpoint|model|api)\s+(?:is\s+)?(?:deprecated|removed|retired)\b/gi,
  /\bdeprecated\s+(?:on|effective|as\s+of)\b/gi,
  /\bsunset(?:ting)?\s+(?:on|date|effective|scheduled)\b/gi,
  /\b(?:shutting\s+down|will\s+shut\s+down|shut\s+down\s+on|end[- ]of[- ]life)\b/gi,
  /\bdiscontinued\b/gi,
  /\bcall\s+(?:is\s+)?closed\b/gi,
  /\bno\s+free\s+tier\b/gi,
  /\bfree\s+tier\s+(?:removed|has\s+ended|ends|ending|expires|discontinued|eliminated)\b/gi,
  /\bdecommissioned\b/gi,
  /\bhas\s+been\s+retired\b/gi,
  /\bretired\s+(?:on|effective)\b/gi,
];

const GENAI_RX = [
  /\bgenai\s+policy\b/gi,
  /\bhuman[- ]written\s+(?:application|proposal)\b/gi,
  /\bai[- ]generated\s+(?:applications?|proposals?)\s+(?:will\s+be\s+)?rejected\b/gi,
];

const NUMERIC_POLICY_RE_V4 = /(\+?\d{1,3}(?:,\d{3})+(?:\.\d+)?|\+?\d+(?:[.,]\d+)?)\s*(?:(?:free|daily|monthly|included|max|maximum|total|active|up\s+to|per)\s+){0,2}(%|usd|eur|gb\s*\/\s*day|gb\s+per\s+day|gb\/d|gb\/month|gb-month|gib|mib|gb|mb\s*\/\s*day|mb\s+per\s+day|mb|events\s*\/\s*day|events\s+per\s+day|events|writes\s*\/\s*day|writes\s+per\s+day|writes|reads\s*\/\s*day|reads\s+per\s+day|reads|req\s*\/\s*day|requests\s*\/\s*day|requests\s+per\s+day|credits\s*\/\s*day|credits\s*\/\s*month|credits|tokens|contacts|responses\/month|neurons|days|day|hours\/month|rpd|rpm|rps|tpd|tpm|files|apps|devices|calls\/month)/gi;

const DEADLINE_RE = /(\b202[6-9]-\d{2}-\d{2}\b|\b\d{1,2}\s+(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+202[6-9]\b|\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\s+\d{1,2},?\s+202[6-9]\b)/gi;

const NOISE_RX = [
  /<script[\s\S]*?<\/script>/gi,
  /<style[\s\S]*?<\/style>/gi,
  /<noscript[\s\S]*?<\/noscript>/gi,
  /<svg[\s\S]*?<\/svg>/gi,
  /<iframe[\s\S]*?<\/iframe>/gi,
  /<footer[\s\S]*?<\/footer>/gi,
  /<nav[\s\S]*?<\/nav>/gi,
  /<aside[\s\S]*?<\/aside>/gi,
  /<template[\s\S]*?<\/template>/gi,
  /<!--[\s\S]*?-->/g,
  /<[^>]+>/g,
  /\b[a-z0-9_-]+\.[0-9a-f]{6,16}\.(?:js|css)\b/gi,
  /\b\d+\s+(?:second|minute|hour|day|week)s?\s+ago\b/gi,
  /copyright\s+(?:\(c\)|&copy;)?\s*20\d{2}(?:-20\d{2})?/gi,
  /build[_-]?id[:=]\s*[0-9a-zA-Z_-]{6,}/gi,
  /nonce[:=]\s*[0-9a-zA-Z_-]{6,}/gi,
  /cookie\s+preferences|we\s+use\s+cookies[^.]*\./gi,
  /tile\s+cache\s+rev\s+[0-9a-f]{6,16}/gi,
];

function clampInt(val, lo, hi) {
  if (!Number.isFinite(val)) return lo;
  return Math.max(lo, Math.min(hi, Math.round(val)));
}

function trimTrailingSlashes(pathStr) {
  let p = String(pathStr || "/");
  while (p.length > 1 && p.charCodeAt(p.length - 1) === 47) {
    p = p.slice(0, -1);
  }
  return p || "/";
}

function trimTrailingDots(hostStr) {
  let h = String(hostStr || "");
  while (h.length > 0 && h.charCodeAt(h.length - 1) === 46) {
    h = h.slice(0, -1);
  }
  return h;
}

function isPureDigits(s, maxLen) {
  if (!s || s.length === 0 || s.length > maxLen) return false;
  return !/[^0-9]/.test(s);
}

function isPureNumber(s) {
  if (!s || s.length === 0) return false;
  let dots = 0;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s.charCodeAt(i);
    if (ch === 46) {
      dots += 1;
      if (dots > 1) return false;
    } else if (ch < 48 || ch > 57) {
      return false;
    }
  }
  return s !== ".";
}

function isByteSeq(s) {
  if (!s || s.length < 2 || s.charCodeAt(0) !== 58 || s.charCodeAt(s.length - 1) !== 58) return false;
  for (let i = 1; i < s.length - 1; i += 1) {
    const c = s.charCodeAt(i);
    const ok =
      (c >= 65 && c <= 90) ||
      (c >= 97 && c <= 122) ||
      (c >= 48 && c <= 57) ||
      c === 43 || c === 47 || c === 61;
    if (!ok) return false;
  }
  return true;
}

function stripQuotes(s) {
  if (!s) return "";
  let out = s.trim();
  if (out.length >= 2 && out.charCodeAt(0) === 34 && out.charCodeAt(out.length - 1) === 34) {
    out = out.slice(1, -1);
  }
  return out;
}

export function gammaUcb90(alphaMilli, betaDaysMilli) {
  const a = Math.max(0.35, (Number(alphaMilli) || 350) / 1000.0);
  const b = Math.max(7.0, (Number(betaDaysMilli) || 7000) / 1000.0);
  const wh = 1.0 - (1.0 / (9.0 * a)) + Z90_QUANTILE / Math.sqrt(9.0 * a);
  if (wh <= 0.1) {
    return (a / b) + (Z90_QUANTILE * Math.sqrt(a)) / b;
  }
  return (a / b) * (wh * wh * wh);
}

export function ewmaUpdateR105(alphaMilli, betaDaysMilli, dtDays, triggered, gammaDecay) {
  const g = Number.isFinite(gammaDecay) ? Math.min(0.99, Math.max(0.50, gammaDecay)) : DEFAULT_EWMA_GAMMA;
  const dt = Math.max(0.02, Number.isFinite(dtDays) ? dtDays : 0.25);
  const w = Math.pow(g, dt);
  const obs = triggered ? 1000 : 0;
  const newAlpha = Math.max(350, Math.round(w * (Number(alphaMilli) || 350) + obs));
  const newBeta = Math.max(7000, Math.round(w * (Number(betaDaysMilli) || 7000) + dt * 1000.0));
  return { alphaMilli: newAlpha, betaDaysMilli: newBeta };
}

export function daysUntilIsoDate(cliffIso, nowDate) {
  if (!cliffIso || typeof cliffIso !== "string") return null;
  const parts = cliffIso.trim().split("-");
  if (parts.length !== 3) return null;
  const y = parseInt(parts[0], 10);
  const m = parseInt(parts[1], 10);
  const d = parseInt(parts[2], 10);
  if (!Number.isFinite(y) || !Number.isFinite(m) || !Number.isFinite(d)) return null;
  const cliffMs = Date.UTC(y, m - 1, d);
  const todayMs = Date.UTC(nowDate.getUTCFullYear(), nowDate.getUTCMonth(), nowDate.getUTCDate());
  return Math.round((cliffMs - todayMs) / 86400000.0);
}

export function nhppAvgMultiplier(cliffIso, peakStart, peakEnd, nowDate) {
  const pkS = Number.isFinite(Number(peakStart)) ? Number(peakStart) : 14;
  const pkE = Number.isFinite(Number(peakEnd)) ? Number(peakEnd) : 22;
  const diurnal = 1.0 + 0.60 * Math.max(0, pkE - pkS) / 24.0;
  const daysLeft = daysUntilIsoDate(cliffIso, nowDate);
  let cliffBoost = 1.0;
  if (daysLeft !== null && daysLeft >= 0 && daysLeft <= 45) {
    cliffBoost = 1.0 + 4.0 * Math.exp(-daysLeft / 7.0);
  }
  return { mult: diurnal * cliffBoost, daysLeft };
}

export function computeDynamicPeriodR104(target, alphaMilli, betaDaysMilli, nowDate, nuRef, t24hMaxPeriodMin) {
  const valUsd = Math.max(1.0, (Number(target.value_at_risk_micro_usd) || 240000000) / 1000000.0);
  const muDay = Math.max(0.05, (Number(target.mu_milli) || 100) / 1000.0);
  const lam = gammaUcb90(alphaMilli, betaDaysMilli);
  const nhppObj = nhppAvgMultiplier(target.external_cliff_utc, target.peak_utc_start, target.peak_utc_end, nowDate);
  const weight = Math.max(1e-9, valUsd * lam * nhppObj.mult * muDay);
  const nu = Math.max(1e-6, Number.isFinite(nuRef) ? nuRef : DEFAULT_LAGRANGE_NU_REF);
  const freq = Math.min(12.0, Math.max(0.5, Math.sqrt(weight / nu)));
  let pMin = Math.round((1440.0 / freq) / 5.0) * 5;
  pMin = clampInt(pMin, 120, 2880);
  const grp = String(target.group_code || "");
  const capT24 = clampInt(Number.isFinite(t24hMaxPeriodMin) ? t24hMaxPeriodMin : DEFAULT_T24H_MAX_PERIOD_MIN, 120, 360);
  if ((grp === "INFRA" || grp === "W14_API") && valUsd >= 600.0 && nhppObj.daysLeft !== null && nhppObj.daysLeft >= 0 && nhppObj.daysLeft <= 2) {
    pMin = Math.min(pMin, capT24);
  }
  return {
    periodMin: pMin,
    lamUcb90Milli: Math.max(1, Math.round(lam * 1000.0)),
    nhppMultMilli: Math.max(1000, Math.round(nhppObj.mult * 1000.0)),
    daysLeft: nhppObj.daysLeft,
  };
}

export function modularWeylNextDue(nowEpochMin, weylOffsetMin, periodMin, minWaitMin) {
  const p = Math.max(30, parseInt(periodMin, 10) || 60);
  const off = ((parseInt(weylOffsetMin, 10) || 0) % p + p) % p;
  const wait = Math.max(0, parseInt(minWaitMin, 10) || 0);
  const floorTarget = nowEpochMin + wait;
  let k;
  if (wait <= 0) {
    k = Math.floor((floorTarget - off) / p) + 1;
  } else {
    k = Math.ceil((floorTarget - off) / p);
    if (off + k * p <= nowEpochMin) k += 1;
  }
  return off + k * p;
}

export function zclThresholdTimeDecayed(utilZ, lowerL, upperU, tauRem, gamma) {
  const z = Math.min(1.0, Math.max(0.0, utilZ));
  const tau = Math.min(1.0, Math.max(0.05, tauRem));
  return Math.pow((upperU * Math.E) / lowerL, z) * (lowerL / Math.E) * Math.pow(tau, gamma);
}

export function evaluateZclAdmissionR107(severity, valMicroUsd, actionCostMin, usedMin, weekBudget, cliffReserveMin, tauRem, shadowGamma, allowZcl) {
  const cost = Math.max(1, parseInt(actionCostMin, 10) || 10);
  const wBud = Math.max(1, parseInt(weekBudget, 10) || 60);
  const resv = clampInt(Number.isFinite(cliffReserveMin) ? cliffReserveMin : DEFAULT_ZCL_CLIFF_RESERVE_MIN, 0, Math.floor(wBud / 2));
  const weight = SEV_ZCL_WEIGHT[severity] !== undefined ? SEV_ZCL_WEIGHT[severity] : 0.0;
  const effValUsd = ((Number(valMicroUsd) || 0) / 1000000.0) * weight;
  const effDensity = effValUsd / cost;
  const isHighCliff = severity === "S3_CARD_WALL_OR_LICENSE_DRIFT" || severity === "S4_DEADLINE_OR_ENDPOINT_DEATH";
  const effectiveCap = isHighCliff ? wBud : Math.max(0, wBud - resv);
  const thresh = zclThresholdTimeDecayed(usedMin / wBud, 25.0, 1200.0, tauRem, shadowGamma);
  const admit = (
    allowZcl === 1 &&
    usedMin + cost <= effectiveCap &&
    (effDensity >= thresh || effDensity >= 1200.0 || severity === "S4_DEADLINE_OR_ENDPOINT_DEATH")
  ) ? 1 : 0;
  return { admit, effDensityMilli: Math.round(effDensity * 1000), threshMilli: Math.round(thresh * 1000), effectiveCap };
}

export function normalizeHtml(raw) {
  let txt = String(raw || "");
  for (let i = 0; i < NOISE_RX.length; i += 1) {
    txt = txt.replace(NOISE_RX[i], " ");
  }
  return txt.replace(/\s+/g, " ").trim();
}

function normalizeNumericUnit(rawUnit) {
  return String(rawUnit || "").trim().toLowerCase().replace(/\s+/g, " ").replace(/ per /g, "/").replace(/ \/ /g, "/");
}

function collectMatches(text, rxList) {
  const out = new Set();
  for (let i = 0; i < rxList.length; i += 1) {
    const rx = rxList[i];
    rx.lastIndex = 0;
    let m;
    while ((m = rx.exec(text)) !== null) {
      out.add(String(m[0]).toLowerCase().replace(/\s+/g, " ").trim());
      if (m.index === rx.lastIndex) rx.lastIndex += 1;
    }
  }
  return Array.from(out).sort();
}

export function sanitizeKnownStaleSideNotes(text, targetUrl) {
  const src = String(text || "");
  const uLow = String(targetUrl || "").toLowerCase();
  if (uLow.indexOf("developers.cloudflare.com/") !== -1 && uLow.indexOf("/vectorize") === -1) {
    return src.replace(CF_WORKERS_STALE_VECTORIZE_RX, " ");
  }
  return src;
}

export function extractPolicySignals(text, targetUrl) {
  const src = sanitizeKnownStaleSideNotes(text, targetUrl);
  const numSet = new Set();
  NUMERIC_POLICY_RE_V4.lastIndex = 0;
  let m;
  while ((m = NUMERIC_POLICY_RE_V4.exec(src)) !== null) {
    const val = String(m[1]).replace(/,/g, "").trim();
    const unit = normalizeNumericUnit(m[2]);
    numSet.add(val + "|" + unit);
    if (m.index === NUMERIC_POLICY_RE_V4.lastIndex) NUMERIC_POLICY_RE_V4.lastIndex += 1;
  }
  const dlSet = new Set();
  DEADLINE_RE.lastIndex = 0;
  while ((m = DEADLINE_RE.exec(src)) !== null) {
    dlSet.add(String(m[1]).toLowerCase().replace(/\s+/g, " ").trim());
    if (m.index === DEADLINE_RE.lastIndex) DEADLINE_RE.lastIndex += 1;
  }
  return {
    noncomm_flags: collectMatches(src, NONCOMM_RX),
    card_wall_flags: collectMatches(src, CARD_WALL_RX),
    license_ip_flags: collectMatches(src, LICENSE_IP_RX),
    death_flags: collectMatches(src, DEATH_RX),
    genai_flags: collectMatches(src, GENAI_RX),
    numeric_limits: Array.from(numSet).sort(),
    deadlines: Array.from(dlSet).sort(),
  };
}

export function parseFeedEntries(xmlText) {
  const src = String(xmlText || "");
  const entries = [];
  const itemRx = /<(item|entry)\b[^>]*>([\s\S]*?)<\/(item|entry)>/gi;
  let im;
  while ((im = itemRx.exec(src)) !== null) {
    const block = im[2];
    const tagVal = (name) => {
      const rx = new RegExp("<" + name + "\\b[^>]*>([\\s\\S]*?)<\\/" + name + ">", "i");
      const mm = rx.exec(block);
      return mm ? mm[1].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim() : "";
    };
    const atomHrefMatch = /<link\b[^>]*\bhref=["']([^"']+)["']/i.exec(block);
    const link = tagVal("link") || (atomHrefMatch ? atomHrefMatch[1].trim() : "");
    const id = tagVal("guid") || tagVal("id") || link || tagVal("title");
    const title = tagVal("title");
    const summary = tagVal("description") || tagVal("summary") || tagVal("content");
    if (id || title) entries.push({ id: id || title, title, link, summary });
  }
  return entries;
}

function isRelevantFeedEntry(entry) {
  const blob = (String(entry.title || "") + " " + String(entry.summary || "")).toLowerCase();
  for (let i = 0; i < RELEVANCE_KEYWORDS.length; i += 1) {
    if (blob.indexOf(RELEVANCE_KEYWORDS[i]) !== -1) return true;
  }
  return false;
}

function setDiff(currArr, baseArr) {
  const b = new Set(Array.isArray(baseArr) ? baseArr : []);
  const out = [];
  const c = Array.isArray(currArr) ? currArr : [];
  for (let i = 0; i < c.length; i += 1) {
    if (!b.has(c[i])) out.push(c[i]);
  }
  return out;
}

function parseBaselineSignals(rawJson) {
  try {
    const obj = JSON.parse(String(rawJson || "{}"));
    if (obj && typeof obj === "object") return obj;
  } catch (_e) {
    // empty baseline
  }
  return {};
}

export function registrableDomain(urlStr) {
  try {
    const host = trimTrailingDots((new URL(urlStr).hostname || "").toLowerCase());
    const parts = host.split(".").filter(Boolean);
    if (parts.length <= 2) return parts.join(".");
    const lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
    if (MULTI_LABEL_PUBLIC_SUFFIXES.has(lastTwo) && parts.length >= 3) {
      return parts[parts.length - 3] + "." + lastTwo;
    }
    return lastTwo;
  } catch (_e) {
    return "";
  }
}

export function isStrictMc06CoreTargetId(targetId) {
  const s = String(targetId || "").trim();
  if (s.length !== 3 || s.charCodeAt(0) !== 87) return false;
  const d1 = s.charCodeAt(1) - 48;
  const d2 = s.charCodeAt(2) - 48;
  if (d1 < 0 || d1 > 9 || d2 < 0 || d2 > 9) return false;
  const n = d1 * 10 + d2;
  return n >= 1 && n <= 34;
}

export function detectRetirementRedirect(origUrlStr, finalUrlStr) {
  if (!origUrlStr || !finalUrlStr || origUrlStr === finalUrlStr) return null;
  try {
    const origDom = registrableDomain(origUrlStr);
    const finalDom = registrableDomain(finalUrlStr);
    if (origDom && finalDom && origDom !== finalDom) {
      return "CROSS_DOMAIN_REDIRECT:" + origDom + "->" + finalDom;
    }
    const uOrig = new URL(origUrlStr);
    const uFinal = new URL(finalUrlStr);
    const origPath = trimTrailingSlashes(uOrig.pathname);
    const finalPath = trimTrailingSlashes(uFinal.pathname);
    const finalLow = finalPath.toLowerCase();
    for (let i = 0; i < RETIREMENT_PATH_MARKERS.length; i += 1) {
      if (finalLow.indexOf(RETIREMENT_PATH_MARKERS[i]) !== -1 && origPath.toLowerCase().indexOf(RETIREMENT_PATH_MARKERS[i]) === -1) {
        return "REDIRECT_TO_RETIREMENT_HUB:" + finalPath;
      }
    }
    const origDepth = origPath === "/" ? 0 : origPath.split("/").filter(Boolean).length;
    if (origDepth >= 2 && finalPath === "/") {
      return "REDIRECT_DEEP_PATH_COLLAPSED_TO_ROOT";
    }
  } catch (_err) {
    return null;
  }
  return null;
}

export function isWafOrBot403(httpStatus, contentType, bodyText) {
  if (httpStatus !== 403) return false;
  const ct = String(contentType || "").toLowerCase();
  const low = String(bodyText || "").toLowerCase();
  if (ct.indexOf("text/html") !== -1 || low.indexOf("<html") !== -1 || low.indexOf("<!doctype html") !== -1) {
    return true;
  }
  for (let i = 0; i < WAF_CHALLENGE_MARKERS.length; i += 1) {
    if (low.indexOf(WAF_CHALLENGE_MARKERS[i]) !== -1) return true;
  }
  return false;
}

export function classifySignalDiff(baseSig, currSig, httpStatus, spendCode, redirectReason) {
  let severity = "S0_NOOP";
  let quarantineClass = "NOISY_DRIFT_QUARANTINE";
  const reasons = [];
  const rules = [];
  const bump = (s, qClass) => {
    if (SEV_ORDER[s] > SEV_ORDER[severity]) {
      severity = s;
      quarantineClass = qClass;
    }
  };
  if (redirectReason) {
    bump("S4_DEADLINE_OR_ENDPOINT_DEATH", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push(redirectReason);
    rules.push("R88_D33_07_REDIRECT_TRAP");
  }
  if ((httpStatus === 429 || httpStatus === 402 || httpStatus === 403) && spendCode) {
    bump("S4_DEADLINE_OR_ENDPOINT_DEATH", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("SPEND_CAP_OR_SILENT_CUT:" + String(httpStatus) + ":" + String(spendCode));
    rules.push("R132_R135_RFC9457");
  }
  if (httpStatus === 404 || httpStatus === 410) {
    bump("S4_DEADLINE_OR_ENDPOINT_DEATH", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("HTTP_" + String(httpStatus) + "_GONE");
    rules.push("R88_R126_R132");
  }
  const addedDeath = setDiff(currSig.death_flags, baseSig.death_flags);
  const addedNoncomm = setDiff(currSig.noncomm_flags, baseSig.noncomm_flags);
  const addedCard = setDiff(currSig.card_wall_flags, baseSig.card_wall_flags);
  const addedLicIp = setDiff(currSig.license_ip_flags, baseSig.license_ip_flags);
  const addedGenai = setDiff(currSig.genai_flags, baseSig.genai_flags);
  const numAdd = setDiff(currSig.numeric_limits, baseSig.numeric_limits);
  const numRem = setDiff(baseSig.numeric_limits, currSig.numeric_limits);
  const dlAdd = setDiff(currSig.deadlines, baseSig.deadlines);

  if (addedDeath.length > 0) {
    bump("S4_DEADLINE_OR_ENDPOINT_DEATH", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("ADDED_DEATH_FLAGS:" + addedDeath.join(","));
    rules.push("R99_R102_R132");
  }
  if (addedNoncomm.length > 0) {
    bump("S3_CARD_WALL_OR_LICENSE_DRIFT", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("ADDED_NONCOMM_LICENSE:" + addedNoncomm.join(","));
    rules.push("R90_R97");
  }
  if (addedCard.length > 0) {
    bump("S3_CARD_WALL_OR_LICENSE_DRIFT", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("ADDED_CARD_WALL:" + addedCard.join(","));
    rules.push("R96_R102");
  }
  if (addedLicIp.length > 0) {
    bump("S3_CARD_WALL_OR_LICENSE_DRIFT", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("ADDED_LICENSE_OR_IP_SHIFT:" + addedLicIp.join(","));
    rules.push("R98_R100_R101");
  }
  if (addedGenai.length > 0) {
    bump("S3_CARD_WALL_OR_LICENSE_DRIFT", "PERMANENT_CAP_OR_SILENT_CUT");
    reasons.push("ADDED_GENAI_POLICY:" + addedGenai.join(","));
    rules.push("R90_GENAI_POLICY");
  }
  if (numAdd.length > 0 || numRem.length > 0) {
    bump("S2_LIMIT_TIGHTENING", "NOISY_DRIFT_QUARANTINE");
    reasons.push("NUMERIC_LIMIT_DELTA:rem=" + String(numRem.length) + ",add=" + String(numAdd.length));
    rules.push("MC06_S2_NUMERIC_V4");
  }
  if (dlAdd.length > 0) {
    bump("S2_LIMIT_TIGHTENING", "NOISY_DRIFT_QUARANTINE");
    reasons.push("NEW_DEADLINE:" + dlAdd.join(","));
    rules.push("MC06_S2_DEADLINE");
  }
  return { severity, quarantineClass, reasons, rules };
}

export function classifyFeedDelta(baseEntryIds, currEntries, targetUrl) {
  const baseSet = new Set(Array.isArray(baseEntryIds) ? baseEntryIds : []);
  let severity = "S0_NOOP";
  let quarantineClass = "NOISY_DRIFT_QUARANTINE";
  const reasons = [];
  const rules = [];
  const bump = (s, qClass) => {
    if (SEV_ORDER[s] > SEV_ORDER[severity]) {
      severity = s;
      quarantineClass = qClass;
    }
  };
  for (let i = 0; i < currEntries.length; i += 1) {
    const ent = currEntries[i];
    if (baseSet.has(ent.id) || !isRelevantFeedEntry(ent)) continue;
    const sig = extractPolicySignals(ent.title + " " + ent.summary, targetUrl);
    if (sig.death_flags.length > 0) {
      bump("S4_DEADLINE_OR_ENDPOINT_DEATH", "PERMANENT_CAP_OR_SILENT_CUT");
      reasons.push("FEED_CLOSURE_OR_SUNSET:" + ent.title.slice(0, 60));
    } else if (sig.noncomm_flags.length > 0 || sig.card_wall_flags.length > 0 || sig.genai_flags.length > 0 || sig.license_ip_flags.length > 0) {
      bump("S3_CARD_WALL_OR_LICENSE_DRIFT", "PERMANENT_CAP_OR_SILENT_CUT");
      reasons.push("FEED_LICENSE_OR_CARD_DRIFT:" + ent.title.slice(0, 60));
      rules.push("R90_SILENT_LICENSE_NONCOMM_DRIFT");
    } else {
      bump("S1_INFO_NEW_CALL", "NOISY_DRIFT_QUARANTINE");
      reasons.push("FEED_NEW_RELEVANT_CALL:" + ent.title.slice(0, 60));
      rules.push("MC06_S1_FEED_CALL");
    }
  }
  return { severity, quarantineClass, reasons, rules };
}

async function sha256Hex(text) {
  const buf = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function parseHttpDateMs(rawVal) {
  if (rawVal === null || rawVal === undefined) return null;
  const s = String(rawVal).trim();
  if (!s || isPureNumber(s)) return null;
  const ms = Date.parse(s);
  return Number.isFinite(ms) ? ms : null;
}

function parseRetryAfterSec(val, refNowMs) {
  if (val === null || val === undefined) return 0;
  const s = String(val).trim();
  if (!s || s.length > 200) return 0;
  if (s.charCodeAt(0) === 45 && isPureDigits(s.slice(1), 10)) return 0;
  if (isPureDigits(s, 9)) return clampInt(parseInt(s, 10), 0, MAX_BACKOFF_SEC);
  const parsed = parseHttpDateMs(s);
  if (parsed !== null) return clampInt(Math.ceil((parsed - refNowMs) / 1000.0), 0, MAX_BACKOFF_SEC);
  return 0;
}

export function parseResetSeconds(rawVal, refNowMs) {
  if (rawVal === null || rawVal === undefined) return null;
  const s = String(rawVal).trim();
  if (!s || s.length > 200) return null;
  if (/^[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}/.test(s)) {
    const ts = Date.parse(s);
    if (Number.isFinite(ts)) {
      return clampInt(Math.ceil((ts - refNowMs) / 1000.0), 0, MAX_BACKOFF_SEC);
    }
    return null;
  }
  const goTokenRx = /([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|m|h|d)/gi;
  const remainder = s.replace(goTokenRx, "");
  if (remainder.length === 0 && s.length > 0) {
    const unitSec = { d: 86400, h: 3600, m: 60, s: 1, ms: 0.001, us: 0.000001, "µs": 0.000001, ns: 0.000000001 };
    let total = 0.0;
    let m;
    goTokenRx.lastIndex = 0;
    while ((m = goTokenRx.exec(s)) !== null) {
      const n = parseFloat(m[1]);
      const u = m[2].toLowerCase();
      if (Number.isFinite(n) && unitSec[u] !== undefined) {
        total += n * unitSec[u];
      }
    }
    if (total <= 0) return 0;
    return clampInt(Math.ceil(total), 0, MAX_BACKOFF_SEC);
  }
  if (s.charCodeAt(0) === 45 && isPureNumber(s.slice(1))) return 0;
  if (isPureNumber(s)) {
    const num = parseFloat(s);
    const nowSec = refNowMs / 1000.0;
    let delta;
    if (num >= 100000000000000) {
      delta = (num / 1000000.0) - nowSec;
    } else if (num >= 100000000000) {
      delta = (num / 1000.0) - nowSec;
    } else if (num >= 1000000000) {
      delta = num - nowSec;
    } else {
      delta = num;
    }
    return clampInt(Math.ceil(delta), 0, MAX_BACKOFF_SEC);
  }
  const parsed = parseHttpDateMs(s);
  if (parsed !== null) {
    return clampInt(Math.ceil((parsed - refNowMs) / 1000.0), 0, MAX_BACKOFF_SEC);
  }
  return null;
}

function splitOutsideQuotes(str, sep) {
  const out = [];
  let cur = "";
  let inQuote = false;
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    if (ch === '"' && (i === 0 || str[i - 1] !== "\\")) {
      inQuote = !inQuote;
      cur += ch;
    } else if (ch === sep && !inQuote) {
      if (cur.trim()) out.push(cur.trim());
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function parseStrictInt(rawVal) {
  if (rawVal === null || rawVal === undefined) return null;
  const s = String(rawVal).trim();
  return isPureDigits(s, 15) ? parseInt(s, 10) : null;
}

function parseStructuredRateLimitBuckets(rlHeader, policyHeader, partitionHeader, reqMethod) {
  const activeMethod = String(reqMethod || "GET").trim().toUpperCase();
  const partitions = {};
  const partitionMethods = {};
  if (partitionHeader) {
    for (const item of splitOutsideQuotes(String(partitionHeader), ",")) {
      const parts = splitOutsideQuotes(item, ";");
      if (parts.length === 0) continue;
      const key = (stripQuotes(parts[0]) || "default").toLowerCase();
      const dims = [];
      let scopedMethod = null;
      for (let i = 1; i < parts.length; i += 1) {
        const eq = parts[i].indexOf("=");
        if (eq >= 0) {
          const pk = parts[i].slice(0, eq).trim().toLowerCase();
          const pv = stripQuotes(parts[i].slice(eq + 1)).trim();
          if (pk === "m" || pk === "method") scopedMethod = pv.toUpperCase();
          else dims.push(pk);
        } else {
          const bare = stripQuotes(parts[i]).trim();
          if (bare) dims.push(bare);
        }
      }
      partitions[key] = dims;
      if (scopedMethod) partitionMethods[key] = scopedMethod;
    }
  }
  const policies = {};
  if (policyHeader) {
    for (const item of splitOutsideQuotes(String(policyHeader), ",")) {
      const parts = splitOutsideQuotes(item, ";");
      if (parts.length === 0) continue;
      const key = (stripQuotes(parts[0]) || "default").toLowerCase();
      let qLim = null, wSec = null, quUnit = "requests", pkVal = null, polMethod = null, malformed = false;
      for (let i = 1; i < parts.length; i += 1) {
        const eq = parts[i].indexOf("=");
        if (eq < 0) continue;
        const pk = parts[i].slice(0, eq).trim().toLowerCase();
        const pv = parts[i].slice(eq + 1).trim();
        if (pk === "q") {
          const p = parseStrictInt(pv);
          if (p === null) { malformed = true; break; }
          qLim = p;
        } else if (pk === "w") {
          const p = parseStrictInt(pv);
          if (p === null) { malformed = true; break; }
          wSec = p;
        } else if (pk === "qu") quUnit = (stripQuotes(pv) || "requests").toLowerCase();
        else if (pk === "pk" && isByteSeq(pv)) pkVal = pv;
        else if (pk === "m" || pk === "method") polMethod = stripQuotes(pv).trim().toUpperCase();
      }
      if (!malformed) policies[key] = { quotaLimit: qLim, windowSec: wSec, quotaUnit: quUnit, partitionKey: pkVal, method: polMethod };
    }
  }
  const buckets = [];
  if (rlHeader) {
    for (const item of splitOutsideQuotes(String(rlHeader), ",")) {
      const parts = splitOutsideQuotes(item, ";");
      if (parts.length === 0) continue;
      const key = (stripQuotes(parts[0]) || "default").toLowerCase();
      const pol = policies[key];
      const scopedMeth = (pol && pol.method) || partitionMethods[key] || null;
      if (scopedMeth && scopedMeth !== "*" && scopedMeth !== activeMethod) continue;
      let remD12 = null, remD11 = null, winD12 = null, rstD11 = null, costVal = null, pkVal = null, bucketMethod = null, malformed = false;
      for (let i = 1; i < parts.length; i += 1) {
        const eq = parts[i].indexOf("=");
        if (eq < 0) continue;
        const pk = parts[i].slice(0, eq).trim().toLowerCase();
        const pv = parts[i].slice(eq + 1).trim();
        if (pk === "a") { const p = parseStrictInt(pv); if (p === null) { malformed = true; break; } remD12 = p; }
        else if (pk === "r") { const p = parseStrictInt(pv); if (p === null) { malformed = true; break; } remD11 = p; }
        else if (pk === "w") { const p = parseStrictInt(pv); if (p === null) { malformed = true; break; } winD12 = clampInt(p, 0, MAX_BACKOFF_SEC); }
        else if (pk === "t") { const p = parseStrictInt(pv); if (p === null) { malformed = true; break; } rstD11 = clampInt(p, 0, MAX_BACKOFF_SEC); }
        else if (pk === "c") { const p = parseStrictInt(pv); if (p !== null) costVal = p; }
        else if (pk === "pk" && isByteSeq(pv)) pkVal = pv;
        else if (pk === "m" || pk === "method") bucketMethod = stripQuotes(pv).trim().toUpperCase();
      }
      if (malformed) continue;
      if (bucketMethod && bucketMethod !== "*" && bucketMethod !== activeMethod) continue;
      const isD12 = remD12 !== null || winD12 !== null || costVal !== null;
      const rem = remD12 !== null ? remD12 : remD11;
      const resetSec = winD12 !== null ? winD12 : (rstD11 !== null ? rstD11 : 0);
      if (rem === null && resetSec === 0) continue;
      buckets.push({
        family: isD12 ? "ietf_rl_d12" : "ietf_rl_d11",
        bucket: key,
        quotaUnit: pol ? pol.quotaUnit : "requests",
        limit: pol ? pol.quotaLimit : null,
        remaining: rem,
        resetSec,
        policyWindowSec: pol ? pol.windowSec : null,
        requestCost: costVal,
        partitionKey: pkVal || (pol ? pol.partitionKey : null),
        partitionDims: partitions[key] || [],
      });
    }
  }
  return buckets;
}

function bucketRank(b) {
  if (b.remaining === 0) return [0, 0.0, -b.resetSec, 0];
  if (b.remaining !== null && b.limit !== null && b.limit > 0) return [1, b.remaining / b.limit, b.remaining, -b.resetSec];
  if (b.remaining !== null) return [2, b.remaining, b.remaining, -b.resetSec];
  return [3, Number.POSITIVE_INFINITY, 0, -b.resetSec];
}

function pickBindingBucket(buckets) {
  if (!buckets || buckets.length === 0) return null;
  let best = buckets[0];
  let bestR = bucketRank(best);
  for (let i = 1; i < buckets.length; i += 1) {
    const c = buckets[i];
    const cr = bucketRank(c);
    for (let j = 0; j < 4; j += 1) {
      if (cr[j] !== bestR[j]) {
        if (cr[j] < bestR[j]) { best = c; bestR = cr; }
        break;
      }
    }
  }
  return best;
}

function normalizeCandidateErrorSlug(rawStr) {
  if (!rawStr) return "";
  let s = String(rawStr).trim().toLowerCase();
  const hashIdx = s.lastIndexOf("#");
  if (hashIdx >= 0 && hashIdx + 1 < s.length) s = s.slice(hashIdx + 1);
  const slashIdx = s.lastIndexOf("/");
  if (slashIdx >= 0 && slashIdx + 1 < s.length) s = s.slice(slashIdx + 1);
  const colonIdx = s.lastIndexOf(":");
  if (colonIdx >= 0 && colonIdx + 1 < s.length) s = s.slice(colonIdx + 1);
  return s.replace(/-/g, "_");
}

export function extractSpendCapErrorCode(bodyText, httpStatus, contentType) {
  if (httpStatus === 402 && (!bodyText || !String(bodyText).trim())) return "payment_required";
  if (isWafOrBot403(httpStatus, contentType, bodyText)) return null;
  if (!bodyText) return null;
  const trimmed = String(bodyText).trim();
  if (!trimmed) return null;
  try {
    const obj = JSON.parse(trimmed);
    const candidates = [];
    if (obj && typeof obj === "object") {
      for (const k of ["code", "error_code", "type", "title", "detail"]) {
        if (obj[k] !== undefined && obj[k] !== null) candidates.push(String(obj[k]));
      }
      if (obj.error && typeof obj.error === "object") {
        for (const k of ["code", "error_code", "type"]) {
          if (obj.error[k] !== undefined && obj.error[k] !== null) candidates.push(String(obj.error[k]));
        }
        if (obj.error.details && typeof obj.error.details === "object" && obj.error.details.error_code) {
          candidates.push(String(obj.error.details.error_code));
        }
      }
    }
    for (const c of candidates) {
      const normSlug = normalizeCandidateErrorSlug(c);
      if (SPEND_CAP_ERROR_CODES.has(normSlug)) return normSlug;
      const normText = String(c).toLowerCase().replace(/-/g, "_");
      for (const code of SPEND_CAP_ERROR_CODES) {
        if (code !== "1300" && normText.indexOf(code) >= 0) return code;
      }
    }
  } catch (_e) {
    // fall through
  }
  const low = trimmed.toLowerCase().replace(/-/g, "_");
  for (const code of SPEND_CAP_ERROR_CODES) {
    if (code !== "1300" && low.indexOf(code) >= 0) return code;
  }
  if (/"code"\s*:\s*"?1300"?/.test(low)) return "1300";
  if (httpStatus === 402 && (low.indexOf("spend") >= 0 || low.indexOf("credit") >= 0 || low.indexOf("billing") >= 0)) {
    return "payment_required";
  }
  return null;
}

export function parseRateLimitEnvelope(headers, nowMs, httpStatus, errorBodyText, guardBandEps, reqMethod) {
  const eps = Number.isFinite(guardBandEps) ? guardBandEps : DEFAULT_GUARD_BAND_EPS;
  const contentType = headers.get("content-type") || "";
  const serverDateMs = parseHttpDateMs(headers.get("date"));
  const refNowMs = serverDateMs !== null ? serverDateMs : nowMs;
  const clockSkewSec = serverDateMs !== null ? Math.round((nowMs - serverDateMs) / 1000.0) : 0;
  const retryAfterSec = parseRetryAfterSec(headers.get("retry-after"), refNowMs);

  const buckets = parseStructuredRateLimitBuckets(
    headers.get("ratelimit"),
    headers.get("ratelimit-policy"),
    headers.get("ratelimit-partition"),
    reqMethod
  );

  const anthSpecs = [
    ["requests", "requests", "anthropic-ratelimit-requests-limit", "anthropic-ratelimit-requests-remaining", "anthropic-ratelimit-requests-reset"],
    ["tokens", "tokens", "anthropic-ratelimit-tokens-limit", "anthropic-ratelimit-tokens-remaining", "anthropic-ratelimit-tokens-reset"],
    ["input_tokens", "tokens", "anthropic-ratelimit-input-tokens-limit", "anthropic-ratelimit-input-tokens-remaining", "anthropic-ratelimit-input-tokens-reset"],
    ["output_tokens", "tokens", "anthropic-ratelimit-output-tokens-limit", "anthropic-ratelimit-output-tokens-remaining", "anthropic-ratelimit-output-tokens-reset"],
  ];
  for (const [bName, qUnit, hLim, hRem, hRst] of anthSpecs) {
    const lim = parseStrictInt(headers.get(hLim));
    const rem = parseStrictInt(headers.get(hRem));
    const rst = parseResetSeconds(headers.get(hRst), refNowMs);
    if (lim !== null || rem !== null || rst !== null) {
      buckets.push({ family: "anthropic_iso8601", bucket: bName, quotaUnit: qUnit, limit: lim, remaining: rem, resetSec: rst || 0 });
    }
  }

  const goSpecs = [
    ["requests", "requests", "x-ratelimit-limit-requests", "x-ratelimit-remaining-requests", "x-ratelimit-reset-requests"],
    ["tokens", "tokens", "x-ratelimit-limit-tokens", "x-ratelimit-remaining-tokens", "x-ratelimit-reset-tokens"],
  ];
  for (const [bName, qUnit, hLim, hRem, hRst] of goSpecs) {
    const lim = parseStrictInt(headers.get(hLim));
    const rem = parseStrictInt(headers.get(hRem));
    const rst = parseResetSeconds(headers.get(hRst), refNowMs);
    if (lim !== null || rem !== null || rst !== null) {
      buckets.push({ family: "openai_go_duration", bucket: bName, quotaUnit: qUnit, limit: lim, remaining: rem, resetSec: rst || 0 });
    }
  }

  const stdLim = parseStrictInt(headers.get("ratelimit-limit")) ?? parseStrictInt(headers.get("x-ratelimit-limit"));
  const stdRem = parseStrictInt(headers.get("ratelimit-remaining")) ?? parseStrictInt(headers.get("x-ratelimit-remaining"));
  const stdRstRaw = headers.get("ratelimit-reset") ?? headers.get("x-ratelimit-reset");
  const stdRst = parseResetSeconds(stdRstRaw, refNowMs);
  if (stdLim !== null || stdRem !== null || stdRst !== null) {
    buckets.push({ family: "x_ratelimit_unix", bucket: "default", quotaUnit: "requests", limit: stdLim, remaining: stdRem, resetSec: stdRst || 0 });
  }

  const binding = pickBindingBucket(buckets);
  let exhaustedMaxReset = 0;
  for (const b of buckets) {
    if (b.remaining === 0 && b.resetSec > exhaustedMaxReset) exhaustedMaxReset = b.resetSec;
  }
  const effectiveBackoffSec = clampInt(Math.max(retryAfterSec, exhaustedMaxReset), 0, MAX_BACKOFF_SEC);
  const isSpendWallStatus = httpStatus === 429 || httpStatus === 402 || httpStatus === 403;
  const spendCode = isSpendWallStatus ? extractSpendCapErrorCode(errorBodyText, httpStatus, contentType) : null;
  const waf403 = isWafOrBot403(httpStatus, contentType, errorBodyText);
  let throttleKind = "none";
  let retryable = 1;
  let quarantineClass = "CLEAN_PASS";
  if (isSpendWallStatus && spendCode !== null) {
    throttleKind = "spend_cap_exhausted";
    retryable = 0;
    quarantineClass = "PERMANENT_CAP_OR_SILENT_CUT";
  } else if (waf403) {
    throttleKind = "waf_bot_403_challenge";
    retryable = 1;
    quarantineClass = "INFRA_TRANSIENT_429";
  } else if (httpStatus === 404 || httpStatus === 410) {
    throttleKind = "endpoint_dead";
    retryable = 0;
    quarantineClass = "PERMANENT_CAP_OR_SILENT_CUT";
  } else if (httpStatus === 429 || httpStatus === 503 || httpStatus >= 500 || retryAfterSec > 0 || (binding && binding.remaining === 0)) {
    throttleKind = "transient_rate_limit";
    retryable = 1;
    quarantineClass = "INFRA_TRANSIENT_429";
  }
  const rlLimit = binding ? binding.limit : null;
  const rlRemaining = binding ? binding.remaining : null;
  let guardBandBreached = throttleKind !== "none" ? 1 : 0;
  let headroomRatioBps = null;
  if (rlRemaining !== null) {
    if (rlLimit !== null && rlLimit > 0) {
      if (rlRemaining <= Math.ceil(rlLimit * eps)) guardBandBreached = 1;
      headroomRatioBps = clampInt((rlRemaining * 10000.0) / rlLimit, 0, 10000);
    } else if (rlRemaining === 0) {
      guardBandBreached = 1;
      headroomRatioBps = 0;
    }
  }
  return {
    providerFamily: binding ? binding.family : (retryAfterSec > 0 ? "retry_after_only" : (waf403 ? "waf_challenge" : "none")),
    bindingBucket: binding ? binding.bucket : "default",
    quotaUnit: binding ? binding.quotaUnit : "requests",
    throttleKind,
    retryable,
    quarantineClass,
    spendCode,
    waf403,
    retryAfterSec,
    rlLimit,
    rlRemaining,
    rlResetSec: binding ? binding.resetSec : 0,
    effectiveBackoffSec,
    clockSkewSec,
    guardBandBreached,
    headroomRatioBps,
    bucketsCount: buckets.length,
  };
}

function weeklyRemainingFrac(now) {
  const dayIdx = (now.getUTCDay() + 6) % 7;
  const elapsedMin = dayIdx * 1440 + now.getUTCHours() * 60 + now.getUTCMinutes();
  return Math.min(1.0, Math.max(0.05, (10080 - elapsedMin) / 10080.0));
}

function isoWeekKey(now) {
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  const dayNum = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - dayNum);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil(((d - yearStart) / 86400000 + 1) / 7);
  return String(d.getUTCFullYear()) + "-W" + String(weekNo).padStart(2, "0");
}

function upsertEnvelopeStmt(db, targetId, httpStatus, rl, backoffUntilMin, throttles, nowIso) {
  return db.prepare(
    "INSERT INTO dw_provider_quota_envelopes (target_id, provider_family, binding_bucket, quota_unit, last_http_status, throttle_kind, retryable, quarantine_class, retry_after_sec, rl_limit, rl_remaining, rl_reset_sec, effective_backoff_sec, clock_skew_sec, guard_band_breached, headroom_ratio_bps, backoff_until_epoch_min, consecutive_throttles, observed_at_utc) "
    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    + "ON CONFLICT(target_id) DO UPDATE SET provider_family=excluded.provider_family, binding_bucket=excluded.binding_bucket, quota_unit=excluded.quota_unit, "
    + "last_http_status=excluded.last_http_status, throttle_kind=excluded.throttle_kind, retryable=excluded.retryable, quarantine_class=excluded.quarantine_class, "
    + "retry_after_sec=excluded.retry_after_sec, rl_limit=excluded.rl_limit, rl_remaining=excluded.rl_remaining, rl_reset_sec=excluded.rl_reset_sec, "
    + "effective_backoff_sec=excluded.effective_backoff_sec, clock_skew_sec=excluded.clock_skew_sec, guard_band_breached=excluded.guard_band_breached, "
    + "headroom_ratio_bps=excluded.headroom_ratio_bps, backoff_until_epoch_min=excluded.backoff_until_epoch_min, "
    + "consecutive_throttles=excluded.consecutive_throttles, observed_at_utc=excluded.observed_at_utc"
  ).bind(
    targetId, rl.providerFamily, rl.bindingBucket, rl.quotaUnit, httpStatus,
    rl.throttleKind, rl.retryable, rl.quarantineClass, rl.retryAfterSec,
    rl.rlLimit, rl.rlRemaining, rl.rlResetSec, rl.effectiveBackoffSec,
    rl.clockSkewSec, rl.guardBandBreached, rl.headroomRatioBps,
    backoffUntilMin, throttles, nowIso
  );
}

function upsertHourlyRollupStmt(db, hourBucketUtc, stats, nowIso) {
  return db.prepare(
    "INSERT INTO dw_poll_hourly_rollup (hour_bucket_utc, polls_total, polls_cold_start, polls_warm, polls_conditional_sent, http_304_count, http_200_count, http_403_waf_count, http_404_410_count, http_429_count, http_5xx_count, net_err_count, bytes_fetched, bytes_saved_est, updated_at_utc) "
    + "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    + "ON CONFLICT(hour_bucket_utc) DO UPDATE SET "
    + "polls_total = dw_poll_hourly_rollup.polls_total + excluded.polls_total, "
    + "polls_cold_start = dw_poll_hourly_rollup.polls_cold_start + excluded.polls_cold_start, "
    + "polls_warm = dw_poll_hourly_rollup.polls_warm + excluded.polls_warm, "
    + "polls_conditional_sent = dw_poll_hourly_rollup.polls_conditional_sent + excluded.polls_conditional_sent, "
    + "http_304_count = dw_poll_hourly_rollup.http_304_count + excluded.http_304_count, "
    + "http_200_count = dw_poll_hourly_rollup.http_200_count + excluded.http_200_count, "
    + "http_403_waf_count = dw_poll_hourly_rollup.http_403_waf_count + excluded.http_403_waf_count, "
    + "http_404_410_count = dw_poll_hourly_rollup.http_404_410_count + excluded.http_404_410_count, "
    + "http_429_count = dw_poll_hourly_rollup.http_429_count + excluded.http_429_count, "
    + "http_5xx_count = dw_poll_hourly_rollup.http_5xx_count + excluded.http_5xx_count, "
    + "net_err_count = dw_poll_hourly_rollup.net_err_count + excluded.net_err_count, "
    + "bytes_fetched = dw_poll_hourly_rollup.bytes_fetched + excluded.bytes_fetched, "
    + "bytes_saved_est = dw_poll_hourly_rollup.bytes_saved_est + excluded.bytes_saved_est, "
    + "updated_at_utc = excluded.updated_at_utc"
  ).bind(
    hourBucketUtc, stats.pollsTotal, stats.pollsColdStart, stats.pollsWarm, stats.pollsConditionalSent,
    stats.http304, stats.http200, stats.http403Waf, stats.http404410, stats.http429,
    stats.http5xx, stats.netErr, stats.bytesFetched, stats.bytesSavedEst, nowIso
  );
}

export default {
  async scheduled(_controller, env) {
    const now = new Date();
    const nowMs = now.getTime();
    const nowEpochMin = Math.floor(nowMs / 60000);
    const nowHourBucket = Math.floor(nowMs / 3600000);
    const maxBatch = Math.min(4, parseInt((env && env.MAX_TARGETS_PER_TICK) || "4", 10));
    const weekBudget = parseInt((env && env.ZCL_WEEKLY_PC_BUDGET_MIN) || "60", 10);
    const cliffReserveMin = parseInt((env && env.ZCL_CLIFF_RESERVE_MIN) || String(DEFAULT_ZCL_CLIFF_RESERVE_MIN), 10);
    const shadowGamma = parseFloat((env && env.SHADOW_GAMMA) || "0.85");
    const ewmaGamma = parseFloat((env && env.EWMA_GAMMA_DECAY) || String(DEFAULT_EWMA_GAMMA));
    const nuRef = parseFloat((env && env.LAGRANGE_NU_REF) || String(DEFAULT_LAGRANGE_NU_REF));
    const t24hMaxP = parseInt((env && env.T24H_CLIFF_MAX_PERIOD_MIN) || String(DEFAULT_T24H_MAX_PERIOD_MIN), 10);
    const guardEps = parseFloat((env && env.GUARD_BAND_EPS) || String(DEFAULT_GUARD_BAND_EPS));
    const fetchTimeoutMs = clampInt(parseInt((env && env.FETCH_TIMEOUT_MS) || String(DEFAULT_FETCH_TIMEOUT_MS), 10), 2000, 12000);
    const retentionHours = clampInt(parseInt((env && env.TELEMETRY_RETENTION_HOURS) || String(DEFAULT_TELEMETRY_RETENTION_HOURS), 10), 48, 720);
    const wk = isoWeekKey(now);
    const tauRem = weeklyRemainingFrac(now);
    const nowIso = now.toISOString();

    const coldRes = await env.DRIFT_DB.prepare(
      "SELECT target_id, next_due_epoch_min FROM dw_targets "
      + "WHERE active = 1 AND last_polled_epoch_min = 0 AND (next_due_epoch_min > ? OR next_due_epoch_min < ?) "
      + "ORDER BY next_due_epoch_min ASC LIMIT 45"
    ).bind(nowEpochMin + 240, nowEpochMin - 60).all();
    const coldRows = coldRes.results || [];
    if (coldRows.length > 0) {
      const healStmts = coldRows.map((r, idx) => {
        const healed = nowEpochMin + 5 * ((idx % 40) + 1);
        return env.DRIFT_DB.prepare(
          "UPDATE dw_targets SET next_due_epoch_min = ?, updated_at_utc = ? WHERE target_id = ?"
        ).bind(healed, nowIso, r.target_id);
      });
      await env.DRIFT_DB.batch(healStmts);
    }

    const legacyRes = await env.DRIFT_DB.prepare(
      "SELECT target_id, period_min, weyl_offset_min FROM dw_targets "
      + "WHERE active = 1 AND next_due_epoch_min < ? ORDER BY next_due_epoch_min ASC LIMIT 10"
    ).bind(MIN_VALID_EPOCH_MIN).all();
    const legacyRows = legacyRes.results || [];
    if (legacyRows.length > 0) {
      const legStmts = legacyRows.map((r) => {
        const healed = modularWeylNextDue(nowEpochMin, r.weyl_offset_min, r.period_min, 0);
        return env.DRIFT_DB.prepare(
          "UPDATE dw_targets SET next_due_epoch_min = ?, updated_at_utc = ? WHERE target_id = ?"
        ).bind(healed, nowIso, r.target_id);
      });
      await env.DRIFT_DB.batch(legStmts);
    }

    const dueRes = await env.DRIFT_DB.prepare(
      "SELECT target_id, group_code, is_mc06_core, url, kind, value_at_risk_micro_usd, action_cost_min, alpha_milli, beta_days_milli, mu_milli, "
      + "external_cliff_utc, peak_utc_start, peak_utc_end, base_period_min, period_min, weyl_offset_min, last_polled_epoch_min, "
      + "last_etag, last_modified, last_canon_sha256, last_signals_json, last_body_bytes, last_http_status, "
      + "consecutive_429_count, consecutive_dead_count, consecutive_net_err_count, last_alert_sig, last_alert_epoch_min "
      + "FROM dw_targets WHERE active = 1 AND next_due_epoch_min <= ? ORDER BY next_due_epoch_min ASC LIMIT ?"
    ).bind(nowEpochMin, maxBatch).all();

    const targets = dueRes.results || [];
    if (targets.length === 0) return;

    const budRow = await env.DRIFT_DB.prepare("SELECT used_min FROM dw_weekly_budget WHERE iso_week = ?").bind(wk).first();
    let usedMin = budRow ? budRow.used_min : 0;
    const batchStmts = [];

    const tickStats = {
      pollsTotal: 0,
      pollsColdStart: 0,
      pollsWarm: 0,
      pollsConditionalSent: 0,
      http304: 0,
      http200: 0,
      http403Waf: 0,
      http404410: 0,
      http429: 0,
      http5xx: 0,
      netErr: 0,
      bytesFetched: 0,
      bytesSavedEst: 0,
    };

    for (const t of targets) {
      const isSediaPost = String(t.kind || "html") === "json_post";
      const isFeed = String(t.kind || "html") === "rss" || String(t.kind || "html") === "atom";
      const pollMethod = isSediaPost ? "POST" : "GET";
      const headers = { "User-Agent": "AlpLab-DriftWatch-v3.9.0-Weyl-Health304/1.0" };
      let isConditional = false;
      if (!isSediaPost) {
        if (t.last_etag) {
          headers["If-None-Match"] = t.last_etag;
          isConditional = true;
        }
        if (t.last_modified) {
          headers["If-Modified-Since"] = t.last_modified;
          isConditional = true;
        }
      } else {
        headers["content-type"] = "application/json";
      }

      const isColdStart = (t.last_polled_epoch_min || 0) === 0 || !t.last_canon_sha256;
      tickStats.pollsTotal += 1;
      if (isColdStart && !isConditional) {
        tickStats.pollsColdStart += 1;
      } else {
        tickStats.pollsWarm += 1;
      }
      if (isConditional) tickStats.pollsConditionalSent += 1;

      let resp;
      try {
        const sediaBody = isSediaPost
          ? JSON.stringify({ bool: { must: [{ terms: { type: ["1", "8"] } }, { terms: { status: ["31094501", "31094502"] } }] } })
          : undefined;
        const fetchOpts = { method: pollMethod, headers, body: sediaBody, redirect: "follow" };
        if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
          fetchOpts.signal = AbortSignal.timeout(fetchTimeoutMs);
        }
        resp = await fetch(t.url, fetchOpts);
      } catch (_err) {
        tickStats.netErr += 1;
        const nextNetErr = (t.consecutive_net_err_count || 0) + 1;
        const waitMin = Math.min(360, 15 * Math.pow(2, Math.min(4, nextNetErr - 1)));
        const retryDue = (!t.last_canon_sha256)
          ? (nowEpochMin + waitMin)
          : modularWeylNextDue(nowEpochMin, t.weyl_offset_min, t.period_min, waitMin);
        batchStmts.push(
          env.DRIFT_DB.prepare(
            "UPDATE dw_targets SET next_due_epoch_min = ?, last_polled_epoch_min = ?, last_http_status = -1, consecutive_net_err_count = ?, updated_at_utc = ? WHERE target_id = ?"
          ).bind(retryDue, nowEpochMin, nextNetErr, nowIso, t.target_id)
        );
        continue;
      }

      const isErrorInspect = resp.status === 429 || resp.status === 402 || resp.status === 403;
      const bodyTextForError = isErrorInspect ? await resp.text() : "";
      const rl = parseRateLimitEnvelope(resp.headers, nowMs, resp.status, bodyTextForError, guardEps, pollMethod);

      const hasPriorPoll = (t.last_polled_epoch_min || 0) > 0 && nowEpochMin > t.last_polled_epoch_min;
      const trueDtDays = hasPriorPoll ? Math.min(14.0, Math.max(0.02, (nowEpochMin - t.last_polled_epoch_min) / 1440.0)) : 0.0;

      if (isErrorInspect && rl.throttleKind === "spend_cap_exhausted") {
        if (resp.status === 429) tickStats.http429 += 1;
        const nextDeadCount = (t.consecutive_dead_count || 0) + 1;
        const capSig = "SPEND_CAP:" + String(resp.status) + ":" + String(rl.spendCode || "unknown");
        const capDue = modularWeylNextDue(nowEpochMin, t.weyl_offset_min, t.period_min, DEAD_REALERT_COOLDOWN_MIN);
        let emitAlert = 0;
        let allowZcl = 1;
        let nextSig = t.last_alert_sig || "";
        let nextAlertEp = t.last_alert_epoch_min || 0;
        const cls = classifySignalDiff(parseBaselineSignals(t.last_signals_json), extractPolicySignals(normalizeHtml(bodyTextForError), t.url), resp.status, rl.spendCode, null);
        if (t.last_alert_sig !== capSig) {
          emitAlert = 1;
          nextSig = capSig;
          nextAlertEp = nowEpochMin;
        } else if ((nowEpochMin - (t.last_alert_epoch_min || 0)) >= DEAD_REALERT_COOLDOWN_MIN) {
          emitAlert = 1;
          allowZcl = 0;
          cls.reasons.push("SPEND_CAP_7D_REMINDER_NO_ZCL_CHARGE");
          nextAlertEp = nowEpochMin;
        }
        batchStmts.push(
          env.DRIFT_DB.prepare(
            "UPDATE dw_targets SET next_due_epoch_min = ?, last_polled_epoch_min = ?, last_http_status = ?, consecutive_dead_count = ?, consecutive_net_err_count = 0, last_alert_sig = ?, last_alert_epoch_min = ?, updated_at_utc = ? WHERE target_id = ?"
          ).bind(capDue, nowEpochMin, resp.status, nextDeadCount, nextSig, nextAlertEp, nowIso, t.target_id)
        );
        batchStmts.push(upsertEnvelopeStmt(env.DRIFT_DB, t.target_id, resp.status, rl, capDue, nextDeadCount, nowIso));
        if (emitAlert === 1) {
          const zEval = evaluateZclAdmissionR107(cls.severity, t.value_at_risk_micro_usd, t.action_cost_min, usedMin, weekBudget, cliffReserveMin, tauRem, shadowGamma, allowZcl);
          if (zEval.admit === 1) usedMin += t.action_cost_min;
          cls.rules.push("R107_ZCL_RESERVE");
          batchStmts.push(
            env.DRIFT_DB.prepare(
              "INSERT INTO dw_events (target_id, detected_at_utc, severity, quarantine_class, rule_refs, reasons, zcl_admitted, zcl_density_milli) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            ).bind(t.target_id, nowIso, cls.severity, cls.quarantineClass, cls.rules.join(","), cls.reasons.join(","), zEval.admit, zEval.effDensityMilli)
          );
        }
        continue;
      }

      if (rl.throttleKind === "waf_bot_403_challenge" || resp.status === 403) {
        tickStats.http403Waf += 1;
        const nextThrottles = (t.consecutive_429_count || 0) + 1;
        const waitMin = Math.min(720, 60 * Math.pow(2, Math.min(4, nextThrottles - 1)));
        const backoffDue = modularWeylNextDue(nowEpochMin, t.weyl_offset_min, t.period_min, waitMin);
        batchStmts.push(
          env.DRIFT_DB.prepare(
            "UPDATE dw_targets SET next_due_epoch_min = ?, last_polled_epoch_min = ?, last_http_status = 403, consecutive_429_count = ?, consecutive_net_err_count = 0, updated_at_utc = ? WHERE target_id = ?"
          ).bind(backoffDue, nowEpochMin, nextThrottles, nowIso, t.target_id)
        );
        batchStmts.push(upsertEnvelopeStmt(env.DRIFT_DB, t.target_id, 403, rl, backoffDue, nextThrottles, nowIso));
        continue;
      }

      if (resp.status === 429 || resp.status === 503 || resp.status >= 500) {
        if (resp.status === 429) tickStats.http429 += 1;
        else tickStats.http5xx += 1;
        const nextThrottles = (t.consecutive_429_count || 0) + 1;
        const fallbackWaitMin = Math.min(360, 15 * Math.pow(2, Math.min(4, nextThrottles - 1)));
        const waitMin = Math.max(fallbackWaitMin, Math.ceil(rl.effectiveBackoffSec / 60));
        const backoffDue = modularWeylNextDue(nowEpochMin, t.weyl_offset_min, t.period_min, waitMin);
        batchStmts.push(
          env.DRIFT_DB.prepare(
            "UPDATE dw_targets SET next_due_epoch_min = ?, last_polled_epoch_min = ?, last_http_status = ?, consecutive_429_count = ?, consecutive_net_err_count = 0, updated_at_utc = ? WHERE target_id = ?"
          ).bind(backoffDue, nowEpochMin, resp.status, nextThrottles, nowIso, t.target_id)
        );
        batchStmts.push(upsertEnvelopeStmt(env.DRIFT_DB, t.target_id, resp.status, rl, backoffDue, nextThrottles, nowIso));
        continue;
      }

      const baseWaitMin = Math.ceil(rl.effectiveBackoffSec / 60);

      if (resp.status === 304) {
        tickStats.http304 += 1;
        tickStats.bytesSavedEst += Math.max(0, t.last_body_bytes || 0);
        const ew304 = hasPriorPoll
          ? ewmaUpdateR105(t.alpha_milli, t.beta_days_milli, trueDtDays, 0, ewmaGamma)
          : { alphaMilli: t.alpha_milli, betaDaysMilli: t.beta_days_milli };
        const dyn304 = computeDynamicPeriodR104(t, ew304.alphaMilli, ew304.betaDaysMilli, now, nuRef, t24hMaxP);
        const nextDue304 = modularWeylNextDue(nowEpochMin, t.weyl_offset_min, dyn304.periodMin, baseWaitMin);
        const refEtag = resp.headers.get("etag") || t.last_etag || "";
        const refLastMod = resp.headers.get("last-modified") || t.last_modified || "";
        if (rl.providerFamily !== "none" || rl.guardBandBreached === 1) {
          batchStmts.push(upsertEnvelopeStmt(env.DRIFT_DB, t.target_id, 304, rl, nextDue304, 0, nowIso));
        }
        const prevSig = t.last_alert_sig || "";
        const preservedSig = (prevSig.indexOf("HTTP_4") === 0 || prevSig.indexOf("SPEND_CAP:") === 0) ? "" : prevSig;
        batchStmts.push(
          env.DRIFT_DB.prepare(
            "UPDATE dw_targets SET period_min = ?, nhpp_mult_milli = ?, lambda_ucb90_milli = ?, next_due_epoch_min = ?, last_polled_epoch_min = ?, "
            + "last_etag = ?, last_modified = ?, alpha_milli = ?, beta_days_milli = ?, last_http_status = 304, "
            + "consecutive_429_count = 0, consecutive_dead_count = 0, consecutive_net_err_count = 0, "
            + "last_alert_sig = ?, updated_at_utc = ? WHERE target_id = ?"
          ).bind(dyn304.periodMin, dyn304.nhppMultMilli, dyn304.lamUcb90Milli, nextDue304, nowEpochMin, refEtag, refLastMod, ew304.alphaMilli, ew304.betaDaysMilli, preservedSig, nowIso, t.target_id)
        );
        continue;
      }

      if (resp.status === 404 || resp.status === 410) tickStats.http404410 += 1;
      else if (resp.status >= 200 && resp.status < 300) tickStats.http200 += 1;

      const rawText = isErrorInspect ? bodyTextForError : await resp.text();
      const bodyBytes = new TextEncoder().encode(rawText).length;
      tickStats.bytesFetched += bodyBytes;
      const normText = normalizeHtml(rawText);
      const canonHash = await sha256Hex(normText);

      const hdrEtag = resp.headers.get("etag");
      const hdrLastMod = resp.headers.get("last-modified");
      const newEtag = resp.status === 200 ? (hdrEtag || "") : (hdrEtag || t.last_etag || "");
      const newLastMod = resp.status === 200 ? (hdrLastMod || "") : (hdrLastMod || t.last_modified || "");
      const redirectTrap = detectRetirementRedirect(t.url, resp.url || t.url);
      const baseSig = parseBaselineSignals(t.last_signals_json);

      let triggered = 0;
      let allowZclCharge = 1;
      let cls = { severity: "S0_NOOP", quarantineClass: "NOISY_DRIFT_QUARANTINE", reasons: [], rules: [] };
      let nextDeadCount = 0;
      let nextAlertSig = t.last_alert_sig || "";
      let nextAlertEpoch = t.last_alert_epoch_min || 0;
      let persistedCanonHash = canonHash;
      let persistedSignalsJson = t.last_signals_json || "{}";
      let deadWaitOverrideMin = 0;

      if (resp.status === 404 || resp.status === 410 || redirectTrap !== null) {
        nextDeadCount = (t.consecutive_dead_count || 0) + 1;
        persistedCanonHash = (resp.status === 404 || resp.status === 410) ? (t.last_canon_sha256 || "") : canonHash;
        const deadSig = redirectTrap ? ("REDIRECT_DEAD:" + redirectTrap) : ("HTTP_" + String(resp.status) + ":" + canonHash.slice(0, 16));
        deadWaitOverrideMin = Math.min(DEAD_REALERT_COOLDOWN_MIN, t.period_min * Math.pow(2, Math.min(4, nextDeadCount - 1)));
        if (t.last_alert_sig !== deadSig) {
          cls = classifySignalDiff(baseSig, extractPolicySignals(normText, t.url), resp.status, null, redirectTrap);
          triggered = 1;
          nextAlertSig = deadSig;
          nextAlertEpoch = nowEpochMin;
        } else if ((nowEpochMin - (t.last_alert_epoch_min || 0)) >= DEAD_REALERT_COOLDOWN_MIN) {
          cls = classifySignalDiff(baseSig, extractPolicySignals(normText, t.url), resp.status, null, redirectTrap);
          cls.reasons.push("DEAD_7D_REMINDER_NO_ZCL_CHARGE");
          triggered = 1;
          allowZclCharge = 0;
          nextAlertEpoch = nowEpochMin;
        }
      } else if (isFeed && resp.status === 200) {
        const entries = parseFeedEntries(rawText);
        const entryIds = entries.map((e) => e.id);
        persistedSignalsJson = JSON.stringify({ feed_ids: entryIds.slice(0, 100) });
        if (Array.isArray(baseSig.feed_ids)) {
          cls = classifyFeedDelta(baseSig.feed_ids, entries, t.url);
          if (cls.severity !== "S0_NOOP") {
            const sig = cls.severity + ":" + canonHash.slice(0, 16);
            if (sig !== t.last_alert_sig) {
              triggered = 1;
              nextAlertSig = sig;
              nextAlertEpoch = nowEpochMin;
            }
          }
        }
      } else {
        nextDeadCount = 0;
        if (t.last_alert_sig && (t.last_alert_sig.indexOf("HTTP_4") === 0 || t.last_alert_sig.indexOf("SPEND_CAP:") === 0 || t.last_alert_sig.indexOf("REDIRECT_DEAD:") === 0)) {
          nextAlertSig = "";
        }
        const currSig = extractPolicySignals(normText, t.url);
        persistedSignalsJson = JSON.stringify(currSig);
        if (!t.last_canon_sha256) {
          cls = classifySignalDiff({}, currSig, resp.status, null, null);
          if (SEV_ORDER[cls.severity] >= SEV_ORDER.S3_CARD_WALL_OR_LICENSE_DRIFT) {
            cls.reasons.push("COLD_START_PREEXISTING_TRAP");
            cls.rules.push("R124");
            triggered = 1;
            nextAlertSig = cls.severity + ":" + canonHash.slice(0, 16);
            nextAlertEpoch = nowEpochMin;
          }
        } else if (canonHash !== t.last_canon_sha256) {
          cls = classifySignalDiff(baseSig, currSig, resp.status, null, null);
          if (cls.severity !== "S0_NOOP") {
            const sig = cls.severity + ":" + canonHash.slice(0, 16);
            if (sig !== t.last_alert_sig) {
              triggered = 1;
              nextAlertSig = sig;
              nextAlertEpoch = nowEpochMin;
            }
          }
        }
      }

      const ew = hasPriorPoll
        ? ewmaUpdateR105(t.alpha_milli, t.beta_days_milli, trueDtDays, triggered, ewmaGamma)
        : { alphaMilli: t.alpha_milli, betaDaysMilli: t.beta_days_milli };
      const dyn = computeDynamicPeriodR104(t, ew.alphaMilli, ew.betaDaysMilli, now, nuRef, t24hMaxP);
      const effWait = Math.max(baseWaitMin, deadWaitOverrideMin);
      const nextDue = modularWeylNextDue(nowEpochMin, t.weyl_offset_min, dyn.periodMin, effWait);

      if (rl.providerFamily !== "none" || rl.guardBandBreached === 1) {
        batchStmts.push(upsertEnvelopeStmt(env.DRIFT_DB, t.target_id, resp.status, rl, nextDue, 0, nowIso));
      }

      batchStmts.push(
        env.DRIFT_DB.prepare(
          "UPDATE dw_targets SET period_min = ?, nhpp_mult_milli = ?, lambda_ucb90_milli = ?, next_due_epoch_min = ?, last_polled_epoch_min = ?, "
          + "last_etag = ?, last_modified = ?, last_canon_sha256 = ?, last_signals_json = ?, last_body_bytes = ?, last_http_status = ?, "
          + "consecutive_429_count = 0, consecutive_dead_count = ?, consecutive_net_err_count = 0, last_alert_sig = ?, last_alert_epoch_min = ?, "
          + "alpha_milli = ?, beta_days_milli = ?, updated_at_utc = ? WHERE target_id = ?"
        ).bind(
          dyn.periodMin, dyn.nhppMultMilli, dyn.lamUcb90Milli, nextDue, nowEpochMin,
          newEtag, newLastMod, persistedCanonHash, persistedSignalsJson, bodyBytes, resp.status,
          nextDeadCount, nextAlertSig, nextAlertEpoch, ew.alphaMilli, ew.betaDaysMilli, nowIso, t.target_id
        )
      );

      if (triggered === 1) {
        const zEval = evaluateZclAdmissionR107(cls.severity, t.value_at_risk_micro_usd, t.action_cost_min, usedMin, weekBudget, cliffReserveMin, tauRem, shadowGamma, allowZclCharge);
        if (zEval.admit === 1) usedMin += t.action_cost_min;
        cls.rules.push("R104_R107_GATE");
        batchStmts.push(
          env.DRIFT_DB.prepare(
            "INSERT INTO dw_events (target_id, detected_at_utc, severity, quarantine_class, rule_refs, reasons, zcl_admitted, zcl_density_milli) "
            + "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(t.target_id, nowIso, cls.severity, cls.quarantineClass, cls.rules.join(","), cls.reasons.join(","), zEval.admit, zEval.effDensityMilli)
        );
      }
    }

    if (tickStats.pollsTotal > 0) {
      batchStmts.push(upsertHourlyRollupStmt(env.DRIFT_DB, nowHourBucket, tickStats, nowIso));
    }
    if (now.getUTCMinutes() < 5) {
      batchStmts.push(
        env.DRIFT_DB.prepare("DELETE FROM dw_poll_hourly_rollup WHERE hour_bucket_utc < ?")
          .bind(nowHourBucket - retentionHours)
      );
    }

    batchStmts.push(
      env.DRIFT_DB.prepare(
        "INSERT INTO dw_weekly_budget (iso_week, budget_min, used_min, updated_at_utc) VALUES (?, ?, ?, ?) "
        + "ON CONFLICT(iso_week) DO UPDATE SET used_min = excluded.used_min, updated_at_utc = excluded.updated_at_utc"
      ).bind(wk, weekBudget, usedMin, nowIso)
    );

    await env.DRIFT_DB.batch(batchStmts);
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    const now = new Date();
    const nowHourBucket = Math.floor(now.getTime() / 3600000);

    if (url.pathname === "/health") {
      const c = await env.DRIFT_DB.prepare(
        "SELECT COUNT(*) AS n, COUNT(DISTINCT weyl_offset_min) AS u_weyl, "
        + "SUM(CASE WHEN is_mc06_core = 1 AND target_id GLOB 'W[0-9][0-9]' AND CAST(SUBSTR(target_id, 2) AS INTEGER) BETWEEN 1 AND 34 THEN 1 ELSE 0 END) AS mc06_core_n, "
        + "SUM(CASE WHEN period_min < base_period_min THEN 1 ELSE 0 END) AS acc_n, "
        + "SUM(CASE WHEN last_polled_epoch_min = 0 THEN 1 ELSE 0 END) AS cold_n, "
        + "SUM(CASE WHEN last_etag != '' OR last_modified != '' THEN 1 ELSE 0 END) AS cond_ready_n "
        + "FROM dw_targets WHERE active = 1"
      ).first();
      const th = await env.DRIFT_DB.prepare(
        "SELECT SUM(CASE WHEN quarantine_class = 'INFRA_TRANSIENT_429' THEN 1 ELSE 0 END) AS tr_n, "
        + "SUM(CASE WHEN quarantine_class = 'PERMANENT_CAP_OR_SILENT_CUT' THEN 1 ELSE 0 END) AS cap_n "
        + "FROM dw_provider_quota_envelopes"
      ).first();
      const tel = await env.DRIFT_DB.prepare(
        "SELECT COALESCE(SUM(polls_total), 0) AS polls_24h, "
        + "COALESCE(SUM(polls_cold_start), 0) AS cold_polls_24h, "
        + "COALESCE(SUM(polls_warm), 0) AS warm_polls_24h, "
        + "COALESCE(SUM(polls_conditional_sent), 0) AS cond_polls_24h, "
        + "COALESCE(SUM(http_304_count), 0) AS h304_24h, "
        + "COALESCE(SUM(http_200_count), 0) AS h200_24h, "
        + "COALESCE(SUM(http_429_count), 0) AS h429_24h, "
        + "COALESCE(SUM(http_403_waf_count), 0) AS h403_24h, "
        + "COALESCE(SUM(http_404_410_count), 0) AS h404_24h, "
        + "COALESCE(SUM(http_5xx_count), 0) AS h5xx_24h, "
        + "COALESCE(SUM(net_err_count), 0) AS net_err_24h, "
        + "COALESCE(SUM(bytes_fetched), 0) AS bytes_fetched_24h, "
        + "COALESCE(SUM(bytes_saved_est), 0) AS bytes_saved_24h, "
        + "COUNT(*) AS active_hours_24h "
        + "FROM dw_poll_hourly_rollup WHERE hour_bucket_utc >= ?"
      ).bind(nowHourBucket - 23).first();
      const wk = isoWeekKey(now);
      const bud = await env.DRIFT_DB.prepare("SELECT used_min, budget_min FROM dw_weekly_budget WHERE iso_week = ?").bind(wk).first();

      const activeTargets = c ? (c.n || 0) : 0;
      const mc06CoreActive = c ? (c.mc06_core_n || 0) : 0;
      const coldPending = c ? (c.cold_n || 0) : 0;
      const condReady = c ? (c.cond_ready_n || 0) : 0;
      const polls24h = tel ? (tel.polls_24h || 0) : 0;
      const warmPolls24h = tel ? (tel.warm_polls_24h || 0) : 0;
      const condPolls24h = tel ? (tel.cond_polls_24h || 0) : 0;
      const h304_24h = tel ? (tel.h304_24h || 0) : 0;
      const raw304Ratio = polls24h > 0 ? Math.round((h304_24h / polls24h) * 10000) / 10000 : null;
      const warm304Ratio = warmPolls24h > 0 ? Math.round((h304_24h / warmPolls24h) * 10000) / 10000 : null;
      const cond304Ratio = condPolls24h > 0 ? Math.round((h304_24h / condPolls24h) * 10000) / 10000 : null;

      let gateStatus = "PASS_40_OF_40_AND_34_OF_34_READY";
      if (activeTargets < 40 || mc06CoreActive < 34) {
        gateStatus = "FAIL_ACTIVE_TARGETS";
      } else if (coldPending > 0 || condPolls24h < 15) {
        gateStatus = "COLD_START_IN_PROGRESS";
      } else if (cond304Ratio !== null && cond304Ratio < 0.65) {
        gateStatus = "WARN_LOW_CONDITIONAL_304";
      }

      return new Response(JSON.stringify({
        status: "ok",
        engine: "IS-FON-93-DRIFT-WATCH-V39-UNIFIED",
        version: "v3.9.0",
        active_targets: activeTargets,
        mc06_core_w01_w34_active: mc06CoreActive,
        unique_weyl_offsets_count: c ? (c.u_weyl || 0) : 0,
        accelerated_cliff_targets: c ? (c.acc_n || 0) : 0,
        cold_start_pending_count: coldPending,
        targets_with_conditional_validators: condReady,
        telemetry_24h: {
          window_hours: 24,
          active_hours_recorded: tel ? (tel.active_hours_24h || 0) : 0,
          polls_24h: polls24h,
          cold_start_polls_24h: tel ? (tel.cold_polls_24h || 0) : 0,
          warm_polls_24h: warmPolls24h,
          conditional_polls_24h: condPolls24h,
          http_304_hits_24h: h304_24h,
          http_200_hits_24h: tel ? (tel.h200_24h || 0) : 0,
          http_429_hits_24h: tel ? (tel.h429_24h || 0) : 0,
          http_403_waf_hits_24h: tel ? (tel.h403_24h || 0) : 0,
          http_404_410_hits_24h: tel ? (tel.h404_24h || 0) : 0,
          http_5xx_hits_24h: tel ? (tel.h5xx_24h || 0) : 0,
          net_err_24h: tel ? (tel.net_err_24h || 0) : 0,
          bytes_fetched_24h: tel ? (tel.bytes_fetched_24h || 0) : 0,
          bytes_saved_est_24h: tel ? (tel.bytes_saved_24h || 0) : 0,
          raw_http_304_ratio_24h: raw304Ratio,
          warm_http_304_ratio_24h: warm304Ratio,
          conditional_http_304_ratio_24h: cond304Ratio,
        },
        t48h_deploy_gate_status: gateStatus,
        infra_transient_429_count: th ? (th.tr_n || 0) : 0,
        permanent_cap_or_dead_count: th ? (th.cap_n || 0) : 0,
        weekly_budget_iso_week: wk,
        weekly_budget_used_min: bud ? bud.used_min : 0,
        weekly_budget_cap_min: bud ? bud.budget_min : 60,
        d90_4_strict_mc06_core: true,
        d90_5_multilabel_psl: true,
        d90_6_cf_vectorize_stale_banner_guard: true,
        d92_splitbrain_closed: true,
        kural3_zero_chr36: true,
        cash_overage_usd: "0.0000 USD",
      }), { headers: { "content-type": "application/json" } });
    }

    if (url.pathname === "/telemetry/24h") {
      const rows = await env.DRIFT_DB.prepare(
        "SELECT hour_bucket_utc, polls_total, polls_cold_start, polls_warm, polls_conditional_sent, http_304_count, http_200_count, http_429_count, http_403_waf_count, http_404_410_count, http_5xx_count, net_err_count, bytes_fetched, bytes_saved_est, updated_at_utc "
        + "FROM dw_poll_hourly_rollup WHERE hour_bucket_utc >= ? ORDER BY hour_bucket_utc ASC"
      ).bind(nowHourBucket - 23).all();
      return new Response(JSON.stringify({ version: "v3.9.0", now_hour_bucket_utc: nowHourBucket, hours: rows.results || [] }), {
        headers: { "content-type": "application/json" },
      });
    }

    if (url.pathname === "/envelopes") {
      const rows = await env.DRIFT_DB.prepare(
        "SELECT target_id, provider_family, binding_bucket, quota_unit, last_http_status, throttle_kind, retryable, quarantine_class, retry_after_sec, rl_limit, rl_remaining, rl_reset_sec, effective_backoff_sec, clock_skew_sec, guard_band_breached, headroom_ratio_bps, backoff_until_epoch_min, consecutive_throttles, observed_at_utc "
        + "FROM dw_provider_quota_envelopes ORDER BY consecutive_throttles DESC, effective_backoff_sec DESC LIMIT 50"
      ).all();
      return new Response(JSON.stringify({ version: "v3.9.0", envelopes: rows.results || [] }), {
        headers: { "content-type": "application/json" },
      });
    }

    return new Response("KONU-5 Drift-Watch v3.9.0 Unified Schema-Parity Edge Poller", { status: 200 });
  },
};
