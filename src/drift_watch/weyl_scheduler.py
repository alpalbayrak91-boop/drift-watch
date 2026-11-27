# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Coprime modular Weyl phase scheduler, RFC 9110 HTTP 304 state machine, and AI cliff guard.

References:
- Hermann Weyl (1916), "Ueber die Gleichverteilung von Zahlen mod. Eins,"
  Mathematische Annalen, 77(3), 313-352.
- IETF RFC 9110 (2022), HTTP Semantics, Section 8.8.3 (ETag) & Section 13.1.2 (If-None-Match).
"""

from __future__ import annotations

import dataclasses
import hashlib
import math
import re
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

WEYL_DEFAULT_MODULUS = 288
WEYL_DEFAULT_STEP = 167
WEYL_DEFAULT_INVERSE = 119
WEYL_DEFAULT_OFFSET = 1
MINUTES_PER_SLOT = 5
WORKERS_AI_MODE = "DETERMINISTIC_REGEX_ONLY"

_RFC9110_ETAG_RE = re.compile(r'\A(?:W/)?"[\x21\x23-\x7e\x80-\xff]*"\Z')
_CLAUSE_SPLIT_RE = re.compile(r"(?:(?<!\d)\.(?!\d))|[;\n|]+|\s--\s|\s-\s")
_WORD_TOKEN_RE = re.compile(r"[a-z0-9_,./%+-]+")
_NON_BACKTRACK_TAG_RE = re.compile(r"<[^>]*>")

NEGATION_TOKENS: FrozenSet[str] = frozenset(
    {"no", "not", "never", "without", "zero", "neither", "none"}
)

QUOTA_UNITS: FrozenSet[str] = frozenset(
    {
        "usd",
        "eur",
        "gb/day",
        "gb/month",
        "gb",
        "gib",
        "mib",
        "mb/day",
        "mb",
        "events/day",
        "events",
        "writes/day",
        "writes",
        "reads/day",
        "reads",
        "req/day",
        "requests/day",
        "credits/day",
        "credits/month",
        "credits",
        "tokens",
        "neurons",
        "hours/month",
        "rpd",
        "rpm",
        "rps",
        "tpd",
        "tpm",
    }
)


def require_strict_int(value: Any, name: str) -> int:
    """Validate that value is an exact Python int and explicitly reject bool."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"STRICT_INT_REQUIRED:{name}:{type(value).__name__}")
    return value


def bezout_modular_inverse(step: int, modulus: int) -> int:
    """Compute exact multiplicative inverse of step modulo modulus, failing closed if non-coprime."""
    s = require_strict_int(step, "step")
    m = require_strict_int(modulus, "modulus")
    if m < 2:
        raise ValueError(f"INVALID_WEYL_MODULUS:{m}")
    if s <= 0:
        raise ValueError(f"INVALID_WEYL_STEP:{s}")
    g = math.gcd(s, m)
    if g != 1:
        raise ValueError(f"NON_COPRIME_WEYL_STEP:gcd({s},{m})={g}")
    inv = pow(s, -1, m)
    return inv


def weyl_slot(
    idx: int,
    modulus: int = WEYL_DEFAULT_MODULUS,
    step: int = WEYL_DEFAULT_STEP,
    offset: int = WEYL_DEFAULT_OFFSET,
) -> int:
    """Compute equispaced coprime Weyl phase slot (idx * step + offset) % modulus."""
    i = require_strict_int(idx, "idx")
    m = require_strict_int(modulus, "modulus")
    s = require_strict_int(step, "step")
    o = require_strict_int(offset, "offset")
    if i < 0:
        raise ValueError(f"NEGATIVE_ENDPOINT_INDEX:{i}")
    if o < 0:
        raise ValueError(f"NEGATIVE_WEYL_OFFSET:{o}")
    bezout_modular_inverse(s, m)
    return (i * s + o) % m


def weyl_minute_offset(
    idx: int,
    modulus: int = WEYL_DEFAULT_MODULUS,
    step: int = WEYL_DEFAULT_STEP,
    offset: int = WEYL_DEFAULT_OFFSET,
    slot_minutes: int = MINUTES_PER_SLOT,
) -> int:
    """Map endpoint index to deterministic minute offset within a 24-hour cycle."""
    sm = require_strict_int(slot_minutes, "slot_minutes")
    if sm <= 0:
        raise ValueError(f"INVALID_SLOT_MINUTES:{sm}")
    return sm * weyl_slot(idx, modulus=modulus, step=step, offset=offset)


@dataclasses.dataclass(frozen=True)
class WeylPhaseScheduler:
    """Collision-free modular Weyl phase scheduler eliminating thundering-herd polling."""

    modulus: int = WEYL_DEFAULT_MODULUS
    step: int = WEYL_DEFAULT_STEP
    offset: int = WEYL_DEFAULT_OFFSET
    slot_minutes: int = MINUTES_PER_SLOT
    step_inverse: int = dataclasses.field(init=False)

    def __post_init__(self) -> None:
        m = require_strict_int(self.modulus, "modulus")
        s = require_strict_int(self.step, "step")
        o = require_strict_int(self.offset, "offset")
        sm = require_strict_int(self.slot_minutes, "slot_minutes")
        if o < 0 or sm <= 0:
            raise ValueError("INVALID_SCHEDULER_OFFSET_OR_SLOT_MINUTES")
        inv = bezout_modular_inverse(s, m)
        object.__setattr__(self, "step_inverse", inv)

    def slot_for(self, idx: int) -> int:
        i = require_strict_int(idx, "idx")
        if i < 0:
            raise ValueError(f"NEGATIVE_ENDPOINT_INDEX:{i}")
        return (i * self.step + self.offset) % self.modulus

    def invert_slot(self, slot: int) -> int:
        sl = require_strict_int(slot, "slot")
        if sl < 0 or sl >= self.modulus:
            raise ValueError(f"SLOT_OUT_OF_RANGE:{sl}")
        return ((sl - self.offset) * self.step_inverse) % self.modulus

    def minute_offset_for(self, idx: int) -> int:
        return self.slot_minutes * self.slot_for(idx)

    def next_due_epoch_min(self, idx: int, now_epoch_min: int, period_min: int) -> int:
        now_m = require_strict_int(now_epoch_min, "now_epoch_min")
        per_m = require_strict_int(period_min, "period_min")
        if now_m < 0 or per_m <= 0:
            raise ValueError("INVALID_EPOCH_OR_PERIOD")
        phase = self.minute_offset_for(idx) % per_m
        delta = (phase - (now_m % per_m)) % per_m
        return now_m + (per_m if delta == 0 else delta)

    def dispersion_audit(self, endpoint_count: int) -> Dict[str, Any]:
        n = require_strict_int(endpoint_count, "endpoint_count")
        if n <= 0 or n > self.modulus:
            raise ValueError(f"INVALID_AUDIT_ENDPOINT_COUNT:{n}")
        slots = [self.slot_for(i) for i in range(n)]
        offsets = [s * self.slot_minutes for s in slots]
        cycle_minutes = self.modulus * self.slot_minutes
        hour_bins = max(1, cycle_minutes // 60)
        hour_counts = [0] * hour_bins
        for off in offsets:
            hour_counts[(off // 60) % hour_bins] += 1
        ordered = sorted(offsets)
        gaps = [(ordered[(i + 1) % n] - ordered[i]) % cycle_minutes for i in range(n)]
        return {
            "modulus": self.modulus,
            "step": self.step,
            "step_inverse": self.step_inverse,
            "endpoint_count": n,
            "unique_slots": len(set(slots)),
            "collision_count": n - len(set(slots)),
            "hourly_min_endpoints": min(hour_counts),
            "hourly_max_endpoints": max(hour_counts),
            "circular_min_gap_min": min(gaps),
            "circular_max_gap_min": max(gaps),
        }


def validate_rfc9110_etag(etag: str) -> str:
    """Validate RFC 9110 Section 8.8.3 entity-tag syntax and block CR/LF header injection."""
    if not isinstance(etag, str):
        raise TypeError(f"ETAG_STR_REQUIRED:{type(etag).__name__}")
    if etag == "":
        return ""
    if "\r" in etag or "\n" in etag or "\x00" in etag:
        raise ValueError("ETAG_HEADER_INJECTION_REJECTED")
    if not _RFC9110_ETAG_RE.match(etag):
        raise ValueError(f"INVALID_RFC9110_ETAG:{etag[:64]}")
    return etag


def rfc9110_strong_etag_match(etag_a: str, etag_b: str) -> bool:
    """RFC 9110 Section 8.8.3.2 strong comparison: neither tag may be weak (W/)."""
    a = validate_rfc9110_etag(etag_a)
    b = validate_rfc9110_etag(etag_b)
    if not a or not b:
        return False
    if a.startswith("W/") or b.startswith("W/"):
        return False
    return a == b


class ConditionalPollStateMachine:
    """RFC 9110 If-None-Match HTTP 304 conditional polling & egress accounting machine."""

    def __init__(self, endpoint_id: str, workers_ai_mode: str = WORKERS_AI_MODE) -> None:
        if not isinstance(endpoint_id, str) or not endpoint_id.strip():
            raise ValueError("ENDPOINT_ID_REQUIRED")
        assert_zero_neuron_cliff_guard(workers_ai_mode)
        self.endpoint_id = endpoint_id.strip()
        self.workers_ai_mode = workers_ai_mode
        self.stored_etag: str = ""
        self.polls_total: int = 0
        self.http_304_hits: int = 0
        self.unsolicited_304_rejections: int = 0
        self.actual_egress_bytes: int = 0
        self.unconditional_egress_bytes: int = 0

    def build_request_headers(self, user_agent: str = "DriftWatch/4.0.0") -> Dict[str, str]:
        if not isinstance(user_agent, str) or "\r" in user_agent or "\n" in user_agent:
            raise ValueError("INVALID_USER_AGENT")
        headers: Dict[str, str] = {
            "User-Agent": user_agent,
            "Accept": "application/json, text/html;q=0.9",
        }
        if self.stored_etag and not self.stored_etag.startswith("W/"):
            headers["If-None-Match"] = self.stored_etag
        return headers

    def record_response(
        self,
        http_status: int,
        response_etag: str = "",
        wire_bytes: int = 0,
        full_representation_bytes: int = 0,
    ) -> Dict[str, Any]:
        status = require_strict_int(http_status, "http_status")
        wb = require_strict_int(wire_bytes, "wire_bytes")
        fb = require_strict_int(full_representation_bytes, "full_representation_bytes")
        if status < 100 or status > 599:
            raise ValueError(f"INVALID_HTTP_STATUS:{status}")
        if wb < 0 or fb < 0:
            raise ValueError("NEGATIVE_BYTE_COUNT_REJECTED")
        if status == 200 and fb < wb:
            fb = wb

        clean_etag = validate_rfc9110_etag(response_etag)
        self.polls_total += 1

        short_circuit_304 = False
        protocol_anomaly = False

        if status == 304:
            has_strong_prior = bool(self.stored_etag and not self.stored_etag.startswith("W/"))
            etag_consistent = (clean_etag == "") or rfc9110_strong_etag_match(self.stored_etag, clean_etag)
            if has_strong_prior and etag_consistent:
                short_circuit_304 = True
                self.http_304_hits += 1
            else:
                protocol_anomaly = True
                self.unsolicited_304_rejections += 1
        elif status == 200 and clean_etag and not clean_etag.startswith("W/"):
            self.stored_etag = clean_etag

        self.actual_egress_bytes += wb
        self.unconditional_egress_bytes += max(wb, fb)
        saved_bytes = self.unconditional_egress_bytes - self.actual_egress_bytes
        reduction_pct = (
            (100.0 * float(saved_bytes) / float(self.unconditional_egress_bytes))
            if self.unconditional_egress_bytes > 0
            else 0.0
        )

        return {
            "endpoint_id": self.endpoint_id,
            "http_status": status,
            "short_circuit_304": short_circuit_304,
            "protocol_anomaly": protocol_anomaly,
            "stored_etag": self.stored_etag,
            "saved_bytes_cumulative": saved_bytes,
            "egress_reduction_pct": round(reduction_pct, 4),
        }


def assert_zero_neuron_cliff_guard(mode: str, neuron_budget: int = 0) -> None:
    """Enforce deterministic zero-AI-neuron mode fail-closed against billing cliffs."""
    if not isinstance(mode, str):
        raise TypeError("WORKERS_AI_MODE_STR_REQUIRED")
    nb = require_strict_int(neuron_budget, "neuron_budget")
    if nb != 0 or mode != WORKERS_AI_MODE:
        raise ValueError(f"WORKERS_AI_CLIFF_GUARD_BLOCKED:mode={mode}:neurons={nb}")


def _infer_scope(tokens: Sequence[str], prev_scope: str) -> str:
    joined = " " + " ".join(tokens[:16]) + " "
    if (
        " free tier " in joined
        or " free plan " in joined
        or " free account " in joined
        or joined.startswith(" free ")
    ):
        return "FREE_SCOPE"
    if " starter " in joined or " trial credit " in joined or " free credit " in joined:
        return "CREDIT_SCOPE"
    if (
        " pro plan " in joined
        or " paid plan " in joined
        or " enterprise " in joined
        or joined.startswith(" paid ")
        or joined.startswith(" pro ")
    ):
        return "PAID_SCOPE"
    return prev_scope


def _has_negation(tokens: Sequence[str], idx: int, window: int = 4) -> bool:
    lo = max(0, idx - window)
    for k in range(lo, idx):
        if tokens[k].strip("(),:") in NEGATION_TOKENS:
            return True
    return False


def extract_clause_scoped_contract(
    body_text: str,
    headers: Optional[Mapping[str, str]] = None,
    json_schema_fields: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Deterministic zero-LLM extractor for API/MCP JSON contracts, RateLimit headers, and policy clauses."""
    if not isinstance(body_text, str):
        raise TypeError("BODY_TEXT_STR_REQUIRED")
    clean = (
        " ".join(body_text.split())
        if "<" not in body_text
        else " ".join(_NON_BACKTRACK_TAG_RE.sub(" ", body_text).split())
    )
    clauses = [c.strip() for c in _CLAUSE_SPLIT_RE.split(clean.lower()) if c.strip()]
    cur_scope = "GENERAL_SCOPE"
    scoped_caps: Dict[str, float] = {}
    billing_wall = False
    deprecation_notice = False

    fillers = {"free", "daily", "monthly", "included", "max", "maximum", "up", "to", "per", "of"}

    for clause in clauses:
        toks = [t.strip(".,:()") for t in _WORD_TOKEN_RE.findall(clause) if t.strip(".,:()")]
        if not toks:
            continue
        cur_scope = _infer_scope(toks, cur_scope)
        n_toks = len(toks)
        for i, tok in enumerate(toks):
            num_txt = tok.replace(",", "").lstrip("+")
            if num_txt and num_txt.replace(".", "", 1).isdigit():
                val = float(num_txt)
                j = i + 1
                steps = 0
                while j < n_toks and toks[j] in fillers and steps < 3:
                    j += 1
                    steps += 1
                if j < n_toks:
                    unit = toks[j]
                    if j + 2 < n_toks and toks[j + 1] in ("/", "per"):
                        cand = f"{unit}/{toks[j + 2]}"
                        if cand in QUOTA_UNITS:
                            unit = cand
                    if unit in QUOTA_UNITS:
                        key = f"{cur_scope}|{unit}"
                        if key not in scoped_caps or val < scoped_caps[key]:
                            scoped_caps[key] = val

            if i + 2 < n_toks and toks[i] == "credit" and toks[i + 1] == "card" and toks[i + 2] == "required":
                if not _has_negation(toks, i):
                    billing_wall = True
            if i + 2 < n_toks and toks[i] == "billing" and toks[i + 1] == "account" and toks[i + 2] == "required":
                if not _has_negation(toks, i):
                    billing_wall = True
            if tok in ("deprecated", "discontinued", "decommissioned") and not _has_negation(toks, i):
                deprecation_notice = True

    header_limit: Optional[int] = None
    if headers is not None:
        norm_h = {str(k).lower(): str(v).strip() for k, v in headers.items()}
        for h_key in ("ratelimit-limit", "x-ratelimit-limit"):
            raw_lim = norm_h.get(h_key, "")
            if raw_lim:
                head_num = raw_lim.split(",", 1)[0].split(";", 1)[0].strip()
                if head_num.isdigit():
                    header_limit = int(head_num)
                    break

    schema_map: Dict[str, str] = {}
    if json_schema_fields is not None:
        for fk, fv in sorted(json_schema_fields.items()):
            schema_map[str(fk)] = str(fv)

    digest_src = repr((sorted(scoped_caps.items()), billing_wall, deprecation_notice, header_limit, sorted(schema_map.items())))
    contract_sha256 = hashlib.sha256(digest_src.encode("utf-8")).hexdigest()

    return {
        "scoped_caps": scoped_caps,
        "billing_wall": billing_wall,
        "deprecation_notice": deprecation_notice,
        "header_ratelimit_limit": header_limit,
        "schema_fields": schema_map,
        "contract_sha256": contract_sha256,
    }


def evaluate_contract_drift(baseline: Mapping[str, Any], current: Mapping[str, Any]) -> Dict[str, Any]:
    """Compare two extracted endpoint contracts directionally without false alarms on quota expansions."""
    reasons: List[str] = []
    rule_ids: List[str] = []

    base_schema = dict(baseline.get("schema_fields") or {})
    curr_schema = dict(current.get("schema_fields") or {})
    for field_name, base_type in sorted(base_schema.items()):
        if field_name not in curr_schema:
            reasons.append(f"SCHEMA_FIELD_REMOVED:{field_name}")
            if "DW-DRIFT-001" not in rule_ids:
                rule_ids.append("DW-DRIFT-001")
        elif curr_schema[field_name] != base_type:
            reasons.append(f"SCHEMA_TYPE_CHANGED:{field_name}:{base_type}->{curr_schema[field_name]}")
            if "DW-DRIFT-001" not in rule_ids:
                rule_ids.append("DW-DRIFT-001")

    base_lim = baseline.get("header_ratelimit_limit")
    curr_lim = current.get("header_ratelimit_limit")
    if isinstance(base_lim, int) and isinstance(curr_lim, int) and curr_lim < base_lim:
        reasons.append(f"RATELIMIT_HEADER_TIGHTENED:{base_lim}->{curr_lim}")
        if "DW-DRIFT-002" not in rule_ids:
            rule_ids.append("DW-DRIFT-002")

    base_caps = dict(baseline.get("scoped_caps") or {})
    curr_caps = dict(current.get("scoped_caps") or {})
    for cap_key, base_val in sorted(base_caps.items()):
        if cap_key.startswith(("FREE_SCOPE|", "GENERAL_SCOPE|", "CREDIT_SCOPE|")) and cap_key in curr_caps:
            curr_val = curr_caps[cap_key]
            if float(curr_val) < float(base_val) * 0.95:
                reasons.append(f"QUOTA_CAP_TIGHTENED:{cap_key}:{base_val}->{curr_val}")
                if "DW-DRIFT-002" not in rule_ids:
                    rule_ids.append("DW-DRIFT-002")

    if bool(current.get("billing_wall")) and not bool(baseline.get("billing_wall")):
        reasons.append("BILLING_WALL_ADDED")
        if "DW-DRIFT-004" not in rule_ids:
            rule_ids.append("DW-DRIFT-004")

    if bool(current.get("deprecation_notice")) and not bool(baseline.get("deprecation_notice")):
        reasons.append("ENDPOINT_DEPRECATION_NOTICE")
        if "DW-DRIFT-005" not in rule_ids:
            rule_ids.append("DW-DRIFT-005")

    return {
        "adverse_contract_drift": len(reasons) > 0,
        "rule_ids": rule_ids,
        "reasons": reasons,
    }
