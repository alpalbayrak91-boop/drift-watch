# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Two-sided Page-Hinkley, Lorden/Moustakides CUSUM, Ville e-process, and transient burst immunity.

Primary Academic References:
- Jean Ville (1939), "Etude critique de la notion de collectif," Gauthier-Villars, Paris.
- E. S. Page (1954), "Continuous Inspection Schemes," Biometrika, 41(1/2), 100-115.
- Gary Lorden (1971), "Procedures for Reacting to a Change in Distribution,"
  Annals of Mathematical Statistics, 42(6), 1897-1908.
- George V. Moustakides (1986), "Optimal Stopping Times for Detecting Changes in Distributions,"
  Annals of Statistics, 14(4), 1379-1387.
"""

from __future__ import annotations

import collections
import dataclasses
import math
from typing import Any, Deque, Dict, List, Mapping, Optional, Sequence

from .merkle_transparency import Rfc6962MerkleAccumulator, build_transparency_receipt
from .weyl_scheduler import (
    WORKERS_AI_MODE,
    ConditionalPollStateMachine,
    assert_zero_neuron_cliff_guard,
    evaluate_contract_drift,
    extract_clause_scoped_contract,
    require_strict_int,
)


def require_finite_number(value: Any, name: str) -> float:
    """Validate that value is a finite int or float and explicitly reject bool, NaN, and Inf."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"FINITE_NUMBER_REQUIRED:{name}:{type(value).__name__}")
    as_f = float(value)
    if not math.isfinite(as_f):
        raise ValueError(f"NON_FINITE_NUMBER_REJECTED:{name}:{value!r}")
    return as_f


def trunc_div(num: int, den: int) -> int:
    """Exact integer division truncating toward zero (bit-exact with JS Math.trunc)."""
    n = require_strict_int(num, "num")
    d = require_strict_int(den, "den")
    if d == 0:
        raise ZeroDivisionError("TRUNC_DIV_BY_ZERO")
    q = abs(n) // abs(d)
    return -q if ((n < 0) ^ (d < 0)) else q


def ville_two_sided_false_alarm_bound(k_slack_bps: int, h_thresh_bps: int, sigma_bps: int) -> float:
    """Closed-form Ville (1939) / Lorden (1971) two-sided sub-Gaussian false-alarm upper bound."""
    k = require_strict_int(k_slack_bps, "k_slack_bps")
    h = require_strict_int(h_thresh_bps, "h_thresh_bps")
    sig = require_strict_int(sigma_bps, "sigma_bps")
    if k <= 0 or h <= 0 or sig <= 0:
        raise ValueError("POSITIVE_CUSUM_AND_SIGMA_REQUIRED")
    exponent = (2.0 * float(k) * float(h)) / float(sig * sig)
    return min(1.0, 2.0 * math.exp(-exponent))


@dataclasses.dataclass
class TwoSidedCusumDetector:
    """Lorden (1971) / Moustakides (1986) minimax-optimal two-sided CUSUM in integer basis points."""

    mu0_bps: int = 0
    k_slack_bps: int = 1_200
    h_thresh_bps: int = 4_800
    s_pos_bps: int = 0
    s_neg_bps: int = 0
    steps: int = 0
    alarms_pos: int = 0
    alarms_neg: int = 0

    def __post_init__(self) -> None:
        require_strict_int(self.mu0_bps, "mu0_bps")
        k = require_strict_int(self.k_slack_bps, "k_slack_bps")
        h = require_strict_int(self.h_thresh_bps, "h_thresh_bps")
        sp = require_strict_int(self.s_pos_bps, "s_pos_bps")
        sn = require_strict_int(self.s_neg_bps, "s_neg_bps")
        st = require_strict_int(self.steps, "steps")
        if k <= 0 or h <= 0:
            raise ValueError("CUSUM_SLACK_AND_THRESHOLD_MUST_BE_POSITIVE")
        if sp < 0 or sn < 0 or st < 0:
            raise ValueError("NEGATIVE_CUSUM_STATE_REJECTED")

    def update(self, x_bps: int, reset_on_alarm: bool = False) -> Dict[str, Any]:
        x = require_strict_int(x_bps, "x_bps")
        if not isinstance(reset_on_alarm, bool):
            raise TypeError("RESET_ON_ALARM_BOOL_REQUIRED")

        self.steps += 1
        cand_pos = self.s_pos_bps + (x - self.mu0_bps - self.k_slack_bps)
        cand_neg = self.s_neg_bps + (self.mu0_bps - x - self.k_slack_bps)
        self.s_pos_bps = cand_pos if cand_pos > 0 else 0
        self.s_neg_bps = cand_neg if cand_neg > 0 else 0

        alarm_up = self.s_pos_bps >= self.h_thresh_bps
        alarm_down = self.s_neg_bps >= self.h_thresh_bps
        direction = "NONE"
        if alarm_up and alarm_down:
            direction = "UP" if self.s_pos_bps >= self.s_neg_bps else "DOWN"
        elif alarm_up:
            direction = "UP"
        elif alarm_down:
            direction = "DOWN"

        if alarm_up:
            self.alarms_pos += 1
        if alarm_down:
            self.alarms_neg += 1

        out = {
            "s_pos_bps": self.s_pos_bps,
            "s_neg_bps": self.s_neg_bps,
            "alarm": alarm_up or alarm_down,
            "direction": direction,
            "steps": self.steps,
        }
        if reset_on_alarm and out["alarm"]:
            self.s_pos_bps = 0
            self.s_neg_bps = 0
        return out


@dataclasses.dataclass
class PageHinkleyDetector:
    """Page (1954) two-sided cumulative deviation detector with integer-truncated running mean."""

    delta_bps: int = 350
    lambda_thresh_bps: int = 5_200
    min_warmup: int = 6
    count: int = 0
    sum_x_bps: int = 0
    m_pos_bps: int = 0
    min_m_pos_bps: int = 0
    m_neg_bps: int = 0
    min_m_neg_bps: int = 0

    def __post_init__(self) -> None:
        d = require_strict_int(self.delta_bps, "delta_bps")
        lam = require_strict_int(self.lambda_thresh_bps, "lambda_thresh_bps")
        w = require_strict_int(self.min_warmup, "min_warmup")
        c = require_strict_int(self.count, "count")
        if d < 0 or lam <= 0 or w < 1 or c < 0:
            raise ValueError("INVALID_PAGE_HINKLEY_PARAMETERS")

    def update(self, x_bps: int, reset_on_alarm: bool = False) -> Dict[str, Any]:
        x = require_strict_int(x_bps, "x_bps")
        if not isinstance(reset_on_alarm, bool):
            raise TypeError("RESET_ON_ALARM_BOOL_REQUIRED")

        self.count += 1
        self.sum_x_bps += x
        mean_bps = trunc_div(self.sum_x_bps, self.count)

        self.m_pos_bps += x - mean_bps - self.delta_bps
        if self.m_pos_bps < self.min_m_pos_bps:
            self.min_m_pos_bps = self.m_pos_bps

        self.m_neg_bps += mean_bps - x - self.delta_bps
        if self.m_neg_bps < self.min_m_neg_bps:
            self.min_m_neg_bps = self.m_neg_bps

        ph_pos = self.m_pos_bps - self.min_m_pos_bps
        ph_neg = self.m_neg_bps - self.min_m_neg_bps
        armed = self.count >= self.min_warmup
        alarm_up = armed and (ph_pos >= self.lambda_thresh_bps)
        alarm_down = armed and (ph_neg >= self.lambda_thresh_bps)

        direction = "NONE"
        if alarm_up and alarm_down:
            direction = "UP" if ph_pos >= ph_neg else "DOWN"
        elif alarm_up:
            direction = "UP"
        elif alarm_down:
            direction = "DOWN"

        out = {
            "mean_bps": mean_bps,
            "ph_pos_bps": ph_pos,
            "ph_neg_bps": ph_neg,
            "alarm": alarm_up or alarm_down,
            "direction": direction,
            "count": self.count,
        }
        if reset_on_alarm and out["alarm"]:
            self.m_pos_bps = 0
            self.min_m_pos_bps = 0
            self.m_neg_bps = 0
            self.min_m_neg_bps = 0
        return out


@dataclasses.dataclass
class VilleEProcessDetector:
    """Ville (1939) non-negative supermartingale / anytime-valid sub-Gaussian e-process."""

    mu0_bps: int = 0
    sigma_bps: int = 500
    drift_alt_bps: int = 1_800
    alpha: float = 0.002
    wealth_pos: float = 1.0
    wealth_neg: float = 1.0
    e_pos: float = 1.0
    e_neg: float = 1.0
    steps: int = 0

    def __post_init__(self) -> None:
        require_strict_int(self.mu0_bps, "mu0_bps")
        sig = require_strict_int(self.sigma_bps, "sigma_bps")
        alt = require_strict_int(self.drift_alt_bps, "drift_alt_bps")
        alp = require_finite_number(self.alpha, "alpha")
        st = require_strict_int(self.steps, "steps")
        if sig <= 0 or alt <= 0 or not (0.0 < alp < 1.0) or st < 0:
            raise ValueError("INVALID_VILLE_EPROCESS_PARAMETERS")

    @property
    def threshold_two_sided(self) -> float:
        return 2.0 / self.alpha

    def update(self, x_bps: int, reset_on_alarm: bool = False) -> Dict[str, Any]:
        x = require_strict_int(x_bps, "x_bps")
        if not isinstance(reset_on_alarm, bool):
            raise TypeError("RESET_ON_ALARM_BOOL_REQUIRED")

        self.steps += 1
        z = float(x - self.mu0_bps)
        var = float(self.sigma_bps * self.sigma_bps)
        lam = float(self.drift_alt_bps) / var
        drift_penalty = 0.5 * float(self.drift_alt_bps * self.drift_alt_bps) / var

        log_lr_pos = max(-40.0, min(40.0, lam * z - drift_penalty))
        log_lr_neg = max(-40.0, min(40.0, -lam * z - drift_penalty))

        mult_pos = math.exp(log_lr_pos)
        mult_neg = math.exp(log_lr_neg)

        self.wealth_pos = min(1e18, self.wealth_pos * mult_pos)
        self.wealth_neg = min(1e18, self.wealth_neg * mult_neg)
        self.e_pos = min(1e18, max(1.0, self.e_pos * mult_pos))
        self.e_neg = min(1e18, max(1.0, self.e_neg * mult_neg))

        thresh = self.threshold_two_sided
        alarm_up = self.e_pos >= thresh or self.wealth_pos >= thresh
        alarm_down = self.e_neg >= thresh or self.wealth_neg >= thresh
        direction = "UP" if alarm_up and (not alarm_down or self.e_pos >= self.e_neg) else ("DOWN" if alarm_down else "NONE")

        out = {
            "wealth_pos": round(self.wealth_pos, 6),
            "wealth_neg": round(self.wealth_neg, 6),
            "e_pos": round(self.e_pos, 6),
            "e_neg": round(self.e_neg, 6),
            "threshold": round(thresh, 4),
            "alarm": alarm_up or alarm_down,
            "direction": direction,
            "anytime_alpha_bound": self.alpha,
        }
        if reset_on_alarm and out["alarm"]:
            self.e_pos = 1.0
            self.e_neg = 1.0
            self.wealth_pos = 1.0
            self.wealth_neg = 1.0
        return out


class StaticThresholdBaseline:
    """Single-tick static threshold baseline (vulnerable to transient HTTP 429/503 bursts)."""

    def __init__(self, threshold_bps: int = 2_200) -> None:
        t = require_strict_int(threshold_bps, "threshold_bps")
        if t <= 0:
            raise ValueError("POSITIVE_THRESHOLD_REQUIRED")
        self.threshold_bps = t

    def update(self, x_bps: int, http_status: int = 200, contract_changed: bool = False) -> bool:
        x = require_strict_int(x_bps, "x_bps")
        st = require_strict_int(http_status, "http_status")
        if st in (410, 429, 503) or contract_changed:
            return True
        return abs(x) >= self.threshold_bps


class RollingZScoreBaseline:
    """Sliding-window z-score baseline (mean/std over trailing window W)."""

    def __init__(self, window_size: int = 24, z_thresh: float = 3.0, min_sigma_bps: float = 250.0) -> None:
        w = require_strict_int(window_size, "window_size")
        zt = require_finite_number(z_thresh, "z_thresh")
        ms = require_finite_number(min_sigma_bps, "min_sigma_bps")
        if w < 4 or zt <= 0.0 or ms <= 0.0:
            raise ValueError("INVALID_ROLLING_ZSCORE_PARAMS")
        self.window_size = w
        self.z_thresh = zt
        self.min_sigma_bps = ms
        self._buf: Deque[int] = collections.deque(maxlen=w)

    def update(self, x_bps: int, contract_changed: bool = False) -> bool:
        x = require_strict_int(x_bps, "x_bps")
        if contract_changed:
            self._buf.append(x)
            return True
        if len(self._buf) < 6:
            self._buf.append(x)
            return False
        mean = sum(self._buf) / float(len(self._buf))
        var = sum((float(v) - mean) ** 2 for v in self._buf) / float(len(self._buf))
        sigma = max(self.min_sigma_bps, math.sqrt(var))
        z = abs(float(x) - mean) / sigma
        self._buf.append(x)
        return z >= self.z_thresh


class CorroboratedDriftMonitor:
    """Drift-Watch v4.0.0 corroborated sequential drift monitor with transient 429/503 spike immunity."""

    TRANSIENT_INFRA_STATUSES = frozenset({429, 502, 503, 504})

    def __init__(
        self,
        endpoint_id: str,
        merkle_accumulator: Optional[Rfc6962MerkleAccumulator] = None,
        *,
        corroboration_window: int = 4,
        structural_corroboration_ticks: int = 2,
        workers_ai_mode: str = WORKERS_AI_MODE,
    ) -> None:
        cw = require_strict_int(corroboration_window, "corroboration_window")
        sc = require_strict_int(structural_corroboration_ticks, "structural_corroboration_ticks")
        if cw < 2:
            raise ValueError("CORROBORATION_WINDOW_MUST_BE_GE_2")
        if sc < 1:
            raise ValueError("STRUCTURAL_CORROBORATION_MUST_BE_GE_1")
        assert_zero_neuron_cliff_guard(workers_ai_mode)

        self.endpoint_id = endpoint_id
        self.corroboration_window = cw
        self.structural_corroboration_ticks = sc
        self.poll_sm = ConditionalPollStateMachine(endpoint_id, workers_ai_mode=workers_ai_mode)
        self.cusum = TwoSidedCusumDetector(mu0_bps=0, k_slack_bps=1_200, h_thresh_bps=4_800)
        self.page_hinkley = PageHinkleyDetector(delta_bps=350, lambda_thresh_bps=5_200, min_warmup=6)
        self.ville = VilleEProcessDetector(mu0_bps=0, sigma_bps=500, drift_alt_bps=1_800, alpha=0.002)
        self.merkle = merkle_accumulator if merkle_accumulator is not None else Rfc6962MerkleAccumulator()

        self._baseline_contract: Optional[Dict[str, Any]] = None
        self._transient_buffer: List[int] = []
        self._consecutive_contract_hits: int = 0
        self._consecutive_410_hits: int = 0

    def observe_tick(
        self,
        epoch_min: int,
        http_status: int,
        residual_bps: int,
        *,
        etag: str = "",
        wire_bytes: int = 256,
        full_representation_bytes: int = 4_096,
        body_text: str = "",
        headers: Optional[Mapping[str, str]] = None,
        json_schema_fields: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        ep_min = require_strict_int(epoch_min, "epoch_min")
        status = require_strict_int(http_status, "http_status")
        x_bps = require_strict_int(residual_bps, "residual_bps")
        if ep_min < 0:
            raise ValueError("NEGATIVE_EPOCH_MIN_REJECTED")

        poll_info = self.poll_sm.record_response(
            status,
            response_etag=etag,
            wire_bytes=wire_bytes,
            full_representation_bytes=full_representation_bytes,
        )

        # 1. Transient HTTP 429 / 503 burst quarantine (< corroboration_window ticks)
        if status in self.TRANSIENT_INFRA_STATUSES:
            self._transient_buffer.append(x_bps)
            if len(self._transient_buffer) < self.corroboration_window:
                return {
                    "endpoint_id": self.endpoint_id,
                    "epoch_min": ep_min,
                    "alarm": False,
                    "state": "INFRA_TRANSIENT_QUARANTINE",
                    "transient_streak": len(self._transient_buffer),
                    "rule_ids": [],
                    "reasons": [f"QUARANTINED_HTTP_{status}_STREAK_{len(self._transient_buffer)}"],
                    "short_circuit_304": False,
                    "receipt": None,
                }
            # Persistent throttle/outage cliff (>= corroboration_window consecutive ticks)
            c_last = {"s_pos_bps": self.cusum.s_pos_bps, "s_neg_bps": self.cusum.s_neg_bps, "alarm": False}
            p_last = {"ph_pos_bps": 0, "ph_neg_bps": 0, "alarm": False}
            v_last = {"e_pos": self.ville.e_pos, "e_neg": self.ville.e_neg, "alarm": False}
            for buffered_x in self._transient_buffer:
                c_last = self.cusum.update(buffered_x, reset_on_alarm=False)
                p_last = self.page_hinkley.update(buffered_x, reset_on_alarm=False)
                v_last = self.ville.update(buffered_x, reset_on_alarm=False)
            streak_len = len(self._transient_buffer)
            self._transient_buffer.clear()
            self.cusum.s_pos_bps = 0
            self.cusum.s_neg_bps = 0
            return self._emit_alarm(
                ep_min=ep_min,
                status=status,
                rule_ids=["DW-DRIFT-005"],
                reasons=[f"PERSISTENT_HTTP_{status}_CLIFF_STREAK_{streak_len}"],
                c_res=c_last,
                p_res=p_last,
                v_res=v_last,
                short_circuit_304=False,
            )

        # Normal non-transient status clears any shorter transient 429/503 burst cleanly
        if self._transient_buffer:
            self._transient_buffer.clear()

        # 2. HTTP 410 Gone endpoint death corroboration
        if status == 410:
            self._consecutive_410_hits += 1
            c_res = self.cusum.update(x_bps, reset_on_alarm=False)
            p_res = self.page_hinkley.update(x_bps, reset_on_alarm=False)
            v_res = self.ville.update(x_bps, reset_on_alarm=False)
            if self._consecutive_410_hits >= self.structural_corroboration_ticks:
                self._consecutive_410_hits = 0
                return self._emit_alarm(
                    ep_min=ep_min,
                    status=status,
                    rule_ids=["DW-DRIFT-005"],
                    reasons=["HTTP_410_GONE_CORROBORATED"],
                    c_res=c_res,
                    p_res=p_res,
                    v_res=v_res,
                    short_circuit_304=False,
                )
            return {
                "endpoint_id": self.endpoint_id,
                "epoch_min": ep_min,
                "alarm": False,
                "state": "PENDING_410_CORROBORATION",
                "transient_streak": 0,
                "rule_ids": [],
                "reasons": ["PENDING_HTTP_410_CORROBORATION"],
                "short_circuit_304": False,
                "receipt": None,
            }
        self._consecutive_410_hits = 0

        # 3. Structural / Clause-Scoped Contract Evaluation (skipped on validated HTTP 304)
        contract_rules: List[str] = []
        contract_reasons: List[str] = []
        if not poll_info["short_circuit_304"] and status == 200:
            has_contract_payload = bool(body_text or headers or json_schema_fields)
            if has_contract_payload:
                curr_contract = extract_clause_scoped_contract(
                    body_text,
                    headers=headers,
                    json_schema_fields=json_schema_fields,
                )
                if self._baseline_contract is None:
                    self._baseline_contract = curr_contract
                else:
                    cdiff = evaluate_contract_drift(self._baseline_contract, curr_contract)
                    if cdiff["adverse_contract_drift"]:
                        self._consecutive_contract_hits += 1
                        if self._consecutive_contract_hits >= self.structural_corroboration_ticks:
                            contract_rules.extend(cdiff["rule_ids"])
                            contract_reasons.extend(cdiff["reasons"])
                            self._baseline_contract = curr_contract
                            self._consecutive_contract_hits = 0
                    else:
                        self._consecutive_contract_hits = 0

        # 4. Sequential Statistical Drift (Lorden/Moustakides CUSUM + Page-Hinkley + Ville E-Process)
        c_res = self.cusum.update(x_bps, reset_on_alarm=False)
        p_res = self.page_hinkley.update(x_bps, reset_on_alarm=False)
        v_res = self.ville.update(x_bps, reset_on_alarm=False)

        seq_corroborated = bool(c_res["alarm"] and (p_res["alarm"] or v_res["alarm"]))
        rule_ids = list(contract_rules)
        reasons = list(contract_reasons)

        if seq_corroborated:
            if "DW-DRIFT-003" not in rule_ids:
                rule_ids.append("DW-DRIFT-003")
            reasons.append(f"CORROBORATED_SEQUENTIAL_DRIFT:{c_res['direction']}")
            self.cusum.s_pos_bps = 0
            self.cusum.s_neg_bps = 0
            self.page_hinkley.m_pos_bps = 0
            self.page_hinkley.min_m_pos_bps = 0
            self.page_hinkley.m_neg_bps = 0
            self.page_hinkley.min_m_neg_bps = 0
            self.ville.e_pos = 1.0
            self.ville.e_neg = 1.0

        if rule_ids:
            return self._emit_alarm(
                ep_min=ep_min,
                status=status,
                rule_ids=rule_ids,
                reasons=reasons,
                c_res=c_res,
                p_res=p_res,
                v_res=v_res,
                short_circuit_304=bool(poll_info["short_circuit_304"]),
            )

        return {
            "endpoint_id": self.endpoint_id,
            "epoch_min": ep_min,
            "alarm": False,
            "state": "CLEAN_304_SHORT_CIRCUIT" if poll_info["short_circuit_304"] else "CLEAN_PASS",
            "transient_streak": 0,
            "rule_ids": [],
            "reasons": [],
            "short_circuit_304": bool(poll_info["short_circuit_304"]),
            "cusum": c_res,
            "page_hinkley": p_res,
            "ville": v_res,
            "receipt": None,
        }

    def _emit_alarm(
        self,
        *,
        ep_min: int,
        status: int,
        rule_ids: Sequence[str],
        reasons: Sequence[str],
        c_res: Mapping[str, Any],
        p_res: Mapping[str, Any],
        v_res: Mapping[str, Any],
        short_circuit_304: bool,
    ) -> Dict[str, Any]:
        event_doc = {
            "version": "4.0.0",
            "endpoint_id": self.endpoint_id,
            "epoch_min": ep_min,
            "http_status": status,
            "rule_ids": list(rule_ids),
            "reasons": list(reasons),
            "cusum_pos_bps": int(c_res["s_pos_bps"]),
            "cusum_neg_bps": int(c_res["s_neg_bps"]),
            "ph_pos_bps": int(p_res["ph_pos_bps"]),
            "ph_neg_bps": int(p_res["ph_neg_bps"]),
            "ville_e_max": round(max(float(v_res["e_pos"]), float(v_res["e_neg"])), 4),
        }
        receipt = build_transparency_receipt(self.merkle, event_doc)
        return {
            "endpoint_id": self.endpoint_id,
            "epoch_min": ep_min,
            "alarm": True,
            "state": "CONFIRMED_DRIFT_ALARM",
            "transient_streak": 0,
            "rule_ids": list(rule_ids),
            "reasons": list(reasons),
            "short_circuit_304": short_circuit_304,
            "cusum": dict(c_res),
            "page_hinkley": dict(p_res),
            "ville": dict(v_res),
            "receipt": receipt,
        }
