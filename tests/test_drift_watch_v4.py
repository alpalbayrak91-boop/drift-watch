# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Comprehensive unit and integration tests for Drift-Watch v4.0.0."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import math
import pathlib
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List, Tuple

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from drift_watch import (  # noqa: E402
    EMPTY_TREE_SHA256,
    EMPTY_TREE_SHA256_HEX,
    MAX_SAFE_JCS_INT,
    MINUTES_PER_SLOT,
    SARIF_RULES,
    WEYL_DEFAULT_INVERSE,
    WEYL_DEFAULT_MODULUS,
    WEYL_DEFAULT_OFFSET,
    WEYL_DEFAULT_STEP,
    WORKERS_AI_MODE,
    ConditionalPollStateMachine,
    CorroboratedDriftMonitor,
    PageHinkleyDetector,
    Rfc6962MerkleAccumulator,
    RollingZScoreBaseline,
    StaticThresholdBaseline,
    TwoSidedCusumDetector,
    VilleEProcessDetector,
    WeylPhaseScheduler,
    assert_zero_neuron_cliff_guard,
    bezout_modular_inverse,
    build_sarif_v210_report,
    build_transparency_receipt,
    cli_main,
    evaluate_contract_drift,
    extract_clause_scoped_contract,
    jcs_canonical_bytes,
    jcs_canonical_str,
    require_finite_number,
    require_strict_int,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    rfc9110_strong_etag_match,
    scan_trace_document,
    trunc_div,
    validate_rfc9110_etag,
    verify_consistency_proof,
    verify_inclusion_proof,
    verify_transparency_receipt,
    ville_two_sided_false_alarm_bound,
    weyl_minute_offset,
    weyl_slot,
)

SERVER_DIR = REPO_ROOT / "server"
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(SERVER_DIR))
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import deploy_cloudflare  # noqa: E402
import drift_watch_edge_mirror as edge_mirror  # noqa: E402


def _invoke_wsgi(
    app: Any,
    method: str = "GET",
    path: str = "/",
    query_string: str = "",
) -> Tuple[str, Dict[str, str], bytes]:
    captured: Dict[str, Any] = {}

    def start_response(status: str, headers: List[Tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = {k.lower(): v for k, v in headers}

    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query_string,
        "SERVER_NAME": "127.0.0.1",
        "SERVER_PORT": "8080",
        "wsgi.url_scheme": "http",
        "wsgi.input": io.BytesIO(b""),
    }
    body = b"".join(app(environ, start_response))
    return captured["status"], captured["headers"], body


class SequentialDetectorTests(unittest.TestCase):
    def test_require_finite_number_rejects_bool_nan_inf(self) -> None:
        self.assertEqual(require_finite_number(0, "x"), 0.0)
        self.assertEqual(require_finite_number(-12.5, "x"), -12.5)
        for bad_type in (True, False, "1.0", None):
            with self.assertRaises(TypeError):
                require_finite_number(bad_type, "x")
        for non_finite in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                require_finite_number(non_finite, "x")

    def test_trunc_div_matches_zero_truncation_and_fail_closed(self) -> None:
        self.assertEqual(trunc_div(7, 3), 2)
        self.assertEqual(trunc_div(-7, 3), -2)
        self.assertEqual(trunc_div(7, -3), -2)
        self.assertEqual(trunc_div(-7, -3), 2)
        self.assertEqual(trunc_div(0, 5), 0)
        with self.assertRaises(ZeroDivisionError):
            trunc_div(10, 0)
        with self.assertRaises(TypeError):
            trunc_div(True, 2)  # type: ignore[arg-type]

    def test_cusum_rejects_bool_and_nonpositive_parameters(self) -> None:
        with self.assertRaises(TypeError):
            TwoSidedCusumDetector(mu0_bps=True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            TwoSidedCusumDetector(k_slack_bps=False)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            TwoSidedCusumDetector(k_slack_bps=0)
        with self.assertRaises(ValueError):
            TwoSidedCusumDetector(h_thresh_bps=-10)
        with self.assertRaises(ValueError):
            TwoSidedCusumDetector(s_pos_bps=-1)
        det = TwoSidedCusumDetector()
        with self.assertRaises(TypeError):
            det.update(True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            det.update(100, reset_on_alarm="yes")  # type: ignore[arg-type]

    def test_cusum_deadband_remains_exact_zero(self) -> None:
        det = TwoSidedCusumDetector(mu0_bps=0, k_slack_bps=1200, h_thresh_bps=4800)
        for val in (0, 1200, -1200, 600, -900, 1199, -1199):
            res = det.update(val)
            self.assertEqual(res["s_pos_bps"], 0)
            self.assertEqual(res["s_neg_bps"], 0)
            self.assertFalse(res["alarm"])
            self.assertEqual(res["direction"], "NONE")

    def test_cusum_two_sided_up_and_down_alarms_and_reset(self) -> None:
        det = TwoSidedCusumDetector(mu0_bps=0, k_slack_bps=1000, h_thresh_bps=3000)
        self.assertFalse(det.update(2500)["alarm"])
        up = det.update(2500, reset_on_alarm=True)
        self.assertTrue(up["alarm"])
        self.assertEqual(up["direction"], "UP")
        self.assertEqual(up["s_pos_bps"], 3000)
        self.assertEqual(det.s_pos_bps, 0)
        self.assertEqual(det.alarms_pos, 1)

        self.assertFalse(det.update(-2500)["alarm"])
        down = det.update(-2500, reset_on_alarm=True)
        self.assertTrue(down["alarm"])
        self.assertEqual(down["direction"], "DOWN")
        self.assertEqual(down["s_neg_bps"], 3000)
        self.assertEqual(det.s_neg_bps, 0)
        self.assertEqual(det.alarms_neg, 1)

    def test_page_hinkley_warmup_guard_and_detection(self) -> None:
        with self.assertRaises(ValueError):
            PageHinkleyDetector(delta_bps=-1)
        with self.assertRaises(ValueError):
            PageHinkleyDetector(lambda_thresh_bps=0)
        with self.assertRaises(ValueError):
            PageHinkleyDetector(min_warmup=0)
        with self.assertRaises(TypeError):
            PageHinkleyDetector(min_warmup=True)  # type: ignore[arg-type]

        ph = PageHinkleyDetector(delta_bps=200, lambda_thresh_bps=3000, min_warmup=6)
        for _ in range(5):
            r = ph.update(4000)
            self.assertFalse(r["alarm"])
        ph_down = PageHinkleyDetector(delta_bps=200, lambda_thresh_bps=2500, min_warmup=4)
        for _ in range(4):
            ph_down.update(0)
        fired = False
        for _ in range(10):
            res = ph_down.update(-2500, reset_on_alarm=True)
            if res["alarm"]:
                self.assertEqual(res["direction"], "DOWN")
                fired = True
                break
        self.assertTrue(fired)
        self.assertEqual(ph_down.m_neg_bps, 0)

    def test_ville_e_process_supermartingale_and_bounds(self) -> None:
        bound = ville_two_sided_false_alarm_bound(1200, 4800, 500)
        expected = min(1.0, 2.0 * math.exp(-(2.0 * 1200.0 * 4800.0) / (500.0 * 500.0)))
        self.assertAlmostEqual(bound, expected, places=15)
        with self.assertRaises(ValueError):
            ville_two_sided_false_alarm_bound(0, 4800, 500)
        with self.assertRaises(TypeError):
            ville_two_sided_false_alarm_bound(True, 4800, 500)  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            VilleEProcessDetector(alpha=float("nan"))
        with self.assertRaises(ValueError):
            VilleEProcessDetector(alpha=1.0)
        with self.assertRaises(TypeError):
            VilleEProcessDetector(alpha=True)  # type: ignore[arg-type]

        ville = VilleEProcessDetector(mu0_bps=0, sigma_bps=500, drift_alt_bps=1800, alpha=0.002)
        self.assertEqual(ville.threshold_two_sided, 1000.0)
        for _ in range(10):
            null_res = ville.update(0)
            self.assertFalse(null_res["alarm"])
            self.assertGreaterEqual(null_res["e_pos"], 1.0)
            self.assertGreaterEqual(null_res["e_neg"], 1.0)

        alarmed = False
        for _ in range(10):
            res = ville.update(2400, reset_on_alarm=True)
            if res["alarm"]:
                self.assertEqual(res["direction"], "UP")
                self.assertGreaterEqual(res["e_pos"], 1000.0)
                alarmed = True
                break
        self.assertTrue(alarmed)
        self.assertEqual(ville.e_pos, 1.0)
        self.assertEqual(ville.wealth_pos, 1.0)

    def test_static_and_rolling_zscore_baselines(self) -> None:
        with self.assertRaises(ValueError):
            StaticThresholdBaseline(threshold_bps=0)
        with self.assertRaises(TypeError):
            StaticThresholdBaseline(threshold_bps=True)  # type: ignore[arg-type]
        sb = StaticThresholdBaseline(threshold_bps=2200)
        self.assertFalse(sb.update(1000, http_status=200))
        self.assertTrue(sb.update(0, http_status=429))
        self.assertTrue(sb.update(2200, http_status=200))

        with self.assertRaises(ValueError):
            RollingZScoreBaseline(window_size=3)
        with self.assertRaises(ValueError):
            RollingZScoreBaseline(z_thresh=float("inf"))
        with self.assertRaises(TypeError):
            RollingZScoreBaseline(z_thresh=False)  # type: ignore[arg-type]
        rz = RollingZScoreBaseline(window_size=12, z_thresh=3.0)
        for i in range(6):
            self.assertFalse(rz.update(100 if i % 2 == 0 else -100))
        self.assertTrue(rz.update(1500))

    def test_corroborated_monitor_transient_429_immunity_vs_persistent_cliff(self) -> None:
        mon = CorroboratedDriftMonitor("W01", corroboration_window=4)
        self.assertFalse(mon.observe_tick(100, 200, 0, etag='"v1"')["alarm"])

        for streak in (1, 2, 3):
            q = mon.observe_tick(100 + streak * 5, 429, 14000)
            self.assertFalse(q["alarm"])
            self.assertEqual(q["state"], "INFRA_TRANSIENT_QUARANTINE")
            self.assertEqual(q["transient_streak"], streak)
            self.assertIsNone(q["receipt"])

        rec = mon.observe_tick(120, 304, 0, etag='"v1"')
        self.assertFalse(rec["alarm"])
        self.assertEqual(rec["state"], "CLEAN_304_SHORT_CIRCUIT")

        for streak in (1, 2, 3):
            q2 = mon.observe_tick(125 + streak * 5, 503, 9500)
            self.assertFalse(q2["alarm"])
        cliff = mon.observe_tick(145, 503, 9500)
        self.assertTrue(cliff["alarm"])
        self.assertEqual(cliff["state"], "CONFIRMED_DRIFT_ALARM")
        self.assertEqual(cliff["rule_ids"], ["DW-DRIFT-005"])
        self.assertIsNotNone(cliff["receipt"])
        self.assertTrue(verify_transparency_receipt(cliff["receipt"])["verified"])

    def test_corroborated_monitor_410_gone_and_parameter_guards(self) -> None:
        with self.assertRaises(ValueError):
            CorroboratedDriftMonitor("W01", corroboration_window=1)
        with self.assertRaises(ValueError):
            CorroboratedDriftMonitor("W01", structural_corroboration_ticks=0)
        with self.assertRaises(ValueError):
            CorroboratedDriftMonitor("W01", workers_ai_mode="WORKERS_AI_LLM")

        mon = CorroboratedDriftMonitor("W02", structural_corroboration_ticks=2)
        with self.assertRaises(ValueError):
            mon.observe_tick(-1, 200, 0)
        pending = mon.observe_tick(10, 410, 5000)
        self.assertFalse(pending["alarm"])
        self.assertEqual(pending["state"], "PENDING_410_CORROBORATION")
        confirmed = mon.observe_tick(15, 410, 5000)
        self.assertTrue(confirmed["alarm"])
        self.assertEqual(confirmed["rule_ids"], ["DW-DRIFT-005"])
        self.assertTrue(verify_transparency_receipt(confirmed["receipt"])["verified"])

    def test_corroborated_monitor_sequential_drift_and_negation_immunity(self) -> None:
        mon = CorroboratedDriftMonitor("W03", structural_corroboration_ticks=2)
        mon.observe_tick(
            0,
            200,
            0,
            etag='"v1"',
            body_text="Free tier includes 10,000 requests/day. No credit card required.",
            headers={"RateLimit-Limit": "1000"},
        )
        # Expansion + negated phrase must not false-alarm
        for k in (1, 2):
            r = mon.observe_tick(
                k * 5,
                200,
                100,
                etag='"v2"',
                body_text="Free tier expanded to 25,000 requests/day. No credit card required.",
                headers={"RateLimit-Limit": "2500"},
            )
            self.assertFalse(r["alarm"])

        # Sustained latency shift fires DW-DRIFT-003 with verified receipt
        alarm_out = None
        for step in range(1, 20):
            out = mon.observe_tick(20 + step * 5, 304, 2600, etag='"v2"')
            if out["alarm"]:
                alarm_out = out
                break
        self.assertIsNotNone(alarm_out)
        assert alarm_out is not None
        self.assertIn("DW-DRIFT-003", alarm_out["rule_ids"])
        self.assertTrue(verify_transparency_receipt(alarm_out["receipt"])["verified"])


class WeylAndContractTests(unittest.TestCase):
    def test_require_strict_int_rejects_bool_and_float(self) -> None:
        self.assertEqual(require_strict_int(0, "n"), 0)
        self.assertEqual(require_strict_int(-5, "n"), -5)
        for bad in (True, False, 1.0, "1", None):
            with self.assertRaises(TypeError):
                require_strict_int(bad, "n")

    def test_bezout_inverse_coprime_and_fail_closed(self) -> None:
        inv = bezout_modular_inverse(WEYL_DEFAULT_STEP, WEYL_DEFAULT_MODULUS)
        self.assertEqual(inv, WEYL_DEFAULT_INVERSE)
        self.assertEqual((WEYL_DEFAULT_STEP * inv) % WEYL_DEFAULT_MODULUS, 1)
        for step, mod in ((168, 288), (12, 288), (2, 1440), (6, 9)):
            with self.assertRaises(ValueError):
                bezout_modular_inverse(step, mod)
        with self.assertRaises(ValueError):
            bezout_modular_inverse(1, 1)
        with self.assertRaises(ValueError):
            bezout_modular_inverse(0, 288)
        with self.assertRaises(TypeError):
            bezout_modular_inverse(True, 288)  # type: ignore[arg-type]

    def test_weyl_bijection_over_288_and_1440_slots(self) -> None:
        sched_288 = WeylPhaseScheduler()
        slots_288 = [sched_288.slot_for(i) for i in range(288)]
        self.assertEqual(sorted(slots_288), list(range(288)))
        for i in range(288):
            self.assertEqual(sched_288.invert_slot(slots_288[i]), i)
            self.assertEqual(weyl_slot(i), slots_288[i])
            self.assertEqual(weyl_minute_offset(i), 5 * slots_288[i])

        sched_1440 = WeylPhaseScheduler(modulus=1440, step=839, offset=1, slot_minutes=1)
        slots_1440 = [sched_1440.slot_for(i) for i in range(1440)]
        self.assertEqual(sorted(slots_1440), list(range(1440)))
        for i in range(1440):
            self.assertEqual(sched_1440.invert_slot(slots_1440[i]), i)

        audit = sched_288.dispersion_audit(50)
        self.assertEqual(audit["unique_slots"], 50)
        self.assertEqual(audit["collision_count"], 0)
        self.assertEqual(audit["hourly_min_endpoints"], 2)
        self.assertEqual(audit["hourly_max_endpoints"], 3)

    def test_weyl_next_due_epoch_and_bounds(self) -> None:
        sched = WeylPhaseScheduler()
        due = sched.next_due_epoch_min(0, now_epoch_min=29_932_000, period_min=15)
        self.assertGreater(due, 29_932_000)
        self.assertEqual(due % 15, sched.minute_offset_for(0) % 15)
        with self.assertRaises(ValueError):
            sched.slot_for(-1)
        with self.assertRaises(ValueError):
            sched.invert_slot(288)
        with self.assertRaises(ValueError):
            sched.next_due_epoch_min(0, -1, 15)
        with self.assertRaises(ValueError):
            sched.next_due_epoch_min(0, 100, 0)

    def test_rfc9110_etag_validation_and_strong_comparison(self) -> None:
        self.assertEqual(validate_rfc9110_etag('"abc-v1"'), '"abc-v1"')
        self.assertEqual(validate_rfc9110_etag('W/"weak-v1"'), 'W/"weak-v1"')
        self.assertTrue(rfc9110_strong_etag_match('"abc-v1"', '"abc-v1"'))
        self.assertFalse(rfc9110_strong_etag_match('W/"abc"', 'W/"abc"'))
        self.assertFalse(rfc9110_strong_etag_match('"abc"', ""))
        for bad_etag in ('"bad"\r\nInject: 1', '"bad"\n', '"bad\x00"', "unquoted", '"has space"'):
            with self.assertRaises(ValueError):
                validate_rfc9110_etag(bad_etag)
        with self.assertRaises(TypeError):
            validate_rfc9110_etag(123)  # type: ignore[arg-type]

    def test_conditional_poll_state_machine_304_bandwidth_and_anomaly(self) -> None:
        sm = ConditionalPollStateMachine("W01")
        self.assertNotIn("If-None-Match", sm.build_request_headers())

        # Unsolicited 304 before any 200 ETag is flagged as protocol anomaly
        anom = sm.record_response(304, wire_bytes=180, full_representation_bytes=4200)
        self.assertFalse(anom["short_circuit_304"])
        self.assertTrue(anom["protocol_anomaly"])
        self.assertEqual(sm.unsolicited_304_rejections, 1)

        r200 = sm.record_response(200, response_etag='"v1"', wire_bytes=4200, full_representation_bytes=4200)
        self.assertFalse(r200["short_circuit_304"])
        self.assertEqual(sm.build_request_headers()["If-None-Match"], '"v1"')

        for _ in range(9):
            r304 = sm.record_response(304, response_etag='"v1"', wire_bytes=180, full_representation_bytes=4200)
            self.assertTrue(r304["short_circuit_304"])
            self.assertFalse(r304["protocol_anomaly"])
        self.assertGreater(r304["egress_reduction_pct"], 70.0)
        self.assertEqual(sm.http_304_hits, 9)

        with self.assertRaises(ValueError):
            sm.build_request_headers(user_agent="Bad\r\nAgent")
        with self.assertRaises(ValueError):
            sm.record_response(99)

    def test_workers_ai_dec1_cliff_guard(self) -> None:
        assert_zero_neuron_cliff_guard(WORKERS_AI_MODE, 0)
        with self.assertRaises(ValueError):
            assert_zero_neuron_cliff_guard("WORKERS_AI_LLM", 0)
        with self.assertRaises(ValueError):
            assert_zero_neuron_cliff_guard(WORKERS_AI_MODE, 1)
        with self.assertRaises(TypeError):
            assert_zero_neuron_cliff_guard(WORKERS_AI_MODE, True)  # type: ignore[arg-type]
        with self.assertRaises(TypeError):
            assert_zero_neuron_cliff_guard(None, 0)  # type: ignore[arg-type]

    def test_clause_scoped_contract_extractor_and_directional_drift(self) -> None:
        base = extract_clause_scoped_contract(
            "Free tier includes 1,500 requests/day; Paid plan includes 250 writes/day. No credit card required.",
            headers={"RateLimit-Limit": "1000"},
            json_schema_fields={"id": "string", "quota": "integer"},
        )
        # Swap numbers between tiers (unscoped setdiff would miss this)
        curr_tier_cut = extract_clause_scoped_contract(
            "Free tier includes 250 requests/day; Paid plan includes 1,500 writes/day. No credit card required.",
            headers={"RateLimit-Limit": "1000"},
            json_schema_fields={"id": "string", "quota": "integer"},
        )
        diff_tier = evaluate_contract_drift(base, curr_tier_cut)
        self.assertTrue(diff_tier["adverse_contract_drift"])
        self.assertIn("DW-DRIFT-002", diff_tier["rule_ids"])

        # Schema break + RateLimit cut + billing wall + deprecation
        curr_multi = extract_clause_scoped_contract(
            "Free tier includes 250 requests/day. Credit card required. Endpoint deprecated.",
            headers={"RateLimit-Limit": "100"},
            json_schema_fields={"id": "string", "quota": "string"},
        )
        diff_multi = evaluate_contract_drift(base, curr_multi)
        for expected_rule in ("DW-DRIFT-001", "DW-DRIFT-002", "DW-DRIFT-004", "DW-DRIFT-005"):
            self.assertIn(expected_rule, diff_multi["rule_ids"])


class JcsAndMerkleTransparencyTests(unittest.TestCase):
    def test_jcs_numbers_minus_zero_large_ints_and_non_finite_rejection(self) -> None:
        self.assertEqual(jcs_canonical_str(-0.0), "0")
        self.assertEqual(jcs_canonical_str(0.0), "0")
        self.assertEqual(jcs_canonical_str(MAX_SAFE_JCS_INT), "9007199254740991")
        self.assertEqual(jcs_canonical_str(-MAX_SAFE_JCS_INT), "-9007199254740991")
        self.assertEqual(jcs_canonical_str(1e20), "100000000000000000000")
        self.assertEqual(jcs_canonical_str(1e21), "1e+21")
        self.assertEqual(jcs_canonical_str(1e-6), "0.000001")
        self.assertEqual(jcs_canonical_str(1e-7), "1e-7")
        self.assertEqual(jcs_canonical_str(0.00001), "0.00001")

        with self.assertRaises(ValueError):
            jcs_canonical_str((1 << 53) + 1)
        for bad_f in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(ValueError):
                jcs_canonical_str(bad_f)

    def test_jcs_key_sorting_utf16_escapes_and_lone_surrogates(self) -> None:
        obj = {
            "\uffff": 1,
            "\U00010000": 2,
            "10": "ten",
            "2": "two",
            "esc": 'a\b\t\n\f\r"\\\x01',
        }
        canon = jcs_canonical_str(obj)
        expected = (
            '{"10":"ten","2":"two","esc":"a\\b\\t\\n\\f\\r\\"\\\\\\u0001",'
            '"\U00010000":2,"\uffff":1}'
        )
        self.assertEqual(canon, expected)
        self.assertEqual(jcs_canonical_bytes(obj), expected.encode("utf-8"))

        with self.assertRaises(ValueError):
            jcs_canonical_str("\ud800")
        with self.assertRaises(ValueError):
            jcs_canonical_str({"\udfff": 1})
        with self.assertRaises(TypeError):
            jcs_canonical_str({1: "non-str-key"})  # type: ignore[dict-item]
        with self.assertRaises(TypeError):
            jcs_canonical_str(object())

    def test_rfc6962_domain_separation_and_empty_tree(self) -> None:
        self.assertEqual(EMPTY_TREE_SHA256, hashlib.sha256(b"").digest())
        self.assertEqual(EMPTY_TREE_SHA256_HEX, hashlib.sha256(b"").hexdigest())
        lh = rfc6962_leaf_hash(b"payload")
        self.assertEqual(lh, hashlib.sha256(b"\x00payload").digest())
        nh = rfc6962_node_hash(lh, lh)
        self.assertEqual(nh, hashlib.sha256(b"\x01" + lh + lh).digest())
        self.assertNotEqual(rfc6962_leaf_hash(lh + lh), nh)
        with self.assertRaises(ValueError):
            rfc6962_node_hash(b"short", lh)

    def test_merkle_accumulator_frontier_and_proofs_1_to_35(self) -> None:
        acc = Rfc6962MerkleAccumulator()
        self.assertEqual(acc.root_hash(), EMPTY_TREE_SHA256)
        payloads: List[bytes] = []
        roots: List[str] = [EMPTY_TREE_SHA256_HEX]

        for i in range(35):
            raw = jcs_canonical_bytes({"seq": i, "tag": f"ev-{i}"})
            payloads.append(raw)
            idx, lh_hex, root_hex = acc.append_bytes(raw)
            self.assertEqual(idx, i)
            self.assertEqual(lh_hex, rfc6962_leaf_hash(raw).hex())
            self.assertEqual(acc.frontier_depth(), (i + 1).bit_count())
            self.assertEqual(acc.root_hash(i + 1).hex(), root_hex)
            roots.append(root_hex)

        for size in range(1, 36):
            for idx in range(size):
                path = acc.inclusion_proof(idx, size)
                self.assertTrue(verify_inclusion_proof(payloads[idx], idx, size, path, roots[size]))
        for first in (0, 1, 2, 3, 4, 7, 8, 15, 16, 23, 35):
            for second in (first, 8, 16, 24, 35):
                if first <= second:
                    cpath = acc.consistency_proof(first, second)
                    self.assertTrue(verify_consistency_proof(first, second, roots[first], roots[second], cpath))

    def test_verify_inclusion_proof_fail_closed_rejections(self) -> None:
        acc = Rfc6962MerkleAccumulator()
        raws = [f"leaf-{i}".encode("utf-8") for i in range(6)]
        for r in raws:
            acc.append_bytes(r)
        root_hex = acc.root_hash().hex()
        proof = acc.inclusion_proof(2, 6)
        self.assertTrue(verify_inclusion_proof(raws[2], 2, 6, proof, root_hex))

        self.assertFalse(verify_inclusion_proof(b"tampered", 2, 6, proof, root_hex))
        self.assertFalse(verify_inclusion_proof(raws[2], 2, 4, proof, root_hex))
        self.assertFalse(verify_inclusion_proof(raws[2], 2, 5, proof, acc.root_hash(5).hex()))
        self.assertFalse(verify_inclusion_proof(raws[2], -1, 6, proof, root_hex))
        self.assertFalse(verify_inclusion_proof(raws[2], 6, 6, proof, root_hex))
        self.assertFalse(verify_inclusion_proof(raws[2], True, 6, proof, root_hex))  # type: ignore[arg-type]
        self.assertFalse(verify_inclusion_proof(raws[2], 2, True, proof, root_hex))  # type: ignore[arg-type]
        self.assertFalse(verify_inclusion_proof(raws[2], 2, 6, proof, root_hex.upper()))
        self.assertFalse(verify_inclusion_proof(raws[2], 2, 6, proof[:-1], root_hex))
        self.assertFalse(verify_inclusion_proof("not-bytes", 2, 6, proof, root_hex))  # type: ignore[arg-type]

    def test_verify_consistency_proof_fail_closed_rejections(self) -> None:
        acc = Rfc6962MerkleAccumulator()
        roots = [EMPTY_TREE_SHA256_HEX]
        for i in range(10):
            _, _, root_hex = acc.append_bytes(f"item-{i}".encode("utf-8"))
            roots.append(root_hex)

        cpath = acc.consistency_proof(5, 10)
        self.assertTrue(verify_consistency_proof(5, 10, roots[5], roots[10], cpath))
        self.assertFalse(verify_consistency_proof(5, 10, roots[4], roots[10], cpath))
        self.assertFalse(verify_consistency_proof(5, 10, roots[5], roots[9], cpath))
        self.assertFalse(verify_consistency_proof(6, 5, roots[6], roots[5], []))
        self.assertFalse(verify_consistency_proof(-1, 5, roots[0], roots[5], []))
        self.assertFalse(verify_consistency_proof(True, 5, roots[1], roots[5], []))  # type: ignore[arg-type]
        self.assertFalse(verify_consistency_proof(0, 5, "0" * 64, roots[5], []))
        self.assertFalse(verify_consistency_proof(5, 5, roots[5], roots[5], [roots[5]]))
        self.assertFalse(verify_consistency_proof(5, 10, roots[5], roots[10], []))

    def test_transparency_receipt_roundtrip_and_tamper_rejection(self) -> None:
        acc = Rfc6962MerkleAccumulator()
        build_transparency_receipt(acc, {"endpoint_id": "W01", "epoch_min": 0})
        rcpt = build_transparency_receipt(acc, {"endpoint_id": "W02", "epoch_min": 5, "val": -0.0})

        ok = verify_transparency_receipt(rcpt, expected_root_hex=rcpt["merkle_root_sha256"], expected_tree_size=2)
        self.assertTrue(ok["verified"])

        tampered = json.loads(json.dumps(rcpt))
        tampered["event"]["epoch_min"] = 99
        self.assertFalse(verify_transparency_receipt(tampered)["verified"])

        bad_size = verify_transparency_receipt(rcpt, expected_tree_size=3)
        self.assertFalse(bad_size["verified"])
        self.assertEqual(bad_size["reason"], "EXPECTED_TREE_SIZE_MISMATCH")

        bad_bool = json.loads(json.dumps(rcpt))
        bad_bool["leaf_index"] = True
        self.assertFalse(verify_transparency_receipt(bad_bool)["verified"])

        bad_schema = json.loads(json.dumps(rcpt))
        bad_schema["schema"] = "wrong-schema"
        self.assertFalse(verify_transparency_receipt(bad_schema)["verified"])


class CliEdgeMirrorAndDeployTests(unittest.TestCase):
    def test_sarif_v210_rules_dw_drift_001_to_005(self) -> None:
        self.assertEqual(
            sorted(SARIF_RULES.keys()),
            ["DW-DRIFT-001", "DW-DRIFT-002", "DW-DRIFT-003", "DW-DRIFT-004", "DW-DRIFT-005"],
        )
        alerts = [
            {
                "endpoint_id": "W01",
                "epoch_min": 120,
                "rule_ids": ["DW-DRIFT-001", "DW-DRIFT-002", "DW-DRIFT-004", "DW-DRIFT-005"],
                "reasons": ["SCHEMA_FIELD_REMOVED:items", "BILLING_WALL_ADDED"],
                "receipt": {"merkle_root_sha256": "a" * 64},
            }
        ]
        sarif = build_sarif_v210_report(alerts)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(len(run["tool"]["driver"]["rules"]), 5)
        self.assertEqual(len(run["results"]), 4)
        self.assertEqual(run["results"][0]["properties"]["merkle_root_sha256"], "a" * 64)

    def test_cli_scan_and_verify_receipt_end_to_end(self) -> None:
        trace_doc = {
            "endpoints": [
                {
                    "endpoint_id": "W01",
                    "corroboration_window": 4,
                    "ticks": [
                        {"epoch_min": 0, "http_status": 200, "residual_bps": 0, "etag": '"v1"'},
                        {"epoch_min": 5, "http_status": 429, "residual_bps": 9000},
                        {"epoch_min": 10, "http_status": 429, "residual_bps": 9000},
                        {"epoch_min": 15, "http_status": 429, "residual_bps": 9000},
                        {"epoch_min": 20, "http_status": 429, "residual_bps": 9000},
                    ],
                }
            ]
        }
        report = scan_trace_document(trace_doc)
        self.assertEqual(report["alerts_count"], 1)
        self.assertEqual(report["merkle_tree_size"], 1)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            trace_path = tmp / "trace.json"
            sarif_path = tmp / "out.sarif.json"
            rcpt_path = tmp / "receipt.json"
            trace_path.write_text(json.dumps(trace_doc), encoding="utf-8")

            buf_out = io.StringIO()
            with contextlib.redirect_stdout(buf_out):
                rc_scan = cli_main(
                    [
                        "scan",
                        str(trace_path),
                        "--sarif-out",
                        str(sarif_path),
                        "--receipt-out",
                        str(rcpt_path),
                        "--fail-on-drift",
                    ]
                )
            self.assertEqual(rc_scan, 1)
            scan_summary = json.loads(buf_out.getvalue())
            self.assertEqual(scan_summary["alerts_count"], 1)
            self.assertTrue(sarif_path.is_file())
            self.assertTrue(rcpt_path.is_file())

            buf_ver = io.StringIO()
            with contextlib.redirect_stdout(buf_ver):
                rc_verify = cli_main(
                    [
                        "verify-receipt",
                        str(rcpt_path),
                        "--expected-root",
                        report["merkle_root_sha256"],
                        "--expected-tree-size",
                        "1",
                    ]
                )
            self.assertEqual(rc_verify, 0)
            self.assertTrue(json.loads(buf_ver.getvalue())["verified"])

    def test_cli_clean_trace_and_fail_closed_errors(self) -> None:
        clean_doc = {
            "endpoints": [
                {
                    "endpoint_id": "W99",
                    "ticks": [
                        {"epoch_min": 0, "http_status": 200, "residual_bps": 0, "etag": '"v1"'},
                        {"epoch_min": 5, "http_status": 304, "residual_bps": 50, "etag": '"v1"'},
                    ],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            clean_path = tmp / "clean.json"
            clean_path.write_text(json.dumps(clean_doc), encoding="utf-8")
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli_main(["scan", str(clean_path), "--fail-on-drift"]), 0)
                self.assertEqual(cli_main(["scan", str(tmp / "missing.json")]), 2)
                bad_rcpt = tmp / "bad_receipt.json"
                bad_rcpt.write_text('{"schema":"bad"}', encoding="utf-8")
                self.assertEqual(cli_main(["verify-receipt", str(bad_rcpt)]), 2)

    def test_edge_mirror_zero_table_scans_and_observability_shield(self) -> None:
        store = edge_mirror.DriftWatchMirrorStore()
        audit = store.verify_zero_table_scans()
        self.assertTrue(audit["zero_full_table_scans"])
        self.assertEqual(audit["full_table_scan_count"], 0)
        self.assertTrue(audit["uses_cold_start_partial_index"])
        self.assertTrue(audit["uses_active_due_covering_index"])

        shield = edge_mirror.parse_observability_shield()
        self.assertTrue(shield["shield_compliant"])
        self.assertEqual(shield["workers_ai_mode"], "DETERMINISTIC_REGEX_ONLY")
        self.assertIs(shield["invocation_logs"], False)
        self.assertIs(shield["traces_enabled"], False)

        self.assertEqual(edge_mirror.resolve_bind_host({}), "127.0.0.1")
        self.assertEqual(edge_mirror.resolve_bind_host({"K_SERVICE": "dw-edge"}), "0.0.0.0")
        self.assertEqual(edge_mirror.resolve_bind_host({"BIND_HOST": "127.0.0.2"}), "127.0.0.2")

    def test_edge_mirror_wsgi_endpoints_and_security_headers(self) -> None:
        app = edge_mirror.create_wsgi_app()

        status, hdrs, body = _invoke_wsgi(app, "GET", "/")
        self.assertEqual(status, "200 OK")
        self.assertIn("text/html", hdrs["content-type"])
        self.assertEqual(hdrs["x-frame-options"], "DENY")
        self.assertEqual(hdrs["x-content-type-options"], "nosniff")
        self.assertIn("sha256-", hdrs["content-security-policy"])
        self.assertIn(b"Drift-Watch v4.0.0", body)

        status_j, hdrs_j, body_j = _invoke_wsgi(app, "GET", "/health")
        self.assertEqual(status_j, "200 OK")
        payload = json.loads(body_j.decode("utf-8"))
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["active_targets"], 20)
        self.assertEqual(payload["unique_weyl_offsets"], 20)
        self.assertTrue(payload["zero_full_table_scans"])
        self.assertEqual(payload["cash_overage_usd"], "0.0000 USD")
        self.assertEqual(hdrs_j["content-security-policy"], edge_mirror.STRICT_JSON_CSP3)

        status_hz, _, _ = _invoke_wsgi(app, "GET", "/healthz")
        self.assertEqual(status_hz, "200 OK")

        status_head, hdrs_head, body_head = _invoke_wsgi(app, "HEAD", "/health")
        self.assertEqual(status_head, "200 OK")
        self.assertEqual(body_head, b"")
        self.assertEqual(int(hdrs_head["content-length"]), len(body_j))

        status_tel, _, body_tel = _invoke_wsgi(app, "GET", "/telemetry/24h")
        self.assertEqual(status_tel, "200 OK")
        self.assertIn("hours", json.loads(body_tel.decode("utf-8")))

        status_405, _, _ = _invoke_wsgi(app, "POST", "/health")
        self.assertEqual(status_405, "405 Method Not Allowed")

        status_404, _, _ = _invoke_wsgi(app, "GET", "/nonexistent")
        self.assertEqual(status_404, "404 Not Found")

    def test_deploy_cloudflare_dry_run_and_uuid_validation(self) -> None:
        test_uuid = "11111111-2222-4333-8444-555555555555"
        rendered = deploy_cloudflare.render_ephemeral_wrangler_toml(
            REPO_ROOT / "wrangler.toml", test_uuid
        )
        self.assertIn(f'database_id = "{test_uuid}"', rendered)
        with self.assertRaises(ValueError):
            deploy_cloudflare.render_ephemeral_wrangler_toml(
                REPO_ROOT / "wrangler.toml", "not-a-uuid"
            )
        with tempfile.TemporaryDirectory() as tmpdir:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts" / "deploy_cloudflare.py"),
                    "--dry-run",
                    "--outdir",
                    tmpdir,
                ],
                cwd=str(REPO_ROOT),
                text=True,
                capture_output=True,
                check=True,
            )
            res = json.loads(proc.stdout)
            self.assertTrue(res["dry_run"])
            self.assertEqual(res["status"], "validated")
            self.assertTrue((pathlib.Path(tmpdir) / "wrangler.generated.toml").is_file())
            self.assertTrue((pathlib.Path(tmpdir) / "cf_drift_watch_v4.ts").is_file())

    def test_cli_scan_trace_rejects_bool_float_and_non_mapping_fields_fail_closed(self) -> None:
        from drift_watch.cli import scan_trace_document

        bad_docs = [
            {
                "endpoints": [
                    {
                        "endpoint_id": "ep-bool-corr",
                        "corroboration_window": True,
                        "ticks": [{"epoch_min": 0, "http_status": 200, "residual_bps": 0}],
                    }
                ]
            },
            {
                "endpoints": [
                    {
                        "endpoint_id": "ep-bool-res",
                        "ticks": [{"epoch_min": 0, "http_status": 200, "residual_bps": True}],
                    }
                ]
            },
            {
                "endpoints": [
                    {
                        "endpoint_id": "ep-float-status",
                        "ticks": [{"epoch_min": 0, "http_status": 200.9, "residual_bps": 0}],
                    }
                ]
            },
            {
                "endpoints": [
                    {
                        "endpoint_id": "ep-bad-headers",
                        "ticks": [{"epoch_min": 0, "http_status": 200, "residual_bps": 0, "headers": ["not-a-map"]}],
                    }
                ]
            },
        ]
        for bad in bad_docs:
            with self.assertRaises(ValueError):
                scan_trace_document(bad)


if __name__ == "__main__":
    unittest.main()
