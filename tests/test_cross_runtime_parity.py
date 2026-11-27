# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""Cross-runtime bit-exact parity tests between Python src/drift_watch and Node.js WebCrypto Worker."""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Dict, List
from urllib.request import pathname2url

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
WORKER_TS_PATH = REPO_ROOT / "worker" / "cf_drift_watch_v4.ts"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from drift_watch import (  # noqa: E402
    EMPTY_TREE_SHA256_HEX,
    MAX_SAFE_JCS_INT,
    MINUTES_PER_SLOT,
    WEYL_DEFAULT_INVERSE,
    WEYL_DEFAULT_MODULUS,
    WEYL_DEFAULT_OFFSET,
    WEYL_DEFAULT_STEP,
    WORKERS_AI_MODE,
    PageHinkleyDetector,
    Rfc6962MerkleAccumulator,
    TwoSidedCusumDetector,
    __version__,
    assert_zero_neuron_cliff_guard,
    bezout_modular_inverse,
    jcs_canonical_bytes,
    jcs_canonical_str,
    rfc6962_leaf_hash,
    rfc6962_node_hash,
    trunc_div,
    verify_consistency_proof,
    verify_inclusion_proof,
    weyl_minute_offset,
    weyl_slot,
)


def _strip_ts_for_legacy_node(ts_source: str) -> str:
    """Minimal fallback TypeScript-to-ESM stripper only used if Node < 22.6 lacks strip-types."""
    cleaned = re.sub(r"export\s+interface\s+\w+\s*\{[\s\S]*?\}\n", "", ts_source)
    cleaned = re.sub(r"\bpublic\s+readonly\s+", "", cleaned)
    cleaned = re.sub(r"\b(?:public|private|readonly)\s+", "", cleaned)
    cleaned = re.sub(r":\s*\"NONE\"\s*\|\s*\"UP\"\s*\|\s*\"DOWN\"", "", cleaned)
    cleaned = re.sub(r"\??:\s*(?:D1Database|D1PreparedStatement|Env|CusumStepResult|PageHinkleyStepResult|Request|Response|Uint8Array\[\]|Uint8Array|Record<[^>]+>|Map<[^>]+>|Array<[^>]+>|Promise<[^>]+>|string\[\]|number\[\]|number|string|boolean|unknown|void)(?:\s*\|\s*(?:null|undefined))*", "", cleaned)
    cleaned = re.sub(r"\)\s*:\s*[A-Za-z0-9_<>,\[\]|\"'\s]+\{", ") {", cleaned)
    cleaned = re.sub(r"\s+as\s+[A-Za-z0-9_<>,\[\]|\"'\s]+", "", cleaned)
    return cleaned


_NODE_DRIVER_JS = r"""
import { pathToFileURL } from "node:url";

const workerUrl = process.env.DW_WORKER_URL;
const inputPayload = JSON.parse(process.env.DW_PARITY_INPUT || "{}");
const mod = await import(workerUrl);

async function expectThrowsAsync(fn) {
  try {
    await fn();
    return false;
  } catch (_err) {
    return true;
  }
}

function expectThrowsSync(fn) {
  try {
    fn();
    return false;
  } catch (_err) {
    return true;
  }
}

const cusumDet = new mod.TwoSidedCusumDetector(0, 1200, 4800);
const cusumNoReset = [];
for (const x of inputPayload.cusumSeries) {
  cusumNoReset.push(cusumDet.update(x, false));
}

const cusumResetDet = new mod.TwoSidedCusumDetector(0, 1000, 3000);
const cusumWithReset = [];
for (const x of inputPayload.cusumSeries) {
  cusumWithReset.push(cusumResetDet.update(x, true));
}

const phDet = new mod.PageHinkleyDetector(350, 5200, 6);
const phNoReset = [];
for (const x of inputPayload.phSeries) {
  phNoReset.push(phDet.update(x, false));
}

const phResetDet = new mod.PageHinkleyDetector(200, 2500, 4);
const phWithReset = [];
for (const x of inputPayload.phSeries) {
  phWithReset.push(phResetDet.update(x, true));
}

const acc = new mod.Rfc6962MerkleAccumulator();
const merkleAppendResults = [];
for (const ev of inputPayload.events) {
  const jcsBytes = mod.jcsCanonicalBytes(ev);
  const res = await acc.appendBytes(jcsBytes);
  merkleAppendResults.push({
    leafIndex: res.leafIndex,
    leafHashHex: res.leafHashHex,
    rootHex: res.rootHex,
    jcsStr: mod.jcsCanonicalStr(ev),
  });
}

const historicalRoots = [];
for (let sz = 0; sz <= acc.size; sz += 1) {
  historicalRoots.push(mod.bytesToHex(await acc.rootHash(sz)));
}

const tsInclusionProofs = [];
for (const [idx, sz] of inputPayload.inclusionQueries) {
  tsInclusionProofs.push({
    idx,
    sz,
    proof: await acc.inclusionProof(idx, sz),
  });
}

const tsConsistencyProofs = [];
for (const [f, s] of inputPayload.consistencyQueries) {
  tsConsistencyProofs.push({
    f,
    s,
    proof: await acc.consistencyProof(f, s),
  });
}

const pyInclusionCheckResults = [];
for (const q of inputPayload.pyInclusionChecks) {
  const ok = await mod.verifyInclusionProof(
    mod.jcsCanonicalBytes(q.event),
    q.idx,
    q.sz,
    q.proof,
    q.rootHex,
  );
  pyInclusionCheckResults.push(ok);
}

const pyConsistencyCheckResults = [];
for (const q of inputPayload.pyConsistencyChecks) {
  const ok = await mod.verifyConsistencyProof(
    q.f,
    q.s,
    q.firstRootHex,
    q.secondRootHex,
    q.proof,
  );
  pyConsistencyCheckResults.push(ok);
}

const leafA = await mod.rfc6962LeafHash(new TextEncoder().encode("alpha"));
const leafB = await mod.rfc6962LeafHash(new TextEncoder().encode("beta"));
const nodeAB = await mod.rfc6962NodeHash(leafA, leafB);
const emptySha = mod.bytesToHex(await mod.sha256Bytes(new Uint8Array(0)));

const worker = mod.default;
const rHealth = await worker.fetch(new Request("https://drift-watch.example/health", { method: "GET" }), {});
const rHealthBody = await rHealth.json();
const rHead = await worker.fetch(new Request("https://drift-watch.example/healthz", { method: "HEAD" }), {});
const rHeadText = await rHead.text();
const rPost = await worker.fetch(new Request("https://drift-watch.example/health", { method: "POST" }), {});
const r404 = await worker.fetch(new Request("https://drift-watch.example/missing", { method: "GET" }), {});
const cliffBlockedInFetch = await expectThrowsAsync(() =>
  worker.fetch(new Request("https://drift-watch.example/health"), { WORKERS_AI_MODE: "WORKERS_AI_LLM" }),
);

const out = {
  constants: {
    VERSION: mod.VERSION,
    WEYL_DEFAULT_MODULUS: mod.WEYL_DEFAULT_MODULUS,
    WEYL_DEFAULT_STEP: mod.WEYL_DEFAULT_STEP,
    WEYL_DEFAULT_INVERSE: mod.WEYL_DEFAULT_INVERSE,
    WEYL_DEFAULT_OFFSET: mod.WEYL_DEFAULT_OFFSET,
    MINUTES_PER_SLOT: mod.MINUTES_PER_SLOT,
    WORKERS_AI_MODE_DEFAULT: mod.WORKERS_AI_MODE_DEFAULT,
  },
  weyl288Slots: Array.from({ length: 288 }, (_, i) => mod.weylSlot(i)),
  weyl288Minutes: Array.from({ length: 288 }, (_, i) => mod.weylMinuteOffset(i)),
  weyl1440Sample: Array.from({ length: 50 }, (_, i) => mod.weylSlot(i, 1440, 839, 7)),
  weylRejects: {
    nonCoprime: expectThrowsSync(() => mod.assertCoprimeWeyl(168, 288)),
    negIdx: expectThrowsSync(() => mod.weylSlot(-1)),
    floatIdx: expectThrowsSync(() => mod.weylSlot(1.5)),
    boolIdx: expectThrowsSync(() => mod.weylSlot(true)),
    cliffBadMode: expectThrowsSync(() => mod.assertZeroNeuronCliffGuard("WORKERS_AI_LLM", 0)),
    cliffBadBudget: expectThrowsSync(() => mod.assertZeroNeuronCliffGuard(mod.WORKERS_AI_MODE_DEFAULT, 1)),
  },
  truncDivResults: inputPayload.truncDivPairs.map(([a, b]) => mod.truncDiv(a, b)),
  truncDivZeroRejected: expectThrowsSync(() => mod.truncDiv(5, 0)),
  cusumNoReset,
  cusumWithReset,
  phNoReset,
  phWithReset,
  jcsSamples: inputPayload.jcsValues.map((v) => mod.jcsCanonicalStr(v)),
  jcsMinusZero: mod.jcsCanonicalStr(-0),
  jcsRejects: {
    nan: expectThrowsSync(() => mod.jcsCanonicalStr(Number.NaN)),
    inf: expectThrowsSync(() => mod.jcsCanonicalStr(Number.POSITIVE_INFINITY)),
    loneSurrogate: expectThrowsSync(() => mod.jcsCanonicalStr(String.fromCharCode(0xd800))),
    loneSurrogateKey: expectThrowsSync(() => {
      const obj = {};
      obj[String.fromCharCode(0xdfff)] = 1;
      return mod.jcsCanonicalStr(obj);
    }),
  },
  emptySha,
  leafAHex: mod.bytesToHex(leafA),
  nodeABHex: mod.bytesToHex(nodeAB),
  merkleAppendResults,
  historicalRoots,
  tsInclusionProofs,
  tsConsistencyProofs,
  pyInclusionCheckResults,
  pyConsistencyCheckResults,
  tsProofFailClosed: {
    consistencyNullPath: await mod.verifyConsistencyProof(1, 2, "a".repeat(64), "b".repeat(64), null),
    consistencyUnsafeInt: await mod.verifyConsistencyProof(1, Number.MAX_SAFE_INTEGER + 1, "a".repeat(64), "b".repeat(64), ["c".repeat(64)]),
    inclusionBadLeaf: await mod.verifyInclusionProof("not-bytes", 0, 1, [], "a".repeat(64)),
    inclusionUnsafeSize: await mod.verifyInclusionProof(new Uint8Array([1]), 0, Number.MAX_SAFE_INTEGER + 1, [], "a".repeat(64)),
  },
  workerHttp: {
    healthStatus: rHealth.status,
    healthBody: rHealthBody,
    healthCsp: rHealth.headers.get("Content-Security-Policy"),
    healthNosniff: rHealth.headers.get("X-Content-Type-Options"),
    headStatus: rHead.status,
    headBodyLen: rHeadText.length,
    postStatus: rPost.status,
    notFoundStatus: r404.status,
    cliffBlockedInFetch,
  },
};

process.stdout.write(JSON.stringify(out));
"""


def _build_test_vectors() -> Dict[str, Any]:
    cusum_series = [0, 1200, -1200, 2800, 2900, 3200, 0, -500, -3100, -3200, -3500, 100]
    ph_series = [0, 100, -100, 50, -50, 0, 2200, 2400, 2600, 2800, -2500, -2700, -2900, -3100]
    trunc_div_pairs = [
        [7, 3],
        [-7, 3],
        [7, -3],
        [-7, -3],
        [0, 5],
        [-1, 2],
        [1, -2],
        [10000, -333],
    ]
    jcs_values: List[Any] = [
        None,
        True,
        False,
        0,
        -0.0,
        1,
        -42,
        MAX_SAFE_JCS_INT,
        -MAX_SAFE_JCS_INT,
        1e20,
        1e21,
        1e-6,
        0.00001,
        3.141592653589793,
        "",
        'hello\b\t\n\f\r"\\\x01world',
        "Istanbul-caf\u00e9-\U0001f680",
        {"10": 1, "2": 2, "1": 3, "\uffff": "high", "\U00010000": "astral"},
        [1, {"b": [True, False, None], "a": -0.0}],
    ]
    events = [
        {
            "version": "4.0.0",
            "endpoint_id": f"W{i + 1:02d}",
            "epoch_min": 29_932_000 + i * 5,
            "http_status": 200 if i % 3 == 0 else 429,
            "rule_ids": ["DW-DRIFT-003"] if i % 2 == 0 else ["DW-DRIFT-001", "DW-DRIFT-002"],
            "cusum_pos_bps": i * 310,
            "cusum_neg_bps": 0,
            "nested": {"10": i, "2": -0.0, "tag": f"node-{i}"},
        }
        for i in range(25)
    ]
    inclusion_queries = [[0, 1], [0, 5], [3, 7], [7, 8], [12, 25], [24, 25]]
    consistency_queries = [[0, 0], [0, 7], [1, 1], [1, 8], [2, 5], [4, 25], [7, 25], [16, 25]]

    py_acc = Rfc6962MerkleAccumulator()
    py_roots = [EMPTY_TREE_SHA256_HEX]
    for ev in events:
        _, _, root_hex, _ = py_acc.append_jcs(ev)
        py_roots.append(root_hex)

    py_inc_checks = [
        {
            "event": events[idx],
            "idx": idx,
            "sz": sz,
            "proof": py_acc.inclusion_proof(idx, sz),
            "rootHex": py_roots[sz],
        }
        for idx, sz in inclusion_queries
    ]
    py_cons_checks = [
        {
            "f": f,
            "s": s,
            "firstRootHex": py_roots[f],
            "secondRootHex": py_roots[s],
            "proof": py_acc.consistency_proof(f, s),
        }
        for f, s in consistency_queries
    ]

    return {
        "cusumSeries": cusum_series,
        "phSeries": ph_series,
        "truncDivPairs": trunc_div_pairs,
        "jcsValues": jcs_values,
        "events": events,
        "inclusionQueries": inclusion_queries,
        "consistencyQueries": consistency_queries,
        "pyInclusionChecks": py_inc_checks,
        "pyConsistencyChecks": py_cons_checks,
        "pyRoots": py_roots,
    }


def _execute_node_parity(payload: Dict[str, Any]) -> Dict[str, Any]:
    node_bin = shutil.which("node")
    if not node_bin:
        raise RuntimeError("Node.js binary not found on PATH; cross-runtime parity requires Node.js")
    if not WORKER_TS_PATH.is_file():
        raise FileNotFoundError(f"Missing TypeScript worker: {WORKER_TS_PATH}")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        driver_path = tmp / "parity_driver.mjs"
        driver_path.write_text(_NODE_DRIVER_JS, encoding="utf-8")

        env_base = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "DW_WORKER_URL": "file://" + pathname2url(str(WORKER_TS_PATH)),
            "DW_PARITY_INPUT": json.dumps(payload),
        }
        import os

        merged_env = dict(os.environ)
        merged_env.update(env_base)

        proc = subprocess.run(
            [node_bin, "--no-warnings", "--experimental-strip-types", str(driver_path)],
            cwd=str(REPO_ROOT),
            env=merged_env,
            text=True,
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            stripped_path = tmp / "cf_drift_watch_v4.mjs"
            stripped_path.write_text(
                _strip_ts_for_legacy_node(WORKER_TS_PATH.read_text(encoding="utf-8")),
                encoding="utf-8",
            )
            merged_env["DW_WORKER_URL"] = "file://" + pathname2url(str(stripped_path))
            proc = subprocess.run(
                [node_bin, "--no-warnings", str(driver_path)],
                cwd=str(REPO_ROOT),
                env=merged_env,
                text=True,
                capture_output=True,
                check=False,
            )
        if proc.returncode != 0:
            raise RuntimeError(
                f"Node parity runner failed (rc={proc.returncode}): {proc.stderr or proc.stdout}"
            )
        return json.loads(proc.stdout)


class CrossRuntimeParityTests(unittest.TestCase):
    vectors: Dict[str, Any]
    node_out: Dict[str, Any]

    @classmethod
    def setUpClass(cls) -> None:
        cls.vectors = _build_test_vectors()
        cls.node_out = _execute_node_parity(cls.vectors)

    def test_constants_and_version_parity(self) -> None:
        c = self.node_out["constants"]
        self.assertEqual(c["VERSION"], __version__)
        self.assertEqual(c["WEYL_DEFAULT_MODULUS"], WEYL_DEFAULT_MODULUS)
        self.assertEqual(c["WEYL_DEFAULT_STEP"], WEYL_DEFAULT_STEP)
        self.assertEqual(c["WEYL_DEFAULT_INVERSE"], WEYL_DEFAULT_INVERSE)
        self.assertEqual(c["WEYL_DEFAULT_OFFSET"], WEYL_DEFAULT_OFFSET)
        self.assertEqual(c["MINUTES_PER_SLOT"], MINUTES_PER_SLOT)
        self.assertEqual(c["WORKERS_AI_MODE_DEFAULT"], WORKERS_AI_MODE)

    def test_weyl_slot_and_minute_offset_288_parity(self) -> None:
        py_slots = [weyl_slot(i) for i in range(288)]
        py_mins = [weyl_minute_offset(i) for i in range(288)]
        self.assertEqual(self.node_out["weyl288Slots"], py_slots)
        self.assertEqual(self.node_out["weyl288Minutes"], py_mins)

    def test_weyl_non_default_modulus_1440_parity(self) -> None:
        py_1440 = [weyl_slot(i, modulus=1440, step=839, offset=7) for i in range(50)]
        self.assertEqual(self.node_out["weyl1440Sample"], py_1440)

    def test_weyl_coprime_and_input_validation_parity(self) -> None:
        rej = self.node_out["weylRejects"]
        self.assertTrue(rej["nonCoprime"])
        self.assertTrue(rej["negIdx"])
        self.assertTrue(rej["floatIdx"])
        self.assertTrue(rej["boolIdx"])
        with self.assertRaises(ValueError):
            bezout_modular_inverse(168, 288)
        with self.assertRaises(ValueError):
            weyl_slot(-1)
        with self.assertRaises(TypeError):
            weyl_slot(True)  # type: ignore[arg-type]

    def test_workers_ai_cliff_guard_parity(self) -> None:
        rej = self.node_out["weylRejects"]
        self.assertTrue(rej["cliffBadMode"])
        self.assertTrue(rej["cliffBadBudget"])
        with self.assertRaises(ValueError):
            assert_zero_neuron_cliff_guard("WORKERS_AI_LLM", 0)
        with self.assertRaises(ValueError):
            assert_zero_neuron_cliff_guard(WORKERS_AI_MODE, 1)

    def test_trunc_div_signed_parity(self) -> None:
        py_res = [trunc_div(a, b) for a, b in self.vectors["truncDivPairs"]]
        self.assertEqual(self.node_out["truncDivResults"], py_res)
        self.assertTrue(self.node_out["truncDivZeroRejected"])
        with self.assertRaises(ZeroDivisionError):
            trunc_div(5, 0)

    def test_two_sided_cusum_trajectory_parity(self) -> None:
        det_no = TwoSidedCusumDetector(mu0_bps=0, k_slack_bps=1200, h_thresh_bps=4800)
        det_rst = TwoSidedCusumDetector(mu0_bps=0, k_slack_bps=1000, h_thresh_bps=3000)
        for idx, x in enumerate(self.vectors["cusumSeries"]):
            p_no = det_no.update(x, reset_on_alarm=False)
            n_no = self.node_out["cusumNoReset"][idx]
            self.assertEqual(n_no["sPosBps"], p_no["s_pos_bps"])
            self.assertEqual(n_no["sNegBps"], p_no["s_neg_bps"])
            self.assertEqual(n_no["alarm"], p_no["alarm"])
            self.assertEqual(n_no["direction"], p_no["direction"])
            self.assertEqual(n_no["steps"], p_no["steps"])

            p_rst = det_rst.update(x, reset_on_alarm=True)
            n_rst = self.node_out["cusumWithReset"][idx]
            self.assertEqual(n_rst["sPosBps"], p_rst["s_pos_bps"])
            self.assertEqual(n_rst["sNegBps"], p_rst["s_neg_bps"])
            self.assertEqual(n_rst["alarm"], p_rst["alarm"])
            self.assertEqual(n_rst["direction"], p_rst["direction"])

    def test_page_hinkley_trajectory_parity(self) -> None:
        ph_no = PageHinkleyDetector(delta_bps=350, lambda_thresh_bps=5200, min_warmup=6)
        ph_rst = PageHinkleyDetector(delta_bps=200, lambda_thresh_bps=2500, min_warmup=4)
        for idx, x in enumerate(self.vectors["phSeries"]):
            p_no = ph_no.update(x, reset_on_alarm=False)
            n_no = self.node_out["phNoReset"][idx]
            self.assertEqual(n_no["meanBps"], p_no["mean_bps"])
            self.assertEqual(n_no["phPosBps"], p_no["ph_pos_bps"])
            self.assertEqual(n_no["phNegBps"], p_no["ph_neg_bps"])
            self.assertEqual(n_no["alarm"], p_no["alarm"])
            self.assertEqual(n_no["direction"], p_no["direction"])
            self.assertEqual(n_no["count"], p_no["count"])

            p_rst = ph_rst.update(x, reset_on_alarm=True)
            n_rst = self.node_out["phWithReset"][idx]
            self.assertEqual(n_rst["meanBps"], p_rst["mean_bps"])
            self.assertEqual(n_rst["phPosBps"], p_rst["ph_pos_bps"])
            self.assertEqual(n_rst["phNegBps"], p_rst["ph_neg_bps"])
            self.assertEqual(n_rst["alarm"], p_rst["alarm"])
            self.assertEqual(n_rst["direction"], p_rst["direction"])

    def test_jcs_numbers_minus_zero_and_boundary_parity(self) -> None:
        self.assertEqual(self.node_out["jcsMinusZero"], jcs_canonical_str(-0.0))
        self.assertEqual(self.node_out["jcsMinusZero"], "0")
        for idx, val in enumerate(self.vectors["jcsValues"]):
            self.assertEqual(self.node_out["jcsSamples"][idx], jcs_canonical_str(val))

    def test_jcs_error_rejection_parity(self) -> None:
        rej = self.node_out["jcsRejects"]
        self.assertTrue(rej["nan"])
        self.assertTrue(rej["inf"])
        self.assertTrue(rej["loneSurrogate"])
        self.assertTrue(rej["loneSurrogateKey"])
        with self.assertRaises(ValueError):
            jcs_canonical_str(float("nan"))
        with self.assertRaises(ValueError):
            jcs_canonical_str("\ud800")

    def test_rfc6962_leaf_and_node_hash_webcrypto_parity(self) -> None:
        self.assertEqual(self.node_out["emptySha"], EMPTY_TREE_SHA256_HEX)
        la = rfc6962_leaf_hash(b"alpha")
        lb = rfc6962_leaf_hash(b"beta")
        nab = rfc6962_node_hash(la, lb)
        self.assertEqual(self.node_out["leafAHex"], la.hex())
        self.assertEqual(self.node_out["nodeABHex"], nab.hex())

    def test_rfc6962_merkle_root_parity_sizes_1_to_25(self) -> None:
        acc = Rfc6962MerkleAccumulator()
        for idx, ev in enumerate(self.vectors["events"]):
            p_idx, p_lh, p_root, p_raw = acc.append_jcs(ev)
            n_row = self.node_out["merkleAppendResults"][idx]
            self.assertEqual(n_row["leafIndex"], p_idx)
            self.assertEqual(n_row["jcsStr"], p_raw.decode("utf-8"))
            self.assertEqual(n_row["leafHashHex"], p_lh)
            self.assertEqual(n_row["rootHex"], p_root)
        self.assertEqual(self.node_out["historicalRoots"], self.vectors["pyRoots"])

    def test_rfc6962_cross_verified_inclusion_proofs(self) -> None:
        # TypeScript-generated proofs verified offline in Python
        for item in self.node_out["tsInclusionProofs"]:
            idx = item["idx"]
            sz = item["sz"]
            raw = jcs_canonical_bytes(self.vectors["events"][idx])
            self.assertTrue(
                verify_inclusion_proof(raw, idx, sz, item["proof"], self.vectors["pyRoots"][sz])
            )
        # Python-generated proofs verified offline in TypeScript WebCrypto
        self.assertEqual(
            self.node_out["pyInclusionCheckResults"],
            [True] * len(self.vectors["pyInclusionChecks"]),
        )

    def test_rfc6962_cross_verified_consistency_proofs(self) -> None:
        # TypeScript-generated consistency proofs verified offline in Python
        for item in self.node_out["tsConsistencyProofs"]:
            f = item["f"]
            s = item["s"]
            self.assertTrue(
                verify_consistency_proof(
                    f,
                    s,
                    self.vectors["pyRoots"][f],
                    self.vectors["pyRoots"][s],
                    item["proof"],
                )
            )
        # Python-generated consistency proofs verified offline in TypeScript WebCrypto
        self.assertEqual(
            self.node_out["pyConsistencyCheckResults"],
            [True] * len(self.vectors["pyConsistencyChecks"]),
        )

    def test_worker_fetch_http_routes_and_security_headers(self) -> None:
        http = self.node_out["workerHttp"]
        self.assertEqual(http["healthStatus"], 200)
        self.assertEqual(http["healthBody"]["status"], "ok")
        self.assertEqual(http["healthBody"]["version"], __version__)
        self.assertEqual(http["healthBody"]["workersAiMode"], WORKERS_AI_MODE)
        self.assertEqual(http["healthBody"]["weylModulus"], WEYL_DEFAULT_MODULUS)
        self.assertEqual(http["healthBody"]["weylStep"], WEYL_DEFAULT_STEP)
        self.assertEqual(http["healthBody"]["weylStepInverse"], WEYL_DEFAULT_INVERSE)
        self.assertEqual(http["healthBody"]["cashOverage"], "0.0000 USD")
        self.assertEqual(http["healthCsp"], "default-src 'none'; frame-ancestors 'none'")
        self.assertEqual(http["healthNosniff"], "nosniff")
        self.assertEqual(http["headStatus"], 200)
        self.assertEqual(http["headBodyLen"], 0)
        self.assertEqual(http["postStatus"], 405)
        self.assertEqual(http["notFoundStatus"], 404)
        self.assertTrue(http["cliffBlockedInFetch"])

    def test_ts_merkle_verifiers_fail_closed_on_null_bad_leaf_and_unsafe_ints(self) -> None:
        fc = self.node_out["tsProofFailClosed"]
        self.assertIs(fc["consistencyNullPath"], False)
        self.assertIs(fc["consistencyUnsafeInt"], False)
        self.assertIs(fc["inclusionBadLeaf"], False)
        self.assertIs(fc["inclusionUnsafeSize"], False)
        stripped_js = _strip_ts_for_legacy_node(WORKER_TS_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as tmpdir:
            mjs_path = pathlib.Path(tmpdir) / "legacy_check.mjs"
            mjs_path.write_text(stripped_js, encoding="utf-8")
            chk = subprocess.run(["node", "--check", str(mjs_path)], capture_output=True, text=True, check=False)
            self.assertEqual(chk.returncode, 0, msg=chk.stderr)


if __name__ == "__main__":
    unittest.main()
