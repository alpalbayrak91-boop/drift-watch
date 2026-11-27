// SPDX-FileCopyrightText: 2026 Alp Albayrak
// SPDX-License-Identifier: MIT
// Drift-Watch v4.0.0 Cloudflare Workers TypeScript Edge Runtime
// Zero external dependencies; WebCrypto SHA-256 + D1 SQLite 0-SCAN + RFC 8785 JCS + RFC 6962 Merkle Frontier.

export interface D1PreparedStatement {
  bind(...values: unknown[]): D1PreparedStatement;
  first<T = Record<string, unknown>>(): Promise<T | null>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
  run(): Promise<{ success: boolean }>;
}

export interface D1Database {
  prepare(query: string): D1PreparedStatement;
  batch(statements: D1PreparedStatement[]): Promise<unknown[]>;
}

export interface Env {
  DRIFT_DB?: D1Database;
  WORKERS_AI_MODE?: string;
  MAX_TARGETS_PER_TICK?: string;
  CUSUM_K_SLACK_BPS?: string;
  CUSUM_H_THRESH_BPS?: string;
  PH_DELTA_BPS?: string;
  PH_LAMBDA_THRESH_BPS?: string;
}

export interface CusumStepResult {
  sPosBps: number;
  sNegBps: number;
  alarm: boolean;
  direction: "NONE" | "UP" | "DOWN";
  steps: number;
}

export interface PageHinkleyStepResult {
  meanBps: number;
  phPosBps: number;
  phNegBps: number;
  alarm: boolean;
  direction: "NONE" | "UP" | "DOWN";
  count: number;
}

export const VERSION = "4.0.0";
export const WEYL_DEFAULT_MODULUS = 288;
export const WEYL_DEFAULT_STEP = 167;
export const WEYL_DEFAULT_INVERSE = 119;
export const WEYL_DEFAULT_OFFSET = 1;
export const MINUTES_PER_SLOT = 5;
export const WORKERS_AI_MODE_DEFAULT = "DETERMINISTIC_REGEX_ONLY";

export const COLD_START_HEAL_SQL =
  "SELECT target_id, url, period_min, weyl_offset_min, last_etag, last_canon_sha256 " +
  "FROM ( " +
  "  SELECT target_id, url, period_min, weyl_offset_min, last_etag, last_canon_sha256, next_due_epoch_min " +
  "  FROM dw_targets INDEXED BY idx_dw_targets_cold_start " +
  "  WHERE active = 1 AND last_polled_epoch_min = 0 AND next_due_epoch_min > ?1 " +
  "  UNION ALL " +
  "  SELECT target_id, url, period_min, weyl_offset_min, last_etag, last_canon_sha256, next_due_epoch_min " +
  "  FROM dw_targets INDEXED BY idx_dw_targets_active_due " +
  "  WHERE active = 1 AND next_due_epoch_min <= ?2 " +
  ") ORDER BY next_due_epoch_min ASC, target_id ASC LIMIT 4;";

const HEX64_LOWER_RE = /^[0-9a-f]{64}$/;

export function requireStrictInt(value: unknown, name: string): number {
  if (typeof value !== "number" || !Number.isInteger(value) || !Number.isSafeInteger(value)) {
    throw new TypeError("STRICT_SAFE_INT_REQUIRED:" + name);
  }
  return value;
}

export function gcdInt(a: number, b: number): number {
  let x = Math.abs(requireStrictInt(a, "a"));
  let y = Math.abs(requireStrictInt(b, "b"));
  while (y !== 0) {
    const t = x % y;
    x = y;
    y = t;
  }
  return x;
}

export function assertCoprimeWeyl(step: number, modulus: number): void {
  const s = requireStrictInt(step, "step");
  const m = requireStrictInt(modulus, "modulus");
  if (m < 2 || s <= 0) {
    throw new RangeError("INVALID_WEYL_PARAMETERS");
  }
  if (gcdInt(s, m) !== 1) {
    throw new RangeError("NON_COPRIME_WEYL_STEP");
  }
}

export function weylSlot(
  idx: number,
  modulus: number = WEYL_DEFAULT_MODULUS,
  step: number = WEYL_DEFAULT_STEP,
  offset: number = WEYL_DEFAULT_OFFSET,
): number {
  const i = requireStrictInt(idx, "idx");
  const m = requireStrictInt(modulus, "modulus");
  const s = requireStrictInt(step, "step");
  const o = requireStrictInt(offset, "offset");
  if (i < 0 || o < 0) {
    throw new RangeError("NEGATIVE_WEYL_INPUT");
  }
  assertCoprimeWeyl(s, m);
  return (i * s + o) % m;
}

export function weylMinuteOffset(
  idx: number,
  modulus: number = WEYL_DEFAULT_MODULUS,
  step: number = WEYL_DEFAULT_STEP,
  offset: number = WEYL_DEFAULT_OFFSET,
  slotMinutes: number = MINUTES_PER_SLOT,
): number {
  const sm = requireStrictInt(slotMinutes, "slotMinutes");
  if (sm <= 0) {
    throw new RangeError("INVALID_SLOT_MINUTES");
  }
  return sm * weylSlot(idx, modulus, step, offset);
}

export function assertZeroNeuronCliffGuard(mode: string, neuronBudget: number = 0): void {
  const nb = requireStrictInt(neuronBudget, "neuronBudget");
  if (typeof mode !== "string" || mode !== WORKERS_AI_MODE_DEFAULT || nb !== 0) {
    throw new RangeError("WORKERS_AI_CLIFF_GUARD_BLOCKED");
  }
}

export function truncDiv(num: number, den: number): number {
  const n = requireStrictInt(num, "num");
  const d = requireStrictInt(den, "den");
  if (d === 0) {
    throw new RangeError("TRUNC_DIV_BY_ZERO");
  }
  const res = Math.trunc(n / d);
  return Object.is(res, -0) ? 0 : res;
}

export class TwoSidedCusumDetector {
  public readonly mu0Bps: number;
  public readonly kSlackBps: number;
  public readonly hThreshBps: number;
  public sPosBps = 0;
  public sNegBps = 0;
  public steps = 0;

  constructor(mu0Bps: number = 0, kSlackBps: number = 1200, hThreshBps: number = 4800) {
    this.mu0Bps = requireStrictInt(mu0Bps, "mu0Bps");
    this.kSlackBps = requireStrictInt(kSlackBps, "kSlackBps");
    this.hThreshBps = requireStrictInt(hThreshBps, "hThreshBps");
    if (this.kSlackBps <= 0 || this.hThreshBps <= 0) {
      throw new RangeError("CUSUM_SLACK_AND_THRESHOLD_MUST_BE_POSITIVE");
    }
  }

  public update(xBps: number, resetOnAlarm: boolean = false): CusumStepResult {
    const x = requireStrictInt(xBps, "xBps");
    if (typeof resetOnAlarm !== "boolean") {
      throw new TypeError("RESET_ON_ALARM_BOOL_REQUIRED");
    }
    this.steps += 1;
    const candPos = this.sPosBps + (x - this.mu0Bps - this.kSlackBps);
    const candNeg = this.sNegBps + (this.mu0Bps - x - this.kSlackBps);
    this.sPosBps = candPos > 0 ? candPos : 0;
    this.sNegBps = candNeg > 0 ? candNeg : 0;

    const alarmUp = this.sPosBps >= this.hThreshBps;
    const alarmDown = this.sNegBps >= this.hThreshBps;
    let direction: "NONE" | "UP" | "DOWN" = "NONE";
    if (alarmUp && alarmDown) {
      direction = this.sPosBps >= this.sNegBps ? "UP" : "DOWN";
    } else if (alarmUp) {
      direction = "UP";
    } else if (alarmDown) {
      direction = "DOWN";
    }

    const out: CusumStepResult = {
      sPosBps: this.sPosBps,
      sNegBps: this.sNegBps,
      alarm: alarmUp || alarmDown,
      direction,
      steps: this.steps,
    };
    if (resetOnAlarm && out.alarm) {
      this.sPosBps = 0;
      this.sNegBps = 0;
    }
    return out;
  }
}

export class PageHinkleyDetector {
  public readonly deltaBps: number;
  public readonly lambdaThreshBps: number;
  public readonly minWarmup: number;
  public count = 0;
  public sumXBps = 0;
  public mPosBps = 0;
  public minMPosBps = 0;
  public mNegBps = 0;
  public minMNegBps = 0;

  constructor(deltaBps: number = 350, lambdaThreshBps: number = 5200, minWarmup: number = 6) {
    this.deltaBps = requireStrictInt(deltaBps, "deltaBps");
    this.lambdaThreshBps = requireStrictInt(lambdaThreshBps, "lambdaThreshBps");
    this.minWarmup = requireStrictInt(minWarmup, "minWarmup");
    if (this.deltaBps < 0 || this.lambdaThreshBps <= 0 || this.minWarmup < 1) {
      throw new RangeError("INVALID_PAGE_HINKLEY_PARAMETERS");
    }
  }

  public update(xBps: number, resetOnAlarm: boolean = false): PageHinkleyStepResult {
    const x = requireStrictInt(xBps, "xBps");
    if (typeof resetOnAlarm !== "boolean") {
      throw new TypeError("RESET_ON_ALARM_BOOL_REQUIRED");
    }
    this.count += 1;
    this.sumXBps += x;
    const meanBps = truncDiv(this.sumXBps, this.count);

    this.mPosBps += x - meanBps - this.deltaBps;
    if (this.mPosBps < this.minMPosBps) {
      this.minMPosBps = this.mPosBps;
    }

    this.mNegBps += meanBps - x - this.deltaBps;
    if (this.mNegBps < this.minMNegBps) {
      this.minMNegBps = this.mNegBps;
    }

    const phPosBps = this.mPosBps - this.minMPosBps;
    const phNegBps = this.mNegBps - this.minMNegBps;
    const armed = this.count >= this.minWarmup;
    const alarmUp = armed && phPosBps >= this.lambdaThreshBps;
    const alarmDown = armed && phNegBps >= this.lambdaThreshBps;

    let direction: "NONE" | "UP" | "DOWN" = "NONE";
    if (alarmUp && alarmDown) {
      direction = phPosBps >= phNegBps ? "UP" : "DOWN";
    } else if (alarmUp) {
      direction = "UP";
    } else if (alarmDown) {
      direction = "DOWN";
    }

    const out: PageHinkleyStepResult = {
      meanBps,
      phPosBps,
      phNegBps,
      alarm: alarmUp || alarmDown,
      direction,
      count: this.count,
    };
    if (resetOnAlarm && out.alarm) {
      this.mPosBps = 0;
      this.minMPosBps = 0;
      this.mNegBps = 0;
      this.minMNegBps = 0;
    }
    return out;
  }
}

export function checkWellFormedUtf16(str: string): void {
  for (let i = 0; i < str.length; i += 1) {
    const code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (i + 1 >= str.length) {
        throw new RangeError("JCS_LONE_SURROGATE_REJECTED");
      }
      const next = str.charCodeAt(i + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new RangeError("JCS_LONE_SURROGATE_REJECTED");
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new RangeError("JCS_LONE_SURROGATE_REJECTED");
    }
  }
}

export function jcsCanonicalStr(value: unknown): string {
  if (value === null) {
    return "null";
  }
  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new RangeError("JCS_NON_FINITE_FLOAT");
    }
    if (value === 0) {
      return "0";
    }
    return String(value);
  }
  if (typeof value === "string") {
    checkWellFormedUtf16(value);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const parts: string[] = [];
    for (const item of value) {
      parts.push(jcsCanonicalStr(item));
    }
    return "[" + parts.join(",") + "]";
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) {
      throw new TypeError("JCS_UNSUPPORTED_OBJECT_PROTOTYPE");
    }
    const rec = value as Record<string, unknown>;
    const keys = Object.keys(rec).sort();
    const pairs: string[] = [];
    for (const k of keys) {
      checkWellFormedUtf16(k);
      const v = rec[k];
      if (v === undefined || typeof v === "function" || typeof v === "symbol") {
        throw new TypeError("JCS_UNSUPPORTED_PROPERTY_VALUE");
      }
      pairs.push(JSON.stringify(k) + ":" + jcsCanonicalStr(v));
    }
    return "{" + pairs.join(",") + "}";
  }
  throw new TypeError("JCS_UNSUPPORTED_TYPE:" + typeof value);
}

export function jcsCanonicalBytes(value: unknown): Uint8Array {
  return new TextEncoder().encode(jcsCanonicalStr(value));
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== "string" || hex.length % 2 !== 0 || !/^[0-9a-f]+$/.test(hex)) {
    throw new RangeError("INVALID_LOWERCASE_HEX");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(buf);
}

export async function rfc6962LeafHash(leafBytes: Uint8Array): Promise<Uint8Array> {
  const buf = new Uint8Array(1 + leafBytes.length);
  buf[0] = 0x00;
  buf.set(leafBytes, 1);
  return sha256Bytes(buf);
}

export async function rfc6962NodeHash(left: Uint8Array, right: Uint8Array): Promise<Uint8Array> {
  if (left.length !== 32 || right.length !== 32) {
    throw new RangeError("NODE_HASH_MUST_BE_32_BYTES");
  }
  const buf = new Uint8Array(65);
  buf[0] = 0x01;
  buf.set(left, 1);
  buf.set(right, 33);
  return sha256Bytes(buf);
}

export function largestPowerOfTwoLessThan(n: number): number {
  const v = requireStrictInt(n, "n");
  if (v < 2) {
    throw new RangeError("TREE_SPLIT_REQUIRES_INT_GE_2");
  }
  let k = 1;
  while (k * 2 < v) {
    k *= 2;
  }
  return k;
}

export class Rfc6962MerkleAccumulator {
  private readonly leafHashes: Uint8Array[] = [];
  private readonly frontier: Array<Uint8Array | null> = [];
  private readonly dyadicCache: Map<string, Uint8Array> = new Map();

  public get size(): number {
    return this.leafHashes.length;
  }

  public async frontierRootHash(): Promise<Uint8Array> {
    if (this.leafHashes.length === 0) {
      return sha256Bytes(new Uint8Array(0));
    }
    let acc: Uint8Array | null = null;
    for (const slot of this.frontier) {
      if (slot !== null) {
        acc = acc === null ? slot : await rfc6962NodeHash(slot, acc);
      }
    }
    if (acc === null) {
      throw new Error("INTERNAL_EMPTY_FRONTIER");
    }
    return acc;
  }

  public async appendBytes(payload: Uint8Array): Promise<{ leafIndex: number; leafHashHex: string; rootHex: string }> {
    const idx = this.leafHashes.length;
    const lh = await rfc6962LeafHash(payload);
    this.leafHashes.push(lh);
    this.dyadicCache.set(String(idx) + ":" + String(idx + 1), lh);

    let carry = lh;
    let level = 0;
    while (true) {
      if (level === this.frontier.length) {
        this.frontier.push(carry);
        break;
      }
      const existing = this.frontier[level];
      if (existing === null) {
        this.frontier[level] = carry;
        break;
      }
      this.frontier[level] = null;
      carry = await rfc6962NodeHash(existing, carry);
      const span = 1 << (level + 1);
      const end = idx + 1;
      this.dyadicCache.set(String(end - span) + ":" + String(end), carry);
      level += 1;
    }

    const root = await this.frontierRootHash();
    return {
      leafIndex: idx,
      leafHashHex: bytesToHex(lh),
      rootHex: bytesToHex(root),
    };
  }

  private async mthSlice(lo: number, hi: number): Promise<Uint8Array> {
    const n = hi - lo;
    if (n === 0) {
      return sha256Bytes(new Uint8Array(0));
    }
    if (n === 1) {
      return this.leafHashes[lo];
    }
    const key = String(lo) + ":" + String(hi);
    const cached = this.dyadicCache.get(key);
    if (cached !== undefined) {
      return cached;
    }
    const k = largestPowerOfTwoLessThan(n);
    const left = await this.mthSlice(lo, lo + k);
    const right = await this.mthSlice(lo + k, hi);
    return rfc6962NodeHash(left, right);
  }

  public async rootHash(treeSize?: number): Promise<Uint8Array> {
    if (treeSize === undefined) {
      return this.frontierRootHash();
    }
    const n = requireStrictInt(treeSize, "treeSize");
    if (n < 0 || n > this.size) {
      throw new RangeError("INVALID_TREE_SIZE");
    }
    if (n === this.size) {
      return this.frontierRootHash();
    }
    return this.mthSlice(0, n);
  }

  public async inclusionProof(leafIndex: number, treeSize?: number): Promise<string[]> {
    const idx = requireStrictInt(leafIndex, "leafIndex");
    const n = treeSize === undefined ? this.size : requireStrictInt(treeSize, "treeSize");
    if (idx < 0 || n <= 0 || idx >= n || n > this.size) {
      throw new RangeError("INVALID_INCLUSION_BOUNDS");
    }
    const raw = await this.buildPath(idx, 0, n);
    return raw.map(bytesToHex);
  }

  private async buildPath(m: number, lo: number, hi: number): Promise<Uint8Array[]> {
    const n = hi - lo;
    if (n <= 1) {
      return [];
    }
    const k = largestPowerOfTwoLessThan(n);
    if (m < k) {
      const sub = await this.buildPath(m, lo, lo + k);
      sub.push(await this.mthSlice(lo + k, hi));
      return sub;
    }
    const sub = await this.buildPath(m - k, lo + k, hi);
    sub.push(await this.mthSlice(lo, lo + k));
    return sub;
  }

  public async consistencyProof(firstSize: number, secondSize?: number): Promise<string[]> {
    const f = requireStrictInt(firstSize, "firstSize");
    const s = secondSize === undefined ? this.size : requireStrictInt(secondSize, "secondSize");
    if (f < 0 || f > s || s > this.size) {
      throw new RangeError("INVALID_CONSISTENCY_BOUNDS");
    }
    if (f === 0 || f === s) {
      return [];
    }
    const raw = await this.buildSubproof(f, 0, s, true);
    return raw.map(bytesToHex);
  }

  private async buildSubproof(m: number, lo: number, hi: number, startFromOldRoot: boolean): Promise<Uint8Array[]> {
    const n = hi - lo;
    if (m === n) {
      return startFromOldRoot ? [] : [await this.mthSlice(lo, hi)];
    }
    const k = largestPowerOfTwoLessThan(n);
    if (m <= k) {
      const sub = await this.buildSubproof(m, lo, lo + k, startFromOldRoot);
      sub.push(await this.mthSlice(lo + k, hi));
      return sub;
    }
    const sub = await this.buildSubproof(m - k, lo + k, hi, false);
    sub.push(await this.mthSlice(lo, lo + k));
    return sub;
  }
}

export async function verifyInclusionProof(
  leafBytes: Uint8Array,
  leafIndex: number,
  expectedTreeSize: number,
  auditPathHex: string[],
  expectedRootHex: string,
): Promise<boolean> {
  if (!(leafBytes instanceof Uint8Array)) {
    return false;
  }
  if (typeof leafIndex !== "number" || !Number.isSafeInteger(leafIndex)) {
    return false;
  }
  if (typeof expectedTreeSize !== "number" || !Number.isSafeInteger(expectedTreeSize)) {
    return false;
  }
  if (leafIndex < 0 || expectedTreeSize <= 0 || leafIndex >= expectedTreeSize) {
    return false;
  }
  if (typeof expectedRootHex !== "string" || !HEX64_LOWER_RE.test(expectedRootHex)) {
    return false;
  }
  if (!Array.isArray(auditPathHex)) {
    return false;
  }

  let fn = leafIndex;
  let sn = expectedTreeSize - 1;
  let running = await rfc6962LeafHash(leafBytes);

  for (const pHex of auditPathHex) {
    if (sn === 0 || typeof pHex !== "string" || !HEX64_LOWER_RE.test(pHex)) {
      return false;
    }
    const sibling = hexToBytes(pHex);
    if ((fn % 2) === 1 || fn === sn) {
      running = await rfc6962NodeHash(sibling, running);
      while ((fn % 2) === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      running = await rfc6962NodeHash(running, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return sn === 0 && bytesToHex(running) === expectedRootHex;
}

export async function verifyConsistencyProof(
  firstSize: number,
  secondSize: number,
  firstRootHex: string,
  secondRootHex: string,
  consistencyPathHex: string[],
): Promise<boolean> {
  if (typeof firstSize !== "number" || !Number.isSafeInteger(firstSize)) {
    return false;
  }
  if (typeof secondSize !== "number" || !Number.isSafeInteger(secondSize)) {
    return false;
  }
  if (firstSize < 0 || secondSize < 0 || firstSize > secondSize) {
    return false;
  }
  if (typeof firstRootHex !== "string" || typeof secondRootHex !== "string") {
    return false;
  }
  if (!HEX64_LOWER_RE.test(firstRootHex) || !HEX64_LOWER_RE.test(secondRootHex)) {
    return false;
  }
  if (!Array.isArray(consistencyPathHex)) {
    return false;
  }
  const emptyHex = bytesToHex(await sha256Bytes(new Uint8Array(0)));
  if (firstSize === 0) {
    if (firstRootHex !== emptyHex) {
      return false;
    }
    if (secondSize === 0 && secondRootHex !== emptyHex) {
      return false;
    }
    return consistencyPathHex.length === 0;
  }
  if (firstSize === secondSize) {
    return consistencyPathHex.length === 0 && firstRootHex === secondRootHex;
  }
  if (consistencyPathHex.length === 0) {
    return false;
  }

  const path: Uint8Array[] = [];
  for (const h of consistencyPathHex) {
    if (typeof h !== "string" || !HEX64_LOWER_RE.test(h)) {
      return false;
    }
    path.push(hexToBytes(h));
  }
  const firstBig = BigInt(firstSize);
  if ((firstBig & (firstBig - 1n)) === 0n) {
    path.unshift(hexToBytes(firstRootHex));
  }

  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while ((fn % 2) === 1) {
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  let fr = path[0];
  let sr = path[0];
  for (let i = 1; i < path.length; i += 1) {
    if (sn === 0) {
      return false;
    }
    const c = path[i];
    if ((fn % 2) === 1 || fn === sn) {
      fr = await rfc6962NodeHash(c, fr);
      sr = await rfc6962NodeHash(c, sr);
      while ((fn % 2) === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      sr = await rfc6962NodeHash(sr, c);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }

  return sn === 0 && bytesToHex(fr) === firstRootHex && bytesToHex(sr) === secondRootHex;
}

const STRICT_JSON_HEADERS: Record<string, string> = {
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "Cache-Control": "no-store",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
};

export default {
  async fetch(request: Request, env: Env = {}): Promise<Response> {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return new Response(
        JSON.stringify({ error: "method_not_allowed", allowed: ["GET", "HEAD"] }),
        { status: 405, headers: STRICT_JSON_HEADERS },
      );
    }
    const aiMode = env.WORKERS_AI_MODE ?? WORKERS_AI_MODE_DEFAULT;
    assertZeroNeuronCliffGuard(aiMode, 0);

    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "/health" || url.pathname === "/healthz") {
      const payload = {
        status: "ok",
        version: VERSION,
        engine: "DRIFT-WATCH-V4-CUSUM-VILLE-RFC6962-WEYL",
        workersAiMode: aiMode,
        weylModulus: WEYL_DEFAULT_MODULUS,
        weylStep: WEYL_DEFAULT_STEP,
        weylStepInverse: WEYL_DEFAULT_INVERSE,
        benchEndpoints: 50,
        cashOverage: "0.0000 USD",
      };
      const encoded = new TextEncoder().encode(JSON.stringify(payload));
      const headers: Record<string, string> = {
        ...STRICT_JSON_HEADERS,
        "Content-Length": String(encoded.byteLength),
      };
      return new Response(request.method === "HEAD" ? null : encoded, { status: 200, headers });
    }
    return new Response(
      JSON.stringify({ error: "not_found", path: url.pathname }),
      { status: 404, headers: STRICT_JSON_HEADERS },
    );
  },
};
