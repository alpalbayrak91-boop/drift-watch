# SPDX-FileCopyrightText: 2026 Alp Albayrak
# SPDX-License-Identifier: MIT
"""V8-exact RFC 8785 JCS serializer and O(log N) RFC 6962 Certificate Transparency Merkle log.

References:
- Anders Rundgren, Bret Jordan, and Samuel Erdtman (2020), IETF RFC 8785:
  JSON Canonicalization Scheme (JCS).
- Ben Laurie, Adam Langley, and Emilia Kasper (2013), IETF RFC 6962:
  Certificate Transparency, Section 2.1 (Merkle Hash Trees).
"""

from __future__ import annotations

import hashlib
import hmac
import math
import re
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

EMPTY_TREE_SHA256: bytes = hashlib.sha256(b"").digest()
EMPTY_TREE_SHA256_HEX: str = EMPTY_TREE_SHA256.hex()
MAX_SAFE_JCS_INT: int = (1 << 53) - 1

_HEX64_LOWER_RE = re.compile(r"\A[0-9a-f]{64}\Z")

_JCS_SHORT_ESCAPES: Dict[int, str] = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _is_strict_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_no_surrogates(text: str) -> None:
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError("JCS_LONE_SURROGATE_REJECTED")


def _jcs_encode_string(text: str) -> str:
    """RFC 8785 Section 3.2.2.2 string serializer rejecting lone UTF-16 surrogates."""
    out: List[str] = ['"']
    for ch in text:
        cp = ord(ch)
        if 0xD800 <= cp <= 0xDFFF:
            raise ValueError("JCS_LONE_SURROGATE_REJECTED")
        short = _JCS_SHORT_ESCAPES.get(cp)
        if short is not None:
            out.append(short)
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _jcs_format_ieee754_float(val: float) -> str:
    """RFC 8785 Section 3.2.2.3 / ECMA-262 Section 7.1.12.1 Number::toString formatter."""
    if not math.isfinite(val):
        raise ValueError("JCS_NON_FINITE_FLOAT")
    if val == 0.0:
        return "0"
    sign = "-" if val < 0.0 else ""
    av = -val if val < 0.0 else val

    s = repr(av).lower()
    if "e" in s:
        mant, exp_s = s.split("e", 1)
        exp10 = int(exp_s)
    else:
        mant, exp10 = s, 0

    if "." in mant:
        int_p, frac_p = mant.split(".", 1)
        raw_digits = int_p + frac_p
        dec_shift = -len(frac_p)
    else:
        raw_digits = mant
        dec_shift = 0

    stripped = raw_digits.lstrip("0")
    k_digits = stripped.rstrip("0")
    trailing_zeros = len(stripped) - len(k_digits)
    k = len(k_digits)
    n = k + exp10 + dec_shift + trailing_zeros

    if k <= n <= 21:
        body = k_digits + ("0" * (n - k))
    elif 0 < n <= 21:
        body = k_digits[:n] + "." + k_digits[n:]
    elif -6 < n <= 0:
        body = "0." + ("0" * (-n)) + k_digits
    else:
        e = n - 1
        e_sign = "+" if e >= 0 else "-"
        m_str = k_digits if k == 1 else (k_digits[0] + "." + k_digits[1:])
        body = f"{m_str}e{e_sign}{abs(e)}"
    return sign + body


def _jcs_utf16_sort_key(key: Any) -> bytes:
    if not isinstance(key, str):
        raise TypeError(f"JCS_OBJECT_KEY_NOT_STR:{type(key).__name__}")
    _check_no_surrogates(key)
    return key.encode("utf-16-be")


def jcs_canonical_str(value: Any) -> str:
    """Serialize a JSON-compatible value into V8-exact RFC 8785 JCS canonical form."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        if abs(value) <= MAX_SAFE_JCS_INT:
            return str(value)
        try:
            as_float = float(value)
        except OverflowError as exc:
            raise ValueError("JCS_INT_OVERFLOW") from exc
        if not math.isfinite(as_float) or int(as_float) != value:
            raise ValueError("JCS_NON_EXACT_IEEE754_INT")
        return _jcs_format_ieee754_float(as_float)
    if isinstance(value, float):
        return _jcs_format_ieee754_float(value)
    if isinstance(value, str):
        return _jcs_encode_string(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs_canonical_str(item) for item in value) + "]"
    if isinstance(value, dict):
        ordered_keys = sorted(value.keys(), key=_jcs_utf16_sort_key)
        return "{" + ",".join(_jcs_encode_string(k) + ":" + jcs_canonical_str(value[k]) for k in ordered_keys) + "}"
    raise TypeError(f"JCS_UNSUPPORTED_TYPE:{type(value).__name__}")


def jcs_canonical_bytes(value: Any) -> bytes:
    """Serialize a JSON-compatible value into UTF-8 encoded RFC 8785 JCS bytes."""
    return jcs_canonical_str(value).encode("utf-8")


def rfc6962_leaf_hash(leaf_bytes: bytes) -> bytes:
    """RFC 6962 Section 2.1 leaf hash: SHA-256(0x00 || leaf_bytes)."""
    if not isinstance(leaf_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("LEAF_BYTES_REQUIRED")
    return hashlib.sha256(b"\x00" + bytes(leaf_bytes)).digest()


def rfc6962_node_hash(left_hash: bytes, right_hash: bytes) -> bytes:
    """RFC 6962 Section 2.1 interior node hash: SHA-256(0x01 || left_hash || right_hash)."""
    if not isinstance(left_hash, (bytes, bytearray)) or not isinstance(right_hash, (bytes, bytearray)):
        raise TypeError("NODE_HASH_BYTES_REQUIRED")
    if len(left_hash) != 32 or len(right_hash) != 32:
        raise ValueError("NODE_HASH_MUST_BE_32_BYTES")
    return hashlib.sha256(b"\x01" + bytes(left_hash) + bytes(right_hash)).digest()


def largest_power_of_two_less_than(n: int) -> int:
    if not _is_strict_int(n) or n < 2:
        raise ValueError("TREE_SPLIT_REQUIRES_INT_GE_2")
    return 1 << ((n - 1).bit_length() - 1)


class Rfc6962MerkleAccumulator:
    """Incremental O(log N) frontier & historical audit-proof RFC 6962 Merkle accumulator."""

    def __init__(self) -> None:
        self._leaf_hashes: List[bytes] = []
        self._frontier: List[Optional[bytes]] = []
        self._dyadic_cache: Dict[Tuple[int, int], bytes] = {}

    @property
    def size(self) -> int:
        return len(self._leaf_hashes)

    def frontier_depth(self) -> int:
        return sum(1 for item in self._frontier if item is not None)

    def frontier_root_hash(self) -> bytes:
        """Fold the O(log N) binary carry frontier from right to left into exact MTH(D[0:N])."""
        if not self._leaf_hashes:
            return EMPTY_TREE_SHA256
        acc: Optional[bytes] = None
        for slot in self._frontier:
            if slot is not None:
                acc = slot if acc is None else rfc6962_node_hash(slot, acc)
        assert acc is not None
        return acc

    def append_bytes(self, payload: bytes) -> Tuple[int, str, str]:
        """Append raw leaf bytes in O(log N) hash compressions and return (index, leaf_hex, root_hex)."""
        lh = rfc6962_leaf_hash(payload)
        idx = len(self._leaf_hashes)
        self._leaf_hashes.append(lh)
        self._dyadic_cache[(idx, idx + 1)] = lh

        # 1. Update O(log N) binary carry frontier
        carry = lh
        level = 0
        while True:
            if level == len(self._frontier):
                self._frontier.append(carry)
                break
            existing = self._frontier[level]
            if existing is None:
                self._frontier[level] = carry
                break
            self._frontier[level] = None
            carry = rfc6962_node_hash(existing, carry)
            span = 1 << (level + 1)
            end = idx + 1
            self._dyadic_cache[(end - span, end)] = carry
            level += 1

        root_hex = self.frontier_root_hash().hex()
        return idx, lh.hex(), root_hex

    def append_jcs(self, event_obj: Mapping[str, Any]) -> Tuple[int, str, str, bytes]:
        """Canonicalize event_obj via RFC 8785 JCS and append to the RFC 6962 transparency log."""
        if not isinstance(event_obj, Mapping):
            raise TypeError("EVENT_MAPPING_REQUIRED")
        raw = jcs_canonical_bytes(dict(event_obj))
        idx, lh_hex, root_hex = self.append_bytes(raw)
        return idx, lh_hex, root_hex, raw

    def _mth_slice(self, lo: int, hi: int) -> bytes:
        n = hi - lo
        if n == 0:
            return EMPTY_TREE_SHA256
        if n == 1:
            return self._leaf_hashes[lo]
        cached = self._dyadic_cache.get((lo, hi))
        if cached is not None:
            return cached
        k = largest_power_of_two_less_than(n)
        left = self._mth_slice(lo, lo + k)
        right = self._mth_slice(lo + k, hi)
        return rfc6962_node_hash(left, right)

    def root_hash(self, tree_size: Optional[int] = None) -> bytes:
        if tree_size is None:
            return self.frontier_root_hash()
        if not _is_strict_int(tree_size) or tree_size < 0 or tree_size > self.size:
            raise ValueError(f"INVALID_TREE_SIZE:{tree_size!r}")
        if tree_size == self.size:
            return self.frontier_root_hash()
        return self._mth_slice(0, tree_size)

    def inclusion_proof(self, leaf_index: int, tree_size: Optional[int] = None) -> List[str]:
        n = self.size if tree_size is None else tree_size
        if not _is_strict_int(leaf_index) or not _is_strict_int(n):
            raise TypeError("STRICT_INT_REQUIRED_FOR_PROOF")
        if leaf_index < 0 or n <= 0 or leaf_index >= n or n > self.size:
            raise ValueError(f"INVALID_INCLUSION_BOUNDS:idx={leaf_index}:size={n}")
        return [h.hex() for h in self._build_path(leaf_index, 0, n)]

    def _build_path(self, m: int, lo: int, hi: int) -> List[bytes]:
        n = hi - lo
        if n <= 1:
            return []
        k = largest_power_of_two_less_than(n)
        if m < k:
            return self._build_path(m, lo, lo + k) + [self._mth_slice(lo + k, hi)]
        return self._build_path(m - k, lo + k, hi) + [self._mth_slice(lo, lo + k)]

    def consistency_proof(self, first_size: int, second_size: Optional[int] = None) -> List[str]:
        n = self.size if second_size is None else second_size
        if not _is_strict_int(first_size) or not _is_strict_int(n):
            raise TypeError("STRICT_INT_REQUIRED_FOR_CONSISTENCY")
        if first_size < 0 or first_size > n or n > self.size:
            raise ValueError(f"INVALID_CONSISTENCY_BOUNDS:first={first_size}:second={n}")
        if first_size == 0 or first_size == n:
            return []
        return [h.hex() for h in self._build_subproof(first_size, 0, n, True)]

    def _build_subproof(self, m: int, lo: int, hi: int, start_from_old_root: bool) -> List[bytes]:
        n = hi - lo
        if m == n:
            return [] if start_from_old_root else [self._mth_slice(lo, hi)]
        k = largest_power_of_two_less_than(n)
        if m <= k:
            return self._build_subproof(m, lo, lo + k, start_from_old_root) + [self._mth_slice(lo + k, hi)]
        return self._build_subproof(m - k, lo + k, hi, False) + [self._mth_slice(lo, lo + k)]


def verify_inclusion_proof(
    leaf_bytes: bytes,
    leaf_index: int,
    expected_tree_size: int,
    audit_path_hex: Sequence[str],
    expected_root_hex: str,
) -> bool:
    """Offline fail-closed RFC 6962 Section 2.1.1 Merkle inclusion proof verifier."""
    if not isinstance(leaf_bytes, (bytes, bytearray)):
        return False
    if not _is_strict_int(leaf_index) or not _is_strict_int(expected_tree_size):
        return False
    if leaf_index < 0 or expected_tree_size <= 0 or leaf_index >= expected_tree_size:
        return False
    if not isinstance(expected_root_hex, str) or not _HEX64_LOWER_RE.match(expected_root_hex):
        return False
    if not isinstance(audit_path_hex, (list, tuple)):
        return False

    fn = leaf_index
    sn = expected_tree_size - 1
    running = rfc6962_leaf_hash(bytes(leaf_bytes))

    for sibling_hex in audit_path_hex:
        if sn == 0:
            return False
        if not isinstance(sibling_hex, str) or not _HEX64_LOWER_RE.match(sibling_hex):
            return False
        sibling = bytes.fromhex(sibling_hex)
        if (fn & 1) == 1 or fn == sn:
            running = rfc6962_node_hash(sibling, running)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            running = rfc6962_node_hash(running, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and hmac.compare_digest(running.hex(), expected_root_hex)


def verify_consistency_proof(
    first_size: int,
    second_size: int,
    first_root_hex: str,
    second_root_hex: str,
    consistency_path_hex: Sequence[str],
) -> bool:
    """Offline fail-closed RFC 6962 Section 2.1.2 Merkle consistency proof verifier."""
    if not _is_strict_int(first_size) or not _is_strict_int(second_size):
        return False
    if first_size < 0 or second_size < 0 or first_size > second_size:
        return False
    if not isinstance(first_root_hex, str) or not _HEX64_LOWER_RE.match(first_root_hex):
        return False
    if not isinstance(second_root_hex, str) or not _HEX64_LOWER_RE.match(second_root_hex):
        return False
    if not isinstance(consistency_path_hex, (list, tuple)):
        return False

    if first_size == 0:
        if not hmac.compare_digest(first_root_hex, EMPTY_TREE_SHA256_HEX):
            return False
        if second_size == 0 and not hmac.compare_digest(second_root_hex, EMPTY_TREE_SHA256_HEX):
            return False
        return len(consistency_path_hex) == 0

    if first_size == second_size:
        return len(consistency_path_hex) == 0 and hmac.compare_digest(first_root_hex, second_root_hex)

    if len(consistency_path_hex) == 0:
        return False

    path_bytes: List[bytes] = []
    for item_hex in consistency_path_hex:
        if not isinstance(item_hex, str) or not _HEX64_LOWER_RE.match(item_hex):
            return False
        path_bytes.append(bytes.fromhex(item_hex))

    if (first_size & (first_size - 1)) == 0:
        path_bytes.insert(0, bytes.fromhex(first_root_hex))

    fn = first_size - 1
    sn = second_size - 1
    while (fn & 1) == 1:
        fn >>= 1
        sn >>= 1

    fr = path_bytes[0]
    sr = path_bytes[0]
    for node in path_bytes[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = rfc6962_node_hash(node, fr)
            sr = rfc6962_node_hash(node, sr)
            while (fn & 1) == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            sr = rfc6962_node_hash(sr, node)
        fn >>= 1
        sn >>= 1

    return (
        sn == 0
        and hmac.compare_digest(fr.hex(), first_root_hex)
        and hmac.compare_digest(sr.hex(), second_root_hex)
    )


def build_transparency_receipt(
    accumulator: Rfc6962MerkleAccumulator,
    event: Mapping[str, Any],
) -> Dict[str, Any]:
    """Append JCS-serialized event to accumulator and emit a self-verifying RFC 6962 receipt."""
    old_size = accumulator.size
    old_root_hex = accumulator.root_hash(old_size).hex()
    event_dict = dict(event)
    leaf_index, leaf_hash_hex, new_root_hex, _ = accumulator.append_jcs(event_dict)
    new_size = accumulator.size
    inc_path = accumulator.inclusion_proof(leaf_index, new_size)
    cons_path = accumulator.consistency_proof(old_size, new_size)
    return {
        "schema": "drift-watch-rfc6962-receipt-v4",
        "event": event_dict,
        "leaf_index": leaf_index,
        "leaf_hash_sha256": leaf_hash_hex,
        "old_tree_size": old_size,
        "expected_tree_size": new_size,
        "old_root_sha256": old_root_hex,
        "merkle_root_sha256": new_root_hex,
        "inclusion_path": inc_path,
        "consistency_path": cons_path,
    }


def verify_transparency_receipt(
    receipt: Mapping[str, Any],
    expected_root_hex: Optional[str] = None,
    expected_tree_size: Optional[int] = None,
) -> Dict[str, Any]:
    """Verify an RFC 6962 + RFC 8785 JCS transparency receipt offline fail-closed."""
    if not isinstance(receipt, Mapping):
        return {"verified": False, "reason": "RECEIPT_NOT_MAPPING"}
    if receipt.get("schema") != "drift-watch-rfc6962-receipt-v4":
        return {"verified": False, "reason": "UNSUPPORTED_RECEIPT_SCHEMA"}

    event = receipt.get("event")
    if not isinstance(event, dict):
        return {"verified": False, "reason": "INVALID_EVENT_OBJECT"}

    try:
        leaf_bytes = jcs_canonical_bytes(event)
    except (TypeError, ValueError) as exc:
        return {"verified": False, "reason": f"JCS_SERIALIZATION_FAILED:{exc}"}

    leaf_idx = receipt.get("leaf_index")
    old_sz = receipt.get("old_tree_size")
    tree_sz = receipt.get("expected_tree_size")
    leaf_hash_hex = receipt.get("leaf_hash_sha256")
    old_root_hex = receipt.get("old_root_sha256")
    root_hex = receipt.get("merkle_root_sha256")
    inc_path = receipt.get("inclusion_path")
    cons_path = receipt.get("consistency_path")

    if not (_is_strict_int(leaf_idx) and _is_strict_int(old_sz) and _is_strict_int(tree_sz)):
        return {"verified": False, "reason": "NON_INT_TREE_PARAMETERS"}
    assert isinstance(leaf_idx, int) and isinstance(old_sz, int) and isinstance(tree_sz, int)

    if expected_tree_size is not None:
        if not _is_strict_int(expected_tree_size) or tree_sz != expected_tree_size:
            return {"verified": False, "reason": "EXPECTED_TREE_SIZE_MISMATCH"}

    if not isinstance(root_hex, str) or not _HEX64_LOWER_RE.match(root_hex):
        return {"verified": False, "reason": "INVALID_MERKLE_ROOT_HEX"}
    if expected_root_hex is not None:
        if not isinstance(expected_root_hex, str) or not hmac.compare_digest(root_hex, expected_root_hex):
            return {"verified": False, "reason": "EXPECTED_ROOT_MISMATCH"}

    computed_leaf_hex = rfc6962_leaf_hash(leaf_bytes).hex()
    if not isinstance(leaf_hash_hex, str) or not hmac.compare_digest(computed_leaf_hex, leaf_hash_hex):
        return {"verified": False, "reason": "LEAF_HASH_MISMATCH"}

    if not isinstance(inc_path, list) or not isinstance(cons_path, list) or not isinstance(old_root_hex, str):
        return {"verified": False, "reason": "MALFORMED_PROOF_FIELDS"}

    if not verify_inclusion_proof(leaf_bytes, leaf_idx, tree_sz, inc_path, root_hex):
        return {"verified": False, "reason": "INCLUSION_PROOF_INVALID"}

    if not verify_consistency_proof(old_sz, tree_sz, old_root_hex, root_hex, cons_path):
        return {"verified": False, "reason": "CONSISTENCY_PROOF_INVALID"}

    return {
        "verified": True,
        "reason": "RFC6962_INCLUSION_AND_CONSISTENCY_VERIFIED",
        "leaf_index": leaf_idx,
        "expected_tree_size": tree_sz,
        "merkle_root_sha256": root_hex,
    }
