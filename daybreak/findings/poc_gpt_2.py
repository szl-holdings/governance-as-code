#!/usr/bin/env python3
"""S2.2 probe: PAE length-prefix manipulation.

DSSEv1 PAE = 'DSSEv1' SP len(type) SP type SP len(payload) SP payload.
Goal: find two DIFFERENT (payload_type, payload) pairs that PAE-encode to
identical bytes (which would allow cross-type signature replay). Also tests
hostile types: embedded spaces, digits, newlines, 'DSSEv1' prefixes, NUL,
multibyte UTF-8 (len must be byte length).

Prints EXPLOIT-WORKS if a collision or cross-type PASS is found, else HELD.
"""
import sys, itertools
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (pae, generate_keypair, sign, canonical, sha256_hex,
                         keyid, verify_receipt, PREDICATE_TYPE)

sk, pk = generate_keypair()
exploit = False

# --- Hostile payload types
hostile_types = [
    "a b", "DSSEv1 5 ", "1 2 3", "x\ny", "x\x00y", "  ", "0",
    "https://szl.dev/predicates/governed-action/v1 ",   # trailing space
    "https://szl.dev/predicates/governed-action/v1\t",
    "prédicaté",           # multibyte utf-8 -> len() must be byte length
    "https://szl.dev/predicates/governed-action/v1",
]
encs = {}
for t in hostile_types:
    e = pae(t, b"PAYLOAD")
    print(f"[probe] pae({t!r:60s}, b'PAYLOAD') = {e[:70]}...")
    if e in encs and encs[e] != t:
        print(f"  !! COLLISION between {encs[e]!r} and {t!r}")
        exploit = True
    encs[e] = t

# --- Brute-force small alphabet for (type, payload) collisions
alphabet_t = ["", "a", "b", " ", "0", "1", "aa", "a ", " a", "ab"]
alphabet_p = [b"", b"a", b"b", b" ", b"0", b"1", b"aa", b"a ", b" a", b"ab", b"DSSEv1"]
seen = {}
for t, p in itertools.product(alphabet_t, alphabet_p):
    e = pae(t, p)
    if e in seen and seen[e] != (t, p):
        print(f"!! COLLISION: {seen[e]} vs {(t, p)} both -> {e}")
        exploit = True
    seen[e] = (t, p)
print(f"[probe] brute force {len(alphabet_t)}x{len(alphabet_p)}: {'collision found' if exploit else 'no collisions'}")

# --- Byte-length check for multibyte type (spec conformance)
t = "prédicaté"
pt = t.encode("utf-8")
e = pae(t, b"")
declared = int(e.split(b" ", 2)[1])
print(f"[probe] multibyte type byte-len declared={declared} actual={len(pt)} chars={len(t)} -> {'OK' if declared == len(pt) else 'MISMATCH (char-vs-byte confusion!)'}")
if declared != len(pt):
    exploit = True

# --- Cross-type replay attempt: sign under hostile type, present under real type.
payload = canonical({"predicateType": PREDICATE_TYPE, "predicate": {"x": 1}})
for ht in hostile_types:
    if ht == PREDICATE_TYPE:
        continue
    sig = sign(sk, ht, payload)
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": "s", "digest": {"sha256": sha256_hex(b"z")}},
            "predicate": {"evidence": {"items": [{"id": "l", "sha256": sha256_hex(b"x"), "present": True}],
                                       "completeness": "COMPLETE"},
                          "timestamps": {"created": "2026-08-30T00:00:00+00:00",
                                         "executed": "2026-08-30T00:00:00+00:00", "ntp_synced": True}}}
    payload2 = canonical(stmt)
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()), "sig": sign(sk, ht, payload2)}]
    v = verify_receipt(stmt, pk)
    if v.verdict == "PASS":
        print(f"!! cross-type replay PASSED with type {ht!r}")
        exploit = True
print("[attempt] cross-type replay with hostile types -> all FAIL" if not exploit else "!! cross-type replay broke through")

print("EXPLOIT-WORKS" if exploit else "HELD")
