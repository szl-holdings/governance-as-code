#!/usr/bin/env python3
"""poc_alpha_16 — structural_fail is a PREFIX-MATCH over reason strings, and
three structural-violation reason strings miss the tuple entirely:

  * "timestamps.executed not parseable RFC3339"  (tuple has only "timestamps.created")
  * "evidence.items not a list"                  (tuple has "evidence item" — no 's', and
                                                  char 8 differs: '.' vs ' ')
  * "rfc3161_token present but not valid base64" (no "rfc3161_token" prefix at all)

These are the same CLASS of defect v2 treats as hard FAIL elsewhere
(garbage `created` -> FAIL via "timestamps.created"), but they slip the net
and land on the SOFT verdict INCOMPLETE via the time_attested/completeness
fallbacks. A signer who wants a deniable, retryable INCOMPLETE instead of an
alarm-raising FAIL garbages only the fields on the right side of the net.
Asymmetric fail-closed-ness is a logic error in the prefix approach itself.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, generate_keypair, verify_receipt,
                         canonical, sha256_hex, sign, keyid, PREDICATE_TYPE)

SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
       "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

def resign(stmt, sk):
    stmt["subject"]["digest"]["sha256"] = sha256_hex(canonical(stmt["predicate"]))
    payload = canonical({k: v for k, v in stmt.items() if k != "signatures"})
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()),
                           "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt

sk, pk = generate_keypair()
def fresh():
    return build_receipt(action_id="a-303", subject_name="prod:svc", actor=SVC,
                         policy_decision=POL,
                         execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                         evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk)

cases = {}

# (a) executed garbage, created fine — compare with created garbage (hard FAIL)
r = fresh(); r["predicate"]["timestamps"]["executed"] = "not-a-date"; resign(r, sk)
cases["executed unparseable"] = verify_receipt(r, pk)
r = fresh(); r["predicate"]["timestamps"]["created"] = "not-a-date"; resign(r, sk)
cases["created unparseable (control)"] = verify_receipt(r, pk)

# (b) evidence.items is a dict, not a list
r = fresh(); r["predicate"]["evidence"]["items"] = {"id": "log"}; resign(r, sk)
cases["items not a list"] = verify_receipt(r, pk)

# (c) rfc3161_token garbage (F8: "must be non-empty base64")
r = fresh(); r["predicate"]["timestamps"]["rfc3161_token"] = "!!!not-base64!!!"; resign(r, sk)
cases["rfc3161 garbage"] = verify_receipt(r, pk)

soft = []
for name, v in cases.items():
    print(f"[*] {name:32s} -> {v.verdict:10s} reasons={[x for x in v.reasons][:1]}")
    soft.append(v.verdict)

works = (cases["executed unparseable"].verdict == "INCOMPLETE"
         and cases["created unparseable (control)"].verdict == "FAIL"
         and cases["items not a list"].verdict == "INCOMPLETE"
         and cases["rfc3161 garbage"].verdict == "INCOMPLETE")
print("EXPLOIT-WORKS" if works else "HELD")
