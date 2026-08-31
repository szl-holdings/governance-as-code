#!/usr/bin/env python3
"""S2.4/S2.6: verify_chain top-line boolean is gameable.

verify_chain() returns all_links_valid=True for:
  V1 an EMPTY chain (vacuous truth — 'the audit log' of zero entries verifies);
  V2 a TRUNCATED chain — any prefix of a valid chain verifies, so deleting the
     most recent (incriminating) receipts is undetectable; no tip/length binding;
  V3 a chain where EVERY receipt is INCOMPLETE — the top-line boolean conflates
     link validity with verdict quality ('all_links_valid=True' while zero
     receipts actually passed).

Prints EXPLOIT-WORKS if any of these returns all_links_valid=True.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EXEC = {"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]

sk, pk = generate_keypair()
exploit = False

r1 = build_receipt(action_id="c-001", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash="GENESIS", signing_key=sk)
r2 = build_receipt(action_id="c-002", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=EV,
                   prev_chain_hash=chain_hash(r1), signing_key=sk)
r3 = build_receipt(action_id="c-003-incriminating", subject_name="prod:svc",
                   actor=HUMAN, policy_decision=POL, execution=EXEC,
                   evidence_items=EV, prev_chain_hash=chain_hash(r2), signing_key=sk)

# V1: empty chain
res = verify_chain([], pk)
print(f"[V1] empty chain -> all_links_valid={res['all_links_valid']} length={res['length']}")
if res["all_links_valid"]:
    exploit = True

# V2: truncate away the incriminating tip
full = verify_chain([r1, r2, r3], pk)
trunc = verify_chain([r1, r2], pk)
print(f"[V2] full chain -> all_links_valid={full['all_links_valid']} (len {full['length']}); "
      f"truncated (tip deleted) -> all_links_valid={trunc['all_links_valid']} (len {trunc['length']})")
if trunc["all_links_valid"] and full["all_links_valid"]:
    exploit = True

# V3: every receipt INCOMPLETE, top-line boolean still True
bad_ev = [{"id": "log", "sha256": "", "present": False}]
i1 = build_receipt(action_id="c-101", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=bad_ev,
                   prev_chain_hash="GENESIS", signing_key=sk)
i2 = build_receipt(action_id="c-102", subject_name="prod:svc", actor=HUMAN,
                   policy_decision=POL, execution=EXEC, evidence_items=bad_ev,
                   prev_chain_hash=chain_hash(i1), signing_key=sk)
res = verify_chain([i1, i2], pk)
print(f"[V3] all-INCOMPLETE chain -> all_links_valid={res['all_links_valid']} "
      f"verdicts={[x['verdict'] for x in res['verdicts']]}")
if res["all_links_valid"]:
    exploit = True

print("EXPLOIT-WORKS" if exploit else "HELD")
