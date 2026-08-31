#!/usr/bin/env python3
"""poc_alpha_4 — chain_id is a uniformity label, not a lineage proof:
SAME-CHAIN equivocation (double-signed fork) is structurally invisible to F6.

Because verify_chain requires all receipts in a presented chain to share ONE
chain_id (else "fork splice", see poc_alpha_3), any chain that verifies at all
must carry a caller-supplied constant chain_id. A signer who equivocates —
signs two children r2a/r2b of the same parent, the classic audit-evasion fork
— gives both children that same chain_id. The auditor shown the cover-up fork
[r1, r2b] sees identity_bound=True, all_links_valid=True, zero reasons.

F6 detects only splices ACROSS chains whose ids honestly differ; the fork
that matters (same signer, same chain, two histories) cannot be seen by
construction. No verifier path recomputes the genesis-derived chain_id, so
the label's semantics are unenforced anyway.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import (build_receipt, chain_hash, generate_keypair,
                         verify_chain, verify_receipt, sha256_hex)

HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}
SVC = {"type": "service", "id": "svc-deploy-bot", "is_service_account": True,
        "auth_method": "mtls"}
POL = {"result": "ALLOW", "policy_hash": sha256_hex(b"policy-v1")}
EV = [{"id": "log", "sha256": sha256_hex(b"x"), "present": True}]
CID = "chain:prod-deploy-0001"  # the only configuration in which v2 chains verify at all

sk, pk = generate_keypair()
r1 = build_receipt(action_id="a-001", subject_name="prod:svc", actor=SVC,
                   policy_decision=POL,
                   execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                   evidence_items=EV, prev_chain_hash="GENESIS", signing_key=sk, chain_id=CID)
# Fork A (the real history): payment of $1k approved
r2a = build_receipt(action_id="a-002-pay-1k", subject_name="prod:svc", actor=SVC,
                    policy_decision=POL,
                    execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED"},
                    evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk, chain_id=CID)
# Fork B (shown to the auditor): nothing happened
r2b = build_receipt(action_id="a-002-noop", subject_name="prod:svc", actor=SVC,
                    policy_decision=POL,
                    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
                    evidence_items=EV, prev_chain_hash=chain_hash(r1), signing_key=sk, chain_id=CID)

real = verify_chain([r1, r2a], pk)
shown = verify_chain([r1, r2b], pk)
print(f"[*] real fork  [r1, r2a]: all_links_valid={real['all_links_valid']}, tip={real['tip'][:16]}…")
print(f"[*] shown fork [r1, r2b]: all_links_valid={shown['all_links_valid']}, tip={shown['tip'][:16]}…")
print(f"[*] shown fork identity_bound={shown['chain_identity_bound']}, reasons={shown['reasons']}")
print(f"[*] equivocation detected: {shown['reasons'] != [] and any('fork' in x for x in shown['reasons'])}")

# The auditor accepts the cover-up fork as a complete valid lineage:
works = (shown["all_links_valid"] is True
         and shown["chain_identity_bound"] is True
         and all(v["verdict"] == "PASS" for v in shown["verdicts"])
         and chain_hash(r2a) != chain_hash(r2b))

# Variant B: verify_receipt never requires chain_id to EXIST. A hand-built
# lineage with NO chain_id at all (signer-adversary, resigned) reports
# chain_identity_bound=True vacuously — the F6 layer is opt-in.
import copy
def strip_cid(stmt, sk):
    stmt = copy.deepcopy(stmt)
    del stmt["predicate"]["chain_id"]
    from receipt_lib import canonical, sign, keyid, PREDICATE_TYPE
    stmt["subject"]["digest"]["sha256"] = sha256_hex(canonical(stmt["predicate"]))
    payload = canonical({k: v for k, v in stmt.items() if k != "signatures"})
    stmt["signatures"] = [{"keyid": keyid(sk.public_key()), "sig": sign(sk, PREDICATE_TYPE, payload)}]
    return stmt
n1 = strip_cid(r1, sk); n2 = strip_cid(r2b, sk)
out_n = verify_chain([n1, n2], pk)
print(f"[*] variant B (chain_id absent everywhere): all_links_valid={out_n['all_links_valid']}, "
      f"identity_bound={out_n['chain_identity_bound']}")
works = works and out_n["all_links_valid"] is True and out_n["chain_identity_bound"] is True
print("EXPLOIT-WORKS" if works else "HELD")
