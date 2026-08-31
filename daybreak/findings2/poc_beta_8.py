import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import verify_chain, build_receipt, generate_keypair

sk, pk = generate_keypair()
r1 = build_receipt(
    action_id="1", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[], prev_chain_hash="GENESIS", signing_key=sk
)

# Bypass the "unanchored" warning without actually anchoring the chain length
res = verify_chain([r1], public_key=pk, min_length=0)
if res["all_links_valid"] and res["anchored"] and len(res["reasons"]) == 0:
    print("EXPLOIT-WORKS: False anchoring via min_length=0 type/logic flaw")
else:
    print("HELD")
