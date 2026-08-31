import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import verify_chain, build_receipt, generate_keypair

sk, pk = generate_keypair()
r1 = build_receipt(
    action_id="1", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[{"id": "1", "present": True, "sha256": "a"*64}],
    prev_chain_hash="GENESIS", signing_key=sk
)
r2 = build_receipt(
    action_id="2", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[{"id": "2", "present": True, "sha256": "b"*64}],
    prev_chain_hash=sys.modules['receipt_lib'].chain_hash(r1), signing_key=sk
)
res = verify_chain([r1, r2], public_key=pk)
if not res["all_links_valid"] and "multiple chain_ids in one lineage" in str(res["reasons"]):
    print("EXPLOIT-WORKS")
else:
    print("HELD")
