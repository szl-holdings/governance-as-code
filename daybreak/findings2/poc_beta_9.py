import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import verify_chain, build_receipt, generate_keypair, canonical, sha256_hex

sk, pk = generate_keypair()

# Receipt 1: ALLOW without policy_hash
r1 = build_receipt(
    action_id="1", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[], prev_chain_hash="GENESIS", signing_key=sk
)

# Receipt 2: DENY without policy_hash (same action/actor/subject)
r2 = build_receipt(
    action_id="1", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "DENY"},
    execution={"side_effect_class": "READ_ONLY", "status": "DENIED"},
    evidence_items=[], prev_chain_hash="GENESIS", signing_key=sk
)

if r1["predicate"]["chain_id"] == r2["predicate"]["chain_id"]:
    print("EXPLOIT-WORKS: policy_hash semantic confusion — ALLOW and DENY have identical chain_id")
else:
    print("HELD")
