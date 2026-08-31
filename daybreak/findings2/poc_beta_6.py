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

# Craft receipt with list as keyid to crash keyring.get()
r1["signatures"][0]["keyid"] = ["crash", "me"]

try:
    verify_chain([r1], keyring={})
    print("HELD")
except TypeError as e:
    if "unhashable type: 'list'" in str(e):
        print("EXPLOIT-WORKS: Batch crash via unhashable keyid in keyring")
    else:
        print("HELD", e)
