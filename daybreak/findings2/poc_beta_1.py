import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import generate_keypair, keyid, build_receipt, verify_receipt

sk_A, pk_A = generate_keypair()
kid_A = keyid(pk_A)

authorized_actors = {
    kid_A: {"id": "service-A", "type": "service"}
}

receipt = build_receipt(
    action_id="act-123",
    subject_name="db-prod",
    actor={"type": "service", "id": "service-B", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"policy_hash": "a"*64, "result": "ALLOW"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[{"id": "ev1", "present": True, "sha256": "b"*64}],
    prev_chain_hash="GENESIS",
    signing_key=sk_A
)

v = verify_receipt(receipt, pk_A, authorized_actors=authorized_actors)
if v.verdict == "PASS":
    print("EXPLOIT-WORKS")
else:
    print("HELD")
    print(v)
