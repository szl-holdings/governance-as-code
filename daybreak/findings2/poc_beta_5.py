import sys, os
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import FlightRecorder, build_receipt, generate_keypair, verify_chain

sk, pk = generate_keypair()

r0 = build_receipt(
    action_id="0", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[], prev_chain_hash="GENESIS", signing_key=sk
)

h0 = sys.modules['receipt_lib'].chain_hash(r0)

r_A = build_receipt(
    action_id="A", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[], prev_chain_hash=h0, signing_key=sk
)

r_B = build_receipt(
    action_id="B", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[], prev_chain_hash=h0, signing_key=sk
)

for r in [r_A, r_B]:
    r["predicate"]["chain_id"] = r0["predicate"]["chain_id"]
    r["subject"]["digest"]["sha256"] = sys.modules['receipt_lib'].sha256_hex(sys.modules['receipt_lib'].canonical(r["predicate"]))
    import base64
    signed = {k: v for k, v in r.items() if k != "signatures"}
    pae = sys.modules['receipt_lib'].pae(r["predicateType"], sys.modules['receipt_lib'].canonical(signed))
    r["signatures"][0]["sig"] = base64.b64encode(sk.sign(pae)).decode()

path = "test_concurrent.fr"
if os.path.exists(path): os.remove(path)

fr = FlightRecorder(path)
fr.append(r0)
fr.append(r_A)
fr.append(r_B)

frames = fr.read_all()
res = verify_chain(frames, public_key=pk)
if not res["all_links_valid"] and any("chain link broken" in str(v.get("reasons", [])) for v in res.get("verdicts", [])):
    print("EXPLOIT-WORKS: Concurrent append permanently breaks chain validity")
else:
    print("HELD")
    print(res)
