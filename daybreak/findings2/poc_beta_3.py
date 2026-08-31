import sys, os
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import FlightRecorder, build_receipt, generate_keypair

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
    prev_chain_hash="GENESIS", signing_key=sk
)
r3 = build_receipt(
    action_id="3", subject_name="s",
    actor={"type": "service", "id": "s1", "auth_method": "mtls", "is_service_account": True},
    policy_decision={"result": "ALLOW", "policy_hash": "a"},
    execution={"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
    evidence_items=[{"id": "3", "present": True, "sha256": "c"*64}],
    prev_chain_hash="GENESIS", signing_key=sk
)

path = "test_log.fr"
if os.path.exists(path): os.remove(path)

fr = FlightRecorder(path)
fr.append(r1)
fr.append(r2)
fr.append(r3)

# Verify all 3 are read
assert len(fr.read_all()) == 3

# Attacker flips a single byte in the middle of r2
data = bytearray(open(path, "rb").read())
# Magic(24) + len(4) + r1 + len(4) + r2
# We'll just find the "action_id": "2" string and flip it
idx = data.find(b'"action_id":"2"')
data[idx] = 0x00 # Corrupt JSON
with open(path, "wb") as f:
    f.write(data)

# Read again
frames = fr.read_all()
if len(frames) == 1:
    print("EXPLOIT-WORKS: Mid-file corruption silently truncates rest of file")
else:
    print("HELD")
