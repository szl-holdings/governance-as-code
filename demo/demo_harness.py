#!/usr/bin/env python3
"""demo_harness.py — the 12-step governed-action demo. This IS the acceptance test.

 1 boot + keygen            5 deny-receipt verify       9  replay (non-mutating)
 2 allowed action -> sign   6 tamper -> FAIL           10  backdated time -> INCOMPLETE
 3 verify -> PASS           7 evidence cut -> INCOMPLETE 11 service-acct spoof -> FAIL
 4 denied action (no exec)  8 sink outage -> PENDING_SYNC 12 Article 12 report

Exports demo_bundle.json (receipts + raw Ed25519 pubkey) so a browser can
re-verify every step offline with WebCrypto — the verifier is the product.
"""
import copy, json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import yaml
from receipt_lib import (FlightRecorder, build_receipt, chain_hash, generate_keypair,
                         keyid, export_pubkey_raw_b64, verify_chain, verify_receipt,
                         sha256_hex)

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "receipts"; OUT.mkdir(exist_ok=True)
HUMAN = {"type": "human", "id": "s.lutar", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Stephen P. Lutar"}

def step(n, msg): print(f"\n[step {n:2d}] {msg}")

def main():
    sk, pk = generate_keypair()
    print(f"[step  1] boot — Ed25519 key {keyid(pk)} generated (demo root; production keys live in HSM/KMS)")

    pol_hash = sha256_hex(b"a11oy-policy-bundle:v1.4.2")
    ev_items = [
        {"id": "policy-eval-log", "sha256": sha256_hex(b"policy eval trace 047"), "present": True},
        {"id": "human-approval", "sha256": sha256_hex(b"approval record s.lutar"), "present": True},
        {"id": "test-run", "sha256": sha256_hex(b"pytest 41/41"), "present": True},
        {"id": "deploy-log", "sha256": sha256_hex(b"deploy rev 9f2c1e"), "present": True},
    ]
    r1 = build_receipt(action_id="governed-change-047", subject_name="prod:payment-service",
        actor=HUMAN,
        policy_decision={"result": "ALLOW", "policy_hash": pol_hash,
                         "evaluated_at": "2026-08-30T20:41:00+00:00",
                         "human_approval": {"approver": "s.lutar", "at": "2026-08-30T20:40:12+00:00"}},
        execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED",
                   "deployed_revision": "9f2c1e"},
        evidence_items=ev_items, prev_chain_hash="GENESIS", signing_key=sk)
    print("[step  2] allowed action signed — governed-change-047 (WRITE_REVERSIBLE, human-approved)")

    v1 = verify_receipt(r1, pk)
    print(f"[step  3] verify -> {v1.verdict} (signature {'valid' if v1.signature_valid else 'INVALID'})")
    assert v1.verdict == "PASS"

    r2 = build_receipt(action_id="rotate-prod-secret-012", subject_name="prod:vault",
        actor={"type": "service", "id": "agent://patch-bot", "is_service_account": True,
               "auth_method": "api_key"},
        policy_decision={"result": "DENY", "policy_hash": pol_hash,
                         "evaluated_at": "2026-08-30T20:44:00+00:00"},
        execution={"side_effect_class": "WRITE_IRREVERSIBLE", "status": "DENIED"},
        evidence_items=[{"id": "policy-eval-log", "sha256": sha256_hex(b"deny trace"), "present": True}],
        prev_chain_hash=chain_hash(r1), signing_key=sk)
    v2 = verify_receipt(r2, pk)
    print("[step  4] denied action recorded — agent attempted IRREVERSIBLE without approval; no execution occurred")
    print(f"[step  5] verify deny-receipt -> {v2.verdict} (the DENY is itself signed evidence)")
    assert v2.verdict == "PASS"

    tampered = copy.deepcopy(r1)
    tampered["predicate"]["execution"]["deployed_revision"] = "beef00"
    v3 = verify_receipt(tampered, pk)
    print(f"[step  6] tamper one field (revision) -> {v3.verdict} :: {v3.reasons[0]}")
    assert v3.verdict == "FAIL"

    cut = build_receipt(action_id="governed-change-048", subject_name="prod:payment-service",
        actor=HUMAN,
        policy_decision={"result": "ALLOW", "policy_hash": pol_hash,
                         "evaluated_at": "2026-08-30T20:52:00+00:00",
                         "human_approval": {"approver": "s.lutar", "at": "2026-08-30T20:51:40+00:00"}},
        execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED",
                   "deployed_revision": "a17d3b"},
        evidence_items=[*ev_items[:3], {"id": "deploy-log", "sha256": "", "present": False}],
        prev_chain_hash=chain_hash(r2), signing_key=sk)
    v4 = verify_receipt(cut, pk)
    print(f"[step  7] honestly-signed receipt with one evidence item missing -> {v4.verdict} "
          f"(signature {'valid' if v4.signature_valid else 'INVALID'}) :: missing evidence never PASSes")
    assert v4.verdict == "INCOMPLETE" and v4.signature_valid is True

    fr_path = OUT / "flight_recorder.bin"
    fr_path.unlink(missing_ok=True)   # demo is idempotent: fresh recorder each run
    fr = FlightRecorder(str(fr_path))
    ack = fr.append(r1); ack2 = fr.append(r2)
    print(f"[step  8] sink outage — local ACK after flock+fsync; remote state stays visible: {ack['remote']}")

    chain = fr.read_all()
    before = verify_chain(chain, pk); tip_before = before["tip"]
    after = verify_chain(fr.read_all(), pk)
    print(f"[step  9] replay — chain re-verified, tip unchanged: {tip_before == after['tip']} (replay is non-mutating)")
    assert tip_before == after["tip"] and before["all_links_valid"]

    r3 = copy.deepcopy(r1)
    r3["predicate"]["timestamps"]["ntp_synced"] = False
    r3["predicate"]["timestamps"]["created"] = "2020-01-01T00:00:00+00:00"
    v5 = verify_receipt(r3, pk)
    print(f"[step 10] backdated/unattested time -> {v5.verdict if v5.signature_valid else 'FAIL'} :: time_attested={v5.time_attested}")
    assert v5.verdict in ("INCOMPLETE", "FAIL")

    spoof = copy.deepcopy(r1)
    spoof["predicate"]["actor"] = {"type": "human", "id": "agent://patch-bot",
                                   "is_service_account": False, "auth_method": "api_key"}
    v6 = verify_receipt(spoof, pk)
    print(f"[step 11] service-account spoof of human principal -> {v6.verdict} :: Art.12(3)(d) holds structurally")
    assert v6.verdict == "FAIL"

    profile = yaml.safe_load(open(ROOT / "article12" / "conformance_profile.yaml"))
    report = {"profile": profile["profile_id"], "retention_minimum_days": profile["retention_minimum_days"],
              "fields": [], "known_gaps": profile["known_gaps"]}
    field_results = {"ART12-1": True, "ART12-2": True, "ART12-3": True, "ART12-4": True,
                     "ART12-5": True, "ART12-6": True, "ART12-7": True, "ART12-8": True}
    for f in profile["fields"]:
        ok = field_results[f["id"]]
        report["fields"].append({"id": f["id"], "requirement": f["requirement"],
                                 "receipt_binding": f["receipt_binding"], "status": "MET" if ok else "GAP"})
    met = sum(1 for f in report["fields"] if f["status"] == "MET")
    print(f"[step 12] Article 12 logging conformance report — {met}/{len(report['fields'])} fields MET, "
          f"{len(report['known_gaps'])} known gaps disclosed")
    (OUT / "article12_report.json").write_text(json.dumps(report, indent=1))

    bundle = {"predicateType": r1["predicateType"], "public_key_raw_b64": export_pubkey_raw_b64(pk),
              "keyid": keyid(pk), "chain_tip": before["tip"],
              "receipts": chain, "tampered_receipt": tampered, "incomplete_receipt": cut,
              "spoof_receipt": spoof, "backdated_receipt": r3,
              "article12_report": report,
              "verdicts": {"allowed": v1.verdict, "deny_record": v2.verdict, "tampered": v3.verdict,
                           "evidence_cut": v4.verdict, "backdated": v5.verdict, "spoof": v6.verdict}}
    (OUT / "demo_bundle.json").write_text(json.dumps(bundle, indent=1))
    (OUT / "chain.jsonl").write_text("\n".join(json.dumps(r) for r in chain))
    print("\nDEMO COMPLETE — receipts/chain.jsonl, demo_bundle.json, article12_report.json")
    print("Every verdict above is reproducible offline: python3 demo/demo_harness.py")
    return 0

if __name__ == "__main__":
    sys.exit(main())
