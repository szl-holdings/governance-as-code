"""The browser verifier (demo_site/verify.js) must reach receipt_lib's verdicts.

Each case is generated here with receipt_lib (honest receipts, post-signing
tampering, and honestly re-signed malformed envelopes), verified in Python, and
verified again by verify.js under Node's WebCrypto. Verdict, signature
validity, schema validity and computed completeness must all match.

Cases where the two implementations knowingly differ are excluded and the
browser is the stricter side for each (see the verify.js header): stray
characters in base64 signatures, a trailing newline before a schema `$`, and
non-integer numbers in extra fields.
"""
from __future__ import annotations

import copy
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from receipt_lib import (  # noqa: E402
    PREDICATE_TYPE,
    build_receipt,
    canonical,
    export_pubkey_raw_b64,
    generate_keypair,
    keyid,
    sha256_hex,
    sign,
    verify_receipt,
)

VERIFY_JS = ROOT / "demo_site" / "verify.js"
NODE = shutil.which("node")
if NODE is None:
    if os.environ.get("GOVERNANCE_REQUIRE_NODE") == "1":
        raise RuntimeError("GOVERNANCE_REQUIRE_NODE=1 but `node` is not on PATH")
    pytest.skip("node is not on PATH; the browser verifier parity check needs Node >= 20 (WebCrypto Ed25519)",
                allow_module_level=True)

HARNESS = r"""
globalThis.crypto ??= require("node:crypto").webcrypto;
const fs = require("node:fs");
const verifier = require(process.argv[2]);
const job = JSON.parse(fs.readFileSync(process.argv[3], "utf8"));
(async () => {
  const out = { verdicts: [], canonical: [], bundles: [] };
  for (const c of job.cases) {
    const { key, keyid } = await verifier.importPublicKey(c.public_key_raw_b64);
    const v = await verifier.verifyReceipt(c.receipt, key);
    out.verdicts.push({ keyid, verdict: v.verdict, signature_valid: v.sigValid,
                        schema_valid: v.schemaValid, evidence_completeness: v.completeness });
  }
  for (const value of job.canonical) out.canonical.push(verifier.canonicalize(value));
  for (const b of job.bundles) {
    const { key } = await verifier.importPublicKey(b.public_key_raw_b64);
    const verdict = async (r) => (await verifier.verifyReceipt(r, key)).verdict;
    out.bundles.push({
      allowed: await verdict(b.receipts[0]), deny_record: await verdict(b.receipts[1]),
      tampered: await verdict(b.tampered_receipt), evidence_cut: await verdict(b.incomplete_receipt),
      backdated: await verdict(b.backdated_receipt), spoof: await verdict(b.spoof_receipt),
      tip: await verifier.chainHashOf(b.receipts[b.receipts.length - 1]),
    });
  }
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { console.error((e && e.stack) || e); process.exit(1); });
"""

HUMAN = {"type": "human", "id": "fixture-owner", "is_service_account": False,
         "auth_method": "hardware_key", "human_principal": "Fixture Owner"}
SERVICE = {"type": "service", "id": "agent://fixture", "is_service_account": True, "auth_method": "api_key"}
POLICY = {"result": "ALLOW", "policy_hash": sha256_hex(b"parity-policy"),
          "evaluated_at": "2026-11-06T00:00:00+00:00"}
EVIDENCE = [{"id": "trace", "sha256": sha256_hex(b"trace"), "present": True},
            {"id": "approval", "sha256": sha256_hex(b"approval"), "present": True}]


def receipt(sk, **kw):
    args = {"action_id": "parity-control", "subject_name": "test:browser-parity", "actor": HUMAN,
            "policy_decision": POLICY, "execution": {"side_effect_class": "READ_ONLY", "status": "EXECUTED"},
            "evidence_items": EVIDENCE, "prev_chain_hash": "GENESIS", "signing_key": sk}
    args.update(kw)
    return build_receipt(**copy.deepcopy(args))


def resign(r, sk, *, rebind=True):
    """Sign exactly this (possibly malformed) envelope so only semantics can reject it."""
    subject = r.get("subject")
    if rebind and isinstance(subject, dict) and isinstance(subject.get("digest"), dict):
        subject["digest"]["sha256"] = sha256_hex(canonical(r.get("predicate")))
    payload = {k: v for k, v in r.items() if k != "signatures"}
    ptype = r.get("predicateType")
    r["signatures"] = [{"keyid": keyid(sk.public_key()),
                        "sig": sign(sk, ptype if isinstance(ptype, str) else "", canonical(payload))}]
    return r


def mutated(sk, path, value=None, *, delete=False, rebind=True):
    r = receipt(sk)
    node = r
    for part in path[:-1]:
        node = node[part]
    if delete:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return resign(r, sk, rebind=rebind)


MISSING_PATHS = [
    ("predicate", "action_id"), ("predicate", "actor"), ("predicate", "policy_decision"),
    ("predicate", "execution"), ("predicate", "evidence"), ("predicate", "timestamps"),
    ("predicate", "prev_chain_hash"), ("predicate", "actor", "id"), ("predicate", "actor", "auth_method"),
    ("predicate", "actor", "human_principal"), ("predicate", "actor", "type"),
    ("predicate", "actor", "is_service_account"), ("predicate", "policy_decision", "result"),
    ("predicate", "policy_decision", "policy_hash"), ("predicate", "policy_decision", "evaluated_at"),
    ("predicate", "execution", "side_effect_class"), ("predicate", "execution", "status"),
    ("predicate", "evidence", "items", 0, "id"), ("predicate", "evidence", "items", 0, "sha256"),
    ("predicate", "evidence", "items", 0, "present"), ("predicate", "evidence", "completeness"),
    ("predicate", "timestamps", "created"), ("predicate", "timestamps", "ntp_synced"),
    ("subject", "name"), ("predicateType",),
]
WRONG_VALUES = [
    (("predicate",), None), (("predicate",), []), (("predicate",), "predicate"),
    (("predicate", "actor"), None), (("predicate", "actor", "type"), "robot"),
    (("predicate", "actor", "type"), True), (("predicate", "actor", "is_service_account"), 0),
    (("predicate", "actor", "human_principal"), ""), (("predicate", "actor", "human_principal"), []),
    (("predicate", "actor", "auth_method"), "api_key"), (("predicate", "actor", "auth_method"), "password"),
    (("predicate", "policy_decision"), []), (("predicate", "policy_decision", "result"), "PASS"),
    (("predicate", "policy_decision", "human_approval"), {"approver": 5}),
    (("predicate", "execution"), None), (("predicate", "execution", "status"), "SUCCESS"),
    (("predicate", "execution", "deployed_revision"), 7), (("predicate", "evidence"), None),
    (("predicate", "evidence", "items"), "items"), (("predicate", "evidence", "items", 0), []),
    (("predicate", "evidence", "items", 0, "id"), 1), (("predicate", "evidence", "items", 0, "sha256"), None),
    (("predicate", "evidence", "items", 0, "present"), "false"),
    (("predicate", "evidence", "items", 0, "present"), "true"),
    (("predicate", "evidence", "items", 0, "present"), 1),
    (("predicate", "evidence", "items", 0, "present"), {"present": True}),
    (("predicate", "evidence", "items", 0, "present"), None),
    (("predicate", "evidence", "items", 0, "present"), []),
    (("predicate", "evidence", "completeness"), "PARTIAL"),
    (("predicate", "evidence", "redaction_commitments"), [1]),
    (("predicate", "timestamps"), None), (("predicate", "timestamps", "ntp_synced"), False),
    (("predicate", "timestamps", "ntp_synced"), 1), (("predicate", "timestamps", "ntp_synced"), "true"),
    (("predicate", "timestamps", "created"), 20261106),
    (("predicate", "prev_chain_hash"), "not-a-hash"), (("predicate", "prev_chain_hash"), "A" * 64),
    (("subject",), None), (("subject", "digest"), "digest"), (("predicateType",), 7),
]


def build_cases():
    sk, pk = generate_keypair()
    _, other_pk = generate_keypair()
    cases = []

    def add(name, r, public_key=pk):
        cases.append((name, r, public_key))

    add("valid_human", receipt(sk))
    add("valid_service", receipt(sk, actor=SERVICE))
    add("deny_record", receipt(sk, actor=SERVICE, policy_decision={**POLICY, "result": "DENY"},
                               execution={"side_effect_class": "WRITE_IRREVERSIBLE", "status": "DENIED"}))
    add("honest_missing_evidence", receipt(sk, evidence_items=[*EVIDENCE[:1],
                                                               {"id": "approval", "sha256": "", "present": False}]))
    add("honest_empty_evidence", receipt(sk, evidence_items=[]))
    add("unicode_strings", receipt(sk, action_id="ação-✓-😀", subject_name="prod:ünïcode-\U0001F600",
                                   actor={**HUMAN, "human_principal": "Zoë Ångström"}))
    add("redaction_and_rfc3161", receipt(sk, redaction_commitments=["c1", "c2"], rfc3161_token="dHNh"))
    add("format_is_annotation_only", receipt(sk, policy_decision={**POLICY, "evaluated_at": "yesterday"}))
    add("human_approval_and_revision", receipt(sk, policy_decision={**POLICY, "human_approval": {
        "approver": "fixture-owner", "at": "2026-11-06T00:00:00+00:00"}},
        execution={"side_effect_class": "WRITE_REVERSIBLE", "status": "EXECUTED", "deployed_revision": "abc123"}))

    extra = receipt(sk)
    # Code-point key order differs from UTF-16 order for U+E000 vs U+1F600.
    extra["x-extra"] = {"": 1, "\U0001F600": 2, "a": [True, None, " \t\"\\\x01\x7f"], "": {}}
    add("extra_fields_code_point_order", resign(extra, sk, rebind=False))

    declared = receipt(sk)
    declared["predicate"]["evidence"]["completeness"] = "INCOMPLETE"
    add("declared_incomplete_computed_complete", resign(declared, sk))

    lie = receipt(sk)
    lie["predicate"]["evidence"]["items"][0]["present"] = False
    add("declared_complete_computed_incomplete", resign(lie, sk))

    tampered = receipt(sk)
    tampered["predicate"]["action_id"] = "altered-after-signing"
    add("tampered_after_signing", tampered)

    spoof = receipt(sk)
    spoof["predicate"]["actor"] = {"type": "human", "id": "agent://fixture", "is_service_account": False,
                                   "auth_method": "api_key"}
    add("unsigned_spoof", spoof)

    other = receipt(sk, action_id="other")
    transplant = receipt(sk)
    transplant["signatures"] = other["signatures"]
    add("signature_transplant", transplant)

    empty = receipt(sk)
    empty["signatures"] = []
    add("empty_signature_list", empty)
    unsigned = receipt(sk)
    del unsigned["signatures"]
    add("no_signatures_key", unsigned)
    add("wrong_public_key", receipt(sk), other_pk)

    unpadded = receipt(sk)
    unpadded["signatures"][0]["sig"] = unpadded["signatures"][0]["sig"].rstrip("=")
    add("unpadded_signature", unpadded)
    for name, sigs in [("sig_not_string", [{"keyid": "k", "sig": 123}]), ("sig_entry_not_object", ["abc"]),
                       ("signatures_object", {"sig": "x"}), ("signatures_string", "abc")]:
        r = receipt(sk)
        r["signatures"] = sigs
        add(name, r)

    foreign = receipt(sk)
    foreign["predicateType"] = "https://example.com/other-predicate/v9"
    add("signed_foreign_predicate_type", resign(foreign, sk))

    drift = receipt(sk)
    drift["subject"]["digest"]["sha256"] = sha256_hex(b"different")
    add("signed_subject_digest_drift", resign(drift, sk, rebind=False))
    add("signed_non_hex_subject_digest", mutated(sk, ("subject", "digest", "sha256"), "XYZ", rebind=False))

    svc = receipt(sk, actor=SERVICE)
    svc["predicate"]["actor"]["is_service_account"] = False
    add("signed_service_not_service_account", resign(svc, sk))
    svc_int = receipt(sk, actor=SERVICE)
    svc_int["predicate"]["actor"]["is_service_account"] = 1
    add("signed_service_account_flag_int", resign(svc_int, sk))

    for path in MISSING_PATHS:
        add("signed_missing_" + ".".join(map(str, path)), mutated(sk, path, delete=True))
    for path, value in WRONG_VALUES:
        add(f"signed_{'.'.join(map(str, path))}={json.dumps(value)}", mutated(sk, path, value))

    for value in (None, [], "receipt", 1, True):
        add(f"non_object_{json.dumps(value)}", value)

    lone = receipt(sk)
    lone["predicate"]["action_id"] = "\ud800"
    add("lone_surrogate_in_predicate", lone)
    lone_subject = receipt(sk)
    lone_subject["subject"]["name"] = "\udc00x"
    add("lone_surrogate_in_subject", lone_subject)
    return cases


def run_harness(tmp_path, job):
    job_path = tmp_path / "job.json"
    job_path.write_text(json.dumps(job, ensure_ascii=True), encoding="utf-8")
    harness = tmp_path / "harness.cjs"
    harness.write_text(HARNESS, encoding="utf-8")
    result = subprocess.run([NODE, str(harness), str(VERIFY_JS), str(job_path)],
                            capture_output=True, text=True, timeout=120, check=False)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def test_browser_and_python_verdicts_match(tmp_path):
    cases = build_cases()
    out = run_harness(tmp_path, {"cases": [{"public_key_raw_b64": export_pubkey_raw_b64(pk), "receipt": r}
                                           for _, r, pk in cases], "canonical": [], "bundles": []})
    assert len(out["verdicts"]) == len(cases)
    mismatches = []
    for (name, r, pk), js in zip(cases, out["verdicts"]):
        py = verify_receipt(r, pk)
        expected = {"keyid": keyid(pk), "verdict": py.verdict, "signature_valid": py.signature_valid,
                    "schema_valid": py.schema_valid, "evidence_completeness": py.evidence_completeness}
        if js != expected:
            mismatches.append((name, expected, js))
    assert not mismatches, mismatches


def test_cases_cover_every_verdict_and_the_former_browser_gaps():
    verdicts = {name: verify_receipt(r, pk).verdict for name, r, pk in build_cases()}
    assert verdicts["valid_human"] == "PASS"
    assert verdicts["honest_missing_evidence"] == "INCOMPLETE"
    # Each of these passed the previous browser check while Python failed it.
    for name in ("signed_foreign_predicate_type", "signed_subject_digest_drift",
                 "signed_service_not_service_account", 'signed_predicate.evidence.items.0.present="false"',
                 "signed_predicate.evidence.items.0.present=1", "signed_missing_predicate.policy_decision",
                 "unpadded_signature", "lone_surrogate_in_predicate"):
        assert verdicts[name] == "FAIL", name


def test_canonical_json_matches_python(tmp_path):
    values = [
        {"b": 1, "a": [True, False, None], "c": {"z": "", "y": "x"}},
        {"": 1, "\U0001F600": 2, "é": 3, "e": 4},
        ["\"quoted\" \\ back", "tab\tnew\nline\r", "\x00\x01\x1f\x7f", "  ", "ação 😀"],
        {"nested": [{"k": [1, -2, 0, 9007199254740991]}]},
        "", 0, True, None,
    ]
    out = run_harness(tmp_path, {"cases": [], "canonical": values, "bundles": []})
    assert out["canonical"] == [canonical(v).decode("utf-8") for v in values]


@pytest.mark.parametrize("bundle_path", ["demo_site/demo_bundle.json", "receipts/demo_bundle.json"])
def test_committed_demo_bundle_reproduces_in_the_browser_verifier(tmp_path, bundle_path):
    bundle = json.loads((ROOT / bundle_path).read_text(encoding="utf-8"))
    out = run_harness(tmp_path, {"cases": [], "canonical": [], "bundles": [bundle]})
    got = out["bundles"][0]
    assert got.pop("tip") == bundle["chain_tip"]
    assert got == bundle["verdicts"]
    assert got == {"allowed": "PASS", "deny_record": "PASS", "tampered": "FAIL",
                   "evidence_cut": "INCOMPLETE", "backdated": "FAIL", "spoof": "FAIL"}
    assert bundle["predicateType"] == PREDICATE_TYPE
