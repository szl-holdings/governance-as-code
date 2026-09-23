#!/usr/bin/env python3
"""receipt_lib.py — GovernedAction/v1 receipts: Ed25519 over DSSE PAE, hash chain, offline verify.

Laws enforced here (not in prose):
  L1  Missing evidence => INCOMPLETE, never PASS.
  L2  A signature attests integrity & origin, never accuracy or performance.
  L3  actor.type=human implies is_service_account=False and auth_method != api_key (Art.12(3)(d)).
  L4  ntp_synced must be True; untrusted time => INCOMPLETE.
  L5  Local durability is ACKed only after flock + fsync. PENDING_SYNC is visible, never hidden.
  L6  Replay is non-mutating: verification never changes the chain.
"""
from __future__ import annotations
import base64, hashlib, json, os
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

PREDICATE_TYPE = "https://szl.dev/predicates/governed-action/v1"

# ---------------------------------------------------------------- canonical form

def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding, per the DSSE spec (v1):
    'DSSEv1' SP <decimal len(type)> SP <type> SP <decimal len(payload)> SP <payload>.
    Prevents signature confusion across payload types."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" " + str(len(payload)).encode() + b" " + payload

# ---------------------------------------------------------------- keys

def generate_keypair():
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def keyid(pk: Ed25519PublicKey) -> str:
    raw = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sha256_hex(raw)[:16]

def export_pubkey_pem(pk: Ed25519PublicKey) -> str:
    return pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def export_pubkey_raw_b64(pk: Ed25519PublicKey) -> str:
    return base64.b64encode(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

def load_pubkey_raw_b64(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(s))

def sign(sk: Ed25519PrivateKey, payload_type: str, payload: bytes) -> str:
    return base64.b64encode(sk.sign(pae(payload_type, payload))).decode()

# ---------------------------------------------------------------- receipt build

def build_receipt(*, action_id, subject_name, actor, policy_decision, execution,
                  evidence_items, prev_chain_hash, signing_key, rfc3161_token=None,
                  redaction_commitments=None):
    """Build and sign a GovernedAction/v1 receipt. Validation is structural, not advisory."""
    now = datetime.now(timezone.utc).isoformat()
    # L3 — human principal law
    if actor["type"] == "human":
        assert actor.get("is_service_account") is False, "L3: human actor must have is_service_account=False"
        assert actor.get("auth_method") != "api_key", "L3: api_key cannot claim a human principal"
        assert actor.get("human_principal"), "L3: Art.12(3)(d) requires human_principal for human actor"
    else:
        assert actor.get("is_service_account") is True, "L3: service actor must have is_service_account=True"
    # L1 — completeness is computed, never asserted
    completeness = "COMPLETE" if all(i.get("present") for i in evidence_items) else "INCOMPLETE"
    predicate = {
        "action_id": action_id,
        "actor": actor,
        "policy_decision": policy_decision,
        "execution": execution,
        "evidence": {
            "items": evidence_items,
            "completeness": completeness,
            "redaction_commitments": redaction_commitments or [],
        },
        "timestamps": {"created": now, "executed": now, "ntp_synced": True,
                       **({"rfc3161_token": rfc3161_token} if rfc3161_token else {})},
        "prev_chain_hash": prev_chain_hash,
    }
    stmt = {"predicateType": PREDICATE_TYPE,
            "subject": {"name": subject_name, "digest": {"sha256": sha256_hex(canonical(predicate))}},
            "predicate": predicate}
    payload = canonical(stmt)
    pk = signing_key.public_key()
    stmt["signatures"] = [{"keyid": keyid(pk), "sig": sign(signing_key, PREDICATE_TYPE, payload)}]
    return stmt

def chain_hash(receipt) -> str:
    return sha256_hex(canonical(receipt))

# ---------------------------------------------------------------- verification

@dataclass
class Verdict:
    verdict: str                 # PASS | FAIL | INCOMPLETE
    signature_valid: bool
    evidence_completeness: str
    reasons: list = field(default_factory=list)
    time_attested: bool = True

def verify_receipt(receipt, public_key: Ed25519PublicKey) -> Verdict:
    reasons, time_attested = [], True
    semantic_valid = True

    if not isinstance(receipt, dict):
        return Verdict(verdict="FAIL", signature_valid=False,
                       evidence_completeness="INCOMPLETE",
                       reasons=["receipt must be an object"], time_attested=False)

    receipt_type = receipt.get("predicateType")
    if receipt_type != PREDICATE_TYPE:
        semantic_valid = False
        reasons.append(f"predicateType mismatch: expected {PREDICATE_TYPE}, got {receipt_type!r}")

    sigs = receipt.get("signatures") or []
    signature_valid = False
    if sigs:
        signed = {k: v for k, v in receipt.items() if k != "signatures"}
        try:
            verify_type = receipt_type if isinstance(receipt_type, str) else ""
            public_key.verify(base64.b64decode(sigs[0]["sig"]), pae(verify_type, canonical(signed)))
            signature_valid = True
        except InvalidSignature:
            reasons.append("signature verification failed — content altered after signing")
        except Exception as e:  # malformed
            reasons.append(f"signature malformed: {e}")
    else:
        reasons.append("no signatures present")

    pred = receipt.get("predicate", {})
    if not isinstance(pred, dict):
        pred = {}
        semantic_valid = False
        reasons.append("predicate must be an object")

    subject = receipt.get("subject", {})
    digest = subject.get("digest", {}) if isinstance(subject, dict) else {}
    declared_subject_digest = digest.get("sha256") if isinstance(digest, dict) else None
    observed_subject_digest = sha256_hex(canonical(pred))
    if declared_subject_digest != observed_subject_digest:
        semantic_valid = False
        reasons.append(
            "subject digest does not bind the canonical predicate: "
            f"declared={declared_subject_digest!r} observed={observed_subject_digest}"
        )

    actor = pred.get("actor", {})
    if not isinstance(actor, dict):
        actor = {}
        semantic_valid = False
        reasons.append("actor must be an object")
    if actor.get("type") == "human":
        if (actor.get("is_service_account") is not False
                or actor.get("auth_method") == "api_key"
                or not actor.get("human_principal")):
            reasons.append("L3 violation: human actor claimed with service-account properties (spoof attempt)")
            semantic_valid = False
    elif actor.get("is_service_account") is not True:
        reasons.append("L3 violation: non-human actor must have is_service_account=true")
        semantic_valid = False

    ts = pred.get("timestamps", {})
    if not isinstance(ts, dict):
        ts = {}
        semantic_valid = False
        reasons.append("timestamps must be an object")
    if ts.get("ntp_synced") is not True:
        time_attested = False
        reasons.append("time not attested (ntp_synced != true)")

    ev = pred.get("evidence", {})
    if not isinstance(ev, dict):
        ev = {}
        semantic_valid = False
        reasons.append("evidence must be an object")
    items = ev.get("items", [])
    if not isinstance(items, list) or any(not isinstance(i, dict) for i in items):
        items = []
        semantic_valid = False
        reasons.append("evidence.items must be an array of objects")
    completeness = "COMPLETE" if (items and all(i.get("present") for i in items)) else "INCOMPLETE"
    if ev.get("completeness") != completeness:
        reasons.append(f"declared completeness {ev.get('completeness')} != computed {completeness}")
    # L1 — missing evidence never PASSes, even with a valid signature.
    # A valid signature also cannot upgrade a semantically invalid GovernedAction envelope.
    if not signature_valid or not semantic_valid:
        verdict = "FAIL"
    elif completeness != "COMPLETE" or not time_attested:
        verdict = "INCOMPLETE"
        if completeness != "COMPLETE":
            reasons.append("evidence incomplete — INCOMPLETE is the verdict, never PASS")
    else:
        verdict = "PASS"
    return Verdict(verdict=verdict, signature_valid=signature_valid,
                   evidence_completeness=completeness, reasons=reasons, time_attested=time_attested)

def verify_chain(receipts, public_key) -> dict:
    """Verify an ordered hash chain. Non-mutating by construction."""
    verdicts, prev = [], "GENESIS"
    for i, r in enumerate(receipts):
        v = verify_receipt(r, public_key)
        linked = r.get("predicate", {}).get("prev_chain_hash") == prev
        if not linked:
            v.reasons.append(f"chain link broken at index {i}")
            v.verdict = "FAIL"
        verdicts.append({"index": i, "action_id": r.get("predicate", {}).get("action_id"),
                         "chain_link": linked, **vars(v)})
        prev = chain_hash(r)
    ok = all(v["verdict"] in ("PASS", "INCOMPLETE") and v["chain_link"] for v in verdicts)
    return {"length": len(receipts), "tip": prev, "all_links_valid": ok, "verdicts": verdicts}

# ---------------------------------------------------------------- flight recorder (L5)

class FlightRecorder:
    """Append-only local durability. ACK means local durability ONLY; remote sync is a separate, visible state."""
    MAGIC = b"A11YFR01" + b"\x00" * 16  # 24-byte magic header
    def __init__(self, path):
        self.path = path
        if not os.path.exists(path):
            with open(path, "wb") as f:
                import fcntl; fcntl.flock(f, fcntl.LOCK_EX)
                f.write(self.MAGIC); f.flush(); os.fsync(f.fileno())
    def append(self, receipt) -> dict:
        blob = canonical(receipt)
        with open(self.path, "ab") as f:
            import fcntl; fcntl.flock(f, fcntl.LOCK_EX)
            f.write(len(blob).to_bytes(4, "big")); f.write(blob)
            f.flush(); os.fsync(f.fileno())     # L5: ACK only after fsync
        return {"durability": "LOCAL_ACK", "remote": "PENDING_SYNC"}  # L5: PENDING_SYNC is visible
    def read_all(self):
        out = []
        with open(self.path, "rb") as f:
            magic = f.read(24)
            assert magic == self.MAGIC, "flight recorder magic mismatch"
            while True:
                hdr = f.read(4)
                if not hdr:
                    break
                n = int.from_bytes(hdr, "big")
                out.append(json.loads(f.read(n)))
        return out
