#!/usr/bin/env python3
"""receipt_lib.py v2 — GovernedAction/v1 receipts, hardened after independent
multi-model adversarial review (2026-08-31: 37 confirmed PoCs against v1).

v1 → v2 changes (each maps to a confirmed exploit class):
  F1  verify_receipt is fail-closed structural: required fields, exact enums,
      case-sensitive actor types, valid RFC3339 times with executed >= created.
      (was: gutted receipts passed; "Human" case-variant bypassed L3)
  F2  subject.digest.sha256 is recomputed against the predicate at verify time.
      (was: digest never recomputed — binding attack)
  F3  signatures[0].keyid must equal keyid(public_key). (was: keyid a free lie)
  F4  evidence items require well-formed 64-hex sha256; `present` must be a
      strict boolean. (was: present:1 / "yes" passed)
  F5  canonical() rejects non-string dict keys and NaN/Infinity (allow_nan=False).
      (was: {1:...} and {"1":...} collided; NaN emitted non-strict JSON)
  F6  verify_chain: empty chain is INVALID; expected_tip/min_length parameters
      bind history length and tip when the caller knows them; receipts carry
      chain_id (genesis-derived) so fork splices across chains are detected;
      a poison receipt yields per-receipt FAIL, never a batch crash.
      (was: vacuous-truth empty chain, silent truncation, cross-fork replay,
      one malformed receipt bricked the whole run)
  F7  FlightRecorder: torn-tail tolerant reads; verify_integrity() reports
      records/corruption/truncation instead of raising. (was: one partial
      write made every intact prior receipt unreadable)
  F8  rfc3161_token, when present, must be non-empty base64; full TSA
      validation remains control-plane scope (disclosed as GAP-01 in the
      Article 12 profile — not hidden).

Laws (unchanged in intent, now enforced on the verify side too):
  L1  Missing evidence => INCOMPLETE, never PASS.
  L2  A signature attests integrity & origin, never accuracy or performance.
  L3  actor.type=human implies is_service_account=False, auth_method!=api_key,
      non-blank human_principal (Art.12(3)(d)).
  L4  ntp_synced must be True; times must parse and be ordered.
  L5  Local durability ACKed only after flock+fsync; PENDING_SYNC visible.
  L6  Replay is non-mutating.
"""
from __future__ import annotations
import base64, hashlib, json, os, re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

PREDICATE_TYPE = "https://szl.dev/predicates/governed-action/v1"
SIDE_EFFECTS = {"READ_ONLY", "WRITE_REVERSIBLE", "WRITE_IRREVERSIBLE", "EXTERNAL_OBSERVABLE"}
EXEC_STATUS = {"EXECUTED", "DENIED", "ROLLED_BACK", "PENDING_SYNC"}
AUTH_METHODS = {"hardware_key", "oidc", "api_key", "mtls"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")

# ---------------------------------------------------------------- canonical form (F5)

class CanonicalizationError(ValueError):
    pass

def _check_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string dict key {k!r}")
            _check_keys(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _check_keys(v)

def canonical(obj) -> bytes:
    _check_keys(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding (spec v1): 'DSSEv1' SP len SP type SP len SP payload."""
    pt = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(pt)).encode() + b" " + pt + b" " + str(len(payload)).encode() + b" " + payload

# ---------------------------------------------------------------- keys

def generate_keypair():
    sk = Ed25519PrivateKey.generate()
    return sk, sk.public_key()

def keyid(pk: Ed25519PublicKey) -> str:
    return sha256_hex(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))[:16]

def export_pubkey_pem(pk: Ed25519PublicKey) -> str:
    return pk.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

def export_pubkey_raw_b64(pk: Ed25519PublicKey) -> str:
    return base64.b64encode(pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()

def load_pubkey_raw_b64(s: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(s))

def sign(sk: Ed25519PrivateKey, payload_type: str, payload: bytes) -> str:
    return base64.b64encode(sk.sign(pae(payload_type, payload))).decode()

# ---------------------------------------------------------------- registry

def load_authorized_actors(path_or_dict):
    """Authorized-actor registry: keyid -> {id, type}. Published out-of-band
    (e.g. committed to a repo); the verifier binds signing keys to identities
    against it. Without it, human-actor claims cap at INCOMPLETE."""
    if isinstance(path_or_dict, dict):
        return path_or_dict
    import yaml
    return yaml.safe_load(open(path_or_dict))["authorized_actors"]

# ---------------------------------------------------------------- receipt build

def _actor_law(actor):
    t = actor.get("type")
    assert t in ("human", "service"), f"L3: actor.type must be exactly 'human' or 'service', got {t!r}"
    assert actor.get("auth_method") in AUTH_METHODS, "L3: unknown auth_method"
    if t == "human":
        assert actor.get("is_service_account") is False, "L3: human actor must have is_service_account=False"
        assert actor.get("auth_method") != "api_key", "L3: api_key cannot claim a human principal"
        hp = actor.get("human_principal")
        assert isinstance(hp, str) and hp.strip(), "L3: Art.12(3)(d) requires a non-blank human_principal"
    else:
        assert actor.get("is_service_account") is True, "L3: service actor must have is_service_account=True"

def build_receipt(*, action_id, subject_name, actor, policy_decision, execution,
                  evidence_items, prev_chain_hash, signing_key, chain_id=None,
                  rfc3161_token=None, redaction_commitments=None):
    now = datetime.now(timezone.utc).isoformat()
    _actor_law(actor)
    assert execution.get("side_effect_class") in SIDE_EFFECTS, "unknown side_effect_class"
    assert execution.get("status") in EXEC_STATUS, "unknown execution status"
    for i in evidence_items:
        assert i.get("present") in (True, False), "evidence present must be strict bool"
        if i["present"]:
            assert HEX64.match(str(i.get("sha256", ""))), f"evidence {i.get('id')}: sha256 must be 64-hex"
    completeness = "COMPLETE" if (evidence_items and all(i["present"] for i in evidence_items)) else "INCOMPLETE"
    if chain_id is None:
        if prev_chain_hash == "GENESIS":
            seed = {"action_id": action_id, "actor": actor, "subject": subject_name,
                    "policy_hash": policy_decision.get("policy_hash")}
            chain_id = "chain:" + sha256_hex(canonical(seed))[:16]
        else:
            chain_id = prev_chain_hash[:16]
    predicate = {
        "action_id": action_id,
        "actor": actor,
        "policy_decision": policy_decision,
        "execution": execution,
        "evidence": {"items": evidence_items, "completeness": completeness,
                     "redaction_commitments": redaction_commitments or []},
        "timestamps": {"created": now, "executed": now, "ntp_synced": True,
                       **({"rfc3161_token": rfc3161_token} if rfc3161_token else {})},
        "prev_chain_hash": prev_chain_hash,
        "chain_id": chain_id,
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

# ---------------------------------------------------------------- verification (fail-closed)

@dataclass
class Verdict:
    verdict: str                 # PASS | FAIL | INCOMPLETE
    signature_valid: bool
    evidence_completeness: str
    reasons: list = field(default_factory=list)
    time_attested: bool = True

def _parse_time(s):
    if not isinstance(s, str):
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None

EPOCH_FLOOR = datetime(2015, 1, 1, tzinfo=timezone.utc)  # receipts predate the project's existence window are implausible

def verify_receipt(receipt, public_key: Ed25519PublicKey, authorized_actors: dict | None = None) -> Verdict:
    """Verify a GovernedAction/v1 receipt. Fail-closed.

    authorized_actors: {keyid: {"id": ..., "type": ...}} from a trusted,
    out-of-band source. When omitted, human-actor identity claims cap at
    INCOMPLETE — an unanchored key cannot prove a human did anything."""
    reasons, time_attested = [], True
    sig_valid = False
    try:
        if not isinstance(receipt, dict):
            return Verdict("FAIL", False, "INCOMPLETE", ["receipt is not an object"], False)
        # --- structural enforcement (F1) -------------------------------------
        if receipt.get("predicateType") != PREDICATE_TYPE:
            reasons.append(f"predicateType mismatch: {receipt.get('predicateType')!r}")
        subj = receipt.get("subject")
        pred = receipt.get("predicate")
        if not isinstance(subj, dict) or not isinstance(pred, dict):
            reasons.append("missing subject or predicate")
            return Verdict("FAIL", False, "INCOMPLETE", reasons, False)
        # --- subject↔predicate binding (F2) -----------------------------------
        try:
            recomputed = sha256_hex(canonical(pred))
        except (CanonicalizationError, ValueError) as e:
            reasons.append(f"predicate not canonicalizable: {e}")
            return Verdict("FAIL", False, "INCOMPLETE", reasons, False)
        declared = (subj.get("digest") or {}).get("sha256")
        if declared != recomputed:
            reasons.append("subject digest does not match predicate (binding broken)")
        # --- required predicate fields ----------------------------------------
        if not isinstance(pred.get("action_id"), str) or not pred["action_id"].strip():
            reasons.append("missing/blank action_id")
        actor = pred.get("actor")
        if not isinstance(actor, dict):
            reasons.append("missing actor")
        else:
            t = actor.get("type")
            if t not in ("human", "service"):
                reasons.append(f"actor.type {t!r} is not exactly 'human' or 'service'")
            elif t == "human":
                if actor.get("is_service_account") is not False:
                    reasons.append("L3: human actor without is_service_account=false")
                if actor.get("auth_method") == "api_key":
                    reasons.append("L3: api_key cannot claim a human principal")
                hp = actor.get("human_principal")
                if not isinstance(hp, str) or not hp.strip():
                    reasons.append("L3: missing/blank human_principal (Art.12(3)(d))")
            else:
                if actor.get("is_service_account") is not True:
                    reasons.append("L3: service actor must carry is_service_account=true")
            if actor.get("auth_method") not in AUTH_METHODS:
                reasons.append(f"unknown auth_method {actor.get('auth_method')!r}")
        pol = pred.get("policy_decision")
        if not isinstance(pol, dict) or pol.get("result") not in ("ALLOW", "DENY"):
            reasons.append("policy_decision.result must be ALLOW or DENY")
        ex = pred.get("execution")
        if not isinstance(ex, dict):
            reasons.append("missing execution")
        else:
            if ex.get("side_effect_class") not in SIDE_EFFECTS:
                reasons.append(f"unknown side_effect_class {ex.get('side_effect_class')!r}")
            if ex.get("status") not in EXEC_STATUS:
                reasons.append(f"unknown execution status {ex.get('status')!r}")
        ts = pred.get("timestamps")
        if not isinstance(ts, dict):
            reasons.append("missing timestamps")
            time_attested = False
        else:
            created, executed = _parse_time(ts.get("created")), _parse_time(ts.get("executed"))
            if created is None:
                reasons.append("timestamps.created not parseable RFC3339")
                time_attested = False
            if executed is None:
                reasons.append("timestamps.executed not parseable RFC3339")
                time_attested = False
            if created is not None:
                now = datetime.now(timezone.utc)
                if created < EPOCH_FLOOR:
                    reasons.append(f"created {ts.get('created')} precedes plausibility floor (2015)")
                    time_attested = False
                if created > now + __import__("datetime").timedelta(hours=24):
                    reasons.append("created is more than 24h in the future")
                    time_attested = False
            if executed is not None and created is not None and executed < created:
                reasons.append("executed precedes created (temporal inversion)")
                time_attested = False
            if ts.get("ntp_synced") is not True:
                reasons.append("time not attested (ntp_synced != true)")
                time_attested = False
            tok = ts.get("rfc3161_token")
            if tok is not None:
                try:
                    if not base64.b64decode(tok, validate=True):
                        raise ValueError("empty")
                except Exception:
                    reasons.append("rfc3161_token present but not valid base64")
                    time_attested = False
        ev = pred.get("evidence")
        if not isinstance(ev, dict):
            reasons.append("missing evidence")
            items, declared_comp = [], None
        else:
            items = ev.get("items") or []
            declared_comp = ev.get("completeness")
            if not isinstance(items, list):
                reasons.append("evidence.items not a list"); items = []
        for i in items:
            if not isinstance(i, dict) or i.get("present") not in (True, False):
                reasons.append("evidence item: present must be strict boolean"); continue
            if i["present"] and not HEX64.match(str(i.get("sha256", ""))):
                reasons.append(f"evidence {i.get('id')}: sha256 not 64-hex")
        rc = (ev or {}).get("redaction_commitments") if isinstance(ev, dict) else None
        if rc:
            for c in rc:
                if not isinstance(c, str) or not re.match(r"^[0-9a-f]{16,64}:[0-9a-f]{64}$", c):
                    reasons.append("redaction_commitment malformed (need salt-hex:sha256-hex)")
        completeness = "COMPLETE" if (items and all(i.get("present") is True for i in items)) else "INCOMPLETE"
        if declared_comp is not None and declared_comp != completeness:
            reasons.append(f"declared completeness {declared_comp} != computed {completeness}")
        # --- signature (F3: keyid must bind to the verifying key) -------------
        sigs = receipt.get("signatures") or []
        if not isinstance(sigs, list) or not sigs:
            reasons.append("no signatures present")
        else:
            # signatures-region purity: only {keyid, sig}, exactly one entry.
            # The region is unsigned by design; anything beyond the two fields
            # is unauthenticated metadata pretending to be attestation.
            for i, s in enumerate(sigs):
                if not isinstance(s, dict) or set(s.keys()) - {"keyid", "sig"}:
                    reasons.append(f"signatures[{i}] carries unauthenticated metadata (extra keys)")
            if len(sigs) != 1:
                reasons.append(f"signatures count {len(sigs)} != 1 — multi-party attestations require an M-of-N scheme, not stacked entries")
            s0 = sigs[0]
            claimed_kid = s0.get("keyid") if isinstance(s0, dict) else None
            kid = keyid(public_key)
            if claimed_kid != kid:
                reasons.append(f"keyid {claimed_kid!r} does not match verifying key {kid}")
            signed = {k: v for k, v in receipt.items() if k != "signatures"}
            try:
                public_key.verify(base64.b64decode(s0["sig"], validate=True),
                                  pae(receipt["predicateType"], canonical(signed)))
                sig_valid = True
            except InvalidSignature:
                reasons.append("signature verification failed — content altered after signing")
            except Exception as e:
                reasons.append(f"signature malformed: {e}")
        # --- identity binding --------------------------------------------------
        actor = pred.get("actor") if isinstance(pred, dict) else None
        if isinstance(actor, dict) and actor.get("type") in ("human", "service"):
            if authorized_actors is not None:
                entry = authorized_actors.get(kid)
                if not entry:
                    reasons.append(f"signing key {kid} not in authorized-actors registry")
                else:
                    if entry.get("type") != actor.get("type"):
                        reasons.append(f"registry binds key {kid} to type {entry.get('type')!r}, receipt claims {actor.get('type')!r}")
                    if actor.get("type") == "human" and entry.get("id") != actor.get("id"):
                        reasons.append(f"registry binds key {kid} to {entry.get('id')!r}, receipt claims {actor.get('id')!r}")
            elif actor.get("type") == "human":
                reasons.append("no authorized-actors registry supplied — human identity claim unverifiable, capping at INCOMPLETE")
    except Exception as e:  # fail-closed: a poison receipt is a FAIL, never a crash
        reasons.append(f"verifier exception (fail-closed): {type(e).__name__}: {e}")
        return Verdict("FAIL", False, "INCOMPLETE", reasons, False)

    structural_fail = any(r.startswith(("missing", "predicateType", "subject digest", "L3", "actor.type",
                                        "unknown", "policy_decision", "evidence item", "signatures[",
                                        "signatures count", "timestamps.created", "created", "keyid",
                                        "signing key", "registry binds", "redaction_commitment",
                                        "executed precedes")) or "sha256 not 64-hex" in r for r in reasons)
    identity_uncapped = any(r.startswith("no authorized-actors registry") for r in reasons)
    time_flag = not time_attested
    if not sig_valid or structural_fail:
        verdict = "FAIL"
    elif completeness != "COMPLETE" or time_flag or identity_uncapped:
        verdict = "INCOMPLETE"
        if completeness != "COMPLETE":
            reasons.append("evidence incomplete — INCOMPLETE is the verdict, never PASS")
    else:
        verdict = "PASS"
    return Verdict(verdict, sig_valid, completeness, reasons, time_attested)

def verify_chain(receipts, public_key=None, expected_tip=None, min_length=None,
                 authorized_actors=None, keyring=None) -> dict:
    """Verify an ordered hash chain. F6: empty chains are invalid; a caller that
    knows the true history length/tip can bind it; chain_id detects fork splices.

    keyring: {keyid: Ed25519PublicKey} for multi-signer chains — each receipt
    verifies against the key its signature claims. Without keyring, every
    receipt verifies against `public_key` (single-signer chains)."""
    if not receipts:
        return {"length": 0, "tip": None, "all_links_valid": False, "chain_identity_bound": False,
                "verdicts": [], "reasons": ["empty chain — vacuous truth is not validity"]}
    reasons, verdicts = [], []
    prev, chain_ids, prev_created = "GENESIS", set(), None
    for i, r in enumerate(receipts):
        if keyring is not None and isinstance(r, dict):
            sigs = r.get("signatures") or []
            kid = sigs[0].get("keyid") if sigs and isinstance(sigs[0], dict) else None
            k = keyring.get(kid)
            if k is None:
                v = Verdict("FAIL", False, "INCOMPLETE", [f"signer keyid {kid!r} not in keyring"], False)
                pred = r.get("predicate") if isinstance(r.get("predicate"), dict) else {}
                linked = pred.get("prev_chain_hash") == prev
                verdicts.append({"index": i, "action_id": pred.get("action_id"), "chain_link": linked, **vars(v)})
                cid = pred.get("chain_id")
                if cid: chain_ids.add(cid)
                prev = chain_hash(r)
                continue
            v = verify_receipt(r, k, authorized_actors=authorized_actors)
        else:
            v = verify_receipt(r, public_key, authorized_actors=authorized_actors)
        pred = r.get("predicate") if isinstance(r, dict) and isinstance(r.get("predicate"), dict) else {}
        linked = pred.get("prev_chain_hash") == prev
        if not linked:
            v.reasons.append(f"chain link broken at index {i}")
            v.verdict = "FAIL"
        cur = _parse_time((pred.get("timestamps") or {}).get("created")) if pred else None
        if prev_created is not None and cur is not None and cur < prev_created:
            v.reasons.append(f"temporal inversion: receipt {i} predates its parent")
            v.verdict = "FAIL"
        if cur is not None:
            prev_created = cur
        cid = pred.get("chain_id")
        if cid:
            chain_ids.add(cid)
        verdicts.append({"index": i, "action_id": pred.get("action_id"),
                         "chain_link": linked, **vars(v)})
        prev = chain_hash(r)
    identity_bound = len(chain_ids) <= 1
    if len(chain_ids) > 1:
        reasons.append(f"multiple chain_ids in one lineage ({len(chain_ids)}) — fork splice")
    links_ok = all(v["chain_link"] and v["verdict"] in ("PASS", "INCOMPLETE") for v in verdicts)
    tip_ok = True
    if expected_tip is not None:
        tip_ok = prev == expected_tip
        if not tip_ok:
            reasons.append("chain tip does not match expected_tip — history truncated or extended")
    len_ok = True
    if min_length is not None and len(receipts) < min_length:
        len_ok = False
        reasons.append(f"chain length {len(receipts)} < expected minimum {min_length}")
    anchored = (expected_tip is not None) or (min_length is not None)
    if not anchored:
        reasons.append("no external anchor supplied (expected_tip/min_length) — internal consistency only; truncation and cross-context replay are undetectable without an out-of-band tip")
    return {"length": len(receipts), "tip": prev,
            "all_links_valid": bool(links_ok and tip_ok and len_ok and identity_bound),
            "chain_identity_bound": identity_bound, "anchored": anchored,
            "verdicts": verdicts, "reasons": reasons}

# ---------------------------------------------------------------- flight recorder (F7, L5)

class FlightRecorder:
    """Append-only local durability. ACK = local durability only; PENDING_SYNC stays visible.
    Torn-tail tolerant: a partial final frame never makes intact prior frames unreadable."""
    MAGIC = b"A11YFR01" + b"\x00" * 16
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
            f.flush(); os.fsync(f.fileno())
        return {"durability": "LOCAL_ACK", "remote": "PENDING_SYNC"}
    def _frames(self):
        data = open(self.path, "rb").read()
        if not data.startswith(self.MAGIC):
            raise ValueError("flight recorder magic mismatch")
        pos, frames, torn = len(self.MAGIC), [], False
        while pos < len(data):
            if pos + 4 > len(data):
                torn = True; break
            n = int.from_bytes(data[pos:pos + 4], "big")
            if pos + 4 + n > len(data):
                torn = True; break
            blob = data[pos + 4:pos + 4 + n]
            try:
                frames.append(json.loads(blob))
            except json.JSONDecodeError:
                torn = True; break
            pos += 4 + n
        return frames, torn
    def read_all(self):
        """Returns all intact frames; a torn tail is truncated, never fatal."""
        frames, _ = self._frames()
        return frames
    def verify_integrity(self):
        frames, torn = self._frames()
        return {"records": len(frames), "torn_tail": torn,
                "sequence": "intact" if not torn else "truncated-at-torn-frame"}
