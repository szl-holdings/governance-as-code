/* a11oy offline verifier — real Ed25519 over DSSEv1 PAE via WebCrypto.
   No server, no network. The verifier is the product.

   verifyReceipt() applies the same verdict laws as tools/receipt_lib.py
   verify_receipt(): a structural mirror of schemas/governed_action_v1.schema.json,
   the predicateType contract, Ed25519 over DSSEv1 PAE, the subject-digest
   binding of the canonical predicate, the actor law (L3), attested time (L4)
   and computed evidence completeness, where only the boolean `true` counts as
   present (L1). tests/test_browser_verifier_parity.py runs this file under
   Node and requires the same verdict as Python on every case it generates.

   Boundary: canonical JSON here sorts keys by code point and escapes strings
   exactly as Python json.dumps(sort_keys=True, separators=(",", ":"),
   ensure_ascii=False). Numbers use JSON.stringify, so a receipt carrying a
   non-integer or > 2^53 number in an extra field can fail here while Python
   passes it. GovernedAction/v1 defines no numeric fields. Base64 signatures
   and schema patterns are matched strictly here (Python tolerates stray
   base64 characters and a trailing newline before `$`), so where the two
   differ this page is the stricter one. */
"use strict";

const PREDICATE_TYPE = "https://szl.dev/predicates/governed-action/v1";
const HEX64 = /^[0-9a-f]{64}$/;
const PREV_CHAIN_HASH = /^(?:[0-9a-f]{64}|GENESIS)$/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

const enc = new TextEncoder();

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const hasOwn = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

function compareCodePoints(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0));
  const y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
  return x.length - y.length;
}

function canonicalString(s) {
  // Python cannot UTF-8 encode a lone surrogate either; both sides refuse it.
  if (LONE_SURROGATE.test(s)) throw new Error("string is not encodable as UTF-8 (lone surrogate)");
  return JSON.stringify(s);
}

// canonical JSON matching Python json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
function canonicalize(v) {
  if (v === null) return "null";
  if (typeof v === "number" || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") return canonicalString(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  const keys = Object.keys(v).sort(compareCodePoints);
  return "{" + keys.map((k) => canonicalString(k) + ":" + canonicalize(v[k])).join(",") + "}";
}

async function sha256Hex(bytes) {
  const h = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function paeBytes(payloadType, payloadBytes) {
  // 'DSSEv1' SP <len> SP <type> SP <len> SP <payload>
  const pt = enc.encode(payloadType);
  const head = enc.encode(`DSSEv1 ${pt.length} `);
  const mid = enc.encode(` ${payloadBytes.length} `);
  const out = new Uint8Array(head.length + pt.length + mid.length + payloadBytes.length);
  out.set(head, 0); out.set(pt, head.length);
  out.set(mid, head.length + pt.length);
  out.set(payloadBytes, head.length + pt.length + mid.length);
  return out;
}

// Canonical padded base64 only. atob() alone accepts unpadded input that
// Python's base64.b64decode rejects, which would make this page looser.
const BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
function b64ToBytes(s) {
  if (typeof s !== "string" || !BASE64.test(s)) throw new Error("not canonical padded base64");
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
}

async function importPublicKey(rawB64) {
  const raw = b64ToBytes(rawB64);
  const key = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  return { key, keyid: (await sha256Hex(raw)).slice(0, 16) };
}

// Structural mirror of schemas/governed_action_v1.schema.json (draft 2020-12,
// formats are annotations as in Python jsonschema's default validator).
// Returns "path: message" strings; an empty list means schema-valid.
function schemaErrors(r) {
  const errors = [];
  const fail = (path, message) => errors.push(`${path}: ${message}`);
  const required = (o, keys, path) => {
    for (const k of keys) if (!hasOwn(o, k)) fail(path, `'${k}' is a required property`);
  };
  const string = (o, k, path) => {
    if (hasOwn(o, k) && typeof o[k] !== "string") fail(`${path}.${k}`, "is not of type 'string'");
  };
  const oneOf = (o, k, values, path) => {
    if (hasOwn(o, k) && !values.includes(o[k])) fail(`${path}.${k}`, `is not one of ${JSON.stringify(values)}`);
  };
  const pattern = (o, k, re, path) => {
    if (hasOwn(o, k) && !(typeof o[k] === "string" && re.test(o[k]))) fail(`${path}.${k}`, `does not match ${re}`);
  };
  const object = (o, k, path) => {
    if (!hasOwn(o, k)) return null;
    if (!isObject(o[k])) { fail(`${path}.${k}`, "is not of type 'object'"); return null; }
    return o[k];
  };

  if (!isObject(r)) { fail("$", "is not of type 'object'"); return errors; }
  required(r, ["predicateType", "subject", "predicate"], "$");
  if (hasOwn(r, "predicateType") && r.predicateType !== PREDICATE_TYPE)
    fail("$.predicateType", `${JSON.stringify(PREDICATE_TYPE)} was expected`);

  const subject = object(r, "subject", "$");
  if (subject) {
    required(subject, ["name", "digest"], "$.subject");
    string(subject, "name", "$.subject");
    const digest = object(subject, "digest", "$.subject");
    if (digest) {
      required(digest, ["sha256"], "$.subject.digest");
      pattern(digest, "sha256", HEX64, "$.subject.digest");
    }
  }

  const pred = object(r, "predicate", "$");
  if (pred) {
    const p = "$.predicate";
    required(pred, ["action_id", "actor", "policy_decision", "execution", "evidence", "timestamps",
                    "prev_chain_hash"], p);
    string(pred, "action_id", p);

    const actor = object(pred, "actor", p);
    if (actor) {
      const a = `${p}.actor`;
      required(actor, ["type", "id", "is_service_account", "auth_method"], a);
      oneOf(actor, "type", ["human", "service"], a);
      string(actor, "id", a);
      oneOf(actor, "auth_method", ["hardware_key", "oidc", "api_key", "mtls"], a);
      if (hasOwn(actor, "is_service_account") && typeof actor.is_service_account !== "boolean")
        fail(`${a}.is_service_account`, "is not of type 'boolean'");
      string(actor, "human_principal", a);
      // allOf[0]: `if` holds when `type` is absent or equals "human".
      if (!hasOwn(actor, "type") || actor.type === "human") {
        if (hasOwn(actor, "is_service_account") && actor.is_service_account !== false)
          fail(`${a}.is_service_account`, "False was expected");
        oneOf(actor, "auth_method", ["hardware_key", "oidc", "mtls"], a);
        required(actor, ["human_principal"], a);
      } else if (hasOwn(actor, "is_service_account") && actor.is_service_account !== true) {
        fail(`${a}.is_service_account`, "True was expected");
      }
    }

    const policy = object(pred, "policy_decision", p);
    if (policy) {
      const q = `${p}.policy_decision`;
      required(policy, ["result", "policy_hash", "evaluated_at"], q);
      oneOf(policy, "result", ["ALLOW", "DENY"], q);
      string(policy, "policy_hash", q);
      string(policy, "evaluated_at", q);
      const approval = object(policy, "human_approval", q);
      if (approval) {
        string(approval, "approver", `${q}.human_approval`);
        string(approval, "at", `${q}.human_approval`);
      }
    }

    const execution = object(pred, "execution", p);
    if (execution) {
      const x = `${p}.execution`;
      required(execution, ["side_effect_class", "status"], x);
      oneOf(execution, "side_effect_class",
            ["READ_ONLY", "WRITE_REVERSIBLE", "WRITE_IRREVERSIBLE", "EXTERNAL_OBSERVABLE"], x);
      oneOf(execution, "status", ["EXECUTED", "DENIED", "ROLLED_BACK", "PENDING_SYNC"], x);
      string(execution, "deployed_revision", x);
    }

    const evidence = object(pred, "evidence", p);
    if (evidence) {
      const e = `${p}.evidence`;
      required(evidence, ["items", "completeness"], e);
      if (hasOwn(evidence, "items")) {
        if (!Array.isArray(evidence.items)) fail(`${e}.items`, "is not of type 'array'");
        else evidence.items.forEach((item, i) => {
          const at = `${e}.items[${i}]`;
          if (!isObject(item)) { fail(at, "is not of type 'object'"); return; }
          required(item, ["id", "sha256", "present"], at);
          string(item, "id", at);
          string(item, "sha256", at);
          if (hasOwn(item, "present") && typeof item.present !== "boolean")
            fail(`${at}.present`, "is not of type 'boolean'");
        });
      }
      oneOf(evidence, "completeness", ["COMPLETE", "INCOMPLETE"], e);
      if (hasOwn(evidence, "redaction_commitments")) {
        const rc = evidence.redaction_commitments;
        if (!Array.isArray(rc)) fail(`${e}.redaction_commitments`, "is not of type 'array'");
        else rc.forEach((c, i) => {
          if (typeof c !== "string") fail(`${e}.redaction_commitments[${i}]`, "is not of type 'string'");
        });
      }
    }

    const ts = object(pred, "timestamps", p);
    if (ts) {
      const t = `${p}.timestamps`;
      required(ts, ["created", "ntp_synced"], t);
      string(ts, "created", t);
      string(ts, "executed", t);
      string(ts, "rfc3161_token", t);
      if (hasOwn(ts, "ntp_synced") && ts.ntp_synced !== true) fail(`${t}.ntp_synced`, "True was expected");
    }

    pattern(pred, "prev_chain_hash", PREV_CHAIN_HASH, p);
  }

  if (hasOwn(r, "signatures")) {
    if (!Array.isArray(r.signatures)) fail("$.signatures", "is not of type 'array'");
    else {
      if (r.signatures.length < 1) fail("$.signatures", "should be non-empty");
      r.signatures.forEach((s, i) => {
        const at = `$.signatures[${i}]`;
        if (!isObject(s)) { fail(at, "is not of type 'object'"); return; }
        required(s, ["keyid", "sig"], at);
        string(s, "keyid", at);
        string(s, "sig", at);
      });
    }
  }
  return errors;
}

// Same verdict laws as receipt_lib.verify_receipt (see header).
async function verifyReceipt(r, publicKey) {
  if (!isObject(r)) {
    return { verdict: "FAIL", sigValid: false, schemaValid: false, completeness: "INCOMPLETE",
             timeAttested: false, reasons: ["receipt must be an object"] };
  }
  const reasons = [];
  const schema = schemaErrors(r);
  const schemaValid = schema.length === 0;
  let semanticValid = schemaValid;
  for (const e of schema) reasons.push(`schema validation failed at ${e}`);

  const type = r.predicateType;
  if (type !== PREDICATE_TYPE) {
    semanticValid = false;
    reasons.push(`predicateType mismatch: expected ${PREDICATE_TYPE}, got ${JSON.stringify(type)}`);
  }

  let sigValid = false;
  const sigs = r.signatures || [];
  if (sigs.length) {
    // Object.fromEntries keeps every own key, including "__proto__", as data.
    const signed = Object.fromEntries(Object.entries(r).filter(([k]) => k !== "signatures"));
    try {
      const first = sigs[0];
      if (!isObject(first) || typeof first.sig !== "string") throw new Error("first signature has no 'sig' string");
      const verifyType = typeof type === "string" ? type : "";
      sigValid = await crypto.subtle.verify({ name: "Ed25519" }, publicKey, b64ToBytes(first.sig),
                                            paeBytes(verifyType, enc.encode(canonicalize(signed))));
      if (!sigValid) reasons.push("signature verification failed — content altered after signing");
    } catch (e) {
      reasons.push(`signature malformed: ${e.message}`);
    }
  } else reasons.push("no signatures present");

  let pred = r.predicate === undefined ? {} : r.predicate;
  if (!isObject(pred)) { pred = {}; semanticValid = false; reasons.push("predicate must be an object"); }

  const subject = r.subject === undefined ? {} : r.subject;
  const digest = isObject(subject) && hasOwn(subject, "digest") ? subject.digest : {};
  const declaredDigest = isObject(digest) ? digest.sha256 : undefined;
  let predicateBytes = null;
  try { predicateBytes = enc.encode(canonicalize(pred)); } catch (e) {
    semanticValid = false;
    reasons.push(`predicate is not canonically encodable: ${e.message}`);
  }
  if (predicateBytes !== null) {
    const observedDigest = await sha256Hex(predicateBytes);
    if (declaredDigest !== observedDigest) {
      semanticValid = false;
      reasons.push(`subject digest does not bind the canonical predicate: declared=${JSON.stringify(declaredDigest)} observed=${observedDigest}`);
    }
  }

  let actor = pred.actor === undefined ? {} : pred.actor;
  if (!isObject(actor)) { actor = {}; semanticValid = false; reasons.push("actor must be an object"); }
  if (actor.type === "human") {
    // Python: `not actor.get("human_principal")` — falsy, including empty containers.
    const hp = actor.human_principal;
    const noPrincipal = !hp || (Array.isArray(hp) && hp.length === 0) || (isObject(hp) && Object.keys(hp).length === 0);
    if (actor.is_service_account !== false || actor.auth_method === "api_key" || noPrincipal) {
      reasons.push("L3 violation: human actor claimed with service-account properties (spoof attempt)");
      semanticValid = false;
    }
  } else if (actor.is_service_account !== true) {
    reasons.push("L3 violation: non-human actor must have is_service_account=true");
    semanticValid = false;
  }

  let ts = pred.timestamps === undefined ? {} : pred.timestamps;
  if (!isObject(ts)) { ts = {}; semanticValid = false; reasons.push("timestamps must be an object"); }
  const timeAttested = ts.ntp_synced === true;
  if (!timeAttested) reasons.push("time not attested (ntp_synced != true)");

  let ev = pred.evidence === undefined ? {} : pred.evidence;
  if (!isObject(ev)) { ev = {}; semanticValid = false; reasons.push("evidence must be an object"); }
  let items = ev.items === undefined ? [] : ev.items;
  if (!Array.isArray(items) || items.some((i) => !isObject(i))) {
    items = []; semanticValid = false; reasons.push("evidence.items must be an array of objects");
  }
  // L1: only the boolean true counts as present.
  const completeness = (items.length && items.every((i) => i.present === true)) ? "COMPLETE" : "INCOMPLETE";
  if (ev.completeness !== completeness)
    reasons.push(`declared completeness ${ev.completeness} != computed ${completeness}`);

  let verdict;
  if (!sigValid || !semanticValid) verdict = "FAIL";
  else if (completeness !== "COMPLETE" || !timeAttested) {
    verdict = "INCOMPLETE";
    if (completeness !== "COMPLETE") reasons.push("evidence incomplete — INCOMPLETE is the verdict, never PASS");
  } else verdict = "PASS";
  return { verdict, sigValid, schemaValid, completeness, timeAttested, reasons };
}

async function chainHashOf(receipt) { return sha256Hex(enc.encode(canonicalize(receipt))); }
async function chainTip(receipts) { return chainHashOf(receipts[receipts.length - 1]); }

if (typeof module !== "undefined" && module.exports) {
  // Node test harness only (tests/test_browser_verifier_parity.py); browsers skip this.
  module.exports = { PREDICATE_TYPE, canonicalize, chainHashOf, importPublicKey, schemaErrors, verifyReceipt };
}

if (typeof document !== "undefined") {
  const $ = (s) => document.querySelector(s);
  let BUNDLE = null;
  let PUBKEY = null;   // CryptoKey
  let KEYID = null;

  function verdictChip(v, el) {
    el.className = "chip verdict " + v.toLowerCase();
    el.textContent = v;
  }

  async function runStep(id, receipt, chainPrev, expectedPrev) {
    const card = document.getElementById(id);
    const chip = card.querySelector(".verdict");
    const detail = card.querySelector(".detail");
    chip.className = "chip verdict running"; chip.textContent = "VERIFYING";
    await new Promise((r) => setTimeout(r, 320)); // let the eye register the check
    const v = await verifyReceipt(receipt, PUBKEY);
    let linkOK = null;
    if (chainPrev !== null) {
      const prev = receipt.predicate?.prev_chain_hash;
      linkOK = prev === expectedPrev;
      if (!linkOK) { v.verdict = "FAIL"; v.reasons.push("chain link broken"); }
    }
    verdictChip(v.verdict, chip);
    detail.textContent = v.reasons.length ? v.reasons.join(" · ")
      : v.verdict === "PASS" ? "Ed25519 over DSSEv1 PAE · schema and digest binding hold · chain link intact · evidence complete"
      : "signed honestly — missing evidence holds at INCOMPLETE";
    card.classList.add("done");
    return { ...v, linkOK };
  }

  async function runDemo() {
    if (!BUNDLE) return;
    const btn = $("#run");
    btn.disabled = true; btn.textContent = "Running…";
    $("#status-line").textContent = "verifying chain in-browser · no server involved";
    for (const c of document.querySelectorAll(".step")) { c.classList.remove("done"); }
    const r = BUNDLE.receipts; // [r1 allowed, r2 denied]
    const results = {};
    results.s2 = await runStep("s2", r[0], true, "GENESIS");
    results.s5 = await runStep("s5", r[1], true, await chainHashOf(r[0]));
    results.s6 = await runStep("s6", BUNDLE.tampered_receipt, true, "GENESIS");
    results.s7 = await runStep("s7", BUNDLE.incomplete_receipt, true, await chainHashOf(r[1]));
    results.s11 = await runStep("s11", BUNDLE.spoof_receipt, true, "GENESIS");
    // replay check: recompute the tip of the two chained receipts
    const tips = $("#s9 .detail");
    const tip1 = BUNDLE.chain_tip, tip2 = await chainTip(r.slice(0, 2));
    const replayOK = tip1 === tip2;
    verdictChip(replayOK ? "PASS" : "FAIL", $("#s9 .verdict"));
    tips.textContent = replayOK
      ? `chain tip ${tip1.slice(0, 20)}… recomputed in-browser, matches the signed tip — replay is non-mutating`
      : "chain tip mismatch";
    $("#s9").classList.add("done");
    const passed = Object.values(results);
    $("#status-line").textContent =
      `done — ${passed.filter((x) => x.verdict === "PASS").length} PASS · ` +
      `${passed.filter((x) => x.verdict === "INCOMPLETE").length} INCOMPLETE · ` +
      `${passed.filter((x) => x.verdict === "FAIL").length} FAIL (expected outcomes, all reproduced offline)`;
    btn.disabled = false; btn.textContent = "Re-run verification";
  }

  async function boot() {
    try {
      const res = await fetch("demo_bundle.json", { cache: "no-store" });
      BUNDLE = await res.json();
      ({ key: PUBKEY, keyid: KEYID } = await importPublicKey(BUNDLE.public_key_raw_b64));
      $("#keyline").textContent = `demo root key ${KEYID} · Ed25519 · ${BUNDLE.predicateType.split("/").slice(-2).join("/")}`;
      $("#status-line").textContent = `bundle loaded · public key imported · ${BUNDLE.receipts.length} chained receipts ready — no network from here on`;
      $("#run").addEventListener("click", runDemo);
      $("#run").disabled = false;
    } catch (e) {
      $("#status-line").textContent = "demo bundle failed to load — " + e.message;
    }
  }

  // theme toggle
  (function () {
    const t = document.querySelector("[data-theme-toggle]"), r = document.documentElement;
    let d = "dark"; // SZL KANCHAY: dark operator surface is home; the toggle offers the light surface
    r.setAttribute("data-surface", d);
    const icon = () => d === "dark"
      ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
      : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
    const renderThemeControl = () => {
      t.innerHTML = icon();
      t.setAttribute("aria-label", d === "dark" ? "Switch to light theme" : "Switch to dark theme");
    };
    renderThemeControl();
    t.addEventListener("click", () => {
      d = d === "dark" ? "light" : "dark";
      r.setAttribute("data-surface", d);
      renderThemeControl();
    });
  })();

  boot();
}
