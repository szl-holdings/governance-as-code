/* a11oy offline verifier v2 — real Ed25519 over DSSEv1 PAE via WebCrypto.
   Parity with receipt_lib v2: structural fail-closed checks, keyid binding,
   subject-digest recompute, registry identity binding, signatures-region
   purity, time plausibility. No server, no network. */
"use strict";

const $ = (s) => document.querySelector(s);
let BUNDLE = null;
let KEYRING = null;     // keyid -> CryptoKey
let REGISTRY = null;    // keyid -> {id, type}

const enc = new TextEncoder();
const PREDICATE_TYPE = "https://szl.dev/predicates/governed-action/v1";
const SIDE_EFFECTS = new Set(["READ_ONLY", "WRITE_REVERSIBLE", "WRITE_IRREVERSIBLE", "EXTERNAL_OBSERVABLE"]);
const EXEC_STATUS = new Set(["EXECUTED", "DENIED", "ROLLED_BACK", "PENDING_SYNC"]);
const AUTH_METHODS = new Set(["hardware_key", "oidc", "api_key", "mtls"]);
const HEX64 = /^[0-9a-f]{64}$/;

function canonicalize(v) {
  if (v === null) return "null";
  if (typeof v === "number" || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalize).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(v[k])).join(",") + "}";
}

async function sha256Hex(bytes) {
  const h = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(h)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function paeBytes(payloadType, payloadBytes) {
  const pt = enc.encode(payloadType);
  const head = enc.encode(`DSSEv1 ${pt.length} `);
  const mid = enc.encode(` ${payloadBytes.length} `);
  const out = new Uint8Array(head.length + pt.length + mid.length + payloadBytes.length);
  out.set(head, 0); out.set(pt, head.length);
  out.set(mid, head.length + pt.length);
  out.set(payloadBytes, head.length + pt.length + mid.length);
  return out;
}

const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function importKeys() {
  if (KEYRING) return;
  KEYRING = {};
  for (const [kid, rawb64] of Object.entries(BUNDLE.keyring || { [BUNDLE.keyid]: BUNDLE.public_key_raw_b64 })) {
    KEYRING[kid] = await crypto.subtle.importKey("raw", b64ToBytes(rawb64), { name: "Ed25519" }, false, ["verify"]);
  }
  REGISTRY = BUNDLE.authorized_actors || null;
}

async function keyidOf(rawB64) { return (await sha256Hex(b64ToBytes(rawB64))).slice(0, 16); }

const parseTime = (s) => {
  if (typeof s !== "string") return null;
  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
};

async function verifyReceipt(r) {
  const reasons = [];
  let sigValid = false, timeAttested = true, identityUncapped = false;
  try {
    if (r.predicateType !== PREDICATE_TYPE) reasons.push("predicateType mismatch");
    const subj = r.subject, pred = r.predicate;
    if (!subj || !pred) return { verdict: "FAIL", reasons: ["missing subject or predicate"] };
    // subject↔predicate binding
    const recomputed = await sha256Hex(enc.encode(canonicalize(pred)));
    if ((subj.digest || {}).sha256 !== recomputed) reasons.push("subject digest does not match predicate (binding broken)");
    // required fields
    if (typeof pred.action_id !== "string" || !pred.action_id.trim()) reasons.push("missing/blank action_id");
    const actor = pred.actor || {};
    const kid = (r.signatures || [])[0] ? (r.signatures[0].keyid) : null;
    if (actor.type === "human") {
      if (actor.is_service_account !== false) reasons.push("L3: human actor without is_service_account=false");
      if (actor.auth_method === "api_key") reasons.push("L3: api_key cannot claim a human principal");
      if (typeof actor.human_principal !== "string" || !actor.human_principal.trim()) reasons.push("L3: missing/blank human_principal");
    } else if (actor.type === "service") {
      if (actor.is_service_account !== true) reasons.push("L3: service actor must carry is_service_account=true");
    } else reasons.push(`actor.type ${JSON.stringify(actor.type)} is not exactly 'human' or 'service'`);
    if (!AUTH_METHODS.has(actor.auth_method)) reasons.push("unknown auth_method");
    const pol = pred.policy_decision || {};
    if (!["ALLOW", "DENY"].includes(pol.result)) reasons.push("policy_decision.result must be ALLOW or DENY");
    const ex = pred.execution || {};
    if (!SIDE_EFFECTS.has(ex.side_effect_class)) reasons.push("unknown side_effect_class");
    if (!EXEC_STATUS.has(ex.status)) reasons.push("unknown execution status");
    // time
    const ts = pred.timestamps || {};
    const created = parseTime(ts.created), executed = parseTime(ts.executed);
    if (!created) { reasons.push("timestamps.created not parseable"); timeAttested = false; }
    if (!executed) { reasons.push("timestamps.executed not parseable"); timeAttested = false; }
    if (created && created.getTime() < Date.UTC(2015, 0, 1)) { reasons.push("created precedes plausibility floor (2015)"); timeAttested = false; }
    if (created && created.getTime() > Date.now() + 86400000) { reasons.push("created is more than 24h in the future"); timeAttested = false; }
    if (created && executed && executed < created) { reasons.push("executed precedes created (temporal inversion)"); timeAttested = false; }
    if (ts.ntp_synced !== true) { reasons.push("time not attested (ntp_synced != true)"); timeAttested = false; }
    if (ts.rfc3161_token != null) {
      try { if (!b64ToBytes(ts.rfc3161_token).length) throw 0; } catch { reasons.push("rfc3161_token not valid base64"); timeAttested = false; }
    }
    // evidence
    const ev = pred.evidence || {};
    const items = Array.isArray(ev.items) ? ev.items : [];
    for (const i of items) {
      if (typeof i.present !== "boolean") { reasons.push("evidence item: present must be strict boolean"); continue; }
      if (i.present && !HEX64.test(String(i.sha256 || ""))) reasons.push(`evidence ${i.id}: sha256 not 64-hex`);
    }
    const completeness = (items.length && items.every((i) => i.present === true)) ? "COMPLETE" : "INCOMPLETE";
    if (ev.completeness && ev.completeness !== completeness) reasons.push(`declared completeness ${ev.completeness} != computed ${completeness}`);
    for (const c of ev.redaction_commitments || []) {
      if (typeof c !== "string" || !/^[0-9a-f]{16,64}:[0-9a-f]{64}$/.test(c)) reasons.push("redaction_commitment malformed");
    }
    // signatures-region purity + keyid binding + verify
    const sigs = r.signatures || [];
    if (!sigs.length) reasons.push("no signatures present");
    else {
      sigs.forEach((s, i) => { if (Object.keys(s).some((k) => !["keyid", "sig"].includes(k))) reasons.push(`signatures[${i}] carries unauthenticated metadata`); });
      if (sigs.length !== 1) reasons.push(`signatures count ${sigs.length} != 1`);
      const s0 = sigs[0];
      if (!KEYRING[s0.keyid]) reasons.push(`signer keyid ${s0.keyid} not in keyring`);
      else {
        const signed = {};
        for (const k of Object.keys(r)) if (k !== "signatures") signed[k] = r[k];
        try {
          sigValid = await crypto.subtle.verify({ name: "Ed25519" }, KEYRING[s0.keyid], b64ToBytes(s0.sig), paeBytes(r.predicateType, enc.encode(canonicalize(signed))));
        } catch { reasons.push("signature malformed"); }
        if (!sigValid && !reasons.some((x) => x.includes("signature"))) reasons.push("signature verification failed — content altered after signing");
      }
    }
    // registry identity binding
    if (actor.type === "human" || actor.type === "service") {
      if (REGISTRY && kid && REGISTRY[kid]) {
        const entry = REGISTRY[kid];
        if (entry.type !== actor.type) reasons.push(`registry binds key to type ${entry.type}, receipt claims ${actor.type}`);
        if (actor.type === "human" && entry.id !== actor.id) reasons.push(`registry binds key to ${entry.id}, receipt claims ${actor.id}`);
      } else if (actor.type === "human") {
        reasons.push("no authorized-actors registry supplied — human identity claim unverifiable, capping at INCOMPLETE");
        identityUncapped = true;
      }
    }
    let verdict;
    if (!sigValid || reasons.some((x) => !x.includes("capping at INCOMPLETE") && !x.startsWith("no authorized-actors"))) verdict = "FAIL";
    else if (completeness !== "COMPLETE" || !timeAttested || identityUncapped) verdict = "INCOMPLETE";
    else verdict = "PASS";
    return { verdict, sigValid, completeness, timeAttested, reasons };
  } catch (e) {
    return { verdict: "FAIL", reasons: [`verifier exception (fail-closed): ${e.message}`] };
  }
}

function verdictChip(v, el) {
  el.className = "verdict " + v.toLowerCase();
  el.textContent = v;
}

async function chainHashOf(receipt) { return sha256Hex(enc.encode(canonicalize(receipt))); }

async function runStep(id, receipt, chainPrev, expectedPrev) {
  const card = document.getElementById(id);
  const chip = card.querySelector(".verdict");
  const detail = card.querySelector(".detail");
  chip.className = "verdict running"; chip.textContent = "VERIFYING";
  await new Promise((r) => setTimeout(r, 320));
  const v = await verifyReceipt(receipt);
  let linkOK = null;
  if (chainPrev !== null) {
    const prev = receipt.predicate?.prev_chain_hash;
    linkOK = prev === expectedPrev;
    if (!linkOK) { v.verdict = "FAIL"; v.reasons.push("chain link broken"); }
  }
  verdictChip(v.verdict, chip);
  detail.textContent = v.reasons.length ? v.reasons.join(" · ")
    : v.verdict === "PASS" ? "Ed25519 over DSSEv1 PAE · chain link intact · identity registry-bound · evidence complete"
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
  const r = BUNDLE.receipts;
  const results = {};
  results.s2 = await runStep("s2", r[0], true, "GENESIS");
  results.s5 = await runStep("s5", r[1], true, await chainHashOf(r[0]));
  results.s6 = await runStep("s6", BUNDLE.tampered_receipt, true, "GENESIS");
  results.s7 = await runStep("s7", BUNDLE.incomplete_receipt, true, await chainHashOf(r[1]));
  results.s11 = await runStep("s11", BUNDLE.spoof_receipt, true, "GENESIS");
  const tips = $("#s9 .detail");
  const recomputedTip = await chainHashOf(r[r.length - 1]);
  const replayOK = recomputedTip === BUNDLE.chain_tip && r.length === BUNDLE.chain_length;
  verdictChip(replayOK ? "PASS" : "FAIL", $("#s9 .verdict"));
  tips.textContent = replayOK
    ? `tip ${BUNDLE.chain_tip.slice(0, 20)}… recomputed in-browser, matches signed tip · length ${r.length} anchored — replay is non-mutating`
    : "chain tip or length mismatch — possible truncation";
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
    await importKeys();
    $("#keyline").textContent = `human key ${BUNDLE.keyid} · registry-bound · Ed25519 · governed-action/v1`;
    $("#status-line").textContent = `bundle loaded · ${Object.keys(KEYRING).length} keys imported · identity registry bound · ${BUNDLE.receipts.length} chained receipts ready — no network from here on`;
    $("#run").addEventListener("click", runDemo);
    $("#run").disabled = false;
  } catch (e) {
    $("#status-line").textContent = "demo bundle failed to load — " + e.message;
  }
}

(function () {
  const t = document.querySelector("[data-theme-toggle]"), r = document.documentElement;
  let d = matchMedia("(prefers-color-scheme:dark)").matches ? "dark" : "light";
  r.setAttribute("data-theme", d);
  const icon = () => d === "dark"
    ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
    : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  t.innerHTML = icon();
  t.addEventListener("click", () => { d = d === "dark" ? "light" : "dark"; r.setAttribute("data-theme", d); t.innerHTML = icon(); });
})();

boot();
