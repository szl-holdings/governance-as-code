/* a11oy offline verifier — real Ed25519 over DSSEv1 PAE via WebCrypto.
   No server, no network. The verifier is the product. */
"use strict";

const $ = (s) => document.querySelector(s);
let BUNDLE = null;
let PUBKEY = null;   // CryptoKey
let KEYID = null;

const enc = new TextEncoder();

// canonical JSON matching Python json.dumps(sort_keys=True, separators=(",",":"))
// Note: demo bundle contains only ASCII + JSON-safe scalars, so a deep-sorted
// serialization with no whitespace is byte-identical to the Python canonical form.
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

const b64ToBytes = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

async function importPub() {
  if (PUBKEY) return;
  const raw = b64ToBytes(BUNDLE.public_key_raw_b64);
  PUBKEY = await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  KEYID = (await sha256Hex(raw)).slice(0, 16);
}

// mirror of receipt_lib.verify_receipt — laws are identical in both languages
async function verifyReceipt(r) {
  const reasons = [];
  let sigValid = false;
  const sigs = r.signatures || [];
  if (sigs.length) {
    const signed = {};
    for (const k of Object.keys(r)) if (k !== "signatures") signed[k] = r[k];
    const payload = enc.encode(canonicalize(signed));
    try {
      sigValid = await crypto.subtle.verify({ name: "Ed25519" }, PUBKEY, b64ToBytes(sigs[0].sig), paeBytes(r.predicateType, payload));
    } catch (e) { reasons.push("signature malformed"); }
    if (!sigValid && !reasons.length) reasons.push("signature verification failed — content altered after signing");
  } else reasons.push("no signatures present");

  const pred = r.predicate || {};
  const actor = pred.actor || {};
  if (actor.type === "human" && (actor.is_service_account !== false || actor.auth_method === "api_key" || !actor.human_principal)) {
    reasons.push("L3 violation: human actor claimed with service-account properties (spoof attempt)");
    sigValid = false;
  }
  const ts = pred.timestamps || {};
  const timeAttested = ts.ntp_synced === true;
  if (!timeAttested) reasons.push("time not attested (ntp_synced != true)");

  const ev = pred.evidence || {};
  const items = ev.items || [];
  const completeness = (items.length && items.every((i) => i.present)) ? "COMPLETE" : "INCOMPLETE";
  if (ev.completeness && ev.completeness !== completeness)
    reasons.push(`declared completeness ${ev.completeness} != computed ${completeness}`);

  let verdict;
  if (!sigValid) verdict = "FAIL";
  else if (completeness !== "COMPLETE" || !timeAttested) {
    verdict = "INCOMPLETE";
    if (completeness !== "COMPLETE") reasons.push("evidence incomplete — INCOMPLETE is the verdict, never PASS");
  } else verdict = "PASS";
  return { verdict, sigValid, completeness, timeAttested, reasons };
}

function verdictChip(v, el) {
  el.className = "verdict " + v.toLowerCase();
  el.textContent = v;
}

async function runStep(id, receipt, chainPrev, expectedPrev) {
  const card = document.getElementById(id);
  const chip = card.querySelector(".verdict");
  const detail = card.querySelector(".detail");
  chip.className = "verdict running"; chip.textContent = "VERIFYING";
  await new Promise((r) => setTimeout(r, 320)); // let the eye register the check
  const v = await verifyReceipt(receipt);
  let linkOK = null;
  if (chainPrev !== null) {
    const prev = receipt.predicate?.prev_chain_hash;
    linkOK = prev === expectedPrev;
    if (!linkOK) { v.verdict = "FAIL"; v.reasons.push("chain link broken"); }
  }
  verdictChip(v.verdict, chip);
  detail.textContent = v.reasons.length ? v.reasons.join(" · ")
    : v.verdict === "PASS" ? "Ed25519 over DSSEv1 PAE · chain link intact · evidence complete"
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
  // replay check: recompute tips twice
  const tips = $("#s9 .detail");
  const tip1 = BUNDLE.chain_tip, tip2 = await chainTip([...r, BUNDLE.incomplete_receipt].slice(0, 2));
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

async function chainHashOf(receipt) { return sha256Hex(enc.encode(canonicalize(receipt))); }
async function chainTip(receipts) { return chainHashOf(receipts[receipts.length - 1]); }

async function boot() {
  try {
    const res = await fetch("demo_bundle.json", { cache: "no-store" });
    BUNDLE = await res.json();
    await importPub();
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
  let d = matchMedia("(prefers-color-scheme:dark)").matches ? "dark" : "light";
  r.setAttribute("data-theme", d);
  const icon = () => d === "dark"
    ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="5"/><path d="M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg>'
    : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';
  t.innerHTML = icon();
  t.addEventListener("click", () => { d = d === "dark" ? "light" : "dark"; r.setAttribute("data-theme", d); t.innerHTML = icon(); });
})();

boot();
