# Daybreak Blue S2 — Independent Adversarial Review (Claude)

**Scope:** `tools/receipt_lib.py` (verify_receipt, verify_chain, canonical, pae, FlightRecorder) against the claim that a GovernedAction/v1 receipt "cannot be made to verify as PASS when its contents are tampered, incomplete, backdated, or identity-spoofed."

**Baseline:** existing suite `tests/adversarial_suite.py` re-run → 16/16 held (A1–A16 as designed). All findings below are NEW variants, each with a self-contained PoC in `daybreak/findings/poc_claude_<n>.py`, executed and printing `EXPLOIT-WORKS` before being claimed. PoCs were run on this checkout; every attack PoC printed EXPLOIT-WORKS, the PAE control (PoC 14) printed HELD.

---

## S2.1 Canonicalization confusion — **PASS-WITH-EXPLOIT**

**PoC:** `poc_claude_11.py`

`canonical()` = `json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)`. json coerces non-string dict keys, so `canonical({1: "smuggled"}) == canonical({"1": "smuggled"})` — identical bytes. End-to-end: a receipt signed with an int-keyed nested dict verifies **PASS** after the key is swapped to a string; two Python-semantically-different predicates share one signature. Reachable through any in-memory producer path (everything except build_receipt itself is attacker-authorable); pure-JSON transports mask it because JSON parsing re-types the keys, but canonical() is not injective over the types it accepts. Supplementary probes (no separate PoC needed): `1` vs `1.0` stay distinct (safe); non-ASCII NFC/NFD byte-distinct (safe — A15's homoglyph class properly FAILs); **`canonical({"a": float("nan")})` emits `NaN` / `Infinity` — non-strict JSON a strict consumer (cross-language verifier, archive tooling) will reject, a secondary integrity hazard.**

## S2.2 PAE length-prefix manipulation — **HELD**

**PoC (control):** `poc_claude_14.py`

DSSEv1 PAE as implemented is injective: both fields length-prefixed with canonical decimal `str(len)` (no leading zeros/negatives possible), so payload bytes can never be re-parsed as header. Swept 8 adversarial (type, payload) pairs — types with trailing spaces, payloads with leading spaces, nested-PAE payloads, types that look like PAE text, NUL-appended payloads: 7 unique encodings from 8 pairs (one exact duplicate), zero collisions, zero cross-verification. **Held by construction, not by luck.**

## S2.3 Signature malleability / cross-context replay — **PASS-WITH-EXPLOIT**

**PoCs:** `poc_claude_3.py` (cross-fork replay), `poc_claude_8.py` (keyid unbound)

Ed25519 itself is non-malleable and transplant across receipts/keys/types holds (A2/A3/A16). But two context bindings are absent:
- **No chain identity.** Receipts carry only `prev_chain_hash`. Any two forks sharing a parent hash are interchangeable: `[r1, r2_alt]` from an abandoned fork verifies with `all_links_valid=True` exactly like the true `[r1, r2]`. Replay "from a different chain" is undetectable whenever the chains share ancestry.
- **keyid is unauthenticated metadata.** `verify_receipt` never compares `sigs[0]["keyid"]` to `keyid(public_key)` and emits no reason on mismatch. A receipt claiming a *different signer's* keyid PASSes silently — any tooling that resolves/log trust by embedded keyid is ratifying a lie.

## S2.4 Chain manipulation — **PASS-WITH-EXPLOIT**

**PoCs:** `poc_claude_1.py` (empty chain), `poc_claude_2.py` (tail truncation), `poc_claude_3.py` (fork splice)

Intra-chain splice (A9) and forged genesis (A10) hold because each receipt's signature binds its own declared `prev_chain_hash`. But `verify_chain` has **no notion of expected length, tip hash, or total ordering beyond pairwise**:
- `verify_chain([])` → `all_links_valid=True` (`all([])` is vacuously true). Suppress the whole log, get a truthy "valid".
- Truncating the newest receipts — exactly the ones an attacker wants gone — validates clean: `[r1]` of `[r1,r2,r3]` → `all_links_valid=True`. Pairwise linkage proves N follows M-1, never that N is the last receipt that existed.
- Fork-splice (above) means the shown lineage need not be the real one even at full length.

## S2.5 Evidence-completeness gaming — **PASS-WITH-EXPLOIT (variant)**

**PoC:** `poc_claude_6.py`

L1 as coded is a **present-flag law, not an evidence law**: `completeness = COMPLETE iff items and all(i.get("present"))`. The offline verifier necessarily can't fetch artifacts — and doesn't even require the hash field be well-formed — so `present: true` with a sha256 of bytes that were never produced by any system is COMPLETE and PASSes. Fabricated evidence passes; *missing* evidence still correctly yields INCOMPLETE (A4/A5 hold). The claim's "incomplete ⇒ never PASS" holds only for receipts that honestly set `present: false`.

## S2.6 Verifier-output manipulation (headline) — **PASS-WITH-EXPLOIT**

**PoCs:** `poc_claude_1.py`, `poc_claude_2.py`, `poc_claude_5.py`, `poc_claude_12.py`, `poc_claude_13.py`

Seven distinct ways the offline verifier outputs a passing-looking result on data that should not pass:
1. Empty bundle → `all_links_valid=True` (PoC 1).
2. Truncated bundle → `all_links_valid=True` (PoC 2).
3. Substituted fork lineage → `all_links_valid=True` (PoC 3).
4. Receipt with **no actor, no action_id, no policy_decision, no execution** → verdict **PASS** with empty reasons (PoC 5). verify_receipt enforces presence of nothing but a signature, non-empty present-true evidence, and ntp_synced.
5. **All-INCOMPLETE chain → `all_links_valid=True`** (PoC 13): verify_chain's `ok` admits `verdict in ("PASS","INCOMPLETE")`, so a bundle with zero complete receipts reports links/verdicts "valid".
6. **Type-confused poison receipt crashes the verifier** (PoC 12): `"timestamps": "a string"` → `AttributeError` inside verify_receipt; inside verify_chain it aborts the entire run at that index — one planted receipt denies verification of every receipt in the batch. No FAIL verdict, just an exception.
7. Lying keyid → PASS without a mismatch reason (PoC 8).

Root cause of 4–6: verify_receipt validates only what it checks; the GovernedAction/v1 mandatory-field schema exists nowhere in code, and `pred.get(...).get(...)` chains assume types. Defense in depth fails at the first unexpected shape.

## S2.7 Redaction vs integrity — **PASS-WITH-EXPLOIT (unenforced design)**

**PoC:** `poc_claude_10.py`

`redaction_commitments` are signed into the predicate but verify_receipt contains **zero logic over them**: garbage commitments (`["GARBAGE", {"salt":"x","sha256":"not-a-hash"}, 42]`) PASS with empty reasons. There is no commitment format, no salt-hash recomputation, no count binding to evidence items. Consequence: the "salted hash commitments" design provides an auditor no evidence about *what* was redacted; nothing distinguishes "PII fields hidden" from "exculpatory log removed" — the auditor proves only that the signer committed to *something*. The committed hash is also unbound to any retrievable artifact, so even honest commitments are unverifiable offline.

## S2.8 Human-principal spoofing — **PASS-WITH-EXPLOIT**

**PoCs:** `poc_claude_4.py` (case-variant type), `poc_claude_5.py` (absent actor)

The verify-side L3 gate is `actor.get("type") == "human"` — **case-sensitive, exact-string**. Receipts are attacker-authorable (the signer holds the key; build-side L3 is `assert`-based and vanishes under `python -O` anyway — supplementary check confirmed the verify-side gate is all that holds under `-O`). A service account mints `actor.type="Human"`, `auth_method="api_key"`, `is_service_account=true`, **no human_principal** → L3 never fires → **PASS**. Any case-insensitive downstream consumer or human reader sees a human actor with API-key auth — the Art.12(3)(d) accountability claim is inverted. The fully absent-actor variant (PoC 5) PASSes a receipt with no principal at all. Classic combinations (exact "human" + api_key / is_service_account=false / empty human_principal) still FAIL via A6–A8. No enumeration or type check exists on `actor.type` — any non-"human" string opts out of the law entirely.

## S2.9 Time manipulation — **PASS-WITH-EXPLOIT**

**PoC:** `poc_claude_7.py`

L4 pins only the **self-attested boolean** `ntp_synced is True`. A receipt claiming `created=1999-01-01` with `ntp_synced: true` — and a garbage `rfc3161_token` — **PASSes** with `time_attested=True`. verify_receipt never compares created/executed to anything (it can't, offline) and contains no code path that validates an RFC 3161 token even though build_receipt emits one. So: backdating/future-dating passes whenever the signer writes the const; the signer *is* the clock. A11 (ntp_synced=false → INCOMPLETE) holds but gates only honest signers. Genuine fix requires verifying the TSA token against the sig payload at verify time; the plumbing exists on the build side and is dead on the verify side.

## S2.10 Denial-of-receipt (availability) — **PASS-WITH-EXPLOIT**

**PoCs:** `poc_claude_9.py` (torn write), `poc_claude_12.py` (poison receipt)

- **FlightRecorder has append-durability but no read-recovery.** `read_all()` does `json.loads(f.read(n))` with no short-read/JSON guard; a crash mid-append (or one flipped length prefix plus partial blob) raises `JSONDecodeError` and **every receipt in the ledger — including fully intact, validly signed ones before the tear — becomes unreadable/unverifiable.** L5's flock+fsync protects the write path; nothing truncates-tolerates the read path.
- **Verifier-side availability:** PoC 12's type-confused receipt aborts verify_chain outright. An attacker who can plant one record denies the audit of all records.

---

## Top 3 confirmed findings (ranked by what a CISO exploits first)

1. **The chain has no length, tip, or identity binding — history can be silently erased or swapped while `all_links_valid=True`.** Empty chain (PoC 1), tail-truncated chain (PoC 2), and fork-substituted lineage (PoC 3) all validate. This defeats the *core* claim: an insider's last action — the one worth hiding — is precisely what truncation removes, and no field pins "how many receipts must exist" or "which tip is real." Fix: sign/attest a chain head checkpoint (length + tip hash) per epoch and require verify_chain to bind to it; `verify_chain([])` must report invalid.

2. **L3 (human-principal) law is bypassable by one capital letter — accountability is forgeable.** `actor.type="Human"` + `auth_method="api_key"` + no `human_principal` → PASS (PoC 4); a receipt with no actor at all → PASS (PoC 5). Build-side L3 lives in `assert`s that disappear under `-O`; verify-side is a case-sensitive string compare with no type enumeration and no mandatory-field schema. An api_key-authenticated service produces receipts any auditor reads as human actions. Fix: enforce a closed enum for `actor.type` (lowercase, validated), apply human/service invariants to *every* receipt, and reject receipts missing any schema-mandatory predicate field.

3. **Evidence "completeness" is a self-asserted flag, and redaction commitments are unverified — fabricated or exculpatory-stripped evidence PASSes.** `present: true` + hash-of-nothing → COMPLETE/PASS (PoC 6); garbage `redaction_commitments` PASS with no reason (PoC 10); combined with unvalidated `rfc3161_token` and self-attested `ntp_synced` (PoC 7), every substantive claim in the receipt — *that evidence exists, that redaction was narrow, that time was real* — is signer-asserted and merely countersigned. The signature attests bytes, and the bytes attest nothing. Fix: verify-side validation of rfc3161 tokens against the signed payload, a normative redaction-commitment format checked against evidence items, and an honest schema note that COMPLETE means "flags claim presence," backed by an evidence-availability protocol for auditors.

**Runners-up:** FlightRecorder torn-write makes the whole ledger unreadable (PoC 9) and one type-confused receipt crashes batch verification (PoC 12) — together they let a single planted record deny an entire audit.

*Method note: every PASS-WITH-EXPLOIT above was executed on this checkout and printed `EXPLOIT-WORKS`; the PAE class (S2.2) printed `HELD`. No finding is asserted without its PoC.*
