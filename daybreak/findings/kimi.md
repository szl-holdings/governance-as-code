# Daybreak Blue — S2 Adversarial Review: kimi findings

**Scope:** `tools/receipt_lib.py` (GovernedAction/v1, Ed25519/DSSEv1 PAE,
prev_chain_hash chain, FlightRecorder) against `tests/adversarial_suite.py`
(16/16 held at baseline; confirmed by re-run).
**Method:** each candidate attack has a runnable PoC under
`daybreak/findings/poc_kimi_<n>.py`; every PoC was executed and printed
`EXPLOIT-WORKS` (unexpected PASS / all_links_valid / silent data loss /
verifier crash) or `HELD`. Only PoCs that ran and printed `EXPLOIT-WORKS`
are claimed below.
**Framing note:** several exploits require signing capability (a compromised,
buggy, or off-library signer). That is in-scope: the suite's own A12 and A5
tests exercise signer-side construction, the claim under attack says
"cannot be made to verify as PASS", and L1–L4 are declared as
laws "enforced here, not in prose" — the verifier must enforce them, because
auditors verify receipts they did not sign.

## Headline

11/11 PoCs printed EXPLOIT-WORKS. Every S2 class has at least one
PASS-WITH-EXPLOIT. The crypto core (Ed25519 over PAE, byte-exact
canonicalization) holds; the verifier's **semantic layer** — the part a CISO
actually relies on — is almost entirely unenforced.

## Per-class results

### S2.1 Canonicalization confusion — HELD
`canonical()` is deterministic byte-exact JSON (sorted keys, tight
separators, UTF-8). Probed: int-vs-string dict keys (`{1:"a"}` vs
`{"1":"a"}`) collide but `json.dumps` rejects mixed-type keys with
TypeError under `sort_keys=True`, so no signed object can exercise the
collision; `1` vs `1.0` serialize differently; NFC vs NFD strings serialize
differently and any post-signing NFC/NFD swap breaks the signature.
Homoglyph id (A15) already held. No same-bytes/different-semantics pair
found that a verifier could accept.

### S2.2 PAE length-prefix manipulation — HELD
PAE is unambiguous: the single space after the decimal length is part of the
grammar and lengths are byte counts, so delimiter smuggling is impossible
through `pae()`. A payload_type containing spaces still round-trips to a
unique encoding (length fields disambiguate). Cross-type confusion already
held (A3). No two distinct (type, payload) pairs PAE-encode identically.

### S2.3 Signature malleability / cross-context replay — PASS-WITH-EXPLOIT
PoCs: `poc_kimi_2.py`, `poc_kimi_10.py`
- **No chain identity / cross-chain replay (poc_kimi_2).** Receipts carry no
  chain ID and every chain roots at the literal string `"GENESIS"`. Two
  chains under the same key are indistinguishable: a receipt from chain B
  verifies PASS standalone (verify_receipt takes no chain context), and a
  full foreign chain handed to an auditor expecting chain A returns
  all_links_valid=True with no signal.
- **Keyid is unsigned and unchecked (poc_kimi_10).** `signatures` is
  excluded from the signed bytes and `sigs[0]["keyid"]` is never compared
  to the verification key. Because the tip's chain_hash is committed by no
  successor, the tip's keyid can be rewritten (`deadbeef…`) with no key
  material and the bundle still verifies PASS / all_links_valid=True —
  signer-attribution forgery on the newest record.
- (In-suite transplant A2 and wrong-key A16 still held.)

### S2.4 Chain manipulation — PASS-WITH-EXPLOIT
PoCs: `poc_kimi_1.py`, `poc_kimi_2.py`, `poc_kimi_3.py`
- **Empty chain (poc_kimi_1).** `verify_chain([])` returns
  `all_links_valid=True, tip="GENESIS"` — vacuous truth over zero receipts.
  An empty bundle "verifies".
- **Silent truncation (poc_kimi_3).** The recorder has no EOF marker, no
  count, no signed tip. Deleting the newest records (or truncating to the
  bare 24-byte magic) leaves a prefix that reads cleanly and verifies
  all_links_valid=True. The most recent — most incriminating — history is
  erasable without a trace in verifier output.
- Cross-position splice (A9) and single-receipt forged genesis (A10) held;
  the bypass is that `all_links_valid` also accepts INCOMPLETE members, and
  "GENESIS" is a universal, unlabeled root (see S2.3).

### S2.5 Evidence-completeness gaming — PASS-WITH-EXPLOIT
PoC: `poc_kimi_7.py`
- `present` is tested for **truthiness, not boolean**: `present: 1` and
  `present: "yes"` compute COMPLETE → PASS.
- An evidence item's sha256 is never compared to anything: a fabricated
  hash, an empty-string hash, or **no sha256 key at all** all PASS.
  `present: true` attests only that a dict exists. L1's "missing evidence ⇒
  INCOMPLETE" holds for the narrow cases the suite tested (A4/A5/A12) but is
  gameable by any signer that doesn't use `build_receipt`.

### S2.6 Verifier-output manipulation (headline) — PASS-WITH-EXPLOIT
PoCs: `poc_kimi_1.py`, `poc_kimi_5.py`, `poc_kimi_10.py`, `poc_kimi_11.py`
An auditor's offline verifier can be made to:
- output all_links_valid=True on an **empty bundle** (poc_kimi_1) or a
  **truncated bundle** (poc_kimi_3);
- **crash entirely** on one validly-signed poisoned record
  (`predicate`/`actor`/`timestamps`/`evidence` = null → uncaught
  AttributeError mid-verify, after signature verification succeeds), taking
  down the whole batch with no verdict for any receipt (poc_kimi_5);
- PASS a receipt whose **subject digest binds a different predicate** —
  the digest is signed but never recomputed; the suite's A14 only covered
  post-signing drift (held, because signatures cover the digest); signer-side
  mis-binding is unchecked, breaking the in-toto subject link any layout
  would consume (poc_kimi_11);
- PASS a receipt with a forged **keyid** (poc_kimi_10).

### S2.7 Redaction vs integrity — PASS-WITH-EXPLOIT
PoC: `poc_kimi_9.py`
`redaction_commitments` is a free-form list the verifier never parses or
cross-references: garbage commitments (`["not-a-commitment", 42, …]`) PASS,
absent commitments PASS, and an item whose exculpatory content was stripped
*before* hashing is indistinguishable from an honest item. As implemented,
the salted-hash commitment design provides **zero redaction accountability**
to an auditor.

### S2.8 Human-principal spoofing — PASS-WITH-EXPLOIT
PoC: `poc_kimi_6.py`
L3 is enforced as a strict-equality sieve `actor["type"] == "human"` and
nowhere else. All of the following verify PASS when built signer-side:
- (a) **actor key entirely absent** — anonymous governed action;
- (b) `type: "Human"` (case confusion) with `is_service_account: true`,
  `auth_method: api_key`, no human_principal — L3 never fires;
- (c) `type: ["human"]` (type confusion) with the same service properties;
- (d) `type: "service"` with `is_service_account: false` built at signing
  time — the suite's A7 tested post-signing tamper (held by the signature);
  the verifier enforces the service side of L3 nowhere;
- (e) `human_principal: " "` (whitespace-only) — truthy;
- (f) no `policy_decision` and no `execution` — an un-governed "governed
  action" still PASSes.
Control: a missing `timestamps` key correctly yields INCOMPLETE — the
asymmetry proves the missing-key handling is accidental, not designed.

### S2.9 Time manipulation — PASS-WITH-EXPLOIT
PoC: `poc_kimi_8.py`
`ntp_synced` is a self-asserted boolean; there is no freshness window, no
created-vs-executed ordering check, and `rfc3161_token` is never opened.
Receipts timestamped `1970-01-01` (with a garbage "RFC 3161 token") and
`9999-12-31` both PASS. The suite's A11 only flipped `ntp_synced` to false
post-signing. **A signer that controls its clock backdates freely — L4 is
honor-system.**

### S2.10 Denial-of-receipt (availability) — PASS-WITH-EXPLOIT
PoCs: `poc_kimi_4.py`, `poc_kimi_5.py`, `poc_kimi_3.py`
- **Torn write (poc_kimi_4).** A 4-byte length prefix promising bytes that
  never landed (crash mid-append or attacker-appended garbage) makes
  `read_all()` raise on `json.loads` — every record, including fully
  fsynced ones, becomes unreadable. Corrupting one byte of the magic does
  the same via AssertionError. No per-record checksum, no truncation
  tolerance, no recovery path: L5's "PENDING_SYNC is never hidden" fails —
  a torn append hides everything.
- **Verifier crash (poc_kimi_5).** One null-typed record DoSes the audit
  batch (see S2.6).
- **Silent truncation (poc_kimi_3).** Availability of recent history can be
  revoked retroactively without detection (see S2.4).

## Three highest-severity confirmed findings

1. **Silent truncation of the FlightRecorder / empty-chain vacuous PASS
   (poc_kimi_3 + poc_kimi_1).** An attacker (or a defendant's own ops team)
   deletes the newest receipts — or the whole log — and the auditor's
   verifier reports `all_links_valid=True`. This defeats the core
   evidentiary claim with *no key material, no signature forgery, and no
   error message*. It is the first thing a CISO's adversary does after an
   incident. Fix: per-record MACs or a signed genesis, a record count/EOF
   commitment, a signed tip checkpoint the verifier requires, and
   `verify_chain` must FAIL on length 0.
2. **Verifier trusts no semantic field it doesn't recompute — time (L4),
   evidence (L1), subject binding (poc_kimi_8 + poc_kimi_7 + poc_kimi_11).**
   Backdated/future receipts with self-asserted `ntp_synced` and garbage
   RFC-3161 tokens PASS; `present: 1`/`"yes"` and missing-or-fabricated
   sha256 PASS; a subject digest pointing at a different predicate PASSes.
   The auditor's PASS currently means "someone signed *something*" and
   nothing more. Any single one of these suffices to launder a fabricated
   record into a PASS bundle.
3. **L3 sieve: human-principal spoofing via absent/case/type-confused actor
   keys (poc_kimi_6).** `"Human"`, `["human"]`, a missing actor, or a
   service actor with `is_service_account: false` all PASS with service
   credentials and api_key auth. Art.12(3)(d) attribution — the regulatory
   point of the receipt — is void whenever the signer doesn't voluntarily
   use `build_receipt`. Fix: the verifier must require actor presence,
   normalize and type-check `type`, enforce both sides of L3, and require
   `policy_decision`/`execution` presence.

(Runner-up, would be #4: single poisoned record crashes the entire
verification batch — poc_kimi_5 — because `verify_receipt` does
`None.get(...)` after signature verification succeeds.)

## Bottom line on the claim under attack

The narrow claim — a *signed* receipt cannot be made to verify PASS when
*tampered after signing* — holds. The operational claim — a bundle an
auditor is handed attests what it appears to attest — **does not**: 11
working exploits, all reproduced above, produce PASS / all_links_valid=True
(or silent loss / total verifier failure) on tampered, incomplete,
backdated, truncated, spoofed, or poisoned data.
