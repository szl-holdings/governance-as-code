# Daybreak Blue — Alpha Round: v2 Adversarial Review (findings2)

**Target:** `tools/receipt_lib.py` v2 line (F1–F8 hardening after the 37 v1 PoCs).
**Method:** 17 self-contained PoCs (`poc_alpha_<n>.py`), each importing the live
library and printing `EXPLOIT-WORKS` / `HELD`. Every PoC was executed before
being claimed. Signer-adversary model (mutate + recompute digest + re-sign)
matches the v1 reviews; several vectors need no key at all.
**Co-evolution note:** fixes landed during the review window (v2.0 01:31 →
v2.2 13:19 → v2.3, md5 `22ebf7a3…`). "Confirmed" = printed EXPLOIT-WORKS on
the named earlier revision; "Final" = verdict on v2.3 end-of-review.
**Final state: 16/17 HELD on v2.3; poc_alpha_4 is the documented residual.**

## Per-attack verdicts

| PoC | Class | Attack | Confirmed on | Closing fix (v2.3) | Final |
|-----|-------|--------|--------------|--------------------|-------|
| 1 | Availability / F6 | One receipt with timezone-naive `created` ("2026-08-31T08:00:00", date-only) crashes `verify_chain` — `cur < prev_created` naive-vs-aware TypeError outside any guard. Keyless; F6's "never a batch crash" broken | v2.0, v2.2 | Strict `RFC3339_STRICT` in `_parse_time` → naive strings return `None`, no comparison occurs | HELD |
| 2 | Availability / F6 | `chain_hash` crash guard was applied only to the main loop: keyring-miss branch still crashed on (B1) NaN content (reachable via `json.loads`) and (B2) unhashable list `chain_id`. Keyless batch DoS on the multi-signer path | v2.2 | v2.3 hardened the branch (guarded hash + isinstance checks) | HELD |
| 3 | Logic / chain_id | Honest default-built 3-hop chain rejected as "fork splice" — non-genesis `chain_id = prev_chain_hash[:16]` gave every hop a different id | v2.0 | `chain_id` mandatory for non-genesis, fail-loud `ValueError` at build | HELD |
| 4 | Chain equivocation | Same-chain double-sign fork: r2a/r2b share parent and constant chain_id; cover-up fork verifies `all_links_valid=True`, `identity_bound=True`, equivocation undetectable by construction (chain_id is a uniformity label, never recomputed) | v2.0–v2.3 | **Residual** — chain_id absence now fails (variant B held); same-chain equivocation is documented as requiring out-of-band anchor (`expected_tip`/`min_length`) per F6 disclosure | **RESIDUAL** |
| 5 | Time / F1 | Plausibility window (2015 floor, +24h) applied only to `created`; `executed="9999-12-31"` PASSed with `time_attested=True` | v2.0–v2.2 | `executed` floor + future window added ("alpha PoC-5") | HELD |
| 6 | Registry | Service-actor `id` unbound: registry key enrolled as `svc-backup-agent` signed as `svc-payments-deployer` → PASS (id check was human-only) | v2.0 | id-binding extended to both types (beta PoC-1 fix) | HELD |
| 7 | Registry | Anonymous-human wildcard: receipt with no `actor.id` + registry row with no `id` → `None == None` vacuous bind → PASS | v2.0–v2.2 | `actor.id` and registry-entry `id` presence both hard-fail ("alpha PoC-7") | HELD |
| 8 | Governance semantics | Stock builder minted policy `DENY` + status `EXECUTED`; verifier PASSed a self-contradictory breach record with empty reasons | v2.0–v2.2 | Cross-check on both sides: build asserts; verify hard-fails ("alpha PoC-8") | HELD |
| 9 | Time / RFC3339 | `fromisoformat` accepted non-RFC3339 forms — ISO week dates, basic format, comma fractions, space separator — all PASSed; cross-implementation verdict divergence on signed audit bytes | v2.0–v2.2 | `RFC3339_STRICT` regex gate ("alpha PoC-9") | HELD |
| 10 | F4 half-fix | `present: 1`/`0` passed the "strict boolean" gate silently (`1 in (True, False)` is `==`-true); build (truthiness) vs verify (`is True`) disagreed on the same receipt's completeness | v2.0–v2.2 | `type(...) is bool` on both sides | HELD |
| 11 | Registry supply-chain | `yaml.safe_load` resolved duplicate keyid rows silently (last-wins); an append-only attacker shadowed a key's identity binding with no error | v2.0–v2.2 | NoDupLoader raises on duplicate keys ("alpha PoC-11") | HELD |
| 12 | chain_id derivation | Genesis seed deterministic over predictable fields (no key/time/environment): independent staging/prod chains emitted identical chain_ids — "lineage id" couldn't identify a lineage | v2.0–v2.2 | Seed now includes `created`, policy result, side-effect class | HELD |
| 13 | Availability / F7 | Torn-tail guard caught only `JSONDecodeError`: a complete invalid-UTF-8 frame crashed `verify_integrity()` and `read_all(tolerate_torn=True)` with uncaught `UnicodeDecodeError`; earlier v2.0 also silently shadowed all post-tear appends while ACKing them | v2.0–v2.2 | v2.3: loud `MidFileCorruption` default + offset reporting; exception-type hole closed | HELD |
| 14 | F7 contract | `verify_integrity()` raised `ValueError` on magic/header corruption (the most common real corruption) instead of reporting records/corruption as F7 states | v2.0–v2.3 | Closed in final v2.3 pass | HELD |
| 15 | structural_fail prefix net | "declared completeness X != computed Y" missed the prefix tuple → advisory-only; a signed lie in the normative field PASSed (reason present, verdict PASS) | v2.0–v2.2 | Prefix classification replaced by explicit `hard_fail` flag ("alpha PoC-15/16") | HELD |
| 16 | INCOMPLETE-vs-FAIL boundary | `executed` unparseable, `items` non-list, and garbage `rfc3161_token` all slipped the prefix net → soft INCOMPLETE where `created`-garbage hard-FAILed — asymmetric fail-closed-ness | v2.0–v2.2 | Same `hard_fail` refactor; all three now FAIL | HELD |
| 17 | F7/v2.2 append path | (a) New under-lock fork check skipped whenever the appended receipt claimed `prev_chain_hash == "GENESIS"` (or omitted it) — mid-ledger fork appended with LOCAL_ACK; (b) one NaN-bearing frame (valid to `json.loads`) bricked every future `append()` via unguarded `canonical(json.loads(last))` — write-path DoS while reads kept working | v2.2 | Closed in final v2.3 pass | HELD |

## Top-3 severity (as confirmed at time of exploitation)

1. **Keyless denial of the entire audit (PoCs 1, 2).** F6's headline promise —
   "a poison receipt yields per-receipt FAIL, never a batch crash" — was broken
   by three independent paths: the naive-vs-aware datetime compare in the new
   temporal check, and the unguarded `chain_hash`/`chain_ids.add` in the
   keyring-miss branch. One planted record (no key, no valid signature needed)
   threw an uncaught exception out of `verify_chain`, denying verdicts for every
   receipt in the batch — exactly the outcome v2 claimed to have eliminated.
2. **chain_id lineage defense void in both directions (PoCs 3, 4, 12).** The
   flagship F6 fix false-positived on the library's own honest chains
   (per-hop id derivation), could not see same-chain equivocation in the only
   configuration that verifies (uniform caller-supplied id), and collided
   deterministically across independent chains. PoC 4 is the standing residual:
   fork detection within one lineage requires the out-of-band anchor the F6
   disclosure names — without it, a double-signing signer shows the auditor a
   cover-up fork that verifies clean.
3. **PASS verdicts on false or contradictory content (PoCs 5, 6, 7, 8).** The
   one-sided time window PASSed a receipt "executed" in year 9999; the registry
   bound service keys to the *string* "service" rather than to an identity
   (PoC 6) and vacuously bound anonymous humans (PoC 7); and a receipt
   recording "policy DENIED this irreversible action AND it EXECUTED" — the
   single event a governed-action receipt exists to surface — PASSed with zero
   reasons (PoC 8), minted by the stock builder itself.

**Runner-ups:** NaN-frame write-path brick + GENESIS-claim fork-check bypass
(PoC 17) and the invalid-UTF-8 integrity-report crash (PoC 13) — availability
of the ledger itself; YAML duplicate-key registry shadowing (PoC 11) —
supply-chain confusion in the trust anchor.

## Bottom line

v2 closed the v1 semantic hole classes structurally, but this round showed the
fixes themselves introduced new edges: an unguarded comparison in the new
temporal check, a half-hardened keyring branch, a prefix-string verdict
classifier with holes, and a chain_id scheme that was simultaneously
over-broad (rejected honest chains) and under-broad (blind to same-chain
forks). All 17 were demonstrated running against the checkout; v2.3 closes 16,
with same-chain equivocation (poc_alpha_4) standing as the documented residual
pending anchored verification (signed chain-head checkpoints / transparency
log), consistent with the F6 disclosure that unanchored verification is
internal-consistency-only.
