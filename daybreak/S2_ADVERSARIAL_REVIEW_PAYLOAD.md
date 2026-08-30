# Daybreak Blue — S2 Adversarial Cryptographic Review Payload

**Authorization context:** First-party defensive review of SZL Holdings' own
receipt library. Scope: vulnerability discovery and secure code review of
`tools/receipt_lib.py` and `tests/adversarial_suite.py`. Out of scope: any
offensive tradecraft, third-party targets, exploit development.

## The claim under attack

"A GovernedAction/v1 receipt, signed with Ed25519 over DSSEv1 PAE and
hash-chained via prev_chain_hash, cannot be made to verify as PASS when its
contents are tampered, incomplete, backdated, or identity-spoofed."

## Source under review

Repo: https://github.com/szl-holdings/governance-as-code
- `tools/receipt_lib.py` — signing, PAE, chain, verify_receipt, FlightRecorder
- `tests/adversarial_suite.py` — the 16 attack classes we already hold

## Required attacks (enumerate each; for each, produce working PoC or state why it fails)

### S2.1 Canonicalization confusion
Can two semantically different receipt objects serialize to the same canonical
bytes? Probe JSON number formatting, unicode normalization, key ordering, and
nested empty structures against `canonical()`.

### S2.2 PAE length-prefix manipulation
DSSEv1 PAE uses decimal lengths with space separators. Can a crafted
payload_type or payload length field cause two different (type, payload) pairs
to PAE-encode identically?

### S2.3 Signature malleability / cross-context replay
Given a valid (receipt, signature, pubkey) triple, produce a different receipt
that verifies. Include: signature transplant across chain positions, replay of
a receipt from a different chain, and key-substitution where the verifier
trusts an embedded keyid rather than an out-of-band key.

### S2.4 Chain manipulation
Splice, reorder, truncate, or extend the chain. Can a verifier be convinced
that receipt N follows receipt M when it does not? Can a forged GENESIS link
be injected without detection by `verify_chain`?

### S2.5 Evidence-completeness gaming
The law is: missing evidence ⇒ INCOMPLETE, never PASS. Find any construction
where a receipt with absent or fabricated evidence produces PASS. Include
`present: true` with a sha256 that does not match anything real.

### S2.6 Verifier-output manipulation (the S2 headline)
Enumerate every way that an auditor's offline verifier could be made to output
PASS on a tampered or incomplete bundle. This is the question a CISO will ask.

### S2.7 Redaction vs integrity
If PII is redacted from evidence before signing, how does an auditor know the
redaction did not also remove exculpatory evidence? Evaluate the
`salted hash commitments` design and propose attacks on it.

### S2.8 Human-principal spoofing
`is_service_account` is pinned false for human actors. Can a service account
produce a receipt that claims a human principal? Probe every field
combination, including type confusion between `"human"`/`"service"` and
missing/extra keys.

### S2.9 Time manipulation
`ntp_synced` is `const: true`. Can a receipt with a backdated or future
timestamp pass? What breaks if the signer controls the clock?

### S2.10 Denial-of-receipt (availability)
Can an attacker prevent a legitimate receipt from being written or verified?
FlightRecorder uses flock + fsync; probe crash-recovery and partial writes.

## Output format

For each attack: PASS-WITH-EXPLOIT (working PoC) or HELD (why it fails).
Then: the three highest-severity findings, ranked by what a CISO would
exploit first. No softening.
