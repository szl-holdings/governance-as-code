# Beta v2 Adversarial Review

## Top-3 Severity Findings

1. **Service Identity Forgery (PoC 1)**
   - **Verdict:** PASS
   - **Severity:** Critical
   - **Description:** The verifier checks that a service actor's `type` matches the `authorized_actors` registry, but fails to check if the actor's `id` matches. This allows any authorized service key to forge receipts claiming the identity of any other service account.

2. **Honest Chain Rejection via chain_id Lineage Logic (PoC 4)**
   - **Verdict:** FAIL (Unexpected rejection of honest chain)
   - **Severity:** High
   - **Description:** `build_receipt` sets `chain_id` to `prev_chain_hash[:16]` for non-GENESIS receipts. Since `prev_chain_hash` changes with every receipt, the `chain_id` changes as well. However, `verify_chain` enforces that a chain must have $\le 1$ unique `chain_id` (identity bound). This logic flaw causes `verify_chain` to reject any valid, honestly built chain longer than one receipt.

3. **Concurrent Append Permanently Breaks Chain Validity (PoC 5)**
   - **Verdict:** FAIL (Permanent DoS)
   - **Severity:** High
   - **Description:** In `FlightRecorder.append`, the canonicalization of the receipt occurs before acquiring the file lock. If two processes concurrently build receipts based on the same `prev_chain_hash` and append them, they will be written sequentially to the file. This creates a fork in the chain lineage stored in a single file, causing `verify_chain` to permanently fail on the broken link.

## Other Confirmed Findings

- **Silent Truncation via Mid-File Corruption in FlightRecorder (PoC 3)**
  - **Verdict:** EXPLOIT-WORKS (Data Loss)
  - **Description:** The "torn-tail tolerant reads" feature catches `json.JSONDecodeError` and treats it as a torn tail, silently stopping iteration. If corruption occurs in the middle of the file, all subsequent valid receipts are silently truncated without raising an integrity error.

- **policy_hash Semantic Confusion (PoC 9)**
  - **Verdict:** EXPLOIT-WORKS
  - **Description:** The GENESIS `chain_id` seed includes `policy_hash` but omits the policy `result` (ALLOW/DENY). Two receipts for the same action/actor/subject with opposite decisions but missing/identical `policy_hash` values will compute identical `chain_id`s, allowing them to be incorrectly spliced into the same chain.

- **False Anchoring via min_length=0 (PoC 8)**
  - **Verdict:** EXPLOIT-WORKS
  - **Description:** Providing `min_length=0` or `min_length=False` causes `len_ok` to remain `True` and sets `anchored=True`, successfully suppressing the "unanchored chain" warning without actually binding the chain's length or tip.

- **Batch Crash via unhashable chain_id (PoC 2)**
  - **Verdict:** EXPLOIT-WORKS (Crash)
  - **Description:** Supplying an unhashable type (e.g., a list) for `chain_id` crashes `verify_chain` with a `TypeError` when it attempts to add it to the `chain_ids` set. 

- **Batch Crash via UnicodeEncodeError on Surrogate (PoC 7)**
  - **Verdict:** EXPLOIT-WORKS (Crash)
  - **Description:** Python's `json.dumps` with `ensure_ascii=False` emits raw surrogates, causing `.encode("utf-8")` to crash with a `UnicodeEncodeError`. Because `verify_chain` calls `chain_hash()` without a try-except block, a single malicious receipt containing a surrogate crashes the entire batch verification.

- **Batch Crash via unhashable keyid in keyring (PoC 6)**
  - **Verdict:** EXPLOIT-WORKS (Crash)
  - **Description:** Providing an unhashable type (e.g., a list) for the signature's `keyid` causes a `TypeError` crash in `verify_chain` when it attempts to perform a lookup in the `keyring` dictionary.
