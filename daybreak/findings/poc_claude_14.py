#!/usr/bin/env python3
"""PoC 14 — S2.2: PAE length-prefix manipulation — attempted, expected HELD.

Control PoC. DSSEv1 PAE = "DSSEv1 " SP len(type) SP type SP len(payload) SP
payload. Both fields are length-prefixed with canonical decimal lengths
(str(len) — no leading zeros, no negatives), so the encoding is injective:
any change to (type, payload) changes the encoding, and no two distinct
pairs collide. This PoC sweeps adversarial (type, payload) pairs — including
types containing spaces/digits and payloads embedding PAE-looking prefixes —
and confirms (a) no collisions and (b) a signature over one pair never
verifies against another.
"""
import sys
sys.path.insert(0, "/home/user/workspace/governance-as-code/tools")
from receipt_lib import generate_keypair, pae, sign, PREDICATE_TYPE
from cryptography.exceptions import InvalidSignature

sk, pk = generate_keypair()

pairs = [
    (PREDICATE_TYPE, b'{"a":1}'),
    (PREDICATE_TYPE + " ", b'{"a":1}'),                      # trailing space in type
    (PREDICATE_TYPE, b' {"a":1}'),                           # leading space in payload
    ("A", pae("B", b"x")),                                   # nested PAE as payload
    ("DSSEv1 1 A 1 x", b""),                                 # type that looks like PAE
    (PREDICATE_TYPE, b'5 DSSEv fake'),                       # payload w/ digits+spaces
    ("https://szl.dev/predicates/governed-action/v1", b'{"a":1}'),  # exact dup of [0]
    (PREDICATE_TYPE, b'{"a":1}\x00'),                        # NUL-appended payload
]

encodings = {}
collision = None
for t, p in pairs:
    e = pae(t, p)
    if e in encodings and encodings[e] != (t, p):
        collision = (encodings[e], (t, p))
    encodings[e] = (t, p)

# cross-verification: signature for pairs[0] must not verify for any other
base_sig = sign(sk, pairs[0][0], pairs[0][1])
cross = False
for t, p in pairs[1:]:
    if (t, p) == pairs[0]:
        continue
    import base64
    try:
        pk.verify(base64.b64decode(base_sig), pae(t, p))
        cross = True
    except InvalidSignature:
        pass

print("pairs tested:", len(pairs), "| unique encodings:", len(encodings),
      "| collision:", collision, "| cross-verify:", cross)

# HELD unless a collision or cross-verification appeared
if collision or cross:
    print("EXPLOIT-WORKS")
else:
    print("HELD")
