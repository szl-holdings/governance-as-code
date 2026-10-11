# Canonical KANCHAY presentation subset

The installed presentation assets use the reviewed [SZL brand bundle](https://github.com/szl-holdings/szl-brand/tree/4309f6fce89179331b0b3ed8c99494e76c5be256/kanchay) at `4309f6fce89179331b0b3ed8c99494e76c5be256`. Its byte-exact `SOURCE.json` names canonical source `27d12e77fc0f9f1a0e5fae8b34adf2380d51d070` and KANCHAY v1.3.0. The generated bundle revision and the canonical source revision are distinct.

## Installed files

- `demo_site/szl/VENDORED.json` records the exact installed subset at that root.

`SOURCE.json` describes the entire upstream bundle. `VENDORED.json` describes only the files actually installed here: each listed digest must match both its bytes and the upstream manifest. It binds the upstream manifest digest and accepted bundle revision. A copied manifest does not imply that every upstream logo or stylesheet was installed. Independent source-owned assets retain their own records.

## Update procedure

Read immutable Git blobs from the accepted brand revision. Verify the upstream manifest and each selected payload before replacing a served asset. Keep the upstream `SOURCE.json` unchanged, regenerate the local subset record from installed files, then run the presentation contracts and browser checks. Do not replace local overlays or independently governed logos with bundle lookalikes.

The demo remains an offline browser verifier. This presentation update does not alter the receipt bundle, signature checks, expected PASS / INCOMPLETE / FAIL outcomes, Article 12 claims or publisher configuration.

The projection scope is static presentation only. It does not attest runtime readiness, cryptographic signing, model quality or deployment.
