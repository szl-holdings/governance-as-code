# Outbound sequence — design-partner motion (feeds COM-004, COM-005, COM-021, COM-022)

Target: the persona in `governance/BUYER_PERSONA.md` — VP Platform / CISO at a
regulated AI adopter with EU AI Act Annex III exposure before Dec 2027.

20 conversations → 2 paid six-month design partners. Drafts below are ready;
sending is the founder's call.

## Touch 1 (Day 0)

Subject: what your agent did last Tuesday — provable?

> When one of your AI agents takes a consequential action in production,
> what record exists afterward — and could an external auditor verify it
> without a login to your platform?
>
> We publish an open receipt format for exactly this (spec:
> github.com/szl-holdings/governance-as-code). Every consequential action
> gets a signed, hash-chained receipt that verifies offline. Missing evidence
> can't pass — it reads INCOMPLETE, by construction.
>
> Worth 20 minutes to run your worst incident scenario through it?

## Touch 2 (Day 4) — the artifact

Subject: the 90-second version

> No deck. Here is the verifier running live:
> https://a11oy-verify.pplx.app — click "Run verification", then tamper with
> the receipt in dev tools and watch it turn red. That's the whole pitch.
>
> If your EU AI Act scoping has started for 2027, Article 12's logging fields
> map one-to-one onto this format (machine-readable profile in the repo).

## Touch 3 (Day 10) — the close

Subject: one workflow, six months, named price

> Concrete proposal: pick one workflow where an agent touches production.
> Six-month design-partner engagement at $50K–150K (Control tier), you keep
> every receipt, we publish conformance results, you get testimonial veto.
> If we can't get one workflow producing verifier-clean receipts in 30 days,
> don't renew. Who on your team owns the agent runbook today?

## Follow-up rule

No touch 4 from this sequence. Silence after touch 3 is a decision; log it in
the pipeline table and move on.

## Pipeline tracker (fill per account)

| Account | Persona fit | Touch 1 | Touch 2 | Touch 3 | Outcome | Receipts flowing? |
|---|---|---|---|---|---|---|
| | | | | | | |
