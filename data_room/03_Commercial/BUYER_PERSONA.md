# Buyer persona — single, named, testable (COM-014)

## The persona

**VP of Platform Engineering or CISO at a regulated-enterprise AI adopter
(US/EU), 500–5,000 employees, with AI agents taking consequential actions in
production and an EU AI Act Annex III exposure arriving Dec 2027.**

Titles to target: VP Engineering, VP Platform, Head of AI Platform, CISO,
Deputy CISO for AI.

## Why this one

- They own the budget line for "agent governance" because they own the
  incident when an agent does something consequential without evidence.
- They have EU AI Act urgency: Article 12 logging obligations for high-risk
  systems land Dec 2027, and scoping starts now.
- They are technical enough to run the 90-second demo and feel it.
- They are the same buyer JetStream and WitnessAI are courting — which
  validates the budget exists.

## Anti-persona (do not sell to these first)

- Pure ML-research teams (no production consequence, no budget for evidence).
- Small startups under 200 people (no compliance forcing function yet).
- Anyone whose first question is "can it also do X for free."

## The 12 founder-led discovery questions

1. When an AI agent takes a consequential action in your production today,
   what evidence exists afterward, and who can see it?
2. Can an external auditor verify that record without entering your platform?
3. What happens to the record when the vendor has an outage? When you switch
   vendors?
4. Which of your agent workflows would fail an Article 12 logging review
   today?
5. Who gets paged when an agent does something irreversible without approval?
6. What would you pay to make question 2 answerable with "yes, offline"?
7. What is your current retention floor for agent action logs?
8. Which of your systems are in Annex III scope for Dec 2027?
9. If you could only govern one workflow this quarter, which one and why?
10. What does "proof" mean to your auditors — a dashboard, or a file they
    can verify themselves?
11. Who else in your org feels this pain — security, compliance, or platform?
12. What would make this a "no" regardless of capability?

**Anti-question — never ask:** "Would you use a governed inference platform?"
It invites polite fiction.

## Validation plan

20 outbound conversations against this persona → target 2 paid six-month
design partners at the Control tier with public testimonial rights. Exit the
design phase only when 80%+ convert AND three use cases work with zero custom
configuration.
