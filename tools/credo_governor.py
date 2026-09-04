#!/usr/bin/env python3
"""credo_governor.py — map Credo Agent Governor outcomes onto GovernedAction/v1.

Credo Agent Governor (research preview, 2026) resolves each harness event to
one of four outcomes: allow | block | escalate | advise.

SZL does not copy that vocabulary. This adapter is the honest translation:

  Credo allow     -> SZL ALLOW  + may execute
  Credo block     -> SZL DENY   + must not execute (the block is the artifact)
  Credo escalate  -> SZL REVIEW + must not execute until a human principal signs
  Credo advise    -> SZL ADVISE + never authority; execution follows the
                     underlying ALLOW/DENY/REVIEW, not the advice text

Laws (fail-closed):
  C1  ADVISE cannot authorize execution.
  C2  Approval cannot lift a hard DENY.
  C3  REVIEW without a human principal is DENY.
  C4  Missing evidence never becomes ALLOW.
  C5  Λ is advisory (Conjecture 1). A Λ floor miss is REVIEW or DENY by
      policy, never a uniqueness theorem.

This file is the format. The control plane that installs it on a live harness
is sold separately.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

CredoOutcome = Literal["allow", "block", "escalate", "advise"]
SzlDecision = Literal["ALLOW", "DENY", "REVIEW", "ADVISE"]
ExecStatus = Literal["EXECUTED", "DENIED", "HELD_FOR_REVIEW", "ADVISED"]


@dataclass(frozen=True)
class GovernorResult:
    credo: CredoOutcome
    szl: SzlDecision
    may_execute: bool
    execution_status: ExecStatus
    reasons: tuple[str, ...]
    lambda_label: str = "ADVISORY"  # Conjecture 1 — never "proven trust"


def map_credo(
    outcome: CredoOutcome,
    *,
    hard_deny: bool = False,
    human_principal: Optional[str] = None,
    evidence_complete: bool = True,
    lambda_below_floor: bool = False,
) -> GovernorResult:
    """Translate one Credo harness event into an SZL decision.

    `hard_deny` is a prior DENY that no later allow/escalate/advise may lift.
    """
    reasons: list[str] = []

    if hard_deny:
        reasons.append("C2: approval cannot lift a hard DENY")
        return GovernorResult(
            credo=outcome,
            szl="DENY",
            may_execute=False,
            execution_status="DENIED",
            reasons=tuple(reasons),
        )

    if not evidence_complete:
        reasons.append("C4: missing evidence never becomes ALLOW")
        return GovernorResult(
            credo=outcome,
            szl="DENY" if outcome == "block" else "REVIEW",
            may_execute=False,
            execution_status="DENIED" if outcome == "block" else "HELD_FOR_REVIEW",
            reasons=tuple(reasons),
        )

    if lambda_below_floor:
        reasons.append("C5: Λ floor miss is advisory-gated, not a uniqueness proof")
        if outcome == "block":
            return GovernorResult(
                credo=outcome,
                szl="DENY",
                may_execute=False,
                execution_status="DENIED",
                reasons=tuple(reasons) + ("policy: block + floor miss => DENY",),
            )
        return GovernorResult(
            credo=outcome,
            szl="REVIEW",
            may_execute=False,
            execution_status="HELD_FOR_REVIEW",
            reasons=tuple(reasons) + ("Λ below floor => REVIEW, never silent allow",),
        )

    if outcome == "allow":
        return GovernorResult(
            credo=outcome,
            szl="ALLOW",
            may_execute=True,
            execution_status="EXECUTED",
            reasons=("Credo allow maps to SZL ALLOW",),
        )

    if outcome == "block":
        return GovernorResult(
            credo=outcome,
            szl="DENY",
            may_execute=False,
            execution_status="DENIED",
            reasons=("Credo block maps to SZL DENY; the block is the artifact",),
        )

    if outcome == "escalate":
        if not human_principal:
            reasons.append("C3: REVIEW without a human principal is DENY")
            return GovernorResult(
                credo=outcome,
                szl="DENY",
                may_execute=False,
                execution_status="DENIED",
                reasons=tuple(reasons),
            )
        return GovernorResult(
            credo=outcome,
            szl="REVIEW",
            may_execute=False,
            execution_status="HELD_FOR_REVIEW",
            reasons=("Credo escalate maps to SZL REVIEW; execution held",
                     f"human_principal={human_principal}"),
        )

    reasons.append("C1: ADVISE cannot authorize execution")
    return GovernorResult(
        credo=outcome,
        szl="ADVISE",
        may_execute=False,
        execution_status="ADVISED",
        reasons=tuple(reasons) + (
            "advise is a warning attached to a later ALLOW/DENY/REVIEW",
        ),
    )


def compose(prior: GovernorResult, incoming: CredoOutcome, **kwargs) -> GovernorResult:
    """Session composition: a prior DENY stays DENY."""
    return map_credo(
        incoming,
        hard_deny=(prior.szl == "DENY"),
        **kwargs,
    )
