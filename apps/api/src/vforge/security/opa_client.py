"""Fail-closed OPA client for Phase 2 scope & authorization policy decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import httpx

PolicyOutcome = Literal["ALLOW", "DENY", "REQUIRES_APPROVAL"]


@dataclass(frozen=True, slots=True)
class PolicyReason:
    """Structured explanation emitted by OPA or fail-closed client boundary."""

    code: str
    message: str


@dataclass(frozen=True, slots=True)
class OpaDecision:
    """Normalized OPA decision response from `data.vforge.scope.decision`."""

    outcome: PolicyOutcome
    allowed: bool
    requires_approval: bool
    reasons: list[PolicyReason]
    policy_version: str


class OpaScopeClient:
    """Evaluates Phase 2 target-scope policies against OPA with fail-closed behavior."""

    def __init__(
        self,
        *,
        base_url: str,
        timeout_seconds: float = 5.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._endpoint = f"{base_url.rstrip('/')}/v1/data/vforge/scope/decision"
        self._timeout_seconds = timeout_seconds
        self._transport = transport

    async def evaluate_scope_decision(
        self,
        opa_input: dict[str, Any],
        *,
        expected_policy_version: str,
    ) -> OpaDecision:
        """Query OPA and return ALLOW / DENY / REQUIRES_APPROVAL; fail closed on errors."""
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout_seconds,
                transport=self._transport,
            ) as client:
                response = await client.post(self._endpoint, json={"input": opa_input})
        except httpx.HTTPError:
            return OpaDecision(
                outcome="DENY",
                allowed=False,
                requires_approval=False,
                reasons=[
                    PolicyReason(
                        code="opa_unavailable",
                        message="Policy engine unreachable; failing closed with DENY",
                    )
                ],
                policy_version=expected_policy_version,
            )

        if response.status_code != 200:
            return OpaDecision(
                outcome="DENY",
                allowed=False,
                requires_approval=False,
                reasons=[
                    PolicyReason(
                        code="opa_http_error",
                        message=(
                            f"Policy engine returned HTTP {response.status_code}; failing closed"
                        ),
                    )
                ],
                policy_version=expected_policy_version,
            )

        try:
            payload = response.json()
        except ValueError:
            return OpaDecision(
                outcome="DENY",
                allowed=False,
                requires_approval=False,
                reasons=[
                    PolicyReason(
                        code="opa_invalid_json",
                        message="Policy engine returned non-JSON response; failing closed",
                    )
                ],
                policy_version=expected_policy_version,
            )

        result = payload.get("result")
        if not isinstance(result, dict):
            return OpaDecision(
                outcome="DENY",
                allowed=False,
                requires_approval=False,
                reasons=[
                    PolicyReason(
                        code="opa_missing_result",
                        message="Policy decision missing from OPA response; failing closed",
                    )
                ],
                policy_version=expected_policy_version,
            )

        outcome_raw = str(result.get("outcome", "DENY"))
        if outcome_raw not in {"ALLOW", "DENY", "REQUIRES_APPROVAL"}:
            return OpaDecision(
                outcome="DENY",
                allowed=False,
                requires_approval=False,
                reasons=[
                    PolicyReason(
                        code="opa_invalid_outcome",
                        message="Policy engine returned unrecognized outcome; failing closed",
                    )
                ],
                policy_version=expected_policy_version,
            )

        reasons: list[PolicyReason] = []
        raw_reasons = result.get("reasons", [])
        if isinstance(raw_reasons, list):
            for entry in raw_reasons:
                if isinstance(entry, dict):
                    reasons.append(
                        PolicyReason(
                            code=str(entry.get("code", "policy_reason")),
                            message=str(entry.get("message", "Policy rule evaluated")),
                        )
                    )
        if not reasons:
            reasons.append(
                PolicyReason(
                    code="policy_decision",
                    message=f"OPA returned outcome {outcome_raw}",
                )
            )

        outcome: PolicyOutcome = outcome_raw  # type: ignore[assignment]
        allowed = bool(result.get("allowed", False)) and outcome == "ALLOW"
        requires_approval = (
            bool(result.get("requires_approval", False)) and outcome == "REQUIRES_APPROVAL"
        )
        policy_version = str(result.get("policy_version") or expected_policy_version)

        return OpaDecision(
            outcome=outcome,
            allowed=allowed,
            requires_approval=requires_approval,
            reasons=reasons,
            policy_version=policy_version,
        )
