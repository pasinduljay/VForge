"""Phase 12 governed AI Rule Author adapter replacing the Phase 11 stub."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vforge.ai_gateway.classification import classify_and_redact_payload

if TYPE_CHECKING:
    from vforge.studio.ai_author import AiGeneratedCandidate


class GovernedRuleAuthorGateway:
    """Governed rule-drafting gateway enforcing pre-egress redaction and injection isolation."""

    def generate_rule_candidate(
        self,
        *,
        engine: str,
        rule_key: str,
        title: str,
        cwe_id: str,
        target_context: str,
        untrusted_source_snippet: str,
    ) -> AiGeneratedCandidate:
        from vforge.studio.ai_author import (
            AiGeneratedCandidate,
            Phase12StubRuleAuthorGateway,
        )

        cls_ctx = classify_and_redact_payload(target_context)
        cls_snippet = classify_and_redact_payload(untrusted_source_snippet)
        base_candidate = Phase12StubRuleAuthorGateway().generate_rule_candidate(
            engine=engine,
            rule_key=rule_key,
            title=title,
            cwe_id=cwe_id,
            target_context=cls_ctx.redacted_text,
            untrusted_source_snippet=cls_snippet.redacted_text,
        )
        redacted_cats = sorted(
            set(cls_ctx.redacted_categories) | set(cls_snippet.redacted_categories)
        )
        summary_preview = classify_and_redact_payload(cls_ctx.redacted_text[:200])
        provenance: dict[str, Any] = {
            **base_candidate.provenance,
            "gateway_mode": "phase12_governed_gateway",
            "provider": "vforge-phase12-ai-gateway",
            "mode": "governed_pre_egress_redacted",
            "auto_promoted": False,
            "requires_human_review": True,
            "data_classification": cls_snippet.classification.value,
            "redaction_applied": cls_ctx.redaction_applied or cls_snippet.redaction_applied,
            "redacted_categories": redacted_cats,
            "prompt_injection_detected": (
                cls_ctx.prompt_injection_detected or cls_snippet.prompt_injection_detected
            ),
            "input_snapshot_sha256": cls_snippet.raw_sha256,
            "untrusted_snippet_bytes": len(untrusted_source_snippet.encode("utf-8")),
            "untrusted_wrapper_applied": True,
            "context_summary": summary_preview.wrapped_untrusted_text,
        }
        return AiGeneratedCandidate(
            rules=base_candidate.rules,
            provenance=provenance,
        )
