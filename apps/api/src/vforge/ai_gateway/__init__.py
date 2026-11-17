"""Phase 12 provider-agnostic AI Gateway package."""

from vforge.ai_gateway.classification import ClassificationResult, classify_and_redact_payload
from vforge.ai_gateway.providers import (
    ModelProvider,
    ModelRequest,
    ModelResponse,
    ProviderHealth,
    ProviderInvocationError,
    ProviderMetadata,
    build_provider_adapter,
    validate_provider_endpoint_url,
    validate_secret_reference,
)
from vforge.ai_gateway.rag import index_knowledge_document, retrieve_tenant_knowledge
from vforge.ai_gateway.roles import (
    FORBIDDEN_PRIVILEGED_TOOL_ACTIONS,
    ROLE_PROFILES,
    get_role_profile,
)
from vforge.ai_gateway.rule_author import GovernedRuleAuthorGateway
from vforge.ai_gateway.service import (
    configure_provider,
    decide_tool_proposal,
    evaluate_tool_proposal_with_opa,
    execute_ai_task,
    get_ai_governance_overview,
    list_model_catalog,
    record_blocked_ai_attempt,
    record_feedback_label,
    record_model_evaluation,
    set_provider_retention_consent,
)

__all__ = [
    "ClassificationResult",
    "FORBIDDEN_PRIVILEGED_TOOL_ACTIONS",
    "GovernedRuleAuthorGateway",
    "ModelProvider",
    "ModelRequest",
    "ModelResponse",
    "ProviderHealth",
    "ProviderInvocationError",
    "ProviderMetadata",
    "ROLE_PROFILES",
    "build_provider_adapter",
    "classify_and_redact_payload",
    "configure_provider",
    "decide_tool_proposal",
    "evaluate_tool_proposal_with_opa",
    "execute_ai_task",
    "get_ai_governance_overview",
    "get_role_profile",
    "index_knowledge_document",
    "list_model_catalog",
    "record_blocked_ai_attempt",
    "record_feedback_label",
    "record_model_evaluation",
    "retrieve_tenant_knowledge",
    "set_provider_retention_consent",
    "validate_provider_endpoint_url",
    "validate_secret_reference",
]
