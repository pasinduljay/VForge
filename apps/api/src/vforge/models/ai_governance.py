"""Phase 12 SQLAlchemy models for runtime AI Provider Governance, RAG, and multi-agent audit."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vforge.db import Base


class AiModelCatalog(Base):
    """Controlled platform model catalogue with retention & local execution metadata."""

    __tablename__ = "ai_model_catalog"
    __table_args__ = (UniqueConstraint("model_slug", name="uq_ai_model_catalog_slug"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    provider_class: Mapped[str] = mapped_column(String(40), nullable=False)
    model_slug: Mapped[str] = mapped_column(String(120), nullable=False)
    display_name: Mapped[str] = mapped_column(String(160), nullable=False)
    capabilities_json: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), nullable=False, default=list
    )
    is_local: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    zdr_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    requires_retention_consent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    cost_per_1k_input_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cost_per_1k_output_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiProviderConfig(Base):
    """Tenant-scoped AI provider connector storing secret-manager references only."""

    __tablename__ = "ai_provider_configs"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_apc_org_id"),
        UniqueConstraint("organization_id", "display_name", name="uq_apc_org_name"),
        CheckConstraint("monthly_budget_usd >= 0.0", name="ck_apc_budget_nonneg"),
        CheckConstraint(
            "max_tokens_per_request >= 64 AND max_tokens_per_request <= 1000000",
            name="ck_apc_max_tokens_bounds",
        ),
        CheckConstraint(
            "secret_ref IS NULL OR ("
            "(secret_ref LIKE 'VF\\_AI\\_%' ESCAPE '\\' OR secret_ref LIKE 'ai/orgs/%') AND "
            "secret_ref NOT LIKE 'sk-%' AND secret_ref NOT LIKE 'AIza%' AND "
            "secret_ref NOT LIKE 'ghp_%' AND secret_ref NOT LIKE 'glpat-%' AND "
            "secret_ref NOT LIKE 'xox%' AND secret_ref NOT LIKE 'AKIA%' AND "
            "secret_ref NOT LIKE 'hf_%' AND secret_ref NOT LIKE 'github_pat_%' AND "
            "secret_ref NOT LIKE 'npm_%' AND secret_ref NOT LIKE 'whsec_%' AND "
            "secret_ref NOT LIKE 'eyJ%')",
            name="ck_apc_secret_ref_not_raw_key",
        ),
        Index("ix_apc_org_enabled", "organization_id", "is_enabled"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    provider_class: Mapped[str] = mapped_column(String(40), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    endpoint_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    secret_ref: Mapped[str | None] = mapped_column(String(160), nullable=True)
    local_only_mode: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    allowed_models_json: Mapped[list[str]] = mapped_column(
        ARRAY(String(120)), nullable=False, default=list
    )
    monthly_budget_usd: Mapped[float] = mapped_column(Float, nullable=False, default=25.0)
    max_tokens_per_request: Mapped[int] = mapped_column(Integer, nullable=False, default=8192)
    retention_consent_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retention_consent_approved_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    retention_consent_approved_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiTaskRequest(Base):
    """Tenant-scoped record of every AI task submitted through pre-egress gates."""

    __tablename__ = "ai_task_requests"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_atr_org_id"),
        ForeignKeyConstraint(
            ["organization_id", "provider_config_id"],
            ["ai_provider_configs.organization_id", "ai_provider_configs.id"],
            name="fk_atr_org_provider_cfg",
            ondelete="RESTRICT",
        ),
        Index("ix_atr_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    task_type: Mapped[str] = mapped_column(String(64), nullable=False)
    role_name: Mapped[str] = mapped_column(String(64), nullable=False)
    data_classification: Mapped[str] = mapped_column(String(32), nullable=False)
    redaction_applied: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    prompt_injection_detected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    consent_acknowledged: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    provider_config_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    model_slug: Mapped[str] = mapped_column(String(120), nullable=False)
    input_snapshot_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    input_summary_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    block_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    requested_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiRun(Base):
    """Execution telemetry and structured output (without raw secrets/hidden thoughts)."""

    __tablename__ = "ai_runs"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_airun_org_id"),
        ForeignKeyConstraint(
            ["organization_id", "task_request_id"],
            ["ai_task_requests.organization_id", "ai_task_requests.id"],
            name="fk_airun_org_task",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "provider_config_id"],
            ["ai_provider_configs.organization_id", "ai_provider_configs.id"],
            name="fk_airun_org_provider_cfg",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "token_input_count >= 0 AND token_output_count >= 0 AND estimated_cost_usd >= 0.0",
            name="ck_airun_nonneg_usage",
        ),
        Index("ix_airun_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    task_request_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    provider_config_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    role_name: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_class: Mapped[str] = mapped_column(String(40), nullable=False)
    model_slug: Mapped[str] = mapped_column(String(120), nullable=False)
    prompt_template_version: Mapped[str] = mapped_column(String(64), nullable=False)
    fallback_triggered: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    output_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    structured_output_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict
    )
    rationale_summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    uncertainty_notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    token_input_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    token_output_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estimated_cost_usd: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    latency_ms: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="completed")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiToolProposal(Base):
    """Policy-evaluated AI tool call proposal; never executed without OPA + human gating."""

    __tablename__ = "ai_tool_proposals"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_atp_org_id"),
        ForeignKeyConstraint(
            ["organization_id", "ai_run_id"],
            ["ai_runs.organization_id", "ai_runs.id"],
            name="fk_atp_org_run",
            ondelete="CASCADE",
        ),
        Index("ix_atp_org_run", "organization_id", "ai_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    ai_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tool_action: Mapped[str] = mapped_column(String(80), nullable=False)
    target_resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    arguments_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    opa_allowed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    opa_decision_reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(40), nullable=False, default="proposed")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiToolApproval(Base):
    """Append-only human decision record on an OPA-permitted AI tool proposal."""

    __tablename__ = "ai_tool_approvals"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "proposal_id"],
            ["ai_tool_proposals.organization_id", "ai_tool_proposals.id"],
            name="fk_ata_org_proposal",
            ondelete="CASCADE",
        ),
        Index("ix_ata_org_proposal", "organization_id", "proposal_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    proposal_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    decision: Mapped[str] = mapped_column(String(32), nullable=False)
    decided_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    decided_email: Mapped[str] = mapped_column(String(255), nullable=False)
    comment: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class KnowledgeDocument(Base):
    """Tenant-isolated curated knowledge document for approved RAG retrieval."""

    __tablename__ = "knowledge_documents"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_kdoc_org_id"),
        UniqueConstraint("organization_id", "slug", name="uq_kdoc_org_slug"),
        Index("ix_kdoc_org_type", "organization_id", "source_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    source_type: Mapped[str] = mapped_column(String(48), nullable=False)
    source_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    is_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class KnowledgeChunk(Base):
    """Indexed text chunk scoped cleanly by tenant and parent KnowledgeDocument."""

    __tablename__ = "knowledge_chunks"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "document_id"],
            ["knowledge_documents.organization_id", "knowledge_documents.id"],
            name="fk_kchunk_org_doc",
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "document_id", "chunk_index", name="uq_kchunk_doc_idx"),
        Index("ix_kchunk_org_doc", "organization_id", "document_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    document_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    chunk_index: Mapped[int] = mapped_column(Integer, nullable=False)
    chunk_text: Mapped[str] = mapped_column(Text, nullable=False)
    keywords_json: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list
    )
    chunk_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiFeedbackLabel(Base):
    """Tenant-isolated human feedback label for curated offline evaluation (never auto-shared)."""

    __tablename__ = "ai_feedback_labels"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "ai_run_id"],
            ["ai_runs.organization_id", "ai_runs.id"],
            name="fk_afl_org_run",
            ondelete="CASCADE",
        ),
        Index("ix_afl_org_run", "organization_id", "ai_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    ai_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    label: Mapped[str] = mapped_column(String(40), nullable=False)
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")
    de_identified: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    cross_tenant_sharing_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    labeled_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class ModelEvaluationRun(Base):
    """Deterministic evaluation suite metrics comparing model versions against curated fixtures."""

    __tablename__ = "model_evaluation_runs"
    __table_args__ = (
        CheckConstraint(
            "true_positive_rate >= 0.0 AND true_positive_rate <= 1.0 "
            "AND false_positive_rate >= 0.0 AND false_positive_rate <= 1.0",
            name="ck_mer_rates_bounds",
        ),
        Index("ix_mer_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    model_slug: Mapped[str] = mapped_column(String(120), nullable=False)
    suite_name: Mapped[str] = mapped_column(String(120), nullable=False)
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    true_positive_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    false_positive_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    regression_passed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    evaluated_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )


class AiAuditEvent(Base):
    """Append-only cryptographic/metadata audit trail of all Phase 12 AI gateway operations."""

    __tablename__ = "ai_audit_events"
    __table_args__ = (Index("ix_aiae_org_occurred", "organization_id", "occurred_at"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    actor_email: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_class: Mapped[str | None] = mapped_column(String(40), nullable=True)
    model_slug: Mapped[str | None] = mapped_column(String(120), nullable=True)
    data_classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=text("now()")
    )
