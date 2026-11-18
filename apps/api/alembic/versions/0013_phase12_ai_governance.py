"""Phase 12 AI Provider Governance tenant-isolated schema, RLS, and model catalog."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0013_phase12_ai_governance"
down_revision: str | None = "0012_phase11_rule_skill_studio"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = (
    "ai_provider_configs",
    "ai_task_requests",
    "ai_runs",
    "ai_tool_proposals",
    "ai_tool_approvals",
    "knowledge_documents",
    "knowledge_chunks",
    "ai_feedback_labels",
    "model_evaluation_runs",
    "ai_audit_events",
)

_IMMUTABLE_TABLES = (
    "ai_tool_approvals",
    "ai_feedback_labels",
    "ai_audit_events",
)


def upgrade() -> None:
    # 1. Controlled Platform Model Catalog
    op.create_table(
        "ai_model_catalog",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("provider_class", sa.String(40), nullable=False),
        sa.Column("model_slug", sa.String(120), nullable=False),
        sa.Column("display_name", sa.String(160), nullable=False),
        sa.Column("capabilities_json", postgresql.ARRAY(sa.String(64)), nullable=False),
        sa.Column("is_local", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("zdr_available", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "requires_retention_consent", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("cost_per_1k_input_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("cost_per_1k_output_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("model_slug", name="uq_ai_model_catalog_slug"),
    )

    # Seed baseline model catalog entries (enterprise-30d-v1 marked 30d non-ZDR consent)
    catalog_tbl = sa.table(
        "ai_model_catalog",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("provider_class", sa.String),
        sa.column("model_slug", sa.String),
        sa.column("display_name", sa.String),
        sa.column("capabilities_json", postgresql.ARRAY(sa.String)),
        sa.column("is_local", sa.Boolean),
        sa.column("retention_days", sa.Integer),
        sa.column("zdr_available", sa.Boolean),
        sa.column("requires_retention_consent", sa.Boolean),
        sa.column("cost_per_1k_input_usd", sa.Float),
        sa.column("cost_per_1k_output_usd", sa.Float),
        sa.column("is_active", sa.Boolean),
    )
    op.bulk_insert(
        catalog_tbl,
        [
            {
                "id": uuid.UUID("12000000-0000-0000-0000-000000000001"),
                "provider_class": "managed_zdr",
                "model_slug": "managed-fast-v1",
                "display_name": "Managed Cloud ZDR Fast v1",
                "capabilities_json": ["rule_draft", "triage", "remediation", "structured_json"],
                "is_local": False,
                "retention_days": 0,
                "zdr_available": True,
                "requires_retention_consent": False,
                "cost_per_1k_input_usd": 0.0005,
                "cost_per_1k_output_usd": 0.0015,
                "is_active": True,
            },
            {
                "id": uuid.UUID("12000000-0000-0000-0000-000000000002"),
                "provider_class": "managed_zdr",
                "model_slug": "managed-reasoning-v2",
                "display_name": "Managed Cloud ZDR Reasoning v2",
                "capabilities_json": ["architecture_review", "rule_draft", "adversarial_review"],
                "is_local": False,
                "retention_days": 0,
                "zdr_available": True,
                "requires_retention_consent": False,
                "cost_per_1k_input_usd": 0.0025,
                "cost_per_1k_output_usd": 0.008,
                "is_active": True,
            },
            {
                "id": uuid.UUID("12000000-0000-0000-0000-000000000003"),
                "provider_class": "managed_retained",
                "model_slug": "enterprise-30d-v1",
                "display_name": "Enterprise Cloud 30d Retained v1",
                "capabilities_json": ["architecture_review", "independent_critic", "remediation"],
                "is_local": False,
                "retention_days": 30,
                "zdr_available": False,
                "requires_retention_consent": True,
                "cost_per_1k_input_usd": 0.003,
                "cost_per_1k_output_usd": 0.015,
                "is_active": True,
            },
            {
                "id": uuid.UUID("12000000-0000-0000-0000-000000000004"),
                "provider_class": "openai",
                "model_slug": "gpt-5-codex",
                "display_name": "GPT-5 Codex",
                "capabilities_json": ["rule_draft", "remediation", "evidence_verify"],
                "is_local": False,
                "retention_days": 0,
                "zdr_available": True,
                "requires_retention_consent": False,
                "cost_per_1k_input_usd": 0.002,
                "cost_per_1k_output_usd": 0.008,
                "is_active": True,
            },
            {
                "id": uuid.UUID("12000000-0000-0000-0000-000000000005"),
                "provider_class": "openai_compatible",
                "model_slug": "openai-compatible-default",
                "display_name": "Customer OpenAI-Compatible Endpoint",
                "capabilities_json": ["triage", "rule_draft", "remediation"],
                "is_local": False,
                "retention_days": 0,
                "zdr_available": True,
                "requires_retention_consent": False,
                "cost_per_1k_input_usd": 0.001,
                "cost_per_1k_output_usd": 0.002,
                "is_active": True,
            },
            {
                "id": uuid.UUID("12000000-0000-0000-0000-000000000006"),
                "provider_class": "local_inference",
                "model_slug": "ollama/qwen3-coder",
                "display_name": "Local Ollama / vLLM Qwen3 Coder",
                "capabilities_json": ["classification", "triage", "remediation", "rule_draft"],
                "is_local": True,
                "retention_days": 0,
                "zdr_available": True,
                "requires_retention_consent": False,
                "cost_per_1k_input_usd": 0.0,
                "cost_per_1k_output_usd": 0.0,
                "is_active": True,
            },
        ],
    )

    # 2. Tenant-Scoped Provider Configurations (secret references only)
    op.create_table(
        "ai_provider_configs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_class", sa.String(40), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("endpoint_url", sa.String(512), nullable=True),
        sa.Column("secret_ref", sa.String(160), nullable=True),
        sa.Column("local_only_mode", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("allowed_models_json", postgresql.ARRAY(sa.String(120)), nullable=False),
        sa.Column("monthly_budget_usd", sa.Float(), nullable=False, server_default="25.0"),
        sa.Column("max_tokens_per_request", sa.Integer(), nullable=False, server_default="8192"),
        sa.Column(
            "retention_consent_approved", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("retention_consent_approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("retention_consent_approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "id", name="uq_apc_org_id"),
        sa.UniqueConstraint("organization_id", "display_name", name="uq_apc_org_name"),
        sa.CheckConstraint("monthly_budget_usd >= 0.0", name="ck_apc_budget_nonneg"),
        sa.CheckConstraint(
            "max_tokens_per_request >= 64 AND max_tokens_per_request <= 1000000",
            name="ck_apc_max_tokens_bounds",
        ),
        sa.CheckConstraint(
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
    )
    op.create_index("ix_apc_org_enabled", "ai_provider_configs", ["organization_id", "is_enabled"])

    # 3. AI Task Requests
    op.create_table(
        "ai_task_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_type", sa.String(64), nullable=False),
        sa.Column("role_name", sa.String(64), nullable=False),
        sa.Column("data_classification", sa.String(32), nullable=False),
        sa.Column("redaction_applied", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "prompt_injection_detected", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("consent_acknowledged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("provider_config_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("model_slug", sa.String(120), nullable=False),
        sa.Column("input_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("input_summary_redacted", sa.Text(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("block_reason", sa.Text(), nullable=True),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "provider_config_id"],
            ["ai_provider_configs.organization_id", "ai_provider_configs.id"],
            name="fk_atr_org_provider_cfg",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_atr_org_id"),
    )
    op.create_index("ix_atr_org_created", "ai_task_requests", ["organization_id", "created_at"])

    # 4. AI Runs
    op.create_table(
        "ai_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_request_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_config_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("role_name", sa.String(64), nullable=False),
        sa.Column("provider_class", sa.String(40), nullable=False),
        sa.Column("model_slug", sa.String(120), nullable=False),
        sa.Column("prompt_template_version", sa.String(64), nullable=False),
        sa.Column("fallback_triggered", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("output_sha256", sa.String(64), nullable=False),
        sa.Column(
            "structured_output_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("rationale_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("uncertainty_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("token_input_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("token_output_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("estimated_cost_usd", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("latency_ms", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", sa.String(32), nullable=False, server_default="completed"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "task_request_id"],
            ["ai_task_requests.organization_id", "ai_task_requests.id"],
            name="fk_airun_org_task",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "provider_config_id"],
            ["ai_provider_configs.organization_id", "ai_provider_configs.id"],
            name="fk_airun_org_provider_cfg",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_airun_org_id"),
        sa.CheckConstraint(
            "token_input_count >= 0 AND token_output_count >= 0 AND estimated_cost_usd >= 0.0",
            name="ck_airun_nonneg_usage",
        ),
    )
    op.create_index("ix_airun_org_created", "ai_runs", ["organization_id", "created_at"])

    # 5. AI Tool Proposals & Approvals
    op.create_table(
        "ai_tool_proposals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ai_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_action", sa.String(80), nullable=False),
        sa.Column("target_resource_type", sa.String(64), nullable=False),
        sa.Column("target_resource_id", sa.String(128), nullable=False),
        sa.Column(
            "arguments_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("opa_allowed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("opa_decision_reason", sa.Text(), nullable=False),
        sa.Column("status", sa.String(40), nullable=False, server_default="proposed"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "ai_run_id"],
            ["ai_runs.organization_id", "ai_runs.id"],
            name="fk_atp_org_run",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_atp_org_id"),
    )
    op.create_index("ix_atp_org_run", "ai_tool_proposals", ["organization_id", "ai_run_id"])

    op.create_table(
        "ai_tool_approvals",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("proposal_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("decision", sa.String(32), nullable=False),
        sa.Column("decided_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("decided_email", sa.String(255), nullable=False),
        sa.Column("comment", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "proposal_id"],
            ["ai_tool_proposals.organization_id", "ai_tool_proposals.id"],
            name="fk_ata_org_proposal",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_ata_org_proposal", "ai_tool_approvals", ["organization_id", "proposal_id"])

    # 6. Tenant-Isolated Curated Knowledge Documents & Chunks (RAG)
    op.create_table(
        "knowledge_documents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(120), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("source_type", sa.String(48), nullable=False),
        sa.Column("source_uri", sa.String(512), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("is_approved", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("uploaded_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("organization_id", "id", name="uq_kdoc_org_id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_kdoc_org_slug"),
    )
    op.create_index("ix_kdoc_org_type", "knowledge_documents", ["organization_id", "source_type"])

    op.create_table(
        "knowledge_chunks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("document_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("chunk_text", sa.Text(), nullable=False),
        sa.Column("keywords_json", postgresql.ARRAY(sa.String(80)), nullable=False),
        sa.Column("chunk_sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_id"],
            ["knowledge_documents.organization_id", "knowledge_documents.id"],
            name="fk_kchunk_org_doc",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "organization_id", "document_id", "chunk_index", name="uq_kchunk_doc_idx"
        ),
    )
    op.create_index("ix_kchunk_org_doc", "knowledge_chunks", ["organization_id", "document_id"])

    # 7. Feedback Labels & Deterministic Evaluation Suites
    op.create_table(
        "ai_feedback_labels",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ai_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("label", sa.String(40), nullable=False),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("de_identified", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "cross_tenant_sharing_enabled", sa.Boolean(), nullable=False, server_default=sa.false()
        ),
        sa.Column("labeled_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "ai_run_id"],
            ["ai_runs.organization_id", "ai_runs.id"],
            name="fk_afl_org_run",
            ondelete="CASCADE",
        ),
    )
    op.create_index("ix_afl_org_run", "ai_feedback_labels", ["organization_id", "ai_run_id"])

    op.create_table(
        "model_evaluation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("model_slug", sa.String(120), nullable=False),
        sa.Column("suite_name", sa.String(120), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("true_positive_rate", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("false_positive_rate", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("regression_passed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("evaluated_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "true_positive_rate >= 0.0 AND true_positive_rate <= 1.0 "
            "AND false_positive_rate >= 0.0 AND false_positive_rate <= 1.0",
            name="ck_mer_rates_bounds",
        ),
    )
    op.create_index(
        "ix_mer_org_created", "model_evaluation_runs", ["organization_id", "created_at"]
    )

    # 8. Append-Only AI Audit Events
    op.create_table(
        "ai_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_email", sa.String(255), nullable=False),
        sa.Column("provider_class", sa.String(40), nullable=True),
        sa.Column("model_slug", sa.String(120), nullable=True),
        sa.Column("data_classification", sa.String(32), nullable=True),
        sa.Column(
            "details_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_aiae_org_occurred", "ai_audit_events", ["organization_id", "occurred_at"])

    # 9. Enable + Force RLS across all tenant-scoped tables
    for tbl in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{tbl} ON {tbl}
            USING (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
            """
        )

    # 10. Append-only triggers
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase12_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Phase 12 AI audit and approval records are append-only.'
                USING ERRCODE = '55000';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for imm_table in _IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase12_immutable_mutation();
            """
        )

    # 11. Least-privilege runtime grants for vforge_app
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT ON ai_model_catalog TO vforge_app;

                GRANT SELECT, INSERT ON
                    ai_tool_approvals, ai_feedback_labels, ai_audit_events
                    TO vforge_app;
                REVOKE UPDATE, DELETE ON
                    ai_tool_approvals, ai_feedback_labels, ai_audit_events
                    FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON
                    ai_provider_configs, ai_task_requests, ai_runs, ai_tool_proposals,
                    knowledge_documents, knowledge_chunks, model_evaluation_runs
                    TO vforge_app;
                REVOKE DELETE ON
                    ai_provider_configs, ai_task_requests, ai_runs, ai_tool_proposals,
                    knowledge_documents, knowledge_chunks, model_evaluation_runs
                    FROM vforge_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    for imm_table in _IMMUTABLE_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase12_immutable_mutation();")

    for tbl in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")

    op.drop_index("ix_aiae_org_occurred", table_name="ai_audit_events")
    op.drop_table("ai_audit_events")

    op.drop_index("ix_mer_org_created", table_name="model_evaluation_runs")
    op.drop_table("model_evaluation_runs")

    op.drop_index("ix_afl_org_run", table_name="ai_feedback_labels")
    op.drop_table("ai_feedback_labels")

    op.drop_index("ix_kchunk_org_doc", table_name="knowledge_chunks")
    op.drop_table("knowledge_chunks")

    op.drop_index("ix_kdoc_org_type", table_name="knowledge_documents")
    op.drop_table("knowledge_documents")

    op.drop_index("ix_ata_org_proposal", table_name="ai_tool_approvals")
    op.drop_table("ai_tool_approvals")

    op.drop_index("ix_atp_org_run", table_name="ai_tool_proposals")
    op.drop_table("ai_tool_proposals")

    op.drop_index("ix_airun_org_created", table_name="ai_runs")
    op.drop_table("ai_runs")

    op.drop_index("ix_atr_org_created", table_name="ai_task_requests")
    op.drop_table("ai_task_requests")

    op.drop_index("ix_apc_org_enabled", table_name="ai_provider_configs")
    op.drop_table("ai_provider_configs")

    op.drop_table("ai_model_catalog")
