"""Phase 15 optional AI red-team session governance (lab-only, human-approved, budgeted)."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0016_phase15_ai_redteam"
down_revision: str | None = "0015_phase14_hardening_dr"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = (
    "ai_redteam_sessions",
    "ai_redteam_observations",
    "ai_redteam_events",
    "ai_redteam_benchmarks",
)


def _uuid_pk() -> sa.Column:  # type: ignore[type-arg]
    return sa.Column(
        "id",
        postgresql.UUID(as_uuid=True),
        primary_key=True,
        nullable=False,
        server_default=sa.text("gen_random_uuid()"),
    )


def upgrade() -> None:
    op.create_table(
        "ai_redteam_sessions",
        _uuid_pk(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(160), nullable=False),
        sa.Column("objective", sa.String(1000), nullable=False),
        sa.Column("engine", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default=sa.text("'requested'")),
        sa.Column("tool_allowlist", postgresql.JSONB(), nullable=False),
        sa.Column("target_urls", postgresql.JSONB(), nullable=False),
        sa.Column("max_duration_seconds", sa.Integer(), nullable=False),
        sa.Column("max_tool_calls", sa.Integer(), nullable=False),
        sa.Column("max_tokens", sa.Integer(), nullable=False),
        sa.Column("tool_calls_used", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("tokens_used", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approval_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("end_reason", sa.String(200), nullable=True),
        sa.Column(
            "cleanup_attested",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("cleanup_summary", sa.Text(), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE", name="fk_rts_org"
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_rts_org_id_id"),
        sa.CheckConstraint("engine IN ('strix', 'pentagi')", name="ck_rts_engine"),
        sa.CheckConstraint(
            "status IN ('requested', 'approved', 'running', 'completed', "
            "'terminated', 'expired', 'rejected')",
            name="ck_rts_status",
        ),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="ck_rts_approver_not_requester",
        ),
        sa.CheckConstraint(
            "max_duration_seconds BETWEEN 60 AND 3600", name="ck_rts_duration_bounds"
        ),
        sa.CheckConstraint("max_tool_calls BETWEEN 1 AND 500", name="ck_rts_tool_call_bounds"),
        sa.CheckConstraint("max_tokens BETWEEN 1000 AND 2000000", name="ck_rts_token_bounds"),
        sa.CheckConstraint("tool_calls_used >= 0 AND tokens_used >= 0", name="ck_rts_usage_nonneg"),
        sa.CheckConstraint(
            "status NOT IN ('approved', 'running', 'completed') OR approved_by IS NOT NULL",
            name="ck_rts_approval_required",
        ),
        sa.CheckConstraint(
            "status NOT IN ('completed', 'terminated') OR cleanup_attested = true",
            name="ck_rts_cleanup_attested_on_close",
        ),
    )
    op.create_index("ix_rts_org_status", "ai_redteam_sessions", ["organization_id", "status"])
    op.create_index("ix_rts_org_created", "ai_redteam_sessions", ["organization_id", "created_at"])

    op.create_table(
        "ai_redteam_observations",
        _uuid_pk(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column(
            "classification", sa.String(16), nullable=False, server_default=sa.text("'hypothesis'")
        ),
        sa.Column("evidence_summary", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default=sa.text("'ai_agent'")),
        sa.Column("recorded_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_note", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "session_id"],
            ["ai_redteam_sessions.organization_id", "ai_redteam_sessions.id"],
            ondelete="CASCADE",
            name="fk_rto_org_session",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_rto_org_id_id"),
        sa.CheckConstraint(
            "classification IN ('hypothesis', 'confirmed', 'rejected')",
            name="ck_rto_classification",
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_rto_severity"
        ),
        sa.CheckConstraint(
            "classification = 'hypothesis' OR (reviewed_by IS NOT NULL "
            "AND reviewed_by <> recorded_by AND char_length(btrim(review_note)) >= 12)",
            name="ck_rto_confirmed_requires_independent_review",
        ),
        sa.CheckConstraint(
            "(classification = 'hypothesis' AND reviewed_by IS NULL) "
            "OR (classification IN ('confirmed', 'rejected') AND reviewed_by IS NOT NULL)",
            name="ck_rto_decided_has_reviewer",
        ),
    )
    op.create_index(
        "ix_rto_org_session", "ai_redteam_observations", ["organization_id", "session_id"]
    )

    op.create_table(
        "ai_redteam_events",
        _uuid_pk(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("event_type", sa.String(48), nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_email", sa.String(320), nullable=True),
        sa.Column("tool_name", sa.String(64), nullable=True),
        sa.Column("target_host", sa.String(255), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["organization_id", "session_id"],
            ["ai_redteam_sessions.organization_id", "ai_redteam_sessions.id"],
            ondelete="CASCADE",
            name="fk_rte_org_session",
        ),
        sa.CheckConstraint(
            "outcome IN ('allowed', 'denied', 'completed', 'failed')", name="ck_rte_outcome"
        ),
    )
    op.create_index(
        "ix_rte_org_session_time",
        "ai_redteam_events",
        ["organization_id", "session_id", "occurred_at"],
    )

    op.create_table(
        "ai_redteam_benchmarks",
        _uuid_pk(),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("ground_truth_slugs", postgresql.JSONB(), nullable=False),
        sa.Column("ai_detected_slugs", postgresql.JSONB(), nullable=False),
        sa.Column("zap_detected_slugs", postgresql.JSONB(), nullable=False),
        sa.Column("nuclei_detected_slugs", postgresql.JSONB(), nullable=False),
        sa.Column("metrics_json", postgresql.JSONB(), nullable=False),
        sa.Column(
            "data_provenance",
            sa.String(48),
            nullable=False,
            server_default=sa.text("'operator_supplied_unverified'"),
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "session_id"],
            ["ai_redteam_sessions.organization_id", "ai_redteam_sessions.id"],
            ondelete="CASCADE",
            name="fk_rtb_org_session",
        ),
    )
    op.create_index(
        "ix_rtb_org_created", "ai_redteam_benchmarks", ["organization_id", "created_at"]
    )

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

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT, UPDATE ON ai_redteam_sessions TO vforge_app;
                REVOKE DELETE ON ai_redteam_sessions FROM vforge_app;
                GRANT SELECT, INSERT, UPDATE ON ai_redteam_observations TO vforge_app;
                REVOKE DELETE ON ai_redteam_observations FROM vforge_app;
                GRANT SELECT, INSERT ON ai_redteam_events, ai_redteam_benchmarks
                    TO vforge_app;
                REVOKE UPDATE, DELETE ON ai_redteam_events, ai_redteam_benchmarks
                    FROM vforge_app;
            END IF;
        END $$;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase15_immutable_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Table % is append-only and cannot be mutated (%)',
                TG_TABLE_NAME, TG_OP;
        END;
        $$;
        """
    )
    for tbl in ("ai_redteam_events", "ai_redteam_benchmarks"):
        op.execute(
            f"""
            CREATE TRIGGER trg_{tbl}_immutable
            BEFORE UPDATE OR DELETE ON {tbl}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase15_immutable_mutation();
            """
        )

    # Observations: must be inserted as 'hypothesis', only a one-time review transition
    # is permitted, and all evidence/identity fields are frozen at the database layer.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION guard_phase15_observation_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'ai_redteam_observations rows cannot be deleted';
            END IF;
            IF TG_OP = 'INSERT' THEN
                IF NEW.classification <> 'hypothesis'
                   OR NEW.reviewed_by IS NOT NULL
                   OR NEW.reviewed_at IS NOT NULL THEN
                    RAISE EXCEPTION
                        'ai_redteam_observations must be inserted as unreviewed hypothesis';
                END IF;
                RETURN NEW;
            END IF;
            IF OLD.classification <> 'hypothesis' THEN
                RAISE EXCEPTION 'ai_redteam_observations decision is final once set';
            END IF;
            IF NEW.id <> OLD.id
               OR NEW.organization_id <> OLD.organization_id
               OR NEW.session_id <> OLD.session_id
               OR NEW.title <> OLD.title
               OR NEW.category <> OLD.category
               OR NEW.severity <> OLD.severity
               OR NEW.evidence_summary <> OLD.evidence_summary
               OR NEW.evidence_sha256 <> OLD.evidence_sha256
               OR NEW.source <> OLD.source
               OR NEW.recorded_by <> OLD.recorded_by
               OR NEW.created_at <> OLD.created_at THEN
                RAISE EXCEPTION 'ai_redteam_observations evidence and identity are immutable';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_ai_redteam_observations_guard
        BEFORE INSERT OR UPDATE OR DELETE ON ai_redteam_observations
        FOR EACH ROW EXECUTE FUNCTION guard_phase15_observation_update();
        """
    )

    # Session identity/scope frozen once created: only lifecycle + usage columns may change,
    # and terminal sessions are completely immutable.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION guard_phase15_session_update()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                RAISE EXCEPTION 'ai_redteam_sessions rows cannot be deleted';
            END IF;
            IF OLD.status IN ('completed', 'terminated', 'expired', 'rejected') THEN
                RAISE EXCEPTION 'ai_redteam_sessions terminal session is immutable';
            END IF;
            IF NEW.id <> OLD.id
               OR NEW.organization_id <> OLD.organization_id
               OR NEW.title <> OLD.title
               OR NEW.objective <> OLD.objective
               OR NEW.engine <> OLD.engine
               OR NEW.tool_allowlist <> OLD.tool_allowlist
               OR NEW.target_urls <> OLD.target_urls
               OR NEW.max_duration_seconds <> OLD.max_duration_seconds
               OR NEW.max_tool_calls <> OLD.max_tool_calls
               OR NEW.max_tokens <> OLD.max_tokens
               OR NEW.requested_by <> OLD.requested_by
               OR NEW.created_at <> OLD.created_at THEN
                RAISE EXCEPTION 'ai_redteam_sessions scope, allowlists and budgets are immutable';
            END IF;
            IF OLD.approved_by IS NOT NULL
               AND (NEW.approved_by IS DISTINCT FROM OLD.approved_by
                    OR NEW.approved_at IS DISTINCT FROM OLD.approved_at
                    OR NEW.approval_expires_at IS DISTINCT FROM OLD.approval_expires_at) THEN
                RAISE EXCEPTION 'ai_redteam_sessions approval metadata is immutable once set';
            END IF;
            IF OLD.started_at IS NOT NULL
               AND NEW.started_at IS DISTINCT FROM OLD.started_at THEN
                RAISE EXCEPTION 'ai_redteam_sessions started_at is immutable once set';
            END IF;
            IF NEW.tool_calls_used < OLD.tool_calls_used OR NEW.tokens_used < OLD.tokens_used THEN
                RAISE EXCEPTION 'ai_redteam_sessions usage counters are monotonic';
            END IF;
            IF NEW.tool_calls_used > NEW.max_tool_calls OR NEW.tokens_used > NEW.max_tokens THEN
                RAISE EXCEPTION 'ai_redteam_sessions budget exceeded';
            END IF;
            RETURN NEW;
        END;
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_ai_redteam_sessions_guard
        BEFORE UPDATE OR DELETE ON ai_redteam_sessions
        FOR EACH ROW EXECUTE FUNCTION guard_phase15_session_update();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_ai_redteam_sessions_guard ON ai_redteam_sessions;")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_ai_redteam_observations_guard ON ai_redteam_observations;"
    )
    for tbl in ("ai_redteam_events", "ai_redteam_benchmarks"):
        op.execute(f"DROP TRIGGER IF EXISTS trg_{tbl}_immutable ON {tbl};")
    op.execute("DROP FUNCTION IF EXISTS guard_phase15_session_update();")
    op.execute("DROP FUNCTION IF EXISTS guard_phase15_observation_update();")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase15_immutable_mutation();")
    for tbl in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")
        op.drop_table(tbl)
