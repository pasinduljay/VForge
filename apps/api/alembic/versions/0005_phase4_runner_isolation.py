"""Phase 4 runner pools, mTLS runners, heartbeats, events, executions, and encrypted artifacts.

Revision ID: 0005_phase4_runner_isolation
Revises: 0004_phase3_orchestration
Create Date: 2026-11-12 18:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0005_phase4_runner_isolation"
down_revision: str | Sequence[str] | None = "0004_phase3_orchestration"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MUTABLE_TENANT_TABLES = (
    "runner_pools",
    "runners",
    "runner_heartbeats",
    "tool_executions",
)
_IMMUTABLE_TENANT_TABLES = (
    "runner_events",
    "artifacts",
)


def upgrade() -> None:
    op.create_table(
        "runner_pools",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column(
            "pool_type",
            sa.String(length=30),
            server_default=sa.text("'standard'"),
            nullable=False,
        ),
        sa.Column(
            "max_concurrent_jobs",
            sa.Integer(),
            server_default=sa.text("4"),
            nullable=False,
        ),
        sa.Column(
            "active",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_runner_pools_org",
        ),
        sa.UniqueConstraint("organization_id", "slug", name="uq_runner_pools_org_slug"),
        sa.UniqueConstraint("organization_id", "id", name="uq_runner_pools_org_id_id"),
        sa.CheckConstraint(
            "pool_type IN ('standard', 'dast_egress', 'airgapped')",
            name="ck_runner_pools_type",
        ),
        sa.CheckConstraint("max_concurrent_jobs >= 1", name="ck_runner_pools_conc_pos"),
    )
    op.create_index("ix_runner_pools_org", "runner_pools", ["organization_id"])

    op.create_table(
        "runners",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("pool_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=160), nullable=False),
        sa.Column("runner_identity", sa.String(length=255), nullable=False),
        sa.Column("cert_sha256", sa.String(length=64), nullable=False),
        sa.Column("cert_subject", sa.String(length=255), nullable=False),
        sa.Column("cert_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column(
            "capabilities_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "pool_id"],
            ["runner_pools.organization_id", "runner_pools.id"],
            ondelete="RESTRICT",
            name="fk_runners_org_pool",
        ),
        sa.ForeignKeyConstraint(
            ["revoked_by"],
            ["app_users.id"],
            ondelete="RESTRICT",
            name="fk_runners_revoked_by",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_runners_org_id_id"),
        sa.UniqueConstraint("cert_sha256", name="uq_runners_cert_sha256"),
        sa.UniqueConstraint("runner_identity", name="uq_runners_identity"),
        sa.CheckConstraint(
            "status IN ('pending', 'active', 'draining', 'revoked')",
            name="ck_runners_status",
        ),
        sa.CheckConstraint(
            "cert_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_runners_cert_sha256_hex",
        ),
    )
    op.create_index("ix_runners_org_status", "runners", ["organization_id", "status"])
    op.create_index("ix_runners_pool", "runners", ["pool_id"])

    op.add_column(
        "runner_jobs",
        sa.Column(
            "execution_mode",
            sa.String(length=20),
            server_default=sa.text("'simulated'"),
            nullable=False,
        ),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("target_pool_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("claimed_by_runner_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("manifest_signature", sa.Text(), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("manifest_signing_key_id", sa.String(length=120), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("manifest_expires_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "runner_jobs",
        sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_check_constraint(
        "ck_runner_jobs_exec_mode",
        "runner_jobs",
        "execution_mode IN ('simulated', 'runner')",
    )
    op.create_foreign_key(
        "fk_runner_jobs_org_pool",
        "runner_jobs",
        "runner_pools",
        ["organization_id", "target_pool_id"],
        ["organization_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "fk_runner_jobs_org_runner",
        "runner_jobs",
        "runners",
        ["organization_id", "claimed_by_runner_id"],
        ["organization_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_runner_jobs_claimable",
        "runner_jobs",
        ["organization_id", "target_pool_id", "status"],
        postgresql_where=sa.text("execution_mode = 'runner' AND status = 'leased'"),
    )

    op.create_table(
        "runner_heartbeats",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("cpu_percent", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("memory_mb", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("active_containers", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "metrics_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="CASCADE",
            name="fk_runner_hb_org_runner",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="SET NULL (runner_job_id)",
            name="fk_runner_hb_org_job",
        ),
        sa.CheckConstraint("cpu_percent >= 0", name="ck_runner_hb_cpu_nonneg"),
        sa.CheckConstraint("memory_mb >= 0", name="ck_runner_hb_mem_nonneg"),
        sa.CheckConstraint("active_containers >= 0", name="ck_runner_hb_containers_nonneg"),
    )
    op.create_index("ix_runner_hb_runner_time", "runner_heartbeats", ["runner_id", "recorded_at"])

    op.create_table(
        "runner_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column(
            "severity",
            sa.String(length=20),
            server_default=sa.text("'info'"),
            nullable=False,
        ),
        sa.Column(
            "details_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="RESTRICT",
            name="fk_runner_events_org_runner",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="RESTRICT",
            name="fk_runner_events_org_job",
        ),
        sa.CheckConstraint(
            "severity IN ('info', 'warning', 'security')",
            name="ck_runner_events_severity",
        ),
    )
    op.create_index(
        "ix_runner_events_org_created", "runner_events", ["organization_id", "created_at"]
    )

    op.create_table(
        "tool_executions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_id", sa.String(length=100), nullable=False),
        sa.Column("tool_version", sa.String(length=100), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.String(length=50), nullable=False),
        sa.Column("config_hash", sa.String(length=128), nullable=True),
        sa.Column("rule_pack_hash", sa.String(length=128), nullable=True),
        sa.Column("template_snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'running'"),
            nullable=False,
        ),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "execution_metrics",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="CASCADE",
            name="fk_tool_exec_org_job",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="RESTRICT",
            name="fk_tool_exec_org_runner",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_tool_executions_org_id_id"),
        sa.CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'timed_out', 'cancelled')",
            name="ck_tool_exec_status",
        ),
    )
    op.create_index("ix_tool_exec_job", "tool_executions", ["runner_job_id"])

    op.create_table(
        "artifacts",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("artifact_type", sa.String(length=50), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("encryption_algorithm", sa.String(length=40), nullable=False),
        sa.Column("encryption_key_id", sa.String(length=120), nullable=False),
        sa.Column("wrapped_dek_b64", sa.Text(), nullable=False),
        sa.Column("nonce_b64", sa.String(length=64), nullable=False),
        sa.Column("aad_b64", sa.Text(), nullable=False),
        sa.Column("content_type", sa.String(length=150), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_artifacts_org_run",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="RESTRICT",
            name="fk_artifacts_org_job",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["tool_executions.organization_id", "tool_executions.id"],
            ondelete="RESTRICT",
            name="fk_artifacts_org_exec",
        ),
        sa.UniqueConstraint("storage_key", name="uq_artifacts_storage_key"),
        sa.UniqueConstraint("organization_id", "id", name="uq_artifacts_org_id_id"),
        sa.CheckConstraint(
            "artifact_type IN ('raw_output', 'execution_log', 'manifest')",
            name="ck_artifacts_type",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_artifacts_size_nonneg"),
        sa.CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="ck_artifacts_sha256_hex"),
        sa.CheckConstraint(
            "ciphertext_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_artifacts_ct_sha256_hex",
        ),
    )
    op.create_index("ix_artifacts_org_run", "artifacts", ["organization_id", "scan_run_id"])

    for table in _MUTABLE_TENANT_TABLES + _IMMUTABLE_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY p_{table}_tenant_isolation ON {table}
            FOR ALL
            USING (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            """
        )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase4_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION '% is immutable/append-only: % is not permitted', TG_TABLE_NAME, TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase4_immutable_mutation();
            """
        )

    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE {", ".join(_MUTABLE_TENANT_TABLES)}
                TO vforge_app;
                GRANT SELECT, INSERT ON TABLE {", ".join(_IMMUTABLE_TENANT_TABLES)}
                TO vforge_app;
                REVOKE UPDATE, DELETE ON TABLE {", ".join(_IMMUTABLE_TENANT_TABLES)}
                FROM vforge_app;
            END IF;
        END
        $$;
        """  # noqa: S608
    )

    op.create_table(
        "runner_liveness",
        sa.Column("runner_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(length=30), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("runner_id", name="pk_runner_liveness"),
        sa.ForeignKeyConstraint(
            ["runner_id"],
            ["runners.id"],
            ondelete="CASCADE",
            name="fk_runner_liveness_runner",
        ),
    )
    op.create_index(
        "ix_runner_liveness_status_hb", "runner_liveness", ["status", "last_heartbeat_at"]
    )
    op.execute("REVOKE ALL ON TABLE runner_liveness FROM PUBLIC")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                REVOKE ALL ON TABLE runner_liveness FROM vforge_app;
            END IF;
        END
        $$;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public._sync_runner_liveness()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                DELETE FROM public.runner_liveness WHERE runner_id = OLD.id;
                RETURN OLD;
            END IF;
            INSERT INTO public.runner_liveness (runner_id, status, last_heartbeat_at)
            VALUES (NEW.id, NEW.status, NEW.last_heartbeat_at)
            ON CONFLICT (runner_id) DO UPDATE
            SET status = EXCLUDED.status,
                last_heartbeat_at = EXCLUDED.last_heartbeat_at;
            RETURN NEW;
        END;
        $$;
        REVOKE ALL ON FUNCTION public._sync_runner_liveness() FROM PUBLIC;

        CREATE TRIGGER trg_runners_liveness_sync
        AFTER INSERT OR UPDATE OR DELETE ON public.runners
        FOR EACH ROW
        EXECUTE FUNCTION public._sync_runner_liveness();

        CREATE OR REPLACE FUNCTION public.count_online_runners(p_cutoff timestamptz)
        RETURNS integer
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT COUNT(*)::integer
            FROM public.runner_liveness
            WHERE status = 'active'
              AND last_heartbeat_at IS NOT NULL
              AND last_heartbeat_at >= p_cutoff;
        $$;
        REVOKE ALL ON FUNCTION public.count_online_runners(timestamptz) FROM PUBLIC;
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT EXECUTE ON FUNCTION public.count_online_runners(timestamptz) TO vforge_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS public.count_online_runners(timestamptz)")
    op.execute("DROP TRIGGER IF EXISTS trg_runners_liveness_sync ON public.runners")
    op.execute("DROP FUNCTION IF EXISTS public._sync_runner_liveness()")
    op.drop_index("ix_runner_liveness_status_hb", table_name="runner_liveness")
    op.drop_table("runner_liveness")

    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table}")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase4_immutable_mutation()")

    op.drop_index("ix_artifacts_org_run", table_name="artifacts")
    op.drop_table("artifacts")
    op.drop_index("ix_tool_exec_job", table_name="tool_executions")
    op.drop_table("tool_executions")
    op.drop_index("ix_runner_events_org_created", table_name="runner_events")
    op.drop_table("runner_events")
    op.drop_index("ix_runner_hb_runner_time", table_name="runner_heartbeats")
    op.drop_table("runner_heartbeats")

    op.drop_index("ix_runner_jobs_claimable", table_name="runner_jobs")
    op.drop_constraint("fk_runner_jobs_org_runner", "runner_jobs", type_="foreignkey")
    op.drop_constraint("fk_runner_jobs_org_pool", "runner_jobs", type_="foreignkey")
    op.drop_constraint("ck_runner_jobs_exec_mode", "runner_jobs", type_="check")
    op.drop_column("runner_jobs", "claimed_at")
    op.drop_column("runner_jobs", "cancel_requested_at")
    op.drop_column("runner_jobs", "manifest_expires_at")
    op.drop_column("runner_jobs", "manifest_signing_key_id")
    op.drop_column("runner_jobs", "manifest_signature")
    op.drop_column("runner_jobs", "manifest_sha256")
    op.drop_column("runner_jobs", "claimed_by_runner_id")
    op.drop_column("runner_jobs", "target_pool_id")
    op.drop_column("runner_jobs", "execution_mode")

    op.drop_index("ix_runners_pool", table_name="runners")
    op.drop_index("ix_runners_org_status", table_name="runners")
    op.drop_table("runners")
    op.drop_index("ix_runner_pools_org", table_name="runner_pools")
    op.drop_table("runner_pools")
