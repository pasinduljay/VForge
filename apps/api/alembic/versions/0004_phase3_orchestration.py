"""Phase 3 orchestration tables, target leases, transactional outbox, and RLS

Revision ID: 0004_phase3_orchestration
Revises: 0003_phase2_scope_snapshots
Create Date: 2026-11-12 17:15:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0004_phase3_orchestration"
down_revision: str | Sequence[str] | None = "0003_phase2_scope_snapshots"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = (
    "scan_runs",
    "scan_stages",
    "runner_jobs",
    "scan_target_leases",
    "outbox_events",
)


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_scan_profiles_org_id_id",
        "scan_profiles",
        ["organization_id", "id"],
    )
    op.create_unique_constraint(
        "uq_scope_snapshots_org_id_id",
        "scope_snapshots",
        ["organization_id", "id"],
    )

    op.create_table(
        "scan_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_profile_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authorization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scope_snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            sa.String(length=40),
            server_default=sa.text("'queued'"),
            nullable=False,
        ),
        sa.Column(
            "coverage_status",
            sa.String(length=40),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "runner_pool",
            sa.String(length=80),
            server_default=sa.text("'control-preflight'"),
            nullable=False,
        ),
        sa.Column("source_snapshot_hash", sa.String(length=128), nullable=True),
        sa.Column("target_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("profile_snapshot", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("plan_manifest", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("policy_snapshot_hash", sa.String(length=128), nullable=False),
        sa.Column("policy_version", sa.String(length=50), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column("request_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("cancel_requested_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("cancel_reason", sa.Text(), nullable=True),
        sa.Column("error_summary", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.ForeignKeyConstraint(["requested_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["cancel_requested_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_project",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "environment_id"],
            ["environments.organization_id", "environments.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_environment",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_profile_id"],
            ["scan_profiles.organization_id", "scan_profiles.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_scan_profile",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "authorization_id"],
            ["authorizations.organization_id", "authorizations.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_authorization",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "scope_snapshot_id"],
            ["scope_snapshots.organization_id", "scope_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_snapshot",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_scan_runs_org_id_id"),
        sa.UniqueConstraint("organization_id", "idempotency_key", name="uq_scan_runs_org_idemp"),
        sa.CheckConstraint(
            "status IN ('draft', 'scope_validation', 'awaiting_approval', 'queued', "
            "'provisioning', 'running', 'collecting', 'normalizing', 'correlating', "
            "'reporting', 'cancelling', 'completed', 'completed_with_errors', 'partial', "
            "'failed', 'rejected', 'cancelled')",
            name="ck_scan_runs_status",
        ),
        sa.CheckConstraint(
            "coverage_status IN ('pending', 'complete', 'partial', 'failed', 'not_applicable')",
            name="ck_scan_runs_coverage_status",
        ),
    )
    op.create_index("ix_scan_runs_org_created", "scan_runs", ["organization_id", "created_at"])
    op.create_index("ix_scan_runs_org_status", "scan_runs", ["organization_id", "status"])

    op.create_table(
        "scan_stages",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("stage_key", sa.String(length=100), nullable=False),
        sa.Column("stage_order", sa.Integer(), nullable=False),
        sa.Column("stage_kind", sa.String(length=40), nullable=False),
        sa.Column("depends_on_stage_key", sa.String(length=100), nullable=True),
        sa.Column(
            "requires_target_lease",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("lease_risk_class", sa.String(length=40), nullable=True),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_scan_stages_org_run",
        ),
        sa.UniqueConstraint("scan_run_id", "stage_key", name="uq_scan_stages_run_key"),
        sa.UniqueConstraint("organization_id", "id", name="uq_scan_stages_org_id_id"),
        sa.CheckConstraint(
            "status IN ('pending', 'queued', 'running', 'completed', "
            "'failed', 'skipped', 'cancelled')",
            name="ck_scan_stages_status",
        ),
        sa.CheckConstraint(
            "lease_risk_class IS NULL OR "
            "lease_risk_class IN ('active_http', 'network_scan', 'ai_sandbox')",
            name="ck_scan_stages_lease_risk_class",
        ),
    )
    op.create_index("ix_scan_stages_run_order", "scan_stages", ["scan_run_id", "stage_order"])

    op.create_table(
        "runner_jobs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_stage_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "job_type",
            sa.String(length=60),
            server_default=sa.text("'dummy_orchestration_task'"),
            nullable=False,
        ),
        sa.Column("tool_id", sa.String(length=100), nullable=False),
        sa.Column("tool_version", sa.String(length=100), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column("adapter_version", sa.String(length=50), nullable=False),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "attempt_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "max_attempts",
            sa.Integer(),
            server_default=sa.text("3"),
            nullable=False,
        ),
        sa.Column("lease_owner", sa.String(length=200), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("heartbeat_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "timeout_seconds",
            sa.Integer(),
            server_default=sa.text("300"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column(
            "job_configuration",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "execution_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "result_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("last_error_code", sa.String(length=80), nullable=True),
        sa.Column("last_error_message", sa.Text(), nullable=True),
        sa.Column("dispatched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.UniqueConstraint("idempotency_key"),
        sa.UniqueConstraint("organization_id", "id", name="uq_runner_jobs_org_id_id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_runner_jobs_org_run",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_stage_id"],
            ["scan_stages.organization_id", "scan_stages.id"],
            ondelete="CASCADE",
            name="fk_runner_jobs_org_stage",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'dispatched', 'leased', 'running', 'completed', "
            "'retry_scheduled', 'failed', 'timed_out', 'cancelled', 'abandoned')",
            name="ck_runner_jobs_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_runner_jobs_attempt_nonneg"),
        sa.CheckConstraint("max_attempts >= 1", name="ck_runner_jobs_max_attempts_pos"),
        sa.CheckConstraint("timeout_seconds >= 1", name="ck_runner_jobs_timeout_pos"),
        sa.CheckConstraint("execution_count >= 0", name="ck_runner_jobs_exec_count_nonneg"),
    )
    op.create_index("ix_runner_jobs_org_status", "runner_jobs", ["organization_id", "status"])
    op.create_index("ix_runner_jobs_run", "runner_jobs", ["scan_run_id"])

    op.create_table(
        "scan_target_leases",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_locator", sa.Text(), nullable=False),
        sa.Column(
            "lease_risk_class",
            sa.String(length=40),
            server_default=sa.text("'active_http'"),
            nullable=False,
        ),
        sa.Column("lease_owner", sa.String(length=200), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column(
            "acquired_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "heartbeat_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("released_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_target_leases_org_run",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="CASCADE",
            name="fk_target_leases_org_job",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="RESTRICT",
            name="fk_target_leases_org_asset",
        ),
        sa.CheckConstraint(
            "lease_risk_class IN ('active_http', 'network_scan', 'ai_sandbox')",
            name="ck_target_leases_risk_class",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'released', 'expired', 'revoked')",
            name="ck_target_leases_status",
        ),
    )
    op.create_index(
        "uq_active_target_lease",
        "scan_target_leases",
        ["asset_id", "lease_risk_class"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )
    op.create_index(
        "ix_target_leases_org_status",
        "scan_target_leases",
        ["organization_id", "status"],
    )

    op.create_table(
        "outbox_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=80), nullable=False),
        sa.Column("routing_key", sa.String(length=120), nullable=False),
        sa.Column("idempotency_key", sa.String(length=200), nullable=False),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column(
            "retry_count",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "max_retries",
            sa.Integer(),
            server_default=sa.text("5"),
            nullable=False,
        ),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_outbox_org_run",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="CASCADE",
            name="fk_outbox_org_job",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'published', 'dead_letter')",
            name="ck_outbox_status",
        ),
        sa.CheckConstraint("retry_count >= 0", name="ck_outbox_retry_nonneg"),
    )
    op.create_index(
        "ix_outbox_pending_due",
        "outbox_events",
        ["status", "next_attempt_at"],
        postgresql_where=sa.text("status = 'pending'"),
    )

    for table in _TENANT_TABLES:
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

    op.create_table(
        "orchestration_wakeups",
        sa.Column("work_kind", sa.String(length=40), nullable=False),
        sa.Column("record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("due_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("work_kind", "record_id", name="pk_orchestration_wakeups"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_orchestration_wakeups_org",
        ),
    )
    op.create_index("ix_orchestration_wakeups_due", "orchestration_wakeups", ["due_at"])
    op.create_index(
        "ix_orchestration_wakeups_kind_due",
        "orchestration_wakeups",
        ["work_kind", "due_at"],
    )

    op.execute("REVOKE ALL ON orchestration_wakeups FROM PUBLIC")
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT, UPDATE, DELETE
                ON scan_runs, scan_stages, runner_jobs, scan_target_leases, outbox_events
                TO vforge_app;
                REVOKE ALL ON orchestration_wakeups FROM vforge_app;
            END IF;
        END
        $$;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION public._sync_outbox_wakeup()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'outbox_dispatch' AND record_id = OLD.id;
                RETURN OLD;
            END IF;

            IF NEW.status = 'pending' THEN
                INSERT INTO public.orchestration_wakeups (
                    work_kind, record_id, organization_id, due_at
                )
                VALUES ('outbox_dispatch', NEW.id, NEW.organization_id, NEW.next_attempt_at)
                ON CONFLICT (work_kind, record_id) DO UPDATE
                SET organization_id = EXCLUDED.organization_id,
                    due_at = EXCLUDED.due_at;
            ELSE
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'outbox_dispatch' AND record_id = NEW.id;
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER trg_outbox_wakeups_sync
        AFTER INSERT OR UPDATE OR DELETE ON public.outbox_events
        FOR EACH ROW
        EXECUTE FUNCTION public._sync_outbox_wakeup();

        CREATE OR REPLACE FUNCTION public._sync_runner_job_wakeup()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind IN ('job_retry_due', 'job_lease_expired')
                  AND record_id = OLD.id;
                RETURN OLD;
            END IF;

            IF NEW.status = 'retry_scheduled' AND NEW.next_retry_at IS NOT NULL THEN
                INSERT INTO public.orchestration_wakeups (
                    work_kind, record_id, organization_id, due_at
                )
                VALUES ('job_retry_due', NEW.id, NEW.organization_id, NEW.next_retry_at)
                ON CONFLICT (work_kind, record_id) DO UPDATE
                SET organization_id = EXCLUDED.organization_id,
                    due_at = EXCLUDED.due_at;
            ELSE
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'job_retry_due' AND record_id = NEW.id;
            END IF;

            IF NEW.status IN ('dispatched', 'leased', 'running')
               AND NEW.lease_expires_at IS NOT NULL THEN
                INSERT INTO public.orchestration_wakeups (
                    work_kind, record_id, organization_id, due_at
                )
                VALUES ('job_lease_expired', NEW.id, NEW.organization_id, NEW.lease_expires_at)
                ON CONFLICT (work_kind, record_id) DO UPDATE
                SET organization_id = EXCLUDED.organization_id,
                    due_at = EXCLUDED.due_at;
            ELSE
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'job_lease_expired' AND record_id = NEW.id;
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER trg_runner_jobs_wakeups_sync
        AFTER INSERT OR UPDATE OR DELETE ON public.runner_jobs
        FOR EACH ROW
        EXECUTE FUNCTION public._sync_runner_job_wakeup();

        CREATE OR REPLACE FUNCTION public._sync_target_lease_wakeup()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'target_lease_expired' AND record_id = OLD.id;
                RETURN OLD;
            END IF;

            IF NEW.status = 'active' THEN
                INSERT INTO public.orchestration_wakeups (
                    work_kind, record_id, organization_id, due_at
                )
                VALUES ('target_lease_expired', NEW.id, NEW.organization_id, NEW.expires_at)
                ON CONFLICT (work_kind, record_id) DO UPDATE
                SET organization_id = EXCLUDED.organization_id,
                    due_at = EXCLUDED.due_at;
            ELSE
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'target_lease_expired' AND record_id = NEW.id;
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER trg_target_leases_wakeups_sync
        AFTER INSERT OR UPDATE OR DELETE ON public.scan_target_leases
        FOR EACH ROW
        EXECUTE FUNCTION public._sync_target_lease_wakeup();

        CREATE OR REPLACE FUNCTION public._sync_scan_run_wakeup()
        RETURNS trigger
        LANGUAGE plpgsql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
        BEGIN
            IF TG_OP = 'DELETE' THEN
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'run_cancelling_reconcile' AND record_id = OLD.id;
                RETURN OLD;
            END IF;

            IF NEW.status = 'cancelling' THEN
                INSERT INTO public.orchestration_wakeups (
                    work_kind, record_id, organization_id, due_at
                )
                VALUES ('run_cancelling_reconcile', NEW.id, NEW.organization_id, NEW.updated_at)
                ON CONFLICT (work_kind, record_id) DO UPDATE
                SET organization_id = EXCLUDED.organization_id,
                    due_at = EXCLUDED.due_at;
            ELSE
                DELETE FROM public.orchestration_wakeups
                WHERE work_kind = 'run_cancelling_reconcile' AND record_id = NEW.id;
            END IF;
            RETURN NEW;
        END;
        $$;

        CREATE TRIGGER trg_scan_runs_wakeups_sync
        AFTER INSERT OR UPDATE OR DELETE ON public.scan_runs
        FOR EACH ROW
        EXECUTE FUNCTION public._sync_scan_run_wakeup();

        REVOKE ALL ON FUNCTION public._sync_outbox_wakeup() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public._sync_runner_job_wakeup() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public._sync_target_lease_wakeup() FROM PUBLIC;
        REVOKE ALL ON FUNCTION public._sync_scan_run_wakeup() FROM PUBLIC;

        CREATE OR REPLACE FUNCTION public.list_due_orchestration_work(
            p_limit integer DEFAULT 100,
            p_work_kinds text[] DEFAULT NULL
        )
        RETURNS TABLE(work_kind text, record_id uuid, organization_id uuid)
        LANGUAGE sql
        SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$
            SELECT w.work_kind::text, w.record_id, w.organization_id
            FROM public.orchestration_wakeups w
            WHERE w.due_at <= now()
              AND (p_work_kinds IS NULL OR w.work_kind = ANY(p_work_kinds))
            ORDER BY w.due_at ASC
            LIMIT LEAST(GREATEST(p_limit, 1), 500);
        $$;
        REVOKE ALL ON FUNCTION public.list_due_orchestration_work(integer, text[]) FROM PUBLIC;
        """
    )

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT EXECUTE ON FUNCTION public.list_due_orchestration_work(integer, text[])
                TO vforge_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS public.list_due_orchestration_work(integer, text[])")
    op.execute("DROP FUNCTION IF EXISTS public.list_due_orchestration_work(integer)")
    op.execute("DROP TRIGGER IF EXISTS trg_scan_runs_wakeups_sync ON public.scan_runs")
    op.execute("DROP TRIGGER IF EXISTS trg_target_leases_wakeups_sync ON public.scan_target_leases")
    op.execute("DROP TRIGGER IF EXISTS trg_runner_jobs_wakeups_sync ON public.runner_jobs")
    op.execute("DROP TRIGGER IF EXISTS trg_outbox_wakeups_sync ON public.outbox_events")
    op.execute("DROP FUNCTION IF EXISTS public._sync_scan_run_wakeup()")
    op.execute("DROP FUNCTION IF EXISTS public._sync_target_lease_wakeup()")
    op.execute("DROP FUNCTION IF EXISTS public._sync_runner_job_wakeup()")
    op.execute("DROP FUNCTION IF EXISTS public._sync_outbox_wakeup()")

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                REVOKE ALL
                ON scan_runs, scan_stages, runner_jobs, scan_target_leases, outbox_events
                FROM vforge_app;
            END IF;
        END
        $$;
        """
    )

    for table in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS p_{table}_tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP INDEX IF EXISTS ix_orchestration_wakeups_kind_due")
    op.execute("DROP INDEX IF EXISTS ix_orchestration_wakeups_due")
    op.execute("DROP TABLE IF EXISTS orchestration_wakeups")

    op.drop_index("ix_outbox_pending_due", table_name="outbox_events")
    op.drop_table("outbox_events")

    op.drop_index("ix_target_leases_org_status", table_name="scan_target_leases")
    op.drop_index("uq_active_target_lease", table_name="scan_target_leases")
    op.drop_table("scan_target_leases")

    op.drop_index("ix_runner_jobs_run", table_name="runner_jobs")
    op.drop_index("ix_runner_jobs_org_status", table_name="runner_jobs")
    op.drop_table("runner_jobs")

    op.drop_index("ix_scan_stages_run_order", table_name="scan_stages")
    op.drop_table("scan_stages")

    op.drop_index("ix_scan_runs_org_status", table_name="scan_runs")
    op.drop_index("ix_scan_runs_org_created", table_name="scan_runs")
    op.drop_table("scan_runs")

    op.drop_constraint("uq_scope_snapshots_org_id_id", "scope_snapshots", type_="unique")
    op.drop_constraint("uq_scan_profiles_org_id_id", "scan_profiles", type_="unique")
