"""Phase 5 source snapshots, canonical findings, and immutable scanner occurrences.

Revision ID: 0006_phase5_scanners
Revises: 0005_phase4_runner_isolation
Create Date: 2026-11-12 19:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0006_phase5_scanners"
down_revision: str | Sequence[str] | None = "0005_phase4_runner_isolation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MUTABLE_TENANT_TABLES = (
    "source_snapshots",
    "findings",
)
_IMMUTABLE_TENANT_TABLES = ("finding_occurrences",)


def upgrade() -> None:
    op.create_table(
        "source_snapshots",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_type", sa.String(length=30), nullable=False),
        sa.Column("commit_sha", sa.String(length=64), nullable=True),
        sa.Column("branch", sa.String(length=160), nullable=True),
        sa.Column("archive_sha256", sa.String(length=64), nullable=False),
        sa.Column("storage_key", sa.Text(), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "encryption_algorithm",
            sa.String(length=40),
            server_default=sa.text("'AES-256-GCM'"),
            nullable=False,
        ),
        sa.Column("encryption_key_id", sa.String(length=100), nullable=False),
        sa.Column("wrapped_dek_b64", sa.Text(), nullable=False),
        sa.Column("nonce_b64", sa.Text(), nullable=False),
        sa.Column("aad_b64", sa.Text(), nullable=False),
        sa.Column("file_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column("total_bytes", sa.BigInteger(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "detected_languages",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "coverage_report",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'ready'"),
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_source_snapshots"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_source_snapshots_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_source_snapshots_org_project",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="RESTRICT",
            name="fk_source_snapshots_org_asset",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["app_users.id"],
            ondelete="RESTRICT",
            name="fk_source_snapshots_created_by",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_source_snapshots_org_id_id"),
        sa.UniqueConstraint("storage_key", name="uq_source_snapshots_storage_key"),
        sa.CheckConstraint(
            "source_type IN ('archive_tar_gz', 'archive_zip', 'git_commit')",
            name="ck_source_snapshots_type",
        ),
        sa.CheckConstraint(
            "status IN ('ready', 'rejected', 'purged')",
            name="ck_source_snapshots_status",
        ),
        sa.CheckConstraint("file_count >= 0", name="ck_source_snapshots_file_count"),
        sa.CheckConstraint("total_bytes >= 0", name="ck_source_snapshots_total_bytes"),
    )
    op.create_index(
        "ix_source_snapshots_org_proj_created",
        "source_snapshots",
        ["organization_id", "project_id", "created_at"],
    )

    op.add_column(
        "scan_runs",
        sa.Column("source_snapshot_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "scan_runs",
        sa.Column(
            "coverage_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
    )
    op.create_foreign_key(
        "fk_scan_runs_org_source_snapshot",
        "scan_runs",
        "source_snapshots",
        ["organization_id", "source_snapshot_id"],
        ["organization_id", "id"],
        ondelete="RESTRICT",
    )

    op.create_table(
        "findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("fingerprint", sa.String(length=128), nullable=False),
        sa.Column("category", sa.String(length=30), nullable=False),
        sa.Column("scanner_tool_id", sa.String(length=100), nullable=False),
        sa.Column("scanner_version", sa.String(length=100), nullable=False),
        sa.Column("rule_id", sa.String(length=200), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column(
            "validation_status",
            sa.String(length=30),
            server_default=sa.text("'unverified'"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            server_default=sa.text("'open'"),
            nullable=False,
        ),
        sa.Column(
            "cwe_ids",
            postgresql.ARRAY(sa.String(length=40)),
            server_default=sa.text("'{}'::varchar[]"),
            nullable=False,
        ),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("code_snippet_redacted", sa.Text(), nullable=True),
        sa.Column(
            "secret_redacted",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("remediation", sa.Text(), nullable=True),
        sa.Column("occurrence_count", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column(
            "first_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_findings"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_findings_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_findings_org_project",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_findings_org_id_id"),
        sa.UniqueConstraint(
            "organization_id", "project_id", "fingerprint", name="uq_findings_org_proj_fp"
        ),
        sa.CheckConstraint(
            "category IN ('sast', 'secret', 'sca', 'iac', 'dast', 'network')",
            name="ck_findings_category",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')",
            name="ck_findings_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_findings_confidence",
        ),
        sa.CheckConstraint(
            "validation_status IN ("
            "'unverified', 'reproduced', 'human_confirmed', "
            "'false_positive', 'accepted_risk', 'fixed', 'reopened')",
            name="ck_findings_validation_status",
        ),
        sa.CheckConstraint(
            "status IN ('open', 'in_progress', 'resolved', 'risk_accepted', 'false_positive')",
            name="ck_findings_status",
        ),
    )
    op.create_index(
        "ix_findings_org_proj_sev", "findings", ["organization_id", "project_id", "severity"]
    )
    op.create_index("ix_findings_org_status", "findings", ["organization_id", "status"])

    op.create_table(
        "finding_occurrences",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("scanner_tool_id", sa.String(length=100), nullable=False),
        sa.Column("scanner_version", sa.String(length=100), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column("rule_id", sa.String(length=200), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("start_line", sa.Integer(), nullable=True),
        sa.Column("end_line", sa.Integer(), nullable=True),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column(
            "secret_redacted",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("snippet_redacted", sa.Text(), nullable=True),
        sa.Column(
            "raw_finding_sanitized",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_finding_occurrences"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org_finding",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org_run",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["tool_executions.organization_id", "tool_executions.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org_exec",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "evidence_artifact_id"],
            ["artifacts.organization_id", "artifacts.id"],
            ondelete="RESTRICT",
            name="fk_finding_occ_org_artifact",
        ),
    )
    op.create_index(
        "ix_finding_occ_org_run", "finding_occurrences", ["organization_id", "scan_run_id"]
    )
    op.create_index(
        "ix_finding_occ_org_finding", "finding_occurrences", ["organization_id", "finding_id"]
    )

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
        CREATE OR REPLACE FUNCTION prevent_phase5_immutable_mutation()
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
            FOR EACH ROW EXECUTE FUNCTION prevent_phase5_immutable_mutation();
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


def downgrade() -> None:
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table}")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase5_immutable_mutation()")

    op.drop_index("ix_finding_occ_org_finding", table_name="finding_occurrences")
    op.drop_index("ix_finding_occ_org_run", table_name="finding_occurrences")
    op.drop_table("finding_occurrences")

    op.drop_index("ix_findings_org_status", table_name="findings")
    op.drop_index("ix_findings_org_proj_sev", table_name="findings")
    op.drop_table("findings")

    op.drop_constraint("fk_scan_runs_org_source_snapshot", "scan_runs", type_="foreignkey")
    op.drop_column("scan_runs", "coverage_summary")
    op.drop_column("scan_runs", "source_snapshot_id")

    op.drop_index("ix_source_snapshots_org_proj_created", table_name="source_snapshots")
    op.drop_table("source_snapshots")
