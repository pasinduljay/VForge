"""Phase 6 supply chain SBOM documents, offline vuln DB snapshots, and IaC/SCA traceability.

Revision ID: 0007_phase6_supply_chain_iac
Revises: 0006_phase5_scanners
Create Date: 2026-11-12 22:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0007_phase6_supply_chain_iac"
down_revision: str | Sequence[str] | None = "0006_phase5_scanners"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TENANT_TABLES = (
    "sbom_documents",
    "vulnerability_db_snapshots",
)


def upgrade() -> None:
    op.create_table(
        "sbom_documents",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_snapshot_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("execution_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("sbom_format", sa.String(length=30), nullable=False),
        sa.Column("spec_version", sa.String(length=40), nullable=False),
        sa.Column("serial_number", sa.String(length=120), nullable=True),
        sa.Column("bom_sha256", sa.String(length=64), nullable=False),
        sa.Column("tool_id", sa.String(length=60), nullable=False),
        sa.Column("tool_version", sa.String(length=60), nullable=False),
        sa.Column("image_digest", sa.Text(), nullable=False),
        sa.Column(
            "cataloger_config",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("component_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "components_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_sbom_documents"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_sbom_documents_org",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_sbom_documents_org_project",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_sbom_documents_org_run",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "source_snapshot_id"],
            ["source_snapshots.organization_id", "source_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_sbom_documents_org_snapshot",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["tool_executions.organization_id", "tool_executions.id"],
            ondelete="CASCADE",
            name="fk_sbom_documents_org_exec",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "artifact_id"],
            ["artifacts.organization_id", "artifacts.id"],
            ondelete="RESTRICT",
            name="fk_sbom_documents_org_artifact",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_sbom_documents_org_id_id"),
        sa.UniqueConstraint(
            "organization_id",
            "execution_id",
            "sbom_format",
            name="uq_sbom_documents_org_exec_fmt",
        ),
        sa.CheckConstraint(
            "sbom_format IN ('cyclonedx-json', 'spdx-json')",
            name="ck_sbom_documents_format",
        ),
        sa.CheckConstraint("component_count >= 0", name="ck_sbom_documents_count"),
    )
    op.create_index(
        "ix_sbom_documents_org_run", "sbom_documents", ["organization_id", "scan_run_id"]
    )
    op.create_index(
        "ix_sbom_documents_org_proj_created",
        "sbom_documents",
        ["organization_id", "project_id", "created_at"],
    )

    op.create_table(
        "vulnerability_db_snapshots",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_id", sa.String(length=60), nullable=False),
        sa.Column("schema_version", sa.String(length=40), nullable=False),
        sa.Column("built_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column("db_archive_sha256", sa.String(length=64), nullable=False),
        sa.Column("valid", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "providers_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_vulnerability_db_snapshots"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_vuln_db_snapshots_org",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_vuln_db_snapshots_org_id_id"),
        sa.UniqueConstraint(
            "organization_id",
            "tool_id",
            "schema_version",
            "db_archive_sha256",
            name="uq_vuln_db_snapshots_org_tool_ver_hash",
        ),
    )

    for table in ("findings", "finding_occurrences"):
        prefix = "findings" if table == "findings" else "finding_occ"
        op.add_column(table, sa.Column("purl", sa.Text(), nullable=True))
        op.add_column(table, sa.Column("package_name", sa.String(length=255), nullable=True))
        op.add_column(table, sa.Column("package_version", sa.String(length=120), nullable=True))
        op.add_column(table, sa.Column("fixed_version", sa.String(length=120), nullable=True))
        op.add_column(table, sa.Column("cve_id", sa.String(length=64), nullable=True))
        op.add_column(table, sa.Column("iac_resource", sa.String(length=255), nullable=True))
        op.add_column(
            table,
            sa.Column("sbom_document_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.add_column(
            table,
            sa.Column("vulnerability_db_snapshot_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.create_foreign_key(
            f"fk_{prefix}_org_sbom",
            table,
            "sbom_documents",
            ["organization_id", "sbom_document_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )
        op.create_foreign_key(
            f"fk_{prefix}_org_vuln_db",
            table,
            "vulnerability_db_snapshots",
            ["organization_id", "vulnerability_db_snapshot_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )

    op.create_index("ix_findings_org_purl", "findings", ["organization_id", "purl"])

    for table in _IMMUTABLE_TENANT_TABLES:
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
        CREATE OR REPLACE FUNCTION prevent_phase6_immutable_mutation()
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
            FOR EACH ROW EXECUTE FUNCTION prevent_phase6_immutable_mutation();
            """
        )

    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
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
    op.execute("DROP FUNCTION IF EXISTS prevent_phase6_immutable_mutation()")

    op.drop_index("ix_findings_org_purl", table_name="findings")
    for table in ("finding_occurrences", "findings"):
        prefix = "findings" if table == "findings" else "finding_occ"
        op.drop_constraint(f"fk_{prefix}_org_vuln_db", table, type_="foreignkey")
        op.drop_constraint(f"fk_{prefix}_org_sbom", table, type_="foreignkey")
        for col in (
            "vulnerability_db_snapshot_id",
            "sbom_document_id",
            "iac_resource",
            "cve_id",
            "fixed_version",
            "package_version",
            "package_name",
            "purl",
        ):
            op.drop_column(table, col)

    op.drop_table("vulnerability_db_snapshots")
    op.drop_index("ix_sbom_documents_org_proj_created", table_name="sbom_documents")
    op.drop_index("ix_sbom_documents_org_run", table_name="sbom_documents")
    op.drop_table("sbom_documents")
