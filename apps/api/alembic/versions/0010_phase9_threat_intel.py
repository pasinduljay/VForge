"""Phase 9 Threat Intelligence Connectors, Offline Sync, and Gated Enrichment.

Revision ID: 0010_phase9_threat_intel
Revises: 0009_phase8_findings_reporting
Create Date: 2026-11-13 02:30:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0010_phase9_threat_intel"
down_revision: str | Sequence[str] | None = "0009_phase8_findings_reporting"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_GLOBAL_TABLES = ("intel_snapshots",)
_IMMUTABLE_TENANT_TABLES = ("intel_enrichment_events",)
_ALL_TENANT_TABLES = ("intel_enrichment_events",)

_DEFAULT_SOURCES = [
    {
        "id": "11111111-1111-1111-1111-111111111001",
        "slug": "cisa_kev",
        "name": "CISA Known Exploited Vulnerabilities Catalog",
        "source_type": "exploit_catalog",
        "provider_url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "license_name": "Public Domain / CC0",
        "license_url": "https://www.cisa.gov/terms-use",
        "terms_reference": "Official CISA KEV catalog of exploited vulnerabilities in the wild",
        "is_active": True,
        "is_gated": False,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111002",
        "slug": "first_epss",
        "name": "FIRST Exploit Prediction Scoring System",
        "source_type": "probability_feed",
        "provider_url": "https://api.first.org/epss",
        "license_name": "FIRST Data License",
        "license_url": "https://www.first.org/epss/data",
        "terms_reference": "Daily probabilistic near-term exploitation likelihood model",
        "is_active": True,
        "is_gated": False,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111003",
        "slug": "nvd",
        "name": "NIST National Vulnerability Database",
        "source_type": "cve_catalog",
        "provider_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "license_name": "NIST Open Government Data",
        "license_url": "https://nvd.nist.gov/general/terms-of-use",
        "terms_reference": "Official NIST CVE dictionary, CVSS base scores, and CPE mappings",
        "is_active": True,
        "is_gated": False,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111004",
        "slug": "osv",
        "name": "Open Source Vulnerabilities (OSV.dev)",
        "source_type": "package_advisory",
        "provider_url": "https://api.osv.dev/v1",
        "license_name": "CC-BY 4.0",
        "license_url": "https://google.github.io/osv.dev/faq/",
        "terms_reference": "Aggregated open-source package vulnerability ecosystem database",
        "is_active": True,
        "is_gated": False,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111005",
        "slug": "ghsa",
        "name": "GitHub Advisory Database",
        "source_type": "package_advisory",
        "provider_url": "https://api.github.com/advisories",
        "license_name": "CC-BY 4.0",
        "license_url": "https://github.com/github/advisory-database/blob/main/LICENSE.md",
        "terms_reference": "Curated security advisories across software development ecosystems",
        "is_active": True,
        "is_gated": False,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111006",
        "slug": "exploit_db",
        "name": "Exploit-DB / SearchSploit Reference Catalog",
        "source_type": "exploit_catalog",
        "provider_url": "https://www.exploit-db.com",
        "license_name": "GPLv2",
        "license_url": "https://gitlab.com/exploit-database/exploitdb/-/blob/main/LICENSE.md",
        "terms_reference": "Public exploit research archive; reference documentation only",
        "is_active": True,
        "is_gated": False,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111007",
        "slug": "virustotal",
        "name": "VirusTotal Intelligence (Hash Only)",
        "source_type": "ioc_feed",
        "provider_url": "https://www.virustotal.com/api/v3",
        "license_name": "Commercial API License",
        "license_url": "https://docs.virustotal.com/reference/overview",
        "terms_reference": (
            "File hash and IOC intelligence; source/binary uploads forbidden by default"
        ),
        "is_active": False,
        "is_gated": True,
        "requires_scope_auth": False,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111008",
        "slug": "shodan",
        "name": "Shodan Exposure Intelligence",
        "source_type": "exposure_intel",
        "provider_url": "https://api.shodan.io",
        "license_name": "Commercial API License",
        "license_url": "https://developer.shodan.io/api",
        "terms_reference": (
            "Internet host observation; restricted strictly to authorized in-scope targets"
        ),
        "is_active": False,
        "is_gated": True,
        "requires_scope_auth": True,
        "allow_binary_upload": False,
    },
    {
        "id": "11111111-1111-1111-1111-111111111009",
        "slug": "pulsedive",
        "name": "Pulsedive Threat Intelligence",
        "source_type": "ioc_feed",
        "provider_url": "https://pulsedive.com/api",
        "license_name": "Commercial / Community API License",
        "license_url": "https://docs.pulsedive.com/api/overview",
        "terms_reference": "Threat, feed, and indicator intelligence subject to plan limits",
        "is_active": False,
        "is_gated": True,
        "requires_scope_auth": True,
        "allow_binary_upload": False,
    },
]


def upgrade() -> None:
    # 1. Extend findings table with KEV and EPSS columns for prioritized querying
    op.add_column(
        "findings",
        sa.Column(
            "is_known_exploited",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column("epss_score", sa.Numeric(precision=6, scale=5), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("epss_percentile", sa.Numeric(precision=6, scale=5), nullable=True),
    )
    op.create_index(
        "ix_findings_org_kev",
        "findings",
        ["organization_id", "is_known_exploited"],
    )
    op.create_index(
        "ix_findings_org_epss",
        "findings",
        ["organization_id", "epss_score"],
    )

    # 2. Platform reference table: intelligence_sources
    op.create_table(
        "intelligence_sources",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("slug", sa.String(length=50), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("source_type", sa.String(length=50), nullable=False),
        sa.Column("provider_url", sa.Text(), nullable=False),
        sa.Column("license_name", sa.String(length=100), nullable=False),
        sa.Column("license_url", sa.Text(), nullable=True),
        sa.Column("terms_reference", sa.Text(), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "is_gated",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "requires_scope_auth",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "allow_binary_upload",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
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
        sa.PrimaryKeyConstraint("id", name="pk_intelligence_sources"),
        sa.UniqueConstraint("slug", name="uq_intelligence_sources_slug"),
        sa.CheckConstraint(
            "source_type IN ("
            "'cve_catalog', 'exploit_catalog', 'probability_feed', "
            "'package_advisory', 'exposure_intel', 'ioc_feed')",
            name="ck_intel_sources_type",
        ),
    )
    op.create_index(
        "ix_intelligence_sources_type_active",
        "intelligence_sources",
        ["source_type", "is_active"],
    )

    # 3. Synchronizations log: intel_sync_runs
    op.create_table(
        "intel_sync_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "sync_mode",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'incremental'"),
        ),
        sa.Column("cursor_before", sa.Text(), nullable=True),
        sa.Column("cursor_after", sa.Text(), nullable=True),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column(
            "records_fetched",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "records_persisted",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("raw_payload_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id", name="pk_intel_sync_runs"),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_intel_sync_runs_source",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "sync_mode IN ('full', 'incremental', 'ad_hoc')",
            name="ck_intel_sync_runs_mode",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', 'stale', 'quarantined')",
            name="ck_intel_sync_runs_status",
        ),
    )
    op.create_index(
        "ix_intel_sync_runs_source_started",
        "intel_sync_runs",
        ["source_id", "started_at"],
    )

    # 4. Immutable point-in-time snapshots for deterministic replay: intel_snapshots
    op.create_table(
        "intel_snapshots",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_tag", sa.String(length=100), nullable=False),
        sa.Column("snapshot_hash", sa.String(length=64), nullable=False),
        sa.Column("storage_uri", sa.Text(), nullable=True),
        sa.Column(
            "record_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "is_stale",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("stale_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_intel_snapshots"),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_intel_snapshots_source",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "source_id",
            "snapshot_tag",
            name="uq_intel_snapshots_source_tag",
        ),
    )
    op.create_index(
        "ix_intel_snapshots_source_created",
        "intel_snapshots",
        ["source_id", "created_at"],
    )

    # 5. Normalized threat intelligence records: intel_records
    op.create_table(
        "intel_records",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("source_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("source_record_id", sa.String(length=100), nullable=False),
        sa.Column("record_type", sa.String(length=30), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1), nullable=True),
        sa.Column("cvss_vector", sa.String(length=100), nullable=True),
        sa.Column("epss_score", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column("epss_percentile", sa.Numeric(precision=6, scale=5), nullable=True),
        sa.Column(
            "is_known_exploited",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "raw_payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("raw_hash", sa.String(length=64), nullable=False),
        sa.Column("normalized_hash", sa.String(length=64), nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "retrieved_at",
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
        sa.PrimaryKeyConstraint("id", name="pk_intel_records"),
        sa.ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_intel_records_source",
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "source_id",
            "source_record_id",
            name="uq_intel_records_source_rec",
        ),
        sa.CheckConstraint(
            "record_type IN ('cve', 'kev', 'epss', 'osv', 'ghsa', 'cwe', 'edb', 'ioc')",
            name="ck_intel_records_type",
        ),
    )
    op.create_index(
        "ix_intel_records_source_record_id",
        "intel_records",
        ["source_record_id"],
    )
    op.create_index(
        "ix_intel_records_type_kev",
        "intel_records",
        ["record_type", "is_known_exploited"],
    )
    op.create_index(
        "ix_intel_records_type_epss",
        "intel_records",
        ["record_type", "epss_score"],
    )

    # 6. Mappings between records and target identifiers: intel_relationships
    op.create_table(
        "intel_relationships",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("intel_record_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("relationship_type", sa.String(length=50), nullable=False),
        sa.Column("target_identifier_type", sa.String(length=30), nullable=False),
        sa.Column("target_identifier", sa.String(length=255), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_intel_relationships"),
        sa.ForeignKeyConstraint(
            ["intel_record_id"],
            ["intel_records.id"],
            name="fk_intel_relationships_record",
            ondelete="CASCADE",
        ),
        sa.CheckConstraint(
            "relationship_type IN ("
            "'cve_to_cwe', 'cve_to_epss', 'cve_to_kev', "
            "'cve_to_purl', 'cve_to_edb', 'cve_to_att_ck', 'cve_to_ghsa')",
            name="ck_intel_relationships_type",
        ),
        sa.CheckConstraint(
            "target_identifier_type IN ('cve', 'cwe', 'purl', 'edb', 'capec', 'att_ck', 'ghsa')",
            name="ck_intel_relationships_target_type",
        ),
    )
    op.create_index(
        "ix_intel_relationships_target",
        "intel_relationships",
        ["target_identifier_type", "target_identifier"],
    )
    op.create_index(
        "ix_intel_relationships_record_rel",
        "intel_relationships",
        ["intel_record_id", "relationship_type"],
    )

    # 7. Tenant-scoped finding enrichment events with RLS: intel_enrichment_events
    op.create_table(
        "intel_enrichment_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("intel_snapshot_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("intel_record_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "enrichment_data",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_intel_enrichment_events"),
        sa.UniqueConstraint(
            "organization_id",
            "id",
            name="uq_intel_enrichment_events_org_id_id",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_intel_enrichment_events_org",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            name="fk_intel_enrichment_events_org_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            name="fk_intel_enrichment_events_org_finding",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["intel_snapshot_id"],
            ["intel_snapshots.id"],
            name="fk_intel_enrichment_events_snapshot",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["intel_record_id"],
            ["intel_records.id"],
            name="fk_intel_enrichment_events_record",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_intel_enrichment_events_org_finding",
        "intel_enrichment_events",
        ["organization_id", "finding_id"],
    )
    op.create_index(
        "ix_intel_enrichment_events_org_proj_created",
        "intel_enrichment_events",
        ["organization_id", "project_id", "created_at"],
    )

    # 8. Seed default intelligence sources
    sources_table = sa.table(
        "intelligence_sources",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("slug", sa.String),
        sa.column("name", sa.String),
        sa.column("source_type", sa.String),
        sa.column("provider_url", sa.Text),
        sa.column("license_name", sa.String),
        sa.column("license_url", sa.Text),
        sa.column("terms_reference", sa.Text),
        sa.column("is_active", sa.Boolean),
        sa.column("is_gated", sa.Boolean),
        sa.column("requires_scope_auth", sa.Boolean),
        sa.column("allow_binary_upload", sa.Boolean),
    )
    op.bulk_insert(sources_table, _DEFAULT_SOURCES)

    # 9. Row-Level Security (RLS) enforcement on tenant table
    for tbl in _ALL_TENANT_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{tbl} ON {tbl}
            FOR ALL
            TO vforge_app
            USING (organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
            """
        )

    # 10. Append-only triggers
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase9_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Table % is strictly append-only; updates and deletes are forbidden.',
                TG_TABLE_NAME
                USING ERRCODE = '55000';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for imm_table in _IMMUTABLE_GLOBAL_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase9_immutable_mutation();
            """
        )
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase9_immutable_mutation();
            """
        )

    # 11. Runtime role permissions
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                -- Platform reference data
                GRANT SELECT, INSERT, UPDATE ON intelligence_sources TO vforge_app;
                REVOKE DELETE ON intelligence_sources FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON intel_sync_runs TO vforge_app;
                REVOKE DELETE ON intel_sync_runs FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON intel_records TO vforge_app;
                REVOKE DELETE ON intel_records FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE, DELETE ON intel_relationships TO vforge_app;

                -- Immutable snapshot tables
                GRANT SELECT, INSERT ON intel_snapshots TO vforge_app;
                REVOKE UPDATE, DELETE ON intel_snapshots FROM vforge_app;

                -- Tenant-scoped enrichment audit
                GRANT SELECT, INSERT ON intel_enrichment_events TO vforge_app;
                REVOKE UPDATE, DELETE ON intel_enrichment_events FROM vforge_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    # 1. Drop triggers and immutability function
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    for imm_table in _IMMUTABLE_GLOBAL_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase9_immutable_mutation();")

    # 2. Drop RLS policies
    for tbl in _ALL_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")

    # 3. Drop tables in dependency order
    op.drop_index(
        "ix_intel_enrichment_events_org_proj_created", table_name="intel_enrichment_events"
    )
    op.drop_index("ix_intel_enrichment_events_org_finding", table_name="intel_enrichment_events")
    op.drop_table("intel_enrichment_events")

    op.drop_index("ix_intel_relationships_record_rel", table_name="intel_relationships")
    op.drop_index("ix_intel_relationships_target", table_name="intel_relationships")
    op.drop_table("intel_relationships")

    op.drop_index("ix_intel_records_type_epss", table_name="intel_records")
    op.drop_index("ix_intel_records_type_kev", table_name="intel_records")
    op.drop_index("ix_intel_records_source_record_id", table_name="intel_records")
    op.drop_table("intel_records")

    op.drop_index("ix_intel_snapshots_source_created", table_name="intel_snapshots")
    op.drop_table("intel_snapshots")

    op.drop_index("ix_intel_sync_runs_source_started", table_name="intel_sync_runs")
    op.drop_table("intel_sync_runs")

    op.drop_index("ix_intelligence_sources_type_active", table_name="intelligence_sources")
    op.drop_table("intelligence_sources")

    # 4. Remove columns and indexes on findings
    op.drop_index("ix_findings_org_epss", table_name="findings")
    op.drop_index("ix_findings_org_kev", table_name="findings")
    op.drop_column("findings", "epss_percentile")
    op.drop_column("findings", "epss_score")
    op.drop_column("findings", "is_known_exploited")
