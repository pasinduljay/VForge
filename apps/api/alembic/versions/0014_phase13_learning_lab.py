"""Phase 13 Isolated Learning Lab schema, RLS, safety CHECK constraints, and challenge catalog."""

from __future__ import annotations

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0014_phase13_learning_lab"
down_revision: str | None = "0013_phase12_ai_governance"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = (
    "lab_workspaces",
    "lab_challenge_progress",
    "lab_validation_runs",
    "lab_self_scans",
    "lab_audit_events",
)

_IMMUTABLE_TABLES = (
    "lab_validation_runs",
    "lab_self_scans",
    "lab_audit_events",
)


def upgrade() -> None:
    # 1. Curated Learning Challenge Catalog (platform-wide reference track items)
    op.create_table(
        "lab_challenges",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("slug", sa.String(120), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("track_level", sa.String(32), nullable=False),
        sa.Column("target_app", sa.String(40), nullable=False),
        sa.Column("cwe_id", sa.String(32), nullable=False),
        sa.Column("learning_goal", sa.Text(), nullable=False),
        sa.Column(
            "preconditions_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("permitted_target", sa.String(255), nullable=False),
        sa.Column(
            "test_identities_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "test_data_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "permitted_tools_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "expected_finding_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("safe_evidence_criteria", sa.Text(), nullable=False),
        sa.Column("remediation_exercise", sa.Text(), nullable=False),
        sa.Column("retest_instructions", sa.Text(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint("slug", name="uq_lab_challenges_slug"),
        sa.CheckConstraint(
            "track_level IN ('beginner', 'intermediate', 'advanced', 'expert_practice')",
            name="ck_lc_track_level",
        ),
        sa.CheckConstraint(
            "target_app IN ('juice_shop', 'crapi', 'webgoat', 'vforge_sample')",
            name="ck_lc_target_app",
        ),
    )

    challenges_tbl = sa.table(
        "lab_challenges",
        sa.column("id", postgresql.UUID(as_uuid=True)),
        sa.column("slug", sa.String),
        sa.column("title", sa.String),
        sa.column("track_level", sa.String),
        sa.column("target_app", sa.String),
        sa.column("cwe_id", sa.String),
        sa.column("learning_goal", sa.Text),
        sa.column("preconditions_json", postgresql.JSONB),
        sa.column("permitted_target", sa.String),
        sa.column("test_identities_json", postgresql.JSONB),
        sa.column("test_data_json", postgresql.JSONB),
        sa.column("permitted_tools_json", postgresql.JSONB),
        sa.column("expected_finding_json", postgresql.JSONB),
        sa.column("safe_evidence_criteria", sa.Text),
        sa.column("remediation_exercise", sa.Text),
        sa.column("retest_instructions", sa.Text),
        sa.column("explanation", sa.Text),
        sa.column("is_active", sa.Boolean),
    )
    op.bulk_insert(
        challenges_tbl,
        [
            {
                "id": uuid.UUID("d1000001-0000-4000-8000-000000000001"),
                "slug": "beginner-juice-shop-baseline",
                "title": "OWASP Juice Shop — Safe Baseline HTTP & Header Inspection",
                "track_level": "beginner",
                "target_app": "juice_shop",
                "cwe_id": "CWE-200",
                "learning_goal": (
                    "Understand HTTP response headers, asset endpoints, and non-destructive "
                    "scanner baseline output against isolated OWASP Juice Shop."
                ),
                "preconditions_json": [
                    "Opt-in lab compose profile started (`--profile lab`)",
                    "Isolated internal bridge `lab_internal` verified (`internal: true`)",
                ],
                "permitted_target": "http://127.0.0.1:3100",
                "test_identities_json": [
                    {
                        "handle": "beginner-practitioner@disposable.lab.vforge.local",
                        "role": "guest",
                    }
                ],
                "test_data_json": {"endpoint": "/rest/admin/application-version"},
                "permitted_tools_json": ["nmap", "zap"],
                "expected_finding_json": {
                    "category": "information_disclosure",
                    "severity": "low",
                    "evidence_type": "http_response_header",
                },
                "safe_evidence_criteria": (
                    "Read-only GET request capturing missing security headers and exposed server "
                    "metadata without modifying data or mutating accounts."
                ),
                "remediation_exercise": (
                    "Configure strict Content-Security-Policy, X-Content-Type-Options: nosniff, "
                    "and disable version banner emission."
                ),
                "retest_instructions": (
                    "Re-run baseline probe against Juice Shop route and confirm header remediation "
                    "or clean regression pass."
                ),
                "explanation": (
                    "Beginner baseline teaches how HTTP scanners distinguish benign configuration "
                    "signals from high-severity flaws without noisy exploitation."
                ),
                "is_active": True,
            },
            {
                "id": uuid.UUID("d1000001-0000-4000-8000-000000000002"),
                "slug": "intermediate-webgoat-sqli",
                "title": "OWASP WebGoat — Parameterized Query & Source-to-Sink SQLi",
                "track_level": "intermediate",
                "target_app": "webgoat",
                "cwe_id": "CWE-89",
                "learning_goal": (
                    "Trace untrusted HTTP input from controller parameter to SQL sink and compare "
                    "SAST OpenGrep matches with controlled DAST error observation."
                ),
                "preconditions_json": [
                    "WebGoat isolated lab running on loopback 127.0.0.1:3101",
                    "Disposable student account provisioned in current reset epoch",
                ],
                "permitted_target": "http://127.0.0.1:3101/WebGoat",
                "test_identities_json": [
                    {"handle": "student-a@disposable.lab.vforge.local", "role": "student"}
                ],
                "test_data_json": {"lesson": "SqlInjection/attack5a", "probe": "' OR '1'='1"},
                "permitted_tools_json": ["opengrep", "zap"],
                "expected_finding_json": {
                    "category": "sql_injection",
                    "severity": "high",
                    "cwe": "CWE-89",
                },
                "safe_evidence_criteria": (
                    "Single minimal boolean/syntax probe returning query structure proof only; "
                    "no bulk table dumping, schema dropping, or OS command functions."
                ),
                "remediation_exercise": (
                    "Replace dynamic string concatenation with bound PreparedStatement parameters."
                ),
                "retest_instructions": (
                    "Execute `remediation_retest` probe and verify injected metacharacters are "
                    "treated strictly as literal data."
                ),
                "explanation": (
                    "Demonstrates source-to-sink correlation combining static SAST rules with "
                    "minimum-evidence DAST verification."
                ),
                "is_active": True,
            },
            {
                "id": uuid.UUID("d1000001-0000-4000-8000-000000000003"),
                "slug": "advanced-crapi-idor-bola",
                "title": "OWASP crAPI — Multi-Role Object Authorization (BOLA / IDOR)",
                "track_level": "advanced",
                "target_app": "crapi",
                "cwe_id": "CWE-639",
                "learning_goal": (
                    "Validate cross-account BOLA using two disposable test identities "
                    "without touching real data or making persistent edits."
                ),
                "preconditions_json": [
                    "crAPI web & identity containers running inside `lab_internal`",
                    "Two distinct disposable identities (`alice-lab` & `bob-lab`) seeded",
                ],
                "permitted_target": "http://127.0.0.1:3102",
                "test_identities_json": [
                    {"handle": "alice-lab@disposable.lab.vforge.local", "role": "owner"},
                    {"handle": "bob-lab@disposable.lab.vforge.local", "role": "peer"},
                ],
                "test_data_json": {"endpoint": "/workshop/api/shop/orders/{order_id}"},
                "permitted_tools_json": ["zap", "nuclei"],
                "expected_finding_json": {
                    "category": "broken_object_level_authorization",
                    "severity": "high",
                    "cwe": "CWE-639",
                },
                "safe_evidence_criteria": (
                    "Minimal cross-user GET read confirming missing ownership checks with "
                    "redacted bearer tokens and sanitized JSON excerpt."
                ),
                "remediation_exercise": (
                    "Enforce server-side tenant scoping (WHERE id = :id AND owner_id = :sub) "
                    "and PostgreSQL Row-Level Security."
                ),
                "retest_instructions": (
                    "Re-verify cross-user order fetch returns HTTP 403/404 and log evidence hash."
                ),
                "explanation": (
                    "Models how VForge enforces RLS and composite FKs in the control plane by "
                    "contrasting an unprotected API endpoint inside crAPI."
                ),
                "is_active": True,
            },
            {
                "id": uuid.UUID("d1000001-0000-4000-8000-000000000004"),
                "slug": "expert-vforge-rule-studio",
                "title": "Expert Practice — Custom Rule Validation, Regression Corpus & Retest",
                "track_level": "expert_practice",
                "target_app": "vforge_sample",
                "cwe_id": "CWE-502",
                "learning_goal": (
                    "Author a native OpenGrep/Nuclei rule, run positive/negative/near-miss "
                    "fixtures, validate safely, and record remediation retest."
                ),
                "preconditions_json": [
                    "Phase 11 Rule Studio available with peer-review SoD enabled",
                    "Isolated VForge sample target healthy in lab network",
                ],
                "permitted_target": "http://vforge-sample.lab.vforge.local:8090",
                "test_identities_json": [
                    {"handle": "expert-author@disposable.lab.vforge.local", "role": "auditor"}
                ],
                "test_data_json": {"fixture": "unsafe_yaml_deserialization_sample"},
                "permitted_tools_json": ["opengrep", "nuclei", "checkov"],
                "expected_finding_json": {
                    "category": "insecure_deserialization",
                    "severity": "high",
                    "cwe": "CWE-502",
                },
                "safe_evidence_criteria": (
                    "Validate safe AST pattern + benign YAML tag marker without arbitrary gadget "
                    "code execution or persistent backdoors."
                ),
                "remediation_exercise": (
                    "Switch to yaml.safe_load / _NoAliasSafeLoader and verify near-miss safe "
                    "fixtures produce zero false positives."
                ),
                "retest_instructions": (
                    "Run regression harness + retest probe verifying zero FNs and zero FPs."
                ),
                "explanation": (
                    "Connects custom Rule Studio authoring to isolated lab verification and "
                    "defensible retesting."
                ),
                "is_active": True,
            },
        ],
    )

    # 2. Lab Workspaces (Tenant-isolated)
    op.create_table(
        "lab_workspaces",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_slug", sa.String(80), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column(
            "isolation_network_name",
            sa.String(80),
            nullable=False,
            server_default="vforge_lab_internal",
        ),
        sa.Column("egress_denied", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "public_exposure_blocked", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column(
            "consent_to_persist_progress",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("disposable_account_prefix", sa.String(64), nullable=False),
        sa.Column("reset_epoch", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("state", sa.String(32), nullable=False, server_default="ready"),
        sa.Column(
            "disposable_identities_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("last_reset_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.UniqueConstraint("organization_id", "environment_slug", name="uq_lw_org_slug"),
        sa.UniqueConstraint("organization_id", "id", name="uq_lw_org_id"),
        sa.CheckConstraint("egress_denied IS TRUE", name="ck_lw_egress_denied"),
        sa.CheckConstraint("public_exposure_blocked IS TRUE", name="ck_lw_no_public_exposure"),
        sa.CheckConstraint("reset_epoch >= 1", name="ck_lw_reset_epoch"),
        sa.CheckConstraint(
            "state IN ('ready', 'running', 'resetting', 'stopped')",
            name="ck_lw_state",
        ),
    )
    op.create_index("ix_lw_org_state", "lab_workspaces", ["organization_id", "state"])

    # 3. Challenge Progress (requires explicit consent_granted = true)
    op.create_table(
        "lab_challenge_progress",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("challenge_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="not_started"),
        sa.Column("consent_granted", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("reset_epoch", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "validated_evidence_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("remediation_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("retest_passed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("attempts_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_by", postgresql.UUID(as_uuid=True), nullable=False),
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
        sa.ForeignKeyConstraint(
            ["organization_id", "workspace_id"],
            ["lab_workspaces.organization_id", "lab_workspaces.id"],
            name="fk_lcp_org_workspace",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["challenge_id"], ["lab_challenges.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("organization_id", "workspace_id", "challenge_id", name="uq_lcp_ws_ch"),
        sa.CheckConstraint("consent_granted IS TRUE", name="ck_lcp_consent_granted"),
        sa.CheckConstraint(
            "status IN ('not_started', 'in_progress', 'validated', 'remediated', 'retested')",
            name="ck_lcp_status",
        ),
    )
    op.create_index("ix_lcp_org_ws", "lab_challenge_progress", ["organization_id", "workspace_id"])

    # 4. Safe Validation Runs (append-only, strict action allowlist)
    op.create_table(
        "lab_validation_runs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("challenge_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reset_epoch", sa.Integer(), nullable=False),
        sa.Column("tool_slug", sa.String(64), nullable=False),
        sa.Column("target_url", sa.String(255), nullable=False),
        sa.Column("disposable_identity_used", sa.String(120), nullable=False),
        sa.Column("action_type", sa.String(48), nullable=False),
        sa.Column(
            "safety_boundary_verified", sa.Boolean(), nullable=False, server_default=sa.true()
        ),
        sa.Column("evidence_summary_redacted", sa.Text(), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("finding_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("remediation_verified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("status", sa.String(32), nullable=False, server_default="completed"),
        sa.Column("executed_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["organization_id", "workspace_id"],
            ["lab_workspaces.organization_id", "lab_workspaces.id"],
            name="fk_lvr_org_workspace",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["challenge_id"], ["lab_challenges.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "action_type IN ('baseline_probe', 'auth_token_check', 'idor_read_check', "
            "'sqli_error_probe', 'xss_reflection_probe', 'remediation_retest')",
            name="ck_lvr_safe_action_type",
        ),
        sa.CheckConstraint("safety_boundary_verified IS TRUE", name="ck_lvr_boundary_verified"),
    )
    op.create_index("ix_lvr_org_created", "lab_validation_runs", ["organization_id", "created_at"])

    # 5. VForge Self-Scans (append-only verification log)
    op.create_table(
        "lab_self_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("target_component", sa.String(80), nullable=False),
        sa.Column("profile_name", sa.String(80), nullable=False),
        sa.Column("checks_executed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("issues_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "findings_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column("remediation_summary", sa.Text(), nullable=False, server_default=""),
        sa.Column("regression_verified", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("status", sa.String(32), nullable=False, server_default="completed"),
        sa.Column("executed_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "target_component IN ('control_plane_api', 'control_plane_web', "
            "'scanner_contracts', 'runner_agent', 'opa_policies')",
            name="ck_lss_component",
        ),
    )
    op.create_index("ix_lss_org_created", "lab_self_scans", ["organization_id", "created_at"])

    # 6. Immutable Lab Audit Events
    op.create_table(
        "lab_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("workspace_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_email", sa.String(320), nullable=False),
        sa.Column("target_url", sa.String(255), nullable=True),
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
        sa.ForeignKeyConstraint(
            ["organization_id", "workspace_id"],
            ["lab_workspaces.organization_id", "lab_workspaces.id"],
            name="fk_lae_org_workspace",
            ondelete="RESTRICT",
        ),
    )
    op.create_index("ix_lae_org_occurred", "lab_audit_events", ["organization_id", "occurred_at"])

    # 7. Enable & FORCE Row-Level Security
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

    # 8. Append-only triggers on immutable validation, self-scan, and audit logs
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase13_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Phase 13 lab validation, self-scan, and audit logs are append-only.'
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
            FOR EACH ROW EXECUTE FUNCTION prevent_phase13_immutable_mutation();
            """
        )

    # 9. Least-privilege runtime grants for vforge_app
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT ON lab_challenges TO vforge_app;

                GRANT SELECT, INSERT ON
                    lab_validation_runs, lab_self_scans, lab_audit_events
                    TO vforge_app;
                REVOKE UPDATE, DELETE ON
                    lab_validation_runs, lab_self_scans, lab_audit_events
                    FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON
                    lab_workspaces, lab_challenge_progress
                    TO vforge_app;
                REVOKE DELETE ON
                    lab_workspaces, lab_challenge_progress
                    FROM vforge_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    for imm_table in _IMMUTABLE_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase13_immutable_mutation();")

    for tbl in _TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")

    op.drop_index("ix_lae_org_occurred", table_name="lab_audit_events")
    op.drop_table("lab_audit_events")

    op.drop_index("ix_lss_org_created", table_name="lab_self_scans")
    op.drop_table("lab_self_scans")

    op.drop_index("ix_lvr_org_created", table_name="lab_validation_runs")
    op.drop_table("lab_validation_runs")

    op.drop_index("ix_lcp_org_ws", table_name="lab_challenge_progress")
    op.drop_table("lab_challenge_progress")

    op.drop_index("ix_lw_org_state", table_name="lab_workspaces")
    op.drop_table("lab_workspaces")

    op.drop_table("lab_challenges")
