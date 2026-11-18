"""PostgreSQL role separation, privilege escalation prevention, RLS, and immutability tests."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, ProgrammingError
from sqlalchemy.ext.asyncio import create_async_engine

from vforge.config import get_settings
from vforge.db import build_session_factory, set_db_context, verify_runtime_db_identity
from vforge.models import (
    AppUser,
    Asset,
    AssetType,
    AuditEvent,
    Authorization,
    Environment,
    EnvironmentType,
    Finding,
    Membership,
    Organization,
    Project,
    Role,
    ScanProfile,
    ScopeSnapshot,
    SourceSnapshot,
)


async def _seed_tenant(
    sess_factory: object,
    *,
    org_id: uuid.UUID,
    user_id: uuid.UUID,
    proj_id: uuid.UUID,
    env_id: uuid.UUID,
    asset_id: uuid.UUID,
    auth_id: uuid.UUID,
    snap_id: uuid.UUID,
    label: str,
) -> None:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    factory: async_sessionmaker[AsyncSession] = sess_factory  # type: ignore[assignment]
    issuer = "https://idp.rls.test"
    subject = f"sub-{label}-{user_id.hex[:8]}"

    async with factory() as seed_sess:
        async with seed_sess.begin():
            await set_db_context(
                seed_sess,
                org_id=org_id,
                user_id=user_id,
                auth_lookup=(issuer, subject),
            )
            seed_sess.add_all(
                [
                    Organization(
                        id=org_id,
                        name=f"Org {label}",
                        slug=f"org-{label.lower()}-{org_id.hex[:6]}",
                    ),
                    AppUser(
                        id=user_id,
                        oidc_issuer=issuer,
                        oidc_subject=subject,
                        email=f"{label.lower()}@org-{label.lower()}.test",
                        display_name=f"User {label}",
                    ),
                ]
            )
            await seed_sess.flush()
            seed_sess.add_all(
                [
                    Membership(organization_id=org_id, user_id=user_id, role=Role.OWNER.value),
                    Project(
                        id=proj_id,
                        organization_id=org_id,
                        name=f"Project {label}",
                        slug=f"proj-{label.lower()}",
                    ),
                    Environment(
                        id=env_id,
                        organization_id=org_id,
                        project_id=proj_id,
                        name="staging",
                        environment_type=EnvironmentType.STAGING.value,
                    ),
                    Asset(
                        id=asset_id,
                        organization_id=org_id,
                        environment_id=env_id,
                        asset_type=AssetType.WEB_APPLICATION.value,
                        normalized_locator=f"https://{label.lower()}.example.test/",
                    ),
                    ScanProfile(
                        organization_id=org_id,
                        name="baseline",
                        version=1,
                        configuration={"stages": ["sast"], "passive_only": True},
                    ),
                    AuditEvent(
                        organization_id=org_id,
                        actor_id=user_id,
                        action="project.created",
                        resource_type="project",
                        resource_id=proj_id,
                    ),
                ]
            )
            await seed_sess.flush()
            seed_now = datetime.now(UTC)
            seed_sess.add(
                Authorization(
                    id=auth_id,
                    organization_id=org_id,
                    project_id=proj_id,
                    environment_id=env_id,
                    asset_id=asset_id,
                    requested_by=user_id,
                    approved_activities=["passive_web_testing"],
                    authorization_reference=f"CHG-{label}-1",
                    valid_from=seed_now,
                    expires_at=seed_now + timedelta(days=7),
                )
            )
            await seed_sess.flush()
            seed_sess.add(
                ScopeSnapshot(
                    id=snap_id,
                    organization_id=org_id,
                    project_id=proj_id,
                    environment_id=env_id,
                    asset_id=asset_id,
                    authorization_id=auth_id,
                    snapshot_version=1,
                    asset_version=1,
                    policy_version="2026-11-12.v2",
                    target_type="web_application",
                    canonical_locator=f"https://{label.lower()}.example.test/",
                    resolved_ips=[],
                    allowed_ports=[443],
                    permitted_capabilities=["passive_web_testing"],
                    permitted_intensity="passive",
                    scope_definition={},
                    payload={"organization_id": str(org_id)},
                    payload_sha256=(label.lower()[0] * 64),
                    signing_key_id="k1",
                    signature_algorithm="Ed25519",
                    signature=f"sig-{label.lower()}",
                    authorization_expires_at=seed_now + timedelta(days=7),
                    created_by=user_id,
                )
            )


async def test_postgresql_rls_enforced_with_non_owner_role_and_single_connection_pool() -> None:
    settings = get_settings()
    runtime_url = settings.effective_database_url
    if not runtime_url:
        pytest.skip("Runtime database credentials not configured")

    app_engine = create_async_engine(
        runtime_url,
        pool_size=1,
        max_overflow=0,
        pool_reset_on_return="rollback",
    )

    org_a_id = uuid.uuid4()
    org_b_id = uuid.uuid4()
    user_a_id = uuid.uuid4()
    user_b_id = uuid.uuid4()
    proj_a_id = uuid.uuid4()
    proj_b_id = uuid.uuid4()
    env_a_id = uuid.uuid4()
    env_b_id = uuid.uuid4()
    asset_a_id = uuid.uuid4()
    asset_b_id = uuid.uuid4()
    auth_a_id = uuid.uuid4()
    auth_b_id = uuid.uuid4()
    snap_a_id = uuid.uuid4()
    snap_b_id = uuid.uuid4()

    try:
        # 1. Verify runtime DB identity is strictly non-superuser, NOBYPASSRLS, non-owner
        identity = await verify_runtime_db_identity(app_engine)
        assert identity["role"] == "vforge_app"
        assert identity["rolsuper"] is False
        assert identity["rolbypassrls"] is False
        assert identity["rolcreaterole"] is False
        assert identity["rolcreatedb"] is False
        assert identity["rolinherit"] is False
        assert identity["owns_tables"] is False

        app_factory = build_session_factory(app_engine)

        # 2. Verify runtime role cannot escalate to migration or bootstrap roles
        for privileged_role in ("vforge", "vforge_migrator"):
            async with app_factory() as s_esc:
                with pytest.raises(ProgrammingError):
                    async with s_esc.begin():
                        await s_esc.execute(text(f"SET LOCAL ROLE {privileged_role}"))

        # 3. Seed two completely separate tenants under RLS using non-owner vforge_app
        await _seed_tenant(
            app_factory,
            org_id=org_a_id,
            user_id=user_a_id,
            proj_id=proj_a_id,
            env_id=env_a_id,
            asset_id=asset_a_id,
            auth_id=auth_a_id,
            snap_id=snap_a_id,
            label="A",
        )
        await _seed_tenant(
            app_factory,
            org_id=org_b_id,
            user_id=user_b_id,
            proj_id=proj_b_id,
            env_id=env_b_id,
            asset_id=asset_b_id,
            auth_id=auth_b_id,
            snap_id=snap_b_id,
            label="B",
        )

        # 4. Query in Org A context using single pooled connection
        async with app_factory() as s1:
            async with s1.begin():
                role_check = (await s1.execute(text("SELECT current_user"))).scalar_one()
                assert role_check == "vforge_app"
                await set_db_context(s1, org_id=org_a_id, user_id=user_a_id)

                proj_ids = set((await s1.execute(text("SELECT id FROM projects"))).scalars().all())
                assert proj_ids == {proj_a_id}

                asset_ids = set((await s1.execute(text("SELECT id FROM assets"))).scalars().all())
                assert asset_ids == {asset_a_id}

                audit_orgs = set(
                    (await s1.execute(text("SELECT organization_id FROM audit_events")))
                    .scalars()
                    .all()
                )
                assert audit_orgs == {org_a_id}

                snap_ids = set(
                    (await s1.execute(text("SELECT id FROM scope_snapshots"))).scalars().all()
                )
                assert snap_ids == {snap_a_id}

                # Cross-tenant UPDATE affects 0 rows
                upd_res = await s1.execute(
                    text("UPDATE projects SET name = 'pwned' WHERE id = :pid"),
                    {"pid": str(proj_b_id)},
                )
                assert upd_res.rowcount == 0

        # 5. Reuse the exact same single pooled connection WITHOUT setting context -> 0 rows!
        async with app_factory() as s2:
            async with s2.begin():
                leaked = (await s2.execute(text("SELECT id FROM projects"))).scalars().all()
                assert leaked == []

        # 6. Cross-tenant INSERT blocked by RLS WITH CHECK
        async with app_factory() as s3:
            with pytest.raises(ProgrammingError):
                async with s3.begin():
                    await set_db_context(s3, org_id=org_a_id, user_id=user_a_id)
                    await s3.execute(
                        text(
                            "INSERT INTO projects (id, organization_id, name, slug) "
                            "VALUES (:id, :org_id, 'Evil', 'evil-proj')"
                        ),
                        {"id": str(uuid.uuid4()), "org_id": str(org_b_id)},
                    )

        # 7. Composite FK prevents cross-tenant parent reference even inside Org B context
        async with app_factory() as s4:
            with pytest.raises(IntegrityError):
                async with s4.begin():
                    await set_db_context(s4, org_id=org_b_id, user_id=user_b_id)
                    await s4.execute(
                        text(
                            "INSERT INTO environments "
                            "(id, organization_id, project_id, name, environment_type) "
                            "VALUES (:id, :org_id, :proj_id, 'cross-env', 'staging')"
                        ),
                        {
                            "id": str(uuid.uuid4()),
                            "org_id": str(org_b_id),
                            "proj_id": str(proj_a_id),
                        },
                    )

        # 8. Separation of duties DB constraint check
        async with app_factory() as s5:
            with pytest.raises(IntegrityError):
                async with s5.begin():
                    await set_db_context(s5, org_id=org_a_id, user_id=user_a_id)
                    now = datetime.now(UTC)
                    s5.add(
                        Authorization(
                            organization_id=org_a_id,
                            project_id=proj_a_id,
                            environment_id=env_a_id,
                            asset_id=asset_a_id,
                            requested_by=user_a_id,
                            approved_by=user_a_id,  # Same user!
                            approved_activities=["sast"],
                            authorization_reference="CHG-SELF",
                            valid_from=now,
                            expires_at=now + timedelta(days=1),
                            status="approved",
                        )
                    )

        # 9. Append-only audit_events & immutable scope_snapshots enforcement
        async with app_factory() as s6:
            with pytest.raises(ProgrammingError):
                async with s6.begin():
                    await set_db_context(s6, org_id=org_a_id, user_id=user_a_id)
                    await s6.execute(
                        text("DELETE FROM audit_events WHERE organization_id = :oid"),
                        {"oid": str(org_a_id)},
                    )

        async with app_factory() as s7:
            with pytest.raises(ProgrammingError):
                async with s7.begin():
                    await set_db_context(s7, org_id=org_a_id, user_id=user_a_id)
                    await s7.execute(
                        text("UPDATE scope_snapshots SET canonical_locator = 'https://evil.test'"),
                    )

        # 10. Phase 5: source_snapshots / findings RLS isolation & append-only finding_occurrences
        async with app_factory() as s8:
            async with s8.begin():
                await set_db_context(s8, org_id=org_a_id, user_id=user_a_id)
                s8.add(
                    SourceSnapshot(
                        organization_id=org_a_id,
                        project_id=proj_a_id,
                        asset_id=asset_a_id,
                        source_type="archive_tar_gz",
                        archive_sha256="a" * 64,
                        storage_key=f"rls-test/{org_a_id}/{uuid.uuid4()}.tar.gz.enc",
                        ciphertext_sha256="b" * 64,
                        encryption_key_id="vf-test-key",
                        wrapped_dek_b64="dGVzdA==",
                        nonce_b64="dGVzdA==",
                        aad_b64="dGVzdA==",
                        file_count=1,
                        total_bytes=42,
                        created_by=user_a_id,
                    )
                )
                s8.add(
                    Finding(
                        organization_id=org_a_id,
                        project_id=proj_a_id,
                        fingerprint="rls-fp-" + uuid.uuid4().hex,
                        category="sast",
                        scanner_tool_id="opengrep",
                        scanner_version="1.33.1",
                        rule_id="python.rls.test",
                        title="RLS Isolation Check",
                        severity="high",
                        confidence="high",
                        file_path="app.py",
                        start_line=1,
                        end_line=1,
                    )
                )

        async with app_factory() as s9:
            async with s9.begin():
                await set_db_context(s9, org_id=org_b_id, user_id=user_b_id)
                cross_snaps = (
                    await s9.execute(
                        text("SELECT id FROM source_snapshots WHERE organization_id = :oid"),
                        {"oid": str(org_a_id)},
                    )
                ).all()
                cross_findings = (
                    await s9.execute(
                        text("SELECT id FROM findings WHERE organization_id = :oid"),
                        {"oid": str(org_a_id)},
                    )
                ).all()
                assert cross_snaps == []
                assert cross_findings == []

        async with app_factory() as s10:
            with pytest.raises(ProgrammingError):
                async with s10.begin():
                    await set_db_context(s10, org_id=org_a_id, user_id=user_a_id)
                    await s10.execute(
                        text("DELETE FROM finding_occurrences WHERE organization_id = :oid"),
                        {"oid": str(org_a_id)},
                    )
    finally:
        await app_engine.dispose()


async def test_postgresql_migrator_role_separation_when_configured() -> None:
    """When run under migrator context, verify migrator owns tables without SUPERUSER/BYPASSRLS."""
    settings = get_settings()
    migration_url = settings.effective_migration_database_url
    if not migration_url:
        pytest.skip("MIGRATION_DATABASE_URL not exposed to runtime context (expected in API)")

    migrator_engine = create_async_engine(migration_url, pool_size=1, max_overflow=0)
    try:
        async with migrator_engine.connect() as conn:
            res = await conn.execute(
                text(
                    "SELECT current_user, r.rolsuper, r.rolbypassrls, r.rolcreaterole, "
                    "(SELECT count(*) FROM pg_tables "
                    " WHERE schemaname = 'public' AND tableowner = current_user) "
                    "FROM pg_roles r WHERE r.rolname = current_user"
                )
            )
            role_name, rolsuper, rolbypassrls, rolcreaterole, owned_count = res.one()
            assert role_name == "vforge_migrator"
            assert rolsuper is False
            assert rolbypassrls is False
            assert rolcreaterole is False
            assert int(owned_count) > 0

            # FORCE ROW LEVEL SECURITY still yields 0 rows without tenant context
            leaked = (await conn.execute(text("SELECT id FROM projects"))).scalars().all()
            assert leaked == []
    finally:
        await migrator_engine.dispose()
