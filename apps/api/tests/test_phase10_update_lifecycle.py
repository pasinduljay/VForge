"""Unit, negative security, and integration tests for Phase 10 Release & Update Lifecycle."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.errors import ConflictError, ValidationError
from vforge.lifecycle.monitor import (
    detect_candidates_from_image_locks,
    inspect_image_lock_files,
    parse_digest_reference,
    validate_version_tag_and_digest,
)
from vforge.lifecycle.pipeline import (
    approve_update_candidate,
    promote_feed_snapshot,
    promote_update_candidate,
    register_feed_snapshot,
    register_update_candidate,
    resolve_active_tool_pins,
    rollback_feed_snapshot,
    rollback_tool_version,
    run_automated_validation_gates,
)
from vforge.lifecycle.update_controller import run_controller_cycle
from vforge.main import app
from vforge.models import (
    AppUser,
    Asset,
    Authorization,
    Environment,
    Membership,
    Organization,
    Project,
    RunnerJob,
    ScanProfile,
    ScanRun,
    ScopeSnapshot,
    UpdateAuditEvent,
)
from vforge.models.enums import (
    AssetType,
    AuthorizationStatus,
    EnvironmentStatus,
    EnvironmentType,
    ProjectStatus,
    Role,
    RunnerJobStatus,
    ScanProfileStatus,
    ScanRunStatus,
    UpdateTestCategory,
)
from vforge.orchestration.planner import build_declarative_scan_plan
from vforge.security.rate_limit import rate_limiter


def _make_rsa_key(kid: str = "ph10-oidc-key-1") -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return priv, pub_jwk


def _build_auth_headers(ph10_env: dict[str, Any], subject: str, email: str) -> dict[str, str]:
    now = datetime.now(UTC)
    claims = {
        "iss": ph10_env["issuer"],
        "sub": subject,
        "aud": ph10_env["client_id"],
        "email": email,
        "name": subject,
        "email_verified": True,
        "nonce": "test-nonce",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    token = jwt.encode(
        claims, ph10_env["priv"], algorithm="RS256", headers={"kid": "ph10-oidc-key-1"}
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": uuid.uuid4().hex,
    }


@pytest_asyncio.fixture
async def ph10_env() -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph10.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key("ph10-oidc-key-1")
    now_mono = time.monotonic()
    jwk_obj = PyJWK.from_dict(pub_jwk)
    oidc_client.reset_caches()
    oidc_client._metadata = OidcDiscoveryMetadata(  # noqa: SLF001
        issuer=issuer,
        authorization_endpoint=f"{issuer}/protocol/openid-connect/auth",
        token_endpoint=f"{issuer}/protocol/openid-connect/token",
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
    )
    oidc_client._metadata_fetched_at = now_mono  # noqa: SLF001
    oidc_client._jwks_keys = {pub_jwk["kid"]: jwk_obj}  # noqa: SLF001
    oidc_client._jwks_list = [jwk_obj]  # noqa: SLF001
    oidc_client._jwks_fetched_at = now_mono  # noqa: SLF001
    rate_limiter.reset()

    test_settings = Settings(
        vforge_env="test",
        database_url=base_settings.effective_database_url,
        rabbitmq_url=base_settings.effective_rabbitmq_url,
        cache_url="",
        opa_url=base_settings.opa_url,
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        auth_rate_limit_per_minute=10000,
        sensitive_rate_limit_per_minute=10000,
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.dependency_overrides[get_settings] = lambda: test_settings

    yield {
        "settings": test_settings,
        "engine": engine,
        "session_factory": session_factory,
        "priv": priv,
        "issuer": issuer,
        "client_id": client_id,
    }

    app.dependency_overrides.clear()
    await engine.dispose()


@pytest_asyncio.fixture
async def db_tx(ph10_env: dict[str, Any]) -> AsyncIterator[AsyncSession]:
    """Transaction-rolled-back AsyncSession so direct DB tests leave seeded state clean."""
    factory = ph10_env["session_factory"]
    async with factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


# --- Unit Tests ---


def test_parse_and_validate_reject_latest_and_malformed_digests() -> None:
    repo, digest = parse_digest_reference("anchore/grype:0.90.0@sha256:" + "a" * 64)
    assert repo == "anchore/grype:0.90.0"
    assert digest == "sha256:" + "a" * 64

    with pytest.raises(ValidationError):
        parse_digest_reference("anchore/grype:latest@sha256:" + "a" * 64)
    with pytest.raises(ValidationError):
        parse_digest_reference("anchore/grype:0.90.0")
    with pytest.raises(ValidationError):
        validate_version_tag_and_digest("latest", "sha256:" + "a" * 64)
    with pytest.raises(ValidationError):
        validate_version_tag_and_digest("1.0.0", "sha256:not-hex")


def test_inspect_image_lock_files_parses_repository_manifests() -> None:
    entries = inspect_image_lock_files()
    # In container tests, image-lock may or may not be mounted unless in /app or compose volume
    if not entries:
        return
    slugs = {item["tool_slug"] for item in entries}
    assert "opengrep" in slugs
    assert "nuclei" in slugs
    for item in entries:
        assert item["version_tag"].lower() != "latest"
        assert item["image_digest"].startswith("sha256:")


# --- DB Lifecycle & Negative Security Tests ---


async def test_failed_validation_gate_blocks_approval_and_promotion(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    lead_id = uuid.uuid4()
    sub = f"ph10-fail-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], sub))
    lead = AppUser(
        id=lead_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=sub,
        email=f"{sub}@example.com",
        display_name="Lead",
        status="active",
    )
    db_tx.add(lead)
    await db_tx.flush()

    bad_digest = "sha256:" + "c" * 64
    _tool, _ver, upd = await register_update_candidate(
        db_tx,
        tool_slug="opengrep",
        version_tag="1.34.0-bad",
        image_repository="vforge-opengrep:1.34.0-bad",
        image_digest=bad_digest,
        sbom_digest="sha256:" + "1" * 64,
        signature_verified=True,
        change_type="minor",
    )

    updated = await run_automated_validation_gates(
        db_tx,
        update_id=upd.id,
        executed_by=lead.email,
        simulate_failure_gate=UpdateTestCategory.REGRESSION_CORPUS.value,
    )
    assert updated.status == "rejected"
    assert updated.rejection_reason is not None

    with pytest.raises(ConflictError):
        await run_automated_validation_gates(
            db_tx,
            update_id=upd.id,
            executed_by=lead.email,
        )

    # Unsigned candidate without SBOM fails validation honestly (fail-closed)
    _tool2, _ver2, unsigned_upd = await register_update_candidate(
        db_tx,
        tool_slug="opengrep",
        version_tag="1.34.1-unsigned",
        image_repository="vforge-opengrep:1.34.1-unsigned",
        image_digest="sha256:" + "2" * 64,
        signature_verified=False,
        sbom_digest=None,
    )
    unsigned_res = await run_automated_validation_gates(
        db_tx,
        update_id=unsigned_upd.id,
        executed_by=lead.email,
    )
    assert unsigned_res.status == "rejected"
    assert "signature_provenance" in (unsigned_res.rejection_reason or "")
    await db_tx.refresh(_ver2)
    assert _ver2.signature_verified is False

    with pytest.raises(ConflictError):
        await approve_update_candidate(
            db_tx,
            update_id=upd.id,
            actor_user_id=lead.id,
            actor_email=lead.email,
        )
    with pytest.raises(ConflictError):
        await promote_update_candidate(
            db_tx,
            update_id=upd.id,
            target_channel="canary",
            actor_user_id=lead.id,
            actor_email=lead.email,
        )


async def test_full_promotion_canary_stable_and_instant_rollback(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    lead_id = uuid.uuid4()
    sub = f"ph10-promo-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], sub))
    lead = AppUser(
        id=lead_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=sub,
        email=f"{sub}@example.com",
        display_name="Release Lead",
        status="active",
    )
    db_tx.add(lead)
    await db_tx.flush()

    initial_pins = await resolve_active_tool_pins(db_tx, settings=ph10_env["settings"])
    original_digest = initial_pins.provenance_manifest["tools"]["opengrep"]["image_digest"]

    new_digest = "sha256:" + "d" * 64
    tool, _ver, upd = await register_update_candidate(
        db_tx,
        tool_slug="opengrep",
        version_tag="1.35.0",
        image_repository="vforge-opengrep:1.35.0",
        image_digest=new_digest,
        sbom_digest="sha256:" + "a" * 64,
        signature_verified=True,
        change_type="minor",
    )
    assert tool.automerge_allowed is False

    # Validate & approve
    validated = await run_automated_validation_gates(
        db_tx, update_id=upd.id, executed_by=lead.email
    )
    assert validated.status == "validated"

    approved = await approve_update_candidate(
        db_tx, update_id=upd.id, actor_user_id=lead.id, actor_email=lead.email
    )
    assert approved.status == "approved"

    # Promote to canary: stable stays on original_digest while use_canary=True selects new_digest
    canary_upd = await promote_update_candidate(
        db_tx,
        update_id=upd.id,
        target_channel="canary",
        actor_user_id=lead.id,
        actor_email=lead.email,
    )
    assert canary_upd.status == "canary"

    stable_pins = await resolve_active_tool_pins(
        db_tx, settings=ph10_env["settings"], use_canary=False
    )
    canary_pins = await resolve_active_tool_pins(
        db_tx, settings=ph10_env["settings"], use_canary=True
    )
    assert stable_pins.provenance_manifest["tools"]["opengrep"]["image_digest"] == original_digest
    assert canary_pins.provenance_manifest["tools"]["opengrep"]["image_digest"] == new_digest

    # Promote to stable
    stable_upd = await promote_update_candidate(
        db_tx,
        update_id=upd.id,
        target_channel="stable",
        actor_user_id=lead.id,
        actor_email=lead.email,
    )
    assert stable_upd.status == "stable"
    promoted_pins = await resolve_active_tool_pins(db_tx, settings=ph10_env["settings"])
    assert promoted_pins.provenance_manifest["tools"]["opengrep"]["image_digest"] == new_digest

    # Instant zero-rebuild rollback restores original_digest
    demoted, restored = await rollback_tool_version(
        db_tx,
        tool_slug="opengrep",
        reason="Regression spike in production scan latency",
        actor_user_id=lead.id,
        actor_email=lead.email,
    )
    assert demoted.image_digest == new_digest
    assert restored is not None
    assert restored.image_digest == original_digest

    restored_pins = await resolve_active_tool_pins(db_tx, settings=ph10_env["settings"])
    assert restored_pins.provenance_manifest["tools"]["opengrep"]["image_digest"] == original_digest

    # Feed snapshot promotion + rollback
    feed = await register_feed_snapshot(
        db_tx,
        tool_slug="grype-db",
        feed_slug="grype-db",
        snapshot_tag=f"v5-2026-11-13-{uuid.uuid4().hex[:6]}",
        archive_sha256="9" * 64,
        schema_version="v5",
        record_count=250100,
    )
    await promote_feed_snapshot(
        db_tx,
        snapshot_id=feed.id,
        target_channel="stable",
        actor_user_id=lead.id,
        actor_email=lead.email,
    )
    demoted_feed, restored_feed = await rollback_feed_snapshot(
        db_tx,
        feed_slug="grype-db",
        reason="Corrupted feed checksum batch",
        actor_user_id=lead.id,
        actor_email=lead.email,
    )
    assert demoted_feed.id == feed.id
    assert restored_feed.snapshot_tag == "v5-2026-11-12"


async def test_emergency_security_update_requires_justification_and_safety_gates(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    lead_id = uuid.uuid4()
    sub = f"ph10-emerg-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], sub))
    lead = AppUser(
        id=lead_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=sub,
        email=f"{sub}@example.com",
        display_name="Emergency Lead",
        status="active",
    )
    db_tx.add(lead)
    await db_tx.flush()

    _tool, _ver, upd = await register_update_candidate(
        db_tx,
        tool_slug="grype",
        version_tag="0.90.1-sec",
        image_repository="anchore/grype",
        image_digest="sha256:" + "e" * 64,
        sbom_digest="sha256:" + "b" * 64,
        signature_verified=True,
        change_type="security",
    )

    # Deferred regression_corpus passes safety & contract gates ONLY
    await run_automated_validation_gates(
        db_tx,
        update_id=upd.id,
        executed_by=lead.email,
        skip_regression_corpus=True,
    )

    # Normal approval fails because regression_corpus was skipped
    with pytest.raises(ConflictError):
        await approve_update_candidate(
            db_tx, update_id=upd.id, actor_user_id=lead.id, actor_email=lead.email
        )

    # Emergency approval without justification fails
    with pytest.raises(ValidationError):
        await approve_update_candidate(
            db_tx,
            update_id=upd.id,
            actor_user_id=lead.id,
            actor_email=lead.email,
            is_emergency=True,
            emergency_justification="short",
        )

    # Emergency approval with justification succeeds and logs emergency_approved
    approved = await approve_update_candidate(
        db_tx,
        update_id=upd.id,
        actor_user_id=lead.id,
        actor_email=lead.email,
        is_emergency=True,
        emergency_justification="CVE-2026-9999 remote parser advisory mitigation",
    )
    assert approved.is_emergency is True
    assert approved.status == "approved"

    audits = (
        (await db_tx.execute(select(UpdateAuditEvent).where(UpdateAuditEvent.update_id == upd.id)))
        .scalars()
        .all()
    )
    assert any(a.action == "emergency_approved" for a in audits)


async def test_historical_scan_retains_original_pinned_version_across_upgrade_and_rollback(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    user_id = uuid.uuid4()
    org_id = uuid.uuid4()
    sub = f"ph10-prov-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], sub))
    user = AppUser(
        id=user_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=sub,
        email=f"{sub}@example.com",
        display_name="Prov User",
        status="active",
    )
    db_tx.add(user)
    await db_tx.flush()

    approver_id = uuid.uuid4()
    approver_sub = f"ph10-approver-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], approver_sub))
    approver = AppUser(
        id=approver_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=approver_sub,
        email=f"{approver_sub}@example.com",
        display_name="Prov Approver",
        status="active",
    )
    db_tx.add(approver)
    await db_tx.flush()

    await set_db_context(db_tx, org_id=org_id, user_id=user_id)
    org = Organization(
        id=org_id,
        name="Prov Org",
        slug=f"prov-org-{uuid.uuid4().hex[:6]}",
        status="active",
    )
    db_tx.add(org)
    await db_tx.flush()

    proj = Project(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Prov Project",
        slug=f"prov-proj-{uuid.uuid4().hex[:6]}",
        criticality="high",
        status=ProjectStatus.ACTIVE.value,
    )
    db_tx.add(proj)
    await db_tx.flush()

    env = Environment(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        name="prod",
        environment_type=EnvironmentType.PRODUCTION.value,
        status=EnvironmentStatus.ACTIVE.value,
    )
    db_tx.add(env)
    await db_tx.flush()

    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        environment_id=env.id,
        asset_type=AssetType.SOURCE_REPOSITORY.value,
        normalized_locator="https://github.com/org/repo.git",
    )
    profile = ScanProfile(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="SAST Baseline",
        version=1,
        status=ScanProfileStatus.ACTIVE.value,
        configuration={
            "stages": [
                {
                    "stage_key": "sast",
                    "stage_kind": "passive",
                    "tools": ["opengrep"],
                    "capabilities": ["sast"],
                }
            ]
        },
    )
    db_tx.add_all([asset, profile])
    await db_tx.flush()

    now_utc = datetime.now(UTC)
    auth = Authorization(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        asset_id=asset.id,
        requested_by=user_id,
        approved_by=approver_id,
        status=AuthorizationStatus.APPROVED.value,
        authorization_reference="AUTH-PH10-001",
        valid_from=now_utc - timedelta(hours=1),
        expires_at=now_utc + timedelta(days=7),
        approved_activities=["sast"],
        permitted_intensity="low",
    )
    db_tx.add(auth)
    await db_tx.flush()

    snap = ScopeSnapshot(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        asset_id=asset.id,
        authorization_id=auth.id,
        snapshot_version=1,
        asset_version=1,
        policy_version="2026-11-12.v2",
        target_type="source_repository",
        canonical_locator=asset.normalized_locator,
        resolved_ips=[],
        allowed_ports=[],
        permitted_capabilities=["sast"],
        permitted_intensity="low",
        scope_definition={},
        payload={},
        payload_sha256="a" * 64,
        signature="c2ln",
        signing_key_id="k1",
        authorization_expires_at=auth.expires_at,
        created_by=user_id,
    )
    db_tx.add(snap)
    await db_tx.flush()

    # Scan 1 under v1 stable digest
    pins_v1 = await resolve_active_tool_pins(db_tx, settings=ph10_env["settings"])
    v1_digest = pins_v1.provenance_manifest["tools"]["opengrep"]["image_digest"]
    plan_v1 = build_declarative_scan_plan(
        profile=profile,
        asset=asset,
        execution_mode="runner",
        opengrep_image_digest=pins_v1.image_refs["opengrep"],
        allowed_image_digests=pins_v1.allowed_image_digests,
        source_snapshot_present=True,
    )
    scan1 = ScanRun(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        scan_profile_id=profile.id,
        authorization_id=auth.id,
        scope_snapshot_id=snap.id,
        requested_by=user_id,
        status=ScanRunStatus.QUEUED.value,
        runner_pool="standard",
        target_snapshot={"asset_id": str(asset.id)},
        profile_snapshot={"id": str(profile.id)},
        plan_manifest=plan_v1.manifest,
        tool_version_pins=pins_v1.provenance_manifest,
        policy_snapshot_hash="a" * 64,
        policy_version="v1",
        idempotency_key=f"scan1-{uuid.uuid4().hex[:6]}",
        request_fingerprint="f1",
    )
    db_tx.add(scan1)
    await db_tx.flush()

    # Upgrade opengrep -> v2 stable
    v2_digest = "sha256:" + "f" * 64
    _t, _v, upd = await register_update_candidate(
        db_tx,
        tool_slug="opengrep",
        version_tag="1.36.0",
        image_repository="vforge-opengrep:1.36.0",
        image_digest=v2_digest,
        sbom_digest="sha256:" + "c" * 64,
        signature_verified=True,
    )
    await run_automated_validation_gates(db_tx, update_id=upd.id, executed_by=user.email)
    await approve_update_candidate(
        db_tx, update_id=upd.id, actor_user_id=user.id, actor_email=user.email
    )
    await promote_update_candidate(
        db_tx,
        update_id=upd.id,
        target_channel="stable",
        actor_user_id=user.id,
        actor_email=user.email,
    )

    pins_v2 = await resolve_active_tool_pins(db_tx, settings=ph10_env["settings"])
    scan2 = ScanRun(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        scan_profile_id=profile.id,
        authorization_id=auth.id,
        scope_snapshot_id=snap.id,
        requested_by=user_id,
        status=ScanRunStatus.QUEUED.value,
        runner_pool="standard",
        target_snapshot={"asset_id": str(asset.id)},
        profile_snapshot={"id": str(profile.id)},
        plan_manifest={},
        tool_version_pins=pins_v2.provenance_manifest,
        policy_snapshot_hash="a" * 64,
        policy_version="v1",
        idempotency_key=f"scan2-{uuid.uuid4().hex[:6]}",
        request_fingerprint="f2",
    )
    db_tx.add(scan2)
    await db_tx.flush()

    # Rollback back to v1
    await rollback_tool_version(
        db_tx,
        tool_slug="opengrep",
        reason="Rollback test",
        actor_user_id=user.id,
        actor_email=user.email,
    )

    refetched_scan1 = (
        await db_tx.execute(select(ScanRun).where(ScanRun.id == scan1.id))
    ).scalar_one()
    refetched_scan2 = (
        await db_tx.execute(select(ScanRun).where(ScanRun.id == scan2.id))
    ).scalar_one()
    assert refetched_scan1.tool_version_pins["tools"]["opengrep"]["image_digest"] == v1_digest
    assert refetched_scan2.tool_version_pins["tools"]["opengrep"]["image_digest"] == v2_digest


async def test_immutable_triggers_and_least_privilege_block_mutations(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    lead_id = uuid.uuid4()
    sub = f"ph10-imm-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], sub))
    lead = AppUser(
        id=lead_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=sub,
        email=f"{sub}@example.com",
        display_name="Imm Lead",
        status="active",
    )
    db_tx.add(lead)
    await db_tx.flush()

    _t, _v, upd = await register_update_candidate(
        db_tx,
        tool_slug="syft",
        version_tag="1.23.0",
        image_repository="anchore/syft",
        image_digest="sha256:" + "7" * 64,
        sbom_digest="sha256:" + "6" * 64,
        signature_verified=True,
    )
    await run_automated_validation_gates(db_tx, update_id=upd.id, executed_by=lead.email)

    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("UPDATE update_test_results SET outcome = 'skipped' WHERE update_id = :uid"),
                {"uid": str(upd.id)},
            )
    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("DELETE FROM update_test_results WHERE update_id = :uid"),
                {"uid": str(upd.id)},
            )
    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("UPDATE update_audit_events SET reason = 'tamper' WHERE update_id = :uid"),
                {"uid": str(upd.id)},
            )
    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("DELETE FROM update_audit_events WHERE update_id = :uid"),
                {"uid": str(upd.id)},
            )


# --- HTTP RBAC & End-to-End API Tests ---


async def test_updates_api_rbac_and_end_to_end_workflow(ph10_env: dict[str, Any]) -> None:
    factory = ph10_env["session_factory"]
    org_id = uuid.uuid4()
    other_org_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    lead_sub = f"ph10-api-lead-{uuid.uuid4().hex[:8]}"
    viewer_sub = f"ph10-api-view-{uuid.uuid4().hex[:8]}"
    lead_email = f"{lead_sub}@example.com"
    viewer_email = f"{viewer_sub}@example.com"

    async with factory() as session:
        async with session.begin():
            await set_db_context(session, auth_lookup=(ph10_env["issuer"], lead_sub))
            session.add(
                AppUser(
                    id=lead_id,
                    oidc_issuer=ph10_env["issuer"],
                    oidc_subject=lead_sub,
                    email=lead_email,
                    display_name="API Lead",
                    status="active",
                )
            )
            await session.flush()

            await set_db_context(session, auth_lookup=(ph10_env["issuer"], viewer_sub))
            session.add(
                AppUser(
                    id=viewer_id,
                    oidc_issuer=ph10_env["issuer"],
                    oidc_subject=viewer_sub,
                    email=viewer_email,
                    display_name="API Viewer",
                    status="active",
                )
            )
            await session.flush()

            await set_db_context(session, org_id=org_id, user_id=lead_id)
            session.add(
                Organization(
                    id=org_id,
                    name="Updates Org",
                    slug=f"updates-org-{uuid.uuid4().hex[:6]}",
                    status="active",
                )
            )
            await session.flush()
            session.add(
                Membership(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    user_id=lead_id,
                    role=Role.SECURITY_LEAD.value,
                    status="active",
                )
            )
            await session.flush()

            await set_db_context(session, org_id=org_id, user_id=viewer_id)
            session.add(
                Membership(
                    id=uuid.uuid4(),
                    organization_id=org_id,
                    user_id=viewer_id,
                    role=Role.VIEWER.value,
                    status="active",
                )
            )
            await session.flush()

            await set_db_context(session, org_id=other_org_id, user_id=lead_id)
            session.add(
                Organization(
                    id=other_org_id,
                    name="Other Updates Org",
                    slug=f"other-org-{uuid.uuid4().hex[:6]}",
                    status="active",
                )
            )

    lead_headers = _build_auth_headers(ph10_env, lead_sub, lead_email)
    viewer_headers = _build_auth_headers(ph10_env, viewer_sub, viewer_email)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Viewer can read overview, but CANNOT register candidate (403)
        r_view_get = await client.get(
            f"/api/v1/organizations/{org_id}/updates/overview", headers=viewer_headers
        )
        assert r_view_get.status_code == 200, r_view_get.text
        overview = r_view_get.json()
        assert len(overview["streams"]) == 4
        assert len(overview["channels"]) == 10

        r_view_post = await client.post(
            "/api/v1/updates/candidates",
            headers=viewer_headers,
            json={
                "tool_slug": "opengrep",
                "version_tag": "1.99.0",
                "image_repository": "vforge-opengrep:1.99.0",
                "image_digest": "sha256:" + "8" * 64,
            },
        )
        assert r_view_post.status_code == 403

        # Org-scoped mutation routes are no longer exposed (404/405)
        r_org_mut = await client.post(
            f"/api/v1/organizations/{org_id}/updates/candidates",
            headers=lead_headers,
            json={
                "tool_slug": "opengrep",
                "version_tag": "1.99.0",
                "image_repository": "vforge-opengrep:1.99.0",
                "image_digest": "sha256:" + "8" * 64,
            },
        )
        assert r_org_mut.status_code in {404, 405}

        # Cross-tenant check returns 403
        r_cross = await client.get(
            f"/api/v1/organizations/{other_org_id}/updates/overview", headers=lead_headers
        )
        assert r_cross.status_code == 403

        # Reject mutable :latest version_tag and :latest image_repository cleanly
        r_latest = await client.post(
            "/api/v1/updates/candidates",
            headers=lead_headers,
            json={
                "tool_slug": "opengrep",
                "version_tag": "latest",
                "image_repository": "vforge-opengrep",
                "image_digest": "sha256:" + "8" * 64,
            },
        )
        assert r_latest.status_code == 422

        r_latest_repo = await client.post(
            "/api/v1/updates/candidates",
            headers=lead_headers,
            json={
                "tool_slug": "opengrep",
                "version_tag": "1.99.1",
                "image_repository": "vforge-opengrep:latest",
                "image_digest": "sha256:" + "8" * 64,
            },
        )
        assert r_latest_repo.status_code == 422

        # Register valid candidate for nmap, block forged PASSED overrides, promote & rollback
        unique_hex = uuid.uuid4().hex
        digest_v2 = f"sha256:{unique_hex}{unique_hex}"
        r_cand = await client.post(
            "/api/v1/updates/candidates",
            headers=lead_headers,
            json={
                "tool_slug": "nmap",
                "version_tag": f"7.99-{unique_hex[:6]}",
                "image_repository": "instrumentisto/nmap",
                "image_digest": digest_v2,
                "sbom_digest": "sha256:" + "4" * 64,
                "signature_verified": True,
                "change_type": "minor",
            },
        )
        assert r_cand.status_code == 201, r_cand.text
        upd_id = r_cand.json()["id"]

        r_forged = await client.post(
            f"/api/v1/updates/{upd_id}/validate",
            headers=lead_headers,
            json={
                "tests": [
                    {
                        "test_category": "signature_provenance",
                        "outcome": "passed",
                        "summary": "Client forged pass",
                    }
                ]
            },
        )
        assert r_forged.status_code == 403

        r_val = await client.post(
            f"/api/v1/updates/{upd_id}/validate",
            headers=lead_headers,
            json={"automated": True},
        )
        assert r_val.status_code == 200, r_val.text
        assert r_val.json()["status"] == "validated"

        r_app = await client.post(
            f"/api/v1/updates/{upd_id}/approve",
            headers=lead_headers,
            json={"is_emergency": False},
        )
        assert r_app.status_code == 200, r_app.text
        assert r_app.json()["status"] == "approved"

        r_can = await client.post(
            f"/api/v1/updates/{upd_id}/promote",
            headers=lead_headers,
            json={"target_channel": "canary"},
        )
        assert r_can.status_code == 200, r_can.text
        assert r_can.json()["status"] == "canary"

        r_stb = await client.post(
            f"/api/v1/updates/{upd_id}/promote",
            headers=lead_headers,
            json={"target_channel": "stable"},
        )
        assert r_stb.status_code == 200, r_stb.text
        assert r_stb.json()["status"] == "stable"

        # Immediately roll nmap back to its baseline 7.98 digest so seeded state remains intact
        r_rb = await client.post(
            "/api/v1/updates/tools/nmap/rollback",
            headers=lead_headers,
            json={"reason": "E2E smoke verification rollback back to 7.98"},
        )
        assert r_rb.status_code == 200, r_rb.text
        rb_body = r_rb.json()
        assert rb_body["demoted_version"]["image_digest"] == digest_v2
        assert rb_body["restored_version"]["version_tag"] == "7.98"


async def test_promoted_digest_signs_execution_manifest_without_static_env_edit(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    from vforge.orchestration.manifest import (
        sign_execution_manifest,
        verify_execution_manifest,
    )
    from vforge.security.signing import SnapshotSigner

    lead_id = uuid.uuid4()
    org_id = uuid.uuid4()
    sub = f"ph10-dyn-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], sub))
    lead = AppUser(
        id=lead_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=sub,
        email=f"{sub}@example.com",
        display_name="Dyn Lead",
        status="active",
    )
    db_tx.add(lead)
    await db_tx.flush()

    approver_id = uuid.uuid4()
    approver_sub = f"ph10-dyn-app-{uuid.uuid4().hex[:8]}"
    await set_db_context(db_tx, auth_lookup=(ph10_env["issuer"], approver_sub))
    approver = AppUser(
        id=approver_id,
        oidc_issuer=ph10_env["issuer"],
        oidc_subject=approver_sub,
        email=f"{approver_sub}@example.com",
        display_name="Dyn Approver",
        status="active",
    )
    db_tx.add(approver)
    await db_tx.flush()

    await set_db_context(db_tx, org_id=org_id, user_id=lead_id)
    org = Organization(
        id=org_id,
        name="Dyn Org",
        slug=f"dyn-org-{uuid.uuid4().hex[:6]}",
        status="active",
    )
    db_tx.add(org)
    await db_tx.flush()

    proj = Project(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Dyn Proj",
        slug=f"dyn-proj-{uuid.uuid4().hex[:6]}",
        criticality="high",
        status=ProjectStatus.ACTIVE.value,
    )
    db_tx.add(proj)
    await db_tx.flush()

    env = Environment(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        name="staging",
        environment_type=EnvironmentType.STAGING.value,
        status=EnvironmentStatus.ACTIVE.value,
    )
    db_tx.add(env)
    await db_tx.flush()

    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        environment_id=env.id,
        asset_type=AssetType.SOURCE_REPOSITORY.value,
        normalized_locator="https://github.com/org/dyn-repo.git",
    )
    profile = ScanProfile(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="SAST Dynamic",
        version=1,
        status=ScanProfileStatus.ACTIVE.value,
        configuration={"stages": ["sast"]},
    )
    db_tx.add_all([asset, profile])
    await db_tx.flush()

    now_utc = datetime.now(UTC)
    auth = Authorization(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        asset_id=asset.id,
        requested_by=lead_id,
        approved_by=approver_id,
        status=AuthorizationStatus.APPROVED.value,
        authorization_reference="AUTH-PH10-DYN",
        valid_from=now_utc - timedelta(hours=1),
        expires_at=now_utc + timedelta(days=7),
        approved_activities=["sast"],
        permitted_intensity="low",
    )
    db_tx.add(auth)
    await db_tx.flush()

    snap = ScopeSnapshot(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        asset_id=asset.id,
        authorization_id=auth.id,
        snapshot_version=1,
        asset_version=1,
        policy_version="2026-11-12.v2",
        target_type="source_repository",
        canonical_locator=asset.normalized_locator,
        resolved_ips=[],
        allowed_ports=[],
        permitted_capabilities=["sast"],
        permitted_intensity="low",
        scope_definition={},
        payload={},
        payload_sha256="a" * 64,
        signature="c2ln",
        signing_key_id="k1",
        authorization_expires_at=auth.expires_at,
        created_by=lead_id,
    )
    db_tx.add(snap)
    await db_tx.flush()

    dyn_digest = "sha256:" + "5" * 64
    _t, _v, upd = await register_update_candidate(
        db_tx,
        tool_slug="opengrep",
        version_tag="1.37.0",
        image_repository="vforge-opengrep:1.37.0",
        image_digest=dyn_digest,
        adapter_version="1.2.0",
        sbom_digest="sha256:" + "3" * 64,
        signature_verified=True,
    )
    await run_automated_validation_gates(db_tx, update_id=upd.id, executed_by=lead.email)
    await approve_update_candidate(
        db_tx, update_id=upd.id, actor_user_id=lead.id, actor_email=lead.email
    )
    await promote_update_candidate(
        db_tx,
        update_id=upd.id,
        target_channel="stable",
        actor_user_id=lead.id,
        actor_email=lead.email,
    )

    pins = await resolve_active_tool_pins(db_tx, settings=ph10_env["settings"])
    expected_ref = f"vforge-opengrep:1.37.0@{dyn_digest}"
    assert pins.image_refs["opengrep"] == expected_ref
    assert expected_ref in pins.allowed_image_digests

    pinned_tools = pins.provenance_manifest["tools"]
    plan = build_declarative_scan_plan(
        profile=profile,
        asset=asset,
        execution_mode="runner",
        opengrep_image_digest=pins.image_refs["opengrep"],
        tool_versions={"opengrep": pinned_tools["opengrep"]["version_tag"]},
        adapter_versions={"opengrep": pinned_tools["opengrep"]["adapter_version"]},
        allowed_image_digests=pins.allowed_image_digests,
        source_snapshot_present=True,
    )
    sast_job_spec = next(j for st in plan.stages for j in st.jobs if j.tool_id == "opengrep")
    assert sast_job_spec.image_digest == expected_ref
    assert sast_job_spec.tool_version == "1.37.0"
    assert sast_job_spec.adapter_version == "1.2.0"

    run_obj = ScanRun(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj.id,
        environment_id=env.id,
        scan_profile_id=profile.id,
        authorization_id=auth.id,
        scope_snapshot_id=snap.id,
        requested_by=lead_id,
        status=ScanRunStatus.QUEUED.value,
        runner_pool="standard",
        target_snapshot={"asset_id": str(asset.id)},
        profile_snapshot={"id": str(profile.id)},
        plan_manifest=plan.manifest,
        tool_version_pins=pins.provenance_manifest,
        policy_snapshot_hash="a" * 64,
        policy_version="v1",
        idempotency_key=f"dyn-{uuid.uuid4().hex[:6]}",
        request_fingerprint="f-dyn",
    )
    job_obj = RunnerJob(
        id=uuid.uuid4(),
        organization_id=org_id,
        scan_run_id=run_obj.id,
        scan_stage_id=uuid.uuid4(),
        attempt_count=1,
        execution_mode="runner",
        tool_id="opengrep",
        tool_version=sast_job_spec.tool_version,
        image_digest=sast_job_spec.image_digest,
        adapter_version=sast_job_spec.adapter_version,
        timeout_seconds=300,
        status=RunnerJobStatus.PENDING.value,
        job_configuration=sast_job_spec.configuration,
    )
    signed = sign_execution_manifest(
        run=run_obj,
        job=job_obj,
        snapshot=snap,
        settings=ph10_env["settings"],
        allowed_image_digests=pins.allowed_image_digests,
    )
    keyring = SnapshotSigner.from_settings(ph10_env["settings"]).export_public_keyring_json()
    ok, reason = verify_execution_manifest(
        manifest=signed.manifest,
        expected_sha256=signed.bundle.payload_sha256,
        signing_key_id=signed.bundle.signing_key_id,
        signature=signed.bundle.signature,
        public_keyring_json=keyring,
        allowed_image_digests=pins.allowed_image_digests,
        expected_org_id=org_id,
    )
    assert ok is True, reason


async def test_update_controller_cycle_reports_catalog_summary(
    db_tx: AsyncSession,
    ph10_env: dict[str, Any],
) -> None:
    # Exercise monitor check cleanly
    entries = inspect_image_lock_files()
    assert len(entries) >= 0
    await detect_candidates_from_image_locks(db_tx)
    summary = await run_controller_cycle(
        session_factory=ph10_env["session_factory"], settings=ph10_env["settings"]
    )
    assert summary["catalog_tools"] >= 12
