"""Unit, negative security, OPA fail-closed, RLS, and HTTP API tests for Phase 13 Learning Lab."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
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
from vforge.errors import ConflictError, ForbiddenError, ValidationError
from vforge.lab import (
    ALLOWED_SAFE_VALIDATION_ACTIONS,
    FORBIDDEN_EXPLOITATION_MODES,
    evaluate_lab_action_with_opa,
    get_lab_overview,
    list_challenges,
    provision_lab_workspace,
    record_challenge_remediation,
    reset_lab_workspace,
    run_vforge_self_scan,
    update_lab_consent,
    validate_challenge_safely,
    validate_lab_target_url,
    validate_safe_action_and_tool,
    verify_lab_compose_isolation,
)
from vforge.main import app
from vforge.models import (
    AppUser,
    LabAuditEvent,
    LabChallenge,
    LabChallengeProgress,
    LabSelfScan,
    LabValidationRun,
    LabWorkspace,
    Membership,
    Organization,
)
from vforge.models.enums import LabProgressStatus, Role
from vforge.security.rate_limit import rate_limiter


def _make_rsa_key(kid: str = "ph13-oidc-key-1") -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return priv, pub_jwk


def _build_auth_headers(ph13_env: dict[str, Any], subject: str, email: str) -> dict[str, str]:
    now = datetime.now(UTC)
    claims = {
        "iss": ph13_env["issuer"],
        "sub": subject,
        "aud": ph13_env["client_id"],
        "email": email,
        "name": subject,
        "email_verified": True,
        "nonce": "ph13-nonce",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    token = jwt.encode(
        claims, ph13_env["priv"], algorithm="RS256", headers={"kid": "ph13-oidc-key-1"}
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": uuid.uuid4().hex,
    }


@pytest_asyncio.fixture
async def ph13_env() -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph13.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key("ph13-oidc-key-1")
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
async def db_tx(ph13_env: dict[str, Any]) -> AsyncIterator[AsyncSession]:
    factory = ph13_env["session_factory"]
    async with factory() as session:
        async with session.begin():
            yield session
            await session.rollback()


async def _seed_org_actor(
    db: AsyncSession,
    *,
    slug_prefix: str = "ph13",
    role: Role = Role.ADMIN,
) -> tuple[Organization, AppUser]:
    suffix = uuid.uuid4().hex[:8]
    issuer = "https://idp.ph13.test/realms/vforge"
    subject = f"sub-{suffix}"
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()

    await set_db_context(db, auth_lookup=(issuer, subject))
    user = AppUser(
        id=user_id,
        oidc_issuer=issuer,
        oidc_subject=subject,
        email=f"user-{suffix}@vforge.test",
        display_name="Phase13 Test User",
    )
    db.add(user)
    await db.flush()

    await set_db_context(db, user_id=user.id, org_id=org_id)
    org = Organization(
        id=org_id,
        slug=f"{slug_prefix}-{suffix}",
        name=f"Phase13 Org {suffix}",
    )
    db.add(org)
    await db.flush()
    db.add(Membership(id=uuid.uuid4(), organization_id=org_id, user_id=user_id, role=role.value))
    await db.flush()
    return org, user


def test_compose_lab_isolation_invariants_verified_and_tamper_rejected(tmp_path: Path) -> None:
    report = verify_lab_compose_isolation()
    assert report["verified"] is True, report
    assert report["violations"] == []
    assert report["services_checked"] >= 4

    unsafe = tmp_path / "unsafe.compose.yaml"
    unsafe.write_text(
        """
networks:
  lab_internal:
    internal: false
  control: {}
services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    privileged: true
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - control
    ports:
      - "0.0.0.0:3100:3000"
""",
        encoding="utf-8",
    )
    tampered = verify_lab_compose_isolation(unsafe)
    assert tampered["verified"] is False
    joined = " | ".join(tampered["violations"])
    assert "docker.sock" in joined
    assert "internal: true" in joined
    assert "control" in joined
    assert "privileged" in joined
    assert "@sha256" in joined
    assert "127.0.0.1" in joined


def test_target_url_validation_and_exploitation_boundary_enforcement() -> None:
    assert (
        validate_lab_target_url(
            "http://127.0.0.1:3100/rest/user/login",
            permitted_target="http://127.0.0.1:3100",
        )
        == "http://127.0.0.1:3100/rest/user/login"
    )
    assert (
        validate_lab_target_url(
            "http://juice-shop.lab.vforge.local:3000/",
            permitted_target="http://juice-shop.lab.vforge.local:3000",
        )
        == "http://juice-shop.lab.vforge.local:3000/"
    )

    for forbidden_url in (
        "https://example.com/api",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5:3100/",
        "http://127.0.0.1:8000/api/v1/meta",
    ):
        with pytest.raises(ForbiddenError):
            validate_lab_target_url(forbidden_url)
    for bad_input_url in (
        "file:///etc/passwd",
        "http://admin:secret@127.0.0.1:3100/",
        "http://127.0.0.1:3100/?token=supersecret123",
    ):
        with pytest.raises(ValidationError):
            validate_lab_target_url(bad_input_url)

    for forbidden_mode in sorted(FORBIDDEN_EXPLOITATION_MODES):
        with pytest.raises(ForbiddenError):
            validate_safe_action_and_tool(
                action_type=forbidden_mode,
                tool_slug="zap",
                permitted_tools=["zap"],
            )

    with pytest.raises(ForbiddenError):
        validate_safe_action_and_tool(
            action_type="baseline_probe",
            tool_slug="sqlmap-unbounded",
            permitted_tools=["zap", "nuclei"],
        )

    assert validate_safe_action_and_tool(
        action_type="baseline_probe",
        tool_slug="ZAP",
        permitted_tools=["zap", "nuclei"],
    ) == ("baseline_probe", "zap")
    assert "remediation_retest" in ALLOWED_SAFE_VALIDATION_ACTIONS


async def test_opa_lab_boundary_fail_closed_and_allow() -> None:
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()

    unreachable = httpx.MockTransport(lambda req: (_ for _ in ()).throw(httpx.ConnectError("down")))
    settings_ok = Settings(vforge_env="test", opa_url="http://opa.test:8181")

    allowed, reason = await evaluate_lab_action_with_opa(
        settings=settings_ok,
        organization_id=org_id,
        user_id=user_id,
        role="security_analyst",
        action="lab:practice",
        lab_action_type="baseline_probe",
        opa_transport=unreachable,
    )
    assert allowed is False
    assert "failing closed" in reason

    no_opa = Settings(vforge_env="test", opa_url="")
    allowed_empty, _ = await evaluate_lab_action_with_opa(
        settings=no_opa,
        organization_id=org_id,
        user_id=user_id,
        role="admin",
        action="lab:practice",
        lab_action_type="baseline_probe",
    )
    assert allowed_empty is False

    allow_transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"result": True}))
    ok_res, _ = await evaluate_lab_action_with_opa(
        settings=settings_ok,
        organization_id=org_id,
        user_id=user_id,
        role="security_analyst",
        action="lab:practice",
        lab_action_type="baseline_probe",
        opa_transport=allow_transport,
    )
    assert ok_res is True

    # Also check malformed 200 JSON from misconfigured OPA proxy fails closed cleanly
    bad_json_transport = httpx.MockTransport(
        lambda req: httpx.Response(200, content=b"not-valid-json")
    )
    bad_json_res, _ = await evaluate_lab_action_with_opa(
        settings=settings_ok,
        organization_id=org_id,
        user_id=user_id,
        role="admin",
        action="lab:practice",
        lab_action_type="baseline_probe",
        opa_transport=bad_json_transport,
    )
    assert bad_json_res is False

    deny_transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"result": False}))
    denied_res, _ = await evaluate_lab_action_with_opa(
        settings=settings_ok,
        organization_id=org_id,
        user_id=user_id,
        role="admin",
        action="lab:practice",
        lab_action_type="persistence",
        opa_transport=deny_transport,
    )
    assert denied_res is False


async def test_lab_consent_disposable_validation_remediation_retest_and_reset(
    db_tx: AsyncSession,
    ph13_env: dict[str, Any],
) -> None:
    org, user = await _seed_org_actor(db_tx, role=Role.ADMIN)
    challenges = await list_challenges(db_tx)
    assert len(challenges) >= 4
    assert {c.track_level for c in challenges} == {
        "beginner",
        "intermediate",
        "advanced",
        "expert_practice",
    }
    ch = challenges[0]
    tool = ch.permitted_tools_json[0]

    # Provision with consent disabled first (stateless progress mode)
    ws = await provision_lab_workspace(
        db_tx,
        organization_id=org.id,
        environment_slug="lab-sandbox-1",
        display_name="Sandbox One",
        consent_to_persist_progress=False,
        disposable_account_prefix="stud",
        actor_id=user.id,
        actor_email=user.email,
    )
    assert ws.egress_denied is True
    assert ws.public_exposure_blocked is True
    assert ws.reset_epoch == 1
    assert len(ws.disposable_identities_json) == 2

    # Duplicate slug blocked cleanly with savepoint
    with pytest.raises(ConflictError):
        await provision_lab_workspace(
            db_tx,
            organization_id=org.id,
            environment_slug="lab-sandbox-1",
            display_name="Dup",
            consent_to_persist_progress=False,
            actor_id=user.id,
            actor_email=user.email,
        )

    # Real/production email rejected
    allow_opa = httpx.MockTransport(lambda req: httpx.Response(200, json={"result": True}))
    disposable_handle = ws.disposable_identities_json[0]["handle"]
    with pytest.raises(ForbiddenError):
        await validate_challenge_safely(
            db_tx,
            organization_id=org.id,
            workspace_id=ws.id,
            challenge_id=ch.id,
            target_url=ch.permitted_target,
            tool_slug=tool,
            action_type="baseline_probe",
            disposable_identity_used="real-employee@prodcorp.com",
            observed_evidence="Should fail",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=Role.ADMIN.value,
            settings=ph13_env["settings"],
            opa_transport=allow_opa,
        )

    # Stateless validation without consent records run but does NOT persist progress
    run_no_consent, prog_no_consent = await validate_challenge_safely(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        challenge_id=ch.id,
        target_url=ch.permitted_target,
        tool_slug=tool,
        action_type="baseline_probe",
        disposable_identity_used=disposable_handle,
        observed_evidence="Observed precondition cleanly",
        actor_id=user.id,
        actor_email=user.email,
        actor_role=Role.ADMIN.value,
        settings=ph13_env["settings"],
        opa_transport=allow_opa,
    )
    assert run_no_consent.safety_boundary_verified is True
    assert prog_no_consent is None

    with pytest.raises(ForbiddenError):
        await record_challenge_remediation(
            db_tx,
            organization_id=org.id,
            workspace_id=ws.id,
            challenge_id=ch.id,
            remediation_notes="Fixed SQL query parameterization.",
            actor_id=user.id,
            actor_email=user.email,
        )

    # Enable consent explicitly -> validate -> remediate -> retest
    ws = await update_lab_consent(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        consent_to_persist_progress=True,
        actor_id=user.id,
        actor_email=user.email,
    )
    assert ws.consent_to_persist_progress is True

    # Retest before remediation rejected
    with pytest.raises(ValidationError):
        await validate_challenge_safely(
            db_tx,
            organization_id=org.id,
            workspace_id=ws.id,
            challenge_id=ch.id,
            target_url=ch.permitted_target,
            tool_slug=tool,
            action_type="remediation_retest",
            disposable_identity_used=disposable_handle,
            observed_evidence="Retest prematurely",
            actor_id=user.id,
            actor_email=user.email,
            actor_role=Role.ADMIN.value,
            settings=ph13_env["settings"],
            opa_transport=allow_opa,
        )

    run_ok, prog_ok = await validate_challenge_safely(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        challenge_id=ch.id,
        target_url=ch.permitted_target,
        tool_slug=tool,
        action_type="baseline_probe",
        disposable_identity_used=disposable_handle,
        observed_evidence="Confirmed issue; token sk-proj-secret123456789012345 redacted",
        actor_id=user.id,
        actor_email=user.email,
        actor_role=Role.ADMIN.value,
        settings=ph13_env["settings"],
        opa_transport=allow_opa,
    )
    assert "sk-proj-secret123456789012345" not in run_ok.evidence_summary_redacted
    assert prog_ok is not None
    assert prog_ok.status == LabProgressStatus.VALIDATED.value

    remediated = await record_challenge_remediation(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        challenge_id=ch.id,
        remediation_notes="Replaced string concatenation with bound SQLAlchemy query.",
        actor_id=user.id,
        actor_email=user.email,
    )
    assert remediated.status == LabProgressStatus.REMEDIATED.value

    retest_run, prog_retested = await validate_challenge_safely(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        challenge_id=ch.id,
        target_url=ch.permitted_target,
        tool_slug=tool,
        action_type="remediation_retest",
        disposable_identity_used=disposable_handle,
        observed_evidence="Safe probe returned 400 clean validation error.",
        actor_id=user.id,
        actor_email=user.email,
        actor_role=Role.ADMIN.value,
        settings=ph13_env["settings"],
        opa_transport=allow_opa,
    )
    assert retest_run.remediation_verified is True
    assert prog_retested is not None
    assert prog_retested.status == LabProgressStatus.RETESTED.value
    assert prog_retested.retest_passed is True

    # Reset workspace rotates disposable identities and wipes progress cleanly
    ws_reset = await reset_lab_workspace(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        actor_id=user.id,
        actor_email=user.email,
    )
    assert ws_reset.reset_epoch == 2
    assert "-e2-" in ws_reset.disposable_identities_json[0]["handle"]

    overview = await get_lab_overview(db_tx, organization_id=org.id)
    assert overview["progress"][0].status == LabProgressStatus.NOT_STARTED.value
    assert overview["progress"][0].retest_passed is False
    assert overview["compose_isolation"]["verified"] is True

    # Revoking consent clears and hides previously persisted progress
    await update_lab_consent(
        db_tx,
        organization_id=org.id,
        workspace_id=ws.id,
        consent_to_persist_progress=False,
        actor_id=user.id,
        actor_email=user.email,
    )
    ov_revoked = await get_lab_overview(db_tx, organization_id=org.id)
    assert ov_revoked["progress"] == []


async def test_vforge_self_scan_verifies_real_invariants_and_reports_defects(
    db_tx: AsyncSession,
    tmp_path: Path,
) -> None:
    org, user = await _seed_org_actor(db_tx, role=Role.ADMIN)

    clean_scan = await run_vforge_self_scan(
        db_tx,
        organization_id=org.id,
        target_component="control_plane_api",
        profile_name="baseline-self-verify",
        actor_id=user.id,
        actor_email=user.email,
    )
    assert clean_scan.checks_executed >= 2
    assert clean_scan.issues_found == 0
    assert clean_scan.regression_verified is True

    bad_compose = tmp_path / "bad.compose.yaml"
    bad_compose.write_text("services:\n  api:\n    image: alpine:latest\n", encoding="utf-8")
    broken_scan = await run_vforge_self_scan(
        db_tx,
        organization_id=org.id,
        target_component="opa_policies",
        profile_name="negative-check",
        actor_id=user.id,
        actor_email=user.email,
        compose_path=bad_compose,
        lock_dir=tmp_path / "missing-locks",
    )
    assert broken_scan.issues_found >= 1
    assert broken_scan.critical_high_count >= 1
    assert broken_scan.regression_verified is False

    # Unpinned lockfile entry (:latest) must produce honest finding rather than crashing
    lock_dir = tmp_path / "locks"
    lock_dir.mkdir()
    (lock_dir / "bad.json").write_text(
        json.dumps([{"tool_id": "rogue-scanner", "tag": "latest", "digest": "sha256:bad"}]),
        encoding="utf-8",
    )
    bad_lock_scan = await run_vforge_self_scan(
        db_tx,
        organization_id=org.id,
        target_component="control_plane_api",
        profile_name="unpinned-lock-check",
        actor_id=user.id,
        actor_email=user.email,
        lock_dir=lock_dir,
    )
    assert any(f["id"].startswith("SELF-PIN-UNSAFE") for f in bad_lock_scan.findings_json)
    assert bad_lock_scan.regression_verified is False


async def test_phase13_rls_isolation_and_append_only_triggers(
    db_tx: AsyncSession,
    ph13_env: dict[str, Any],
) -> None:
    org_a, user_a = await _seed_org_actor(db_tx, slug_prefix="ph13a", role=Role.ADMIN)
    ws_a = await provision_lab_workspace(
        db_tx,
        organization_id=org_a.id,
        environment_slug="org-a-lab",
        display_name="Org A Lab",
        consent_to_persist_progress=True,
        actor_id=user_a.id,
        actor_email=user_a.email,
    )
    scan_a = await run_vforge_self_scan(
        db_tx,
        organization_id=org_a.id,
        target_component="runner_agent",
        profile_name="rls-check",
        actor_id=user_a.id,
        actor_email=user_a.email,
    )
    ch = (await db_tx.execute(select(LabChallenge).limit(1))).scalar_one()
    allow_opa = httpx.MockTransport(lambda req: httpx.Response(200, json={"result": True}))
    run_a, _ = await validate_challenge_safely(
        db_tx,
        organization_id=org_a.id,
        workspace_id=ws_a.id,
        challenge_id=ch.id,
        target_url=ch.permitted_target,
        tool_slug=ch.permitted_tools_json[0],
        action_type="baseline_probe",
        disposable_identity_used=ws_a.disposable_identities_json[0]["handle"],
        observed_evidence="Tenant A proof",
        actor_id=user_a.id,
        actor_email=user_a.email,
        actor_role=Role.ADMIN.value,
        settings=ph13_env["settings"],
        opa_transport=allow_opa,
    )
    await db_tx.flush()

    # Append-only immutability on lab_validation_runs, lab_self_scans, lab_audit_events
    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("DELETE FROM lab_validation_runs WHERE id = :id"),
                {"id": run_a.id},
            )
    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("UPDATE lab_self_scans SET issues_found = 99 WHERE id = :id"),
                {"id": scan_a.id},
            )
    with pytest.raises(DBAPIError):
        async with db_tx.begin_nested():
            await db_tx.execute(
                text("DELETE FROM lab_audit_events WHERE organization_id = :org"),
                {"org": org_a.id},
            )

    # Tenant B context cannot observe Org A rows
    org_b, user_b = await _seed_org_actor(db_tx, slug_prefix="ph13b", role=Role.ADMIN)
    await set_db_context(db_tx, user_id=user_b.id, org_id=org_b.id)
    assert (await db_tx.execute(select(LabWorkspace))).scalars().all() == []
    assert (await db_tx.execute(select(LabValidationRun))).scalars().all() == []
    assert (await db_tx.execute(select(LabSelfScan))).scalars().all() == []
    assert (await db_tx.execute(select(LabAuditEvent))).scalars().all() == []
    assert (await db_tx.execute(select(LabChallengeProgress))).scalars().all() == []


async def test_phase13_http_api_rbac_and_workflow(ph13_env: dict[str, Any]) -> None:
    factory = ph13_env["session_factory"]
    suffix = uuid.uuid4().hex[:8]

    async with factory() as seed_db:
        async with seed_db.begin():
            org, admin_user = await _seed_org_actor(
                seed_db, slug_prefix=f"ph13http-{suffix}", role=Role.ADMIN
            )
            viewer_id = uuid.uuid4()
            viewer_sub = f"viewer-{suffix}"
            analyst_id = uuid.uuid4()
            analyst_sub = f"analyst-{suffix}"

            await set_db_context(seed_db, auth_lookup=(ph13_env["issuer"], viewer_sub))
            viewer = AppUser(
                id=viewer_id,
                oidc_issuer=ph13_env["issuer"],
                oidc_subject=viewer_sub,
                email=f"viewer-{suffix}@vforge.test",
                display_name="Phase13 Viewer",
            )
            seed_db.add(viewer)
            await seed_db.flush()

            await set_db_context(seed_db, auth_lookup=(ph13_env["issuer"], analyst_sub))
            analyst = AppUser(
                id=analyst_id,
                oidc_issuer=ph13_env["issuer"],
                oidc_subject=analyst_sub,
                email=f"analyst-{suffix}@vforge.test",
                display_name="Phase13 Analyst",
            )
            seed_db.add(analyst)
            await seed_db.flush()

            await set_db_context(seed_db, user_id=admin_user.id, org_id=org.id)
            seed_db.add_all(
                [
                    Membership(
                        id=uuid.uuid4(),
                        organization_id=org.id,
                        user_id=viewer_id,
                        role=Role.VIEWER.value,
                    ),
                    Membership(
                        id=uuid.uuid4(),
                        organization_id=org.id,
                        user_id=analyst_id,
                        role=Role.SECURITY_ANALYST.value,
                    ),
                ]
            )
            await seed_db.flush()

    admin_hdrs = _build_auth_headers(ph13_env, admin_user.oidc_subject, admin_user.email)
    viewer_hdrs = _build_auth_headers(ph13_env, viewer_sub, f"viewer-{suffix}@vforge.test")
    analyst_hdrs = _build_auth_headers(ph13_env, analyst_sub, f"analyst-{suffix}@vforge.test")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Meta exposes Phase 13+ honestly
        meta_resp = await client.get("/api/v1/meta")
        assert meta_resp.status_code == 200
        assert meta_resp.json()["phase"] >= 13
        assert meta_resp.json()["learning_lab_enabled"] is True

        # 2. Viewer can read challenges & overview, denied on manage/practice/self-scan
        ov_resp = await client.get(
            f"/api/v1/organizations/{org.id}/lab/overview", headers=viewer_hdrs
        )
        assert ov_resp.status_code == 200, ov_resp.text
        challenges = ov_resp.json()["challenges"]
        assert len(challenges) >= 4
        assert ov_resp.json()["compose_isolation"]["verified"] is True

        denied_ws = await client.post(
            f"/api/v1/organizations/{org.id}/lab/workspaces",
            headers=viewer_hdrs,
            json={"environment_slug": "denied-ws", "display_name": "Denied"},
        )
        assert denied_ws.status_code == 403

        denied_self = await client.post(
            f"/api/v1/organizations/{org.id}/lab/self-scans",
            headers=analyst_hdrs,
            json={"target_component": "control_plane_api"},
        )
        assert denied_self.status_code == 403

        # 3. Admin provisions workspace & runs self-scan; Analyst validates challenge safely
        ws_resp = await client.post(
            f"/api/v1/organizations/{org.id}/lab/workspaces",
            headers=admin_hdrs,
            json={
                "environment_slug": f"http-lab-{suffix}",
                "display_name": "HTTP Learning Lab",
                "consent_to_persist_progress": True,
                "disposable_account_prefix": "httpstud",
            },
        )
        assert ws_resp.status_code == 201, ws_resp.text
        ws_data = ws_resp.json()
        ws_id = ws_data["id"]
        ident = ws_data["disposable_identities_json"][0]["handle"]

        ch0 = challenges[0]
        # Note: live OPA container runs in compose with Phase 13 policy loaded
        val_resp = await client.post(
            f"/api/v1/organizations/{org.id}/lab/workspaces/{ws_id}/validate",
            headers=analyst_hdrs,
            json={
                "challenge_id": ch0["id"],
                "target_url": ch0["permitted_target"],
                "tool_slug": ch0["permitted_tools_json"][0],
                "action_type": "baseline_probe",
                "disposable_identity_used": ident,
                "observed_evidence": "Verified baseline safely via HTTP test",
            },
        )
        assert val_resp.status_code == 201, val_resp.text
        assert val_resp.json()["progress"]["status"] == "validated"

        # Exploitation boundary rejected via HTTP (persistence forbidden)
        exploit_denied = await client.post(
            f"/api/v1/organizations/{org.id}/lab/workspaces/{ws_id}/validate",
            headers=analyst_hdrs,
            json={
                "challenge_id": ch0["id"],
                "target_url": ch0["permitted_target"],
                "tool_slug": ch0["permitted_tools_json"][0],
                "action_type": "persistence",
                "disposable_identity_used": ident,
                "observed_evidence": "Should be denied",
            },
        )
        assert exploit_denied.status_code == 403

        self_resp = await client.post(
            f"/api/v1/organizations/{org.id}/lab/self-scans",
            headers=admin_hdrs,
            json={"target_component": "control_plane_api", "profile_name": "http-verify"},
        )
        assert self_resp.status_code == 201, self_resp.text
        assert self_resp.json()["regression_verified"] is True
