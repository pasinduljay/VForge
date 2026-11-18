"""Phase 3 tests: planner, state machine, outbox->RabbitMQ dispatch, leases, and RLS."""

from __future__ import annotations

import asyncio
import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from vforge_scope import StaticDnsResolver
from httpx import ASGITransport, AsyncClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, text, update
from sqlalchemy.exc import ProgrammingError

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.errors import ConflictError, ValidationError
from vforge.main import app
from vforge.models.domain import ScanProfile
from vforge.models.enums import (
    LeaseRiskClass,
    RunnerJobStatus,
    ScanProfileStatus,
    ScanRunStatus,
    ScanStageStatus,
)
from vforge.models.orchestration import (
    OutboxEvent,
    RunnerJob,
    ScanRun,
    ScanTargetLease,
)
from vforge.orchestration.broker import RabbitMqOrchestrationBroker
from vforge.orchestration.planner import build_declarative_scan_plan
from vforge.orchestration.service import (
    dispatch_pending_outbox_once,
    process_dispatch_message,
    reconcile_orchestration_once,
)
from vforge.orchestration.state_machine import (
    validate_job_transition,
    validate_run_transition,
    validate_stage_transition,
)
from vforge.security.signing import generate_ed25519_keypair_pem

# --- Pure Unit Tests (State Machine & Declarative Plan Builder) ---


def test_state_machine_legal_and_illegal_transitions() -> None:
    assert (
        validate_run_transition(ScanRunStatus.QUEUED.value, ScanRunStatus.RUNNING.value)
        == "running"
    )
    assert (
        validate_run_transition(ScanRunStatus.RUNNING.value, ScanRunStatus.COMPLETED.value)
        == "completed"
    )
    assert (
        validate_run_transition(ScanRunStatus.RUNNING.value, ScanRunStatus.CANCELLING.value)
        == "cancelling"
    )
    assert (
        validate_run_transition(ScanRunStatus.CANCELLING.value, ScanRunStatus.CANCELLED.value)
        == "cancelled"
    )

    with pytest.raises(ConflictError):
        validate_run_transition(ScanRunStatus.COMPLETED.value, ScanRunStatus.RUNNING.value)
    with pytest.raises(ConflictError):
        validate_run_transition(ScanRunStatus.CANCELLED.value, ScanRunStatus.QUEUED.value)

    assert (
        validate_stage_transition(ScanStageStatus.PENDING.value, ScanStageStatus.QUEUED.value)
        == "queued"
    )
    assert (
        validate_stage_transition(ScanStageStatus.QUEUED.value, ScanStageStatus.RUNNING.value)
        == "running"
    )
    with pytest.raises(ConflictError):
        validate_stage_transition(ScanStageStatus.COMPLETED.value, ScanStageStatus.QUEUED.value)

    assert (
        validate_job_transition(RunnerJobStatus.PENDING.value, RunnerJobStatus.DISPATCHED.value)
        == "dispatched"
    )
    assert (
        validate_job_transition(RunnerJobStatus.DISPATCHED.value, RunnerJobStatus.LEASED.value)
        == "leased"
    )
    assert (
        validate_job_transition(RunnerJobStatus.LEASED.value, RunnerJobStatus.RUNNING.value)
        == "running"
    )
    assert (
        validate_job_transition(RunnerJobStatus.RUNNING.value, RunnerJobStatus.COMPLETED.value)
        == "completed"
    )
    with pytest.raises(ConflictError):
        validate_job_transition(RunnerJobStatus.COMPLETED.value, RunnerJobStatus.LEASED.value)


def test_declarative_plan_builder_and_lease_classification() -> None:
    org_id = uuid.uuid4()
    env_id = uuid.uuid4()
    profile = ScanProfile(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="active-web-check",
        version=1,
        status=ScanProfileStatus.ACTIVE.value,
        configuration={
            "stages": ["passive_dast", "active_dast"],
            "passive_only": False,
            "max_concurrency": 2,
            "request_rate_limit_rps": 5,
            "timeout_seconds": 600,
        },
    )
    from vforge.models.domain import Asset

    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        environment_id=env_id,
        asset_type="web_application",
        normalized_locator="https://app.example.com",
        scope_metadata={},
        registration_state="registered",
        version=1,
    )
    plan = build_declarative_scan_plan(profile=profile, asset=asset)
    assert plan.manifest["scanners_enabled"] is False
    assert plan.manifest["simulated"] is True
    assert len(plan.stages) == 3
    assert plan.stages[0].stage_key == "preflight"
    assert plan.stages[0].requires_target_lease is False
    assert plan.stages[1].stage_kind == "passive_dast"
    assert plan.stages[1].requires_target_lease is False
    assert plan.stages[2].stage_kind == "active_dast"
    assert plan.stages[2].requires_target_lease is True
    assert plan.stages[2].lease_risk_class == LeaseRiskClass.ACTIVE_HTTP.value

    passive_profile = ScanProfile(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="passive-only-misconfigured",
        version=1,
        status=ScanProfileStatus.ACTIVE.value,
        configuration={"stages": ["active_dast"], "passive_only": True, "timeout_seconds": 300},
    )
    with pytest.raises(ValidationError):
        build_declarative_scan_plan(profile=passive_profile, asset=asset)


# --- Live Integration & E2E Tests (Postgres + OPA + RabbitMQ) ---


def _make_rsa_key(kid: str = "ph3-oidc-key-1") -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return priv, pub_jwk


def _sign_oidc_token(
    priv: Any,
    *,
    issuer: str,
    audience: str,
    subject: str,
    email: str,
    name: str,
    nonce: str,
    kid: str = "ph3-oidc-key-1",
) -> str:
    now = datetime.now(UTC)
    claims = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "email": email,
        "name": name,
        "email_verified": True,
        "nonce": nonce,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid})


async def _login_user(
    client: AsyncClient,
    *,
    priv: Any,
    issuer: str,
    audience: str,
    subject: str,
    email: str,
    name: str,
) -> str:
    start_resp = await client.get("/api/v1/auth/oidc/login", params={"mode": "json"})
    assert start_resp.status_code == 200, start_resp.text
    auth_url = start_resp.json()["authorization_url"]
    query = parse_qs(urlsplit(auth_url).query)
    state = query["state"][0]
    nonce = query["nonce"][0]

    code = f"code-{subject}-{uuid.uuid4().hex[:8]}"
    id_token = _sign_oidc_token(
        priv,
        issuer=issuer,
        audience=audience,
        subject=subject,
        email=email,
        name=name,
        nonce=nonce,
    )

    async def _fake_exchange(**_kwargs: Any) -> dict[str, Any]:
        return {"id_token": id_token, "access_token": "opaque"}

    orig_exchange = oidc_client.exchange_code_for_tokens
    oidc_client.exchange_code_for_tokens = _fake_exchange  # type: ignore[method-assign]
    try:
        cb = await client.get(
            "/api/v1/auth/oidc/callback",
            params={"code": code, "state": state},
            follow_redirects=False,
        )
    finally:
        oidc_client.exchange_code_for_tokens = orig_exchange  # type: ignore[method-assign]

    assert cb.status_code == 302
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    csrf = me.json()["csrf_token"]
    assert csrf
    return str(csrf)


@pytest.fixture
async def ph3_env() -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url or not base_settings.effective_rabbitmq_url:
        pytest.skip("Runtime database or RabbitMQ credentials not configured")

    issuer = "https://idp.ph3.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()
    ed_priv, ed_pub = generate_ed25519_keypair_pem()
    keyring_json = json.dumps({"vf-ph3-key": {"public_key_pem": ed_pub, "status": "active"}})

    test_settings = Settings(
        vforge_env="test",
        database_url=base_settings.effective_database_url,
        rabbitmq_url=base_settings.effective_rabbitmq_url,
        cache_url="",
        opa_url=base_settings.opa_url,
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        oidc_redirect_uri="http://127.0.0.1:3000/api/v1/auth/oidc/callback",
        session_ttl_seconds=3600,
        session_idle_timeout_seconds=1800,
        auth_rate_limit_per_minute=500,
        sensitive_rate_limit_per_minute=1000,
        policy_bundle_version="2026-11-12.v2",
        scope_signing_key_id="vf-ph3-key",
        scope_signing_private_key_pem=ed_priv,
        scope_signing_public_keys_json=keyring_json,
        require_live_dns_on_approval=False,
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.dns_resolver = StaticDnsResolver({"app.example.com": ["93.184.216.34"]})
    app.dependency_overrides[get_settings] = lambda: test_settings

    oidc_client.reset_caches()
    oidc_client._metadata = OidcDiscoveryMetadata(  # noqa: SLF001
        issuer=issuer,
        authorization_endpoint=f"{issuer}/protocol/openid-connect/auth",
        token_endpoint=f"{issuer}/protocol/openid-connect/token",
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
    )
    oidc_client._metadata_fetched_at = 10**12  # noqa: SLF001
    oidc_client._jwks_keys = {"ph3-oidc-key-1": jwt.PyJWK.from_dict(pub_jwk)}  # noqa: SLF001
    oidc_client._jwks_list = [jwt.PyJWK.from_dict(pub_jwk)]  # noqa: SLF001
    oidc_client._jwks_fetched_at = 10**12  # noqa: SLF001

    yield {
        "issuer": issuer,
        "priv": priv,
        "settings": test_settings,
        "engine": engine,
        "session_factory": session_factory,
    }

    app.dependency_overrides.clear()
    app.state.dns_resolver = None
    app.state.snapshot_signer = None
    app.state.opa_client = None
    oidc_client.reset_caches()
    await engine.dispose()


async def _setup_org_scan_context(
    client: AsyncClient,
    *,
    csrf: str,
    priv: Any,
    issuer: str,
    slug_prefix: str,
    stages: list[str],
    passive_only: bool = True,
    approved_activities: list[str] | None = None,
    permitted_intensity: str = "passive",
) -> dict[str, Any]:
    org_resp = await client.post(
        "/api/v1/organizations",
        json={"name": f"{slug_prefix} Org", "slug": f"{slug_prefix}-{uuid.uuid4().hex[:6]}"},
        headers={"X-CSRF-Token": csrf},
    )
    assert org_resp.status_code == 201, org_resp.text
    org_id = org_resp.json()["id"]

    # Invite a dedicated security_analyst requester so two-person approval is satisfied.
    analyst_suffix = uuid.uuid4().hex[:8]
    analyst_subject = f"ph3-analyst-{analyst_suffix}"
    analyst_email = f"ph3-analyst-{analyst_suffix}@example.com"
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as analyst_client:
        analyst_csrf = await _login_user(
            analyst_client,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject=analyst_subject,
            email=analyst_email,
            name="Phase 3 Analyst",
        )
        inv_resp = await client.post(
            f"/api/v1/organizations/{org_id}/memberships",
            json={
                "oidc_issuer": issuer,
                "oidc_subject": analyst_subject,
                "email": analyst_email,
                "display_name": "Phase 3 Analyst",
                "role": "security_analyst",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert inv_resp.status_code == 201, inv_resp.text
        sw_resp = await analyst_client.post(
            "/api/v1/auth/switch-organization",
            json={"organization_id": org_id},
            headers={"X-CSRF-Token": analyst_csrf},
        )
        assert sw_resp.status_code == 200, sw_resp.text
        analyst_csrf_new = (await analyst_client.get("/api/v1/auth/me")).json()["csrf_token"]

        proj_resp = await client.post(
            f"/api/v1/organizations/{org_id}/projects",
            json={"name": "Portal", "slug": "portal", "criticality": "high"},
            headers={"X-CSRF-Token": csrf},
        )
        assert proj_resp.status_code == 201, proj_resp.text
        project_id = proj_resp.json()["id"]

        env_resp = await client.post(
            f"/api/v1/organizations/{org_id}/projects/{project_id}/environments",
            json={"name": "staging", "environment_type": "staging"},
            headers={"X-CSRF-Token": csrf},
        )
        assert env_resp.status_code == 201, env_resp.text
        env_id = env_resp.json()["id"]

        asset_resp = await client.post(
            f"/api/v1/organizations/{org_id}/environments/{env_id}/assets",
            json={
                "asset_type": "web_application",
                "locator": "https://app.example.com",
                "scope_metadata": {"owner": "sec"},
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert asset_resp.status_code == 201, asset_resp.text
        asset_id = asset_resp.json()["id"]

        prof_resp = await client.post(
            f"/api/v1/organizations/{org_id}/scan-profiles",
            json={
                "name": f"prof-{uuid.uuid4().hex[:6]}",
                "configuration": {
                    "stages": stages,
                    "passive_only": passive_only,
                    "max_concurrency": 2,
                    "request_rate_limit_rps": 5,
                    "timeout_seconds": 300,
                },
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert prof_resp.status_code == 201, prof_resp.text
        profile_id = prof_resp.json()["id"]

        now = datetime.now(UTC)
        authz_resp = await analyst_client.post(
            f"/api/v1/organizations/{org_id}/authorizations",
            json={
                "asset_id": asset_id,
                "approved_testing_scope": {
                    "target_type": "exact_url",
                    "target": "https://app.example.com",
                    "allowed_hosts": ["app.example.com"],
                },
                "approved_activities": approved_activities or stages,
                "allowed_ports": [443],
                "permitted_intensity": permitted_intensity,
                "allow_private_networks": False,
                "authorization_reference": f"AUTH-{uuid.uuid4().hex[:6]}",
                "valid_from": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(hours=2)).isoformat(),
            },
            headers={"X-CSRF-Token": analyst_csrf_new},
        )
        assert authz_resp.status_code == 201, authz_resp.text
        authz_id = authz_resp.json()["id"]

    approve_resp = await client.post(
        f"/api/v1/organizations/{org_id}/authorizations/{authz_id}/approve",
        json={"reason": "Phase 3 approved"},
        headers={"X-CSRF-Token": csrf},
    )
    assert approve_resp.status_code == 200, approve_resp.text

    snaps_resp = await client.get(
        f"/api/v1/organizations/{org_id}/snapshots",
        params={"authorization_id": authz_id},
    )
    assert snaps_resp.status_code == 200, snaps_resp.text
    assert len(snaps_resp.json()["items"]) >= 1
    snapshot_id = snaps_resp.json()["items"][0]["id"]

    return {
        "org_id": org_id,
        "project_id": project_id,
        "environment_id": env_id,
        "asset_id": asset_id,
        "profile_id": profile_id,
        "authorization_id": authz_id,
        "snapshot_id": snapshot_id,
    }


async def _drive_orchestration_to_completion(
    session_factory: Any,
    settings: Settings,
    *,
    worker_id: str = "test-worker-1",
    max_rounds: int = 12,
) -> list[dict[str, Any]]:
    """Run deterministic outbox -> in-process broker capture + worker execution loop."""
    published: list[dict[str, Any]] = []

    class _CaptureBroker:
        async def publish(
            self,
            *,
            routing_key: str,
            payload: dict[str, Any],
            message_id: str,
            correlation_id: str | None = None,
        ) -> None:
            published.append(
                {"routing_key": routing_key, "payload": payload, "message_id": message_id}
            )

    broker = _CaptureBroker()
    cursor = 0
    for _ in range(max_rounds):
        await reconcile_orchestration_once(session_factory, settings)
        await dispatch_pending_outbox_once(session_factory, broker, settings)
        if cursor == len(published):
            break
        while cursor < len(published):
            msg = published[cursor]
            cursor += 1
            await process_dispatch_message(
                session_factory,
                msg["payload"],
                worker_id=worker_id,
                settings=settings,
                retry_backoff_seconds=0,
                lease_retry_delay_seconds=1,
            )
    return published


async def test_phase3_scan_idempotency_pre_dispatch_denial_and_rls(ph3_env: dict[str, Any]) -> None:
    priv = ph3_env["priv"]
    issuer = ph3_env["issuer"]
    settings = ph3_env["settings"]
    session_factory = ph3_env["session_factory"]

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://test") as c_a,
        AsyncClient(transport=transport, base_url="http://test") as c_b,
    ):
        csrf_a = await _login_user(
            c_a,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject="ph3-owner-a",
            email="ph3-a@example.com",
            name="Owner A",
        )
        csrf_b = await _login_user(
            c_b,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject="ph3-owner-b",
            email="ph3-b@example.com",
            name="Owner B",
        )

        ctx_a = await _setup_org_scan_context(
            c_a, csrf=csrf_a, priv=priv, issuer=issuer, slug_prefix="ph3a", stages=["passive_dast"]
        )
        ctx_b = await _setup_org_scan_context(
            c_b, csrf=csrf_b, priv=priv, issuer=issuer, slug_prefix="ph3b", stages=["passive_dast"]
        )

        # 1. Pre-dispatch capability overreach must fail closed with 403 and audit log.
        bad_prof = await c_a.post(
            f"/api/v1/organizations/{ctx_a['org_id']}/scan-profiles",
            json={
                "name": "overreach-prof",
                "configuration": {"stages": ["active_dast"], "passive_only": False},
            },
            headers={"X-CSRF-Token": csrf_a},
        )
        assert bad_prof.status_code == 201
        denied_resp = await c_a.post(
            f"/api/v1/organizations/{ctx_a['org_id']}/scans",
            json={
                "project_id": ctx_a["project_id"],
                "environment_id": ctx_a["environment_id"],
                "scan_profile_id": bad_prof.json()["id"],
                "authorization_id": ctx_a["authorization_id"],
                "scope_snapshot_id": ctx_a["snapshot_id"],
            },
            headers={"X-CSRF-Token": csrf_a, "Idempotency-Key": "deny-overreach-1"},
        )
        assert denied_resp.status_code == 403, denied_resp.text

        # 2. Authorized scan creation + Idempotency-Key replay & 409 mismatch conflict.
        payload = {
            "project_id": ctx_a["project_id"],
            "environment_id": ctx_a["environment_id"],
            "scan_profile_id": ctx_a["profile_id"],
            "authorization_id": ctx_a["authorization_id"],
            "scope_snapshot_id": ctx_a["snapshot_id"],
        }
        create_resp = await c_a.post(
            f"/api/v1/organizations/{ctx_a['org_id']}/scans",
            json=payload,
            headers={"X-CSRF-Token": csrf_a, "Idempotency-Key": "scan-idemp-1"},
        )
        assert create_resp.status_code == 201, create_resp.text
        run_id = create_resp.json()["id"]
        assert create_resp.json()["status"] == "queued"
        assert len(create_resp.json()["stages"]) == 2  # preflight + passive_dast

        replay_resp = await c_a.post(
            f"/api/v1/organizations/{ctx_a['org_id']}/scans",
            json=payload,
            headers={"X-CSRF-Token": csrf_a, "Idempotency-Key": "scan-idemp-1"},
        )
        assert replay_resp.status_code == 200
        assert replay_resp.json()["id"] == run_id

        conflict_resp = await c_a.post(
            f"/api/v1/organizations/{ctx_a['org_id']}/scans",
            json={**payload, "simulation_delay_ms": 25},
            headers={"X-CSRF-Token": csrf_a, "Idempotency-Key": "scan-idemp-1"},
        )
        assert conflict_resp.status_code == 409

        # 3. Cross-tenant isolation at API and direct PostgreSQL RLS levels.
        cross_api = await c_b.get(f"/api/v1/organizations/{ctx_a['org_id']}/scans/{run_id}")
        assert cross_api.status_code == 403

        async with session_factory() as s:
            await set_db_context(s, org_id=uuid.UUID(ctx_b["org_id"]))
            runs_seen_by_b = (
                await s.execute(select(ScanRun).where(ScanRun.id == uuid.UUID(run_id)))
            ).scalar_one_or_none()
            outbox_seen_by_b = (
                (
                    await s.execute(
                        select(OutboxEvent).where(OutboxEvent.scan_run_id == uuid.UUID(run_id))
                    )
                )
                .scalars()
                .all()
            )
            assert runs_seen_by_b is None
            assert outbox_seen_by_b == []

            # Runtime role must have zero direct read/write privileges on orchestration_wakeups.
            with pytest.raises(ProgrammingError):
                await s.execute(text("SELECT * FROM orchestration_wakeups"))

        # Drive completion cleanly so outbox stays tidy
        await _drive_orchestration_to_completion(session_factory, settings)


async def test_phase3_outbox_rabbitmq_delivery_and_idempotent_redelivery(
    ph3_env: dict[str, Any],
) -> None:
    priv = ph3_env["priv"]
    issuer = ph3_env["issuer"]
    settings = ph3_env["settings"]
    session_factory = ph3_env["session_factory"]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        csrf = await _login_user(
            client,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject="ph3-rmq-user",
            email="ph3-rmq@example.com",
            name="RMQ Tester",
        )
        ctx = await _setup_org_scan_context(
            client,
            csrf=csrf,
            priv=priv,
            issuer=issuer,
            slug_prefix="ph3rmq",
            stages=["passive_dast"],
        )
        create_resp = await client.post(
            f"/api/v1/organizations/{ctx['org_id']}/scans",
            json={
                "project_id": ctx["project_id"],
                "environment_id": ctx["environment_id"],
                "scan_profile_id": ctx["profile_id"],
                "authorization_id": ctx["authorization_id"],
                "scope_snapshot_id": ctx["snapshot_id"],
            },
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": f"rmq-{uuid.uuid4().hex}"},
        )
        assert create_resp.status_code == 201
        run_id = create_resp.json()["id"]

        # Exercise REAL RabbitMQ publish/consume via vforge.events -> orchestration.dispatch
        broker = RabbitMqOrchestrationBroker(settings.effective_rabbitmq_url)
        await broker.ensure_topology()
        received_payloads: list[dict[str, Any]] = []
        done_event = asyncio.Event()

        async def _consumer(msg_payload: dict[str, Any]) -> bool:
            # Process messages belonging to this test run only.
            if msg_payload.get("scan_run_id") == run_id:
                received_payloads.append(msg_payload)
                await process_dispatch_message(
                    session_factory,
                    msg_payload,
                    worker_id="rmq-worker-1",
                    settings=settings,
                )
                await dispatch_pending_outbox_once(session_factory, broker, settings)
                if len(received_payloads) >= 2:
                    done_event.set()
            return True

        await broker.consume_dispatch(_consumer)

        # Wait for either the test's RabbitMQ consumer OR the live orchestrator worker
        # to finish delivering and executing both stages via RabbitMQ.
        for _ in range(40):
            if body_resp := (
                await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{run_id}")
            ):
                if body_resp.status_code == 200 and body_resp.json()["status"] == "completed":
                    break
            await dispatch_pending_outbox_once(session_factory, broker, settings)
            if done_event.is_set():
                break
            await asyncio.sleep(0.25)
        await broker.close()

        detail = await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{run_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["status"] == "completed"
        assert len(body["jobs"]) == 2

        # Re-deliver every job payload to prove duplicate delivery never double-executes!
        for job in body["jobs"]:
            dup_result = await process_dispatch_message(
                session_factory,
                {
                    "organization_id": ctx["org_id"],
                    "scan_run_id": run_id,
                    "scan_stage_id": job["scan_stage_id"],
                    "runner_job_id": job["id"],
                    "idempotency_key": job["idempotency_key"],
                    "job_type": job["job_type"],
                },
                worker_id="rmq-worker-2",
                settings=settings,
            )
            assert dup_result == "already_handled"

        detail_after = await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{run_id}")
        assert detail_after.status_code == 200
        body_after = detail_after.json()
        for job in body_after["jobs"]:
            assert job["status"] == "completed"
            assert job["execution_count"] == 1
            assert job["result_summary"]["simulated"] is True
            assert job["result_summary"]["findings_count"] == 0
            assert job["result_summary"]["scanners_enabled"] is False


async def test_phase3_target_lease_mutual_exclusion_retry_timeout_and_cancel(
    ph3_env: dict[str, Any],
) -> None:
    priv = ph3_env["priv"]
    issuer = ph3_env["issuer"]
    settings = ph3_env["settings"]
    session_factory = ph3_env["session_factory"]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        csrf = await _login_user(
            client,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject="ph3-lease-user",
            email="ph3-lease@example.com",
            name="Lease Tester",
        )
        ctx = await _setup_org_scan_context(
            client,
            csrf=csrf,
            priv=priv,
            issuer=issuer,
            slug_prefix="ph3lease",
            stages=["active_dast"],
            passive_only=False,
            approved_activities=["active_dast"],
            permitted_intensity="medium",
        )

        # Launch r_hold (timeout_hold) first and wait until it holds the active target lease.
        r_hold = await client.post(
            f"/api/v1/organizations/{ctx['org_id']}/scans",
            json={
                "project_id": ctx["project_id"],
                "environment_id": ctx["environment_id"],
                "scan_profile_id": ctx["profile_id"],
                "authorization_id": ctx["authorization_id"],
                "scope_snapshot_id": ctx["snapshot_id"],
                "simulation_mode": "timeout_hold",
                "max_attempts": 1,
            },
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": f"lease-hold-{uuid.uuid4().hex[:6]}"},
        )
        assert r_hold.status_code == 201
        hold_id = r_hold.json()["id"]

        active_leases: list[dict[str, Any]] = []
        for _ in range(25):
            await _drive_orchestration_to_completion(session_factory, settings, max_rounds=4)
            leases_resp = await client.get(
                f"/api/v1/organizations/{ctx['org_id']}/leases", params={"status": "active"}
            )
            assert leases_resp.status_code == 200
            active_leases = [
                lease for lease in leases_resp.json() if lease["scan_run_id"] == hold_id
            ]
            if len(active_leases) == 1:
                break
            await asyncio.sleep(0.2)
        assert len(active_leases) == 1

        # Now launch r_contend targeting the exact same asset + active_http risk class.
        r_contend = await client.post(
            f"/api/v1/organizations/{ctx['org_id']}/scans",
            json={
                "project_id": ctx["project_id"],
                "environment_id": ctx["environment_id"],
                "scan_profile_id": ctx["profile_id"],
                "authorization_id": ctx["authorization_id"],
                "scope_snapshot_id": ctx["snapshot_id"],
            },
            headers={
                "X-CSRF-Token": csrf,
                "Idempotency-Key": f"lease-contend-{uuid.uuid4().hex[:6]}",
            },
        )
        assert r_contend.status_code == 201
        contend_id = r_contend.json()["id"]

        def _active_job(detail: dict[str, Any]) -> dict[str, Any]:
            stage_id = next(
                s["id"] for s in detail["stages"] if s["stage_key"] == "stage_1_active_dast"
            )
            return next(j for j in detail["jobs"] if j["scan_stage_id"] == stage_id)

        contend_detail: dict[str, Any] = {}
        for _ in range(25):
            await _drive_orchestration_to_completion(session_factory, settings, max_rounds=4)
            contend_detail = (
                await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{contend_id}")
            ).json()
            if _active_job(contend_detail)["status"] == "retry_scheduled":
                break
            await asyncio.sleep(0.2)
        contend_active = _active_job(contend_detail)
        assert contend_active["status"] == "retry_scheduled"
        assert contend_active["last_error_code"] == "target_lease_busy"

        # Verify mutual exclusion: still only hold_id holds an active lease.
        leases_during = (
            await client.get(
                f"/api/v1/organizations/{ctx['org_id']}/leases", params={"status": "active"}
            )
        ).json()
        assert [lease["scan_run_id"] for lease in leases_during] == [hold_id]

        # Now expire r_hold's lease timestamps to simulate worker timeout & run reconciler!
        past = datetime.now(UTC) - timedelta(seconds=30)
        async with session_factory() as s:
            async with s.begin():
                await set_db_context(s, org_id=uuid.UUID(ctx["org_id"]))
                await s.execute(
                    update(RunnerJob)
                    .where(
                        RunnerJob.scan_run_id == uuid.UUID(hold_id), RunnerJob.status == "running"
                    )
                    .values(lease_expires_at=past)
                )
                await s.execute(
                    update(ScanTargetLease)
                    .where(
                        ScanTargetLease.scan_run_id == uuid.UUID(hold_id),
                        ScanTargetLease.status == "active",
                    )
                    .values(expires_at=past)
                )

        await reconcile_orchestration_once(session_factory, settings)

        hold_after = (
            await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{hold_id}")
        ).json()
        assert hold_after["status"] == "failed"
        assert _active_job(hold_after)["status"] == "timed_out"
        assert hold_after["leases"][0]["status"] == "expired"

        # Make contend job retry due now and drive completion — it acquires lease & finishes!
        for _ in range(25):
            async with session_factory() as s:
                async with s.begin():
                    await set_db_context(s, org_id=uuid.UUID(ctx["org_id"]))
                    await s.execute(
                        update(RunnerJob)
                        .where(
                            RunnerJob.scan_run_id == uuid.UUID(contend_id),
                            RunnerJob.status == "retry_scheduled",
                        )
                        .values(next_retry_at=past)
                    )
            await _drive_orchestration_to_completion(session_factory, settings, max_rounds=6)
            contend_done = (
                await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{contend_id}")
            ).json()
            if contend_done["status"] == "completed":
                break
            await asyncio.sleep(0.2)

        assert contend_done["status"] == "completed"
        assert contend_done["leases"][0]["status"] == "released"

        # Verify transient_fail_once recovers cleanly on attempt 2!
        r_retry = await client.post(
            f"/api/v1/organizations/{ctx['org_id']}/scans",
            json={
                "project_id": ctx["project_id"],
                "environment_id": ctx["environment_id"],
                "scan_profile_id": ctx["profile_id"],
                "authorization_id": ctx["authorization_id"],
                "scope_snapshot_id": ctx["snapshot_id"],
                "simulation_mode": "transient_fail_once",
                "max_attempts": 3,
            },
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": f"transient-{uuid.uuid4().hex[:6]}"},
        )
        assert r_retry.status_code == 201
        retry_id = r_retry.json()["id"]
        retry_done: dict[str, Any] = {}
        for _ in range(25):
            async with session_factory() as s:
                async with s.begin():
                    await set_db_context(s, org_id=uuid.UUID(ctx["org_id"]))
                    await s.execute(
                        update(RunnerJob)
                        .where(
                            RunnerJob.scan_run_id == uuid.UUID(retry_id),
                            RunnerJob.status == "retry_scheduled",
                        )
                        .values(next_retry_at=datetime.now(UTC) - timedelta(seconds=1))
                    )
            await _drive_orchestration_to_completion(session_factory, settings, max_rounds=6)
            retry_done = (
                await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{retry_id}")
            ).json()
            if retry_done["status"] == "completed":
                break
            await asyncio.sleep(0.2)

        assert retry_done["status"] == "completed"
        retry_active = _active_job(retry_done)
        assert retry_active["attempt_count"] == 2
        assert retry_active["execution_count"] == 1

        # Verify cancellation stops scan cleanly cleanly!
        r_cancel = await client.post(
            f"/api/v1/organizations/{ctx['org_id']}/scans",
            json={
                "project_id": ctx["project_id"],
                "environment_id": ctx["environment_id"],
                "scan_profile_id": ctx["profile_id"],
                "authorization_id": ctx["authorization_id"],
                "scope_snapshot_id": ctx["snapshot_id"],
                "simulation_delay_ms": 2000,
            },
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": f"cancel-{uuid.uuid4().hex[:6]}"},
        )
        assert r_cancel.status_code == 201
        cancel_id = r_cancel.json()["id"]
        cancel_resp = await client.post(
            f"/api/v1/organizations/{ctx['org_id']}/scans/{cancel_id}/cancel",
            json={"reason": "Operator aborted"},
            headers={"X-CSRF-Token": csrf},
        )
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] in {"cancelling", "cancelled"}
        cancel_final = cancel_resp.json()
        for _ in range(20):
            if cancel_final["status"] == "cancelled":
                break
            await _drive_orchestration_to_completion(session_factory, settings, max_rounds=3)
            cancel_final = (
                await client.get(f"/api/v1/organizations/{ctx['org_id']}/scans/{cancel_id}")
            ).json()
            await asyncio.sleep(0.2)
        assert cancel_final["status"] == "cancelled"
