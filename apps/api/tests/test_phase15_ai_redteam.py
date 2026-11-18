"""Comprehensive Phase 15 AI Red-Team Sandbox security, SoD, budget, RLS, trigger & API tests."""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import AsyncIterator
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
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.errors import ConflictError, ForbiddenError, ValidationError
from vforge.main import app
from vforge.models import (
    AppUser,
    Membership,
    Organization,
)
from vforge.models.enums import Role
from vforge.redteam.policy import (
    assert_url_within_session_targets,
    compute_benchmark_metrics,
    validate_session_targets,
    validate_tool_allowlist,
    verify_redteam_compose_isolation,
)
from vforge.redteam.service import (
    approve_or_reject_redteam_session,
    complete_or_terminate_redteam_session,
    create_redteam_benchmark,
    evaluate_redteam_action_with_opa,
    execute_redteam_tool_call,
    record_redteam_observation,
    request_redteam_session,
    review_redteam_observation,
    start_redteam_session,
)
from vforge.security.rate_limit import rate_limiter


def _make_rsa_key(kid: str = "ph15-oidc-key-1") -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    return priv, pub_jwk


def _make_id_token(
    *,
    priv_key: Any,
    kid: str,
    issuer: str,
    client_id: str,
    sub: str,
    email: str,
) -> str:
    now = int(time.time())
    payload = {
        "iss": issuer,
        "sub": sub,
        "aud": client_id,
        "email": email,
        "email_verified": True,
        "name": email.split("@", 1)[0],
        "iat": now,
        "exp": now + 300,
    }
    return jwt.encode(payload, priv_key, algorithm="RS256", headers={"kid": kid})


def _db_available(settings: Settings) -> bool:
    return bool(settings.effective_database_url)


@pytest_asyncio.fixture
async def ph15_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base = get_settings()
    if not _db_available(base):
        pytest.skip("PostgreSQL runtime URL not configured for Phase 15 DB tests")

    priv_key, pub_jwk = _make_rsa_key()
    issuer = "https://auth.vforge.test/realms/vforge"
    client_id = "vforge-ph15-test"

    test_settings = Settings(
        vforge_env="test",
        database_url=base.effective_database_url,
        rabbitmq_url="",
        cache_url="",
        opa_url=base.opa_url,
        artifact_root=str(tmp_path / "artifacts"),
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        oidc_client_secret="ph15-oidc-test-secret",
        session_cookie_secure=False,
        auth_rate_limit_per_minute=10000,
        sensitive_rate_limit_per_minute=10000,
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    async with engine.connect() as conn:
        res = await conn.execute(text("SELECT version_num FROM alembic_version"))
        ver = res.scalar_one_or_none()
        if ver != "0016_phase15_ai_redteam":
            await engine.dispose()
            pytest.skip(f"DB migration head is '{ver}', expected '0016_phase15_ai_redteam'")

    prev_factory = getattr(app.state, "session_factory", None)
    prev_engine = getattr(app.state, "engine", None)
    app.state.session_factory = session_factory
    app.state.engine = engine
    app.dependency_overrides[get_settings] = lambda: test_settings
    rate_limiter.reset()

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

    try:
        yield {
            "settings": test_settings,
            "session_factory": session_factory,
            "priv_key": priv_key,
            "issuer": issuer,
            "client_id": client_id,
            "tmp_path": tmp_path,
        }
    finally:
        oidc_client.reset_caches()
        app.dependency_overrides.pop(get_settings, None)
        app.state.session_factory = prev_factory
        app.state.engine = prev_engine
        await engine.dispose()


async def _seed_org_and_users(
    session: AsyncSession,
) -> tuple[Organization, AppUser, AppUser, AppUser]:
    """Create an organization with a Security Analyst, Security Lead, and Viewer."""
    suffix = uuid.uuid4().hex[:8]
    issuer = "https://auth.vforge.test/realms/vforge"
    org_id = uuid.uuid4()
    analyst_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    viewer_id = uuid.uuid4()

    sub_analyst = f"ph15-analyst-{suffix}"
    await set_db_context(session, auth_lookup=(issuer, sub_analyst))
    analyst = AppUser(
        id=analyst_id,
        oidc_issuer=issuer,
        oidc_subject=sub_analyst,
        email=f"analyst-{suffix}@vforge.test",
        display_name="Phase15 Analyst",
    )
    session.add(analyst)
    await session.flush()

    sub_lead = f"ph15-lead-{suffix}"
    await set_db_context(session, auth_lookup=(issuer, sub_lead))
    lead = AppUser(
        id=lead_id,
        oidc_issuer=issuer,
        oidc_subject=sub_lead,
        email=f"lead-{suffix}@vforge.test",
        display_name="Phase15 Lead",
    )
    session.add(lead)
    await session.flush()

    sub_viewer = f"ph15-viewer-{suffix}"
    await set_db_context(session, auth_lookup=(issuer, sub_viewer))
    viewer = AppUser(
        id=viewer_id,
        oidc_issuer=issuer,
        oidc_subject=sub_viewer,
        email=f"viewer-{suffix}@vforge.test",
        display_name="Phase15 Viewer",
    )
    session.add(viewer)
    await session.flush()

    await set_db_context(session, user_id=lead.id, org_id=org_id)
    org = Organization(id=org_id, name=f"Phase15 Org {suffix}", slug=f"ph15-{suffix}")
    session.add(org)
    await session.flush()

    session.add_all(
        [
            Membership(organization_id=org.id, user_id=lead.id, role=Role.SECURITY_LEAD.value),
            Membership(
                organization_id=org.id, user_id=analyst.id, role=Role.SECURITY_ANALYST.value
            ),
            Membership(organization_id=org.id, user_id=viewer.id, role=Role.VIEWER.value),
        ]
    )
    await session.flush()
    return org, analyst, lead, viewer


# ---------------------------------------------------------------------------
# 1. Sandbox Compose Isolation & Tool/Target Policy Unit Tests
# ---------------------------------------------------------------------------


def test_redteam_compose_isolation_verified_and_tamper_detected(tmp_path: Path) -> None:
    live = verify_redteam_compose_isolation()
    assert live["verified"] is True, f"Live redteam compose violations: {live['violations']}"
    assert live["services_checked"] >= 1

    # Tampered compose with docker.sock, public ports, :latest, root user, secret env
    tampered = tmp_path / "compose.redteam.tampered.yaml"
    tampered.write_text(
        """
services:
  evil-agent:
    image: ghcr.io/example/strix:latest
    privileged: true
    user: "0:0"
    read_only: false
    restart: always
    networks:
      - default
    ports:
      - "9999:9999"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      OPENAI_API_KEY: "sk-secret"
networks:
  default: {}
""",
        encoding="utf-8",
    )
    res = verify_redteam_compose_isolation(tampered)
    assert res["verified"] is False
    joined = " | ".join(res["violations"])
    assert "docker.sock" in joined
    assert "lab_internal" in joined
    assert ":latest" in joined
    assert "privileged" in joined
    assert "ports" in joined
    assert "read_only" in joined
    assert "non-root" in joined
    assert "cap_drop" in joined
    assert "no-new-privileges" in joined
    assert "volumes" in joined
    assert "OPENAI_API_KEY" in joined


def test_tool_allowlist_and_session_target_validation_fail_closed() -> None:
    allowed = validate_tool_allowlist(["http_probe", "DOM_INSPECT", "note_hypothesis"])
    assert allowed == ["dom_inspect", "http_probe", "note_hypothesis"]

    for forbidden in (
        "shell_exec",
        "shell:exec",
        "docker",
        "raw_docker_socket",
        "scope:modify",
        "opa:modify",
        "rule:sign",
        "rule:promote",
        "finding:auto_confirm",
        "network:expand_scope",
    ):
        with pytest.raises(ForbiddenError):
            validate_tool_allowlist(["http_probe", forbidden])

    with pytest.raises(ValidationError):
        validate_tool_allowlist(["unknown_custom_exploit_tool"])

    # Valid isolated lab targets pass
    targets = validate_session_targets(["http://crapi-web:8080", "http://127.0.0.1:8090/login"])
    assert len(targets) == 2

    # External internet, control-plane services, and private LAN IPs are blocked
    for forbidden_url in (
        "https://example.com/admin",
        "http://8.8.8.8:80/",
        "http://169.254.169.254/latest/meta-data/",
        "http://postgres:5432/",
        "http://api:8000/api/v1/meta",
        "http://opa:8181/v1/data",
    ):
        with pytest.raises((ForbiddenError, ValidationError)):
            validate_session_targets([forbidden_url])

    # Within session targets: different path on approved lab host:port is allowed
    matched = assert_url_within_session_targets(
        "http://crapi-web:8080/api/orders/1002", ["http://crapi-web:8080"]
    )
    assert matched.startswith("http://crapi-web:8080")

    with pytest.raises(ForbiddenError):
        assert_url_within_session_targets("http://juice-shop:3000/", ["http://crapi-web:8080"])


def test_benchmark_metrics_comparison_against_zap_and_nuclei() -> None:
    metrics = compute_benchmark_metrics(
        ground_truth=[
            "lab-bola-order-read",
            "lab-jwt-alg-none",
            "lab-sqli-search",
            "lab-reflected-xss",
        ],
        ai_detected=["lab-bola-order-read", "lab-jwt-alg-none", "hallucinated-cve-9999"],
        zap_detected=["lab-sqli-search", "lab-reflected-xss"],
        nuclei_detected=["lab-jwt-alg-none", "lab-sqli-search"],
    )
    assert metrics["ground_truth_count"] == 4
    assert metrics["recall"]["ai_redteam"] == 0.5
    assert metrics["recall"]["zap"] == 0.5
    assert metrics["recall"]["nuclei"] == 0.5
    assert metrics["recall"]["zap_plus_nuclei"] == 0.75
    assert metrics["recall"]["all_engines"] == 1.0
    assert metrics["ai_unique_true_positives"] == ["lab-bola-order-read"]
    assert metrics["claims_outside_ground_truth"]["ai_redteam"] == 1


@pytest.mark.asyncio
async def test_opa_redteam_client_fails_closed_on_transport_error() -> None:
    def _broken_handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("OPA unreachable")

    settings = Settings(vforge_env="test", opa_url="http://opa:8181")
    allowed, reason = await evaluate_redteam_action_with_opa(
        settings=settings,
        organization_id=uuid.uuid4(),
        user_id=uuid.uuid4(),
        role="security_lead",
        action="redteam:approve",
        opa_transport=httpx.MockTransport(_broken_handler),
    )
    assert allowed is False
    assert "ConnectError" in reason


# ---------------------------------------------------------------------------
# 2. Service Lifecycle, SoD, Budget, Lifetime, Hypothesis Review & DB Triggers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_phase15_session_sod_budget_lifetime_and_hypothesis_review(
    ph15_env: dict[str, Any],
) -> None:
    factory = ph15_env["session_factory"]
    async with factory() as db:
        org, analyst, lead, _ = await _seed_org_and_users(db)
        org_id = org.id
        analyst_id = analyst.id
        analyst_email = analyst.email
        lead_id = lead.id
        lead_email = lead.email

        # 1. Analyst requests session
        await set_db_context(db, user_id=analyst_id, org_id=org_id)
        session = await request_redteam_session(
            db,
            organization_id=org_id,
            title="Strix Lab BOLA Hypothesis Session",
            objective=(
                "Probe isolated vulnlab-api order endpoints within 2 tool calls and 1000 tokens."
            ),
            engine="strix",
            tool_allowlist=["http_probe", "note_hypothesis"],
            target_urls=["http://crapi-web:8080"],
            max_duration_seconds=120,
            max_tool_calls=2,
            max_tokens=1000,
            actor_id=analyst_id,
            actor_email=analyst_email,
        )
        session_id = session.id
        assert session.status == "requested"

        # 2. Cannot start before approval
        with pytest.raises(ConflictError):
            await start_redteam_session(
                db,
                organization_id=org_id,
                session_id=session_id,
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # 3. Segregation of Duties: requester (analyst) cannot self-approve
        with pytest.raises(ForbiddenError, match="Segregation of duties"):
            await approve_or_reject_redteam_session(
                db,
                organization_id=org_id,
                session_id=session_id,
                decision="approve",
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # 4. Security Lead (different human) approves session
        await set_db_context(db, user_id=lead_id, org_id=org_id)
        approved = await approve_or_reject_redteam_session(
            db,
            organization_id=org_id,
            session_id=session_id,
            decision="approve",
            approval_ttl_minutes=30,
            reason="Approved for isolated lab BOLA exploration",
            actor_id=lead_id,
            actor_email=lead_email,
        )
        assert approved.status == "approved"
        assert approved.approved_by == lead_id

        # 5. Start session and execute bounded tool calls
        await set_db_context(db, user_id=analyst_id, org_id=org_id)
        started = await start_redteam_session(
            db,
            organization_id=org_id,
            session_id=session_id,
            actor_id=analyst_id,
            actor_email=analyst_email,
        )
        assert started.status == "running"

        call1 = await execute_redteam_tool_call(
            db,
            organization_id=org_id,
            session_id=session_id,
            tool_name="http_probe",
            target_url="http://crapi-web:8080/api/orders/1002",
            input_summary=(
                "GET /api/orders/1002 Authorization: Bearer supersecretjwtvalue1234567890"
            ),
            estimated_tokens=400,
            actor_id=analyst_id,
            actor_email=analyst_email,
        )
        assert call1["outcome"] == "allowed"
        assert call1["tool_calls_used"] == 1
        assert call1["tokens_used"] == 400
        assert call1["classification"] == "hypothesis_only"

        # 6. Forbidden tool & unapproved tool are rejected and audited
        with pytest.raises(ForbiddenError):
            await execute_redteam_tool_call(
                db,
                organization_id=org_id,
                session_id=session_id,
                tool_name="shell:exec",
                input_summary="rm -rf /",
                estimated_tokens=100,
                actor_id=analyst_id,
                actor_email=analyst_email,
            )
        with pytest.raises(ForbiddenError):
            await execute_redteam_tool_call(
                db,
                organization_id=org_id,
                session_id=session_id,
                tool_name="browser_navigate",  # in catalog, but NOT in session.tool_allowlist
                target_url="http://crapi-web:8080/",
                estimated_tokens=100,
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # 7. External / unapproved target URL is rejected
        with pytest.raises(ForbiddenError):
            await execute_redteam_tool_call(
                db,
                organization_id=org_id,
                session_id=session_id,
                tool_name="http_probe",
                target_url="https://example.com/outside-scope",
                estimated_tokens=100,
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # 8. Token budget exceeded is rejected
        with pytest.raises(ConflictError, match="budget exceeded"):
            await execute_redteam_tool_call(
                db,
                organization_id=org_id,
                session_id=session_id,
                tool_name="note_hypothesis",
                input_summary="Exceeding token budget",
                estimated_tokens=700,  # 400 + 700 > 1000
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # Second valid tool call reaches max_tool_calls == 2
        call2 = await execute_redteam_tool_call(
            db,
            organization_id=org_id,
            session_id=session_id,
            tool_name="note_hypothesis",
            input_summary="Summarizing BOLA hypothesis",
            estimated_tokens=300,
            actor_id=analyst_id,
            actor_email=analyst_email,
        )
        assert call2["tool_calls_used"] == 2
        assert call2["tokens_used"] == 700

        # 3rd tool call rejected by max_tool_calls == 2
        with pytest.raises(ConflictError, match="budget exceeded"):
            await execute_redteam_tool_call(
                db,
                organization_id=org_id,
                session_id=session_id,
                tool_name="note_hypothesis",
                input_summary="Call #3 over limit",
                estimated_tokens=100,
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # 9. Record AI observation -> strictly classified as 'hypothesis'
        obs = await record_redteam_observation(
            db,
            organization_id=org_id,
            session_id=session_id,
            title="Potential BOLA on /api/orders/1002",
            category="bola_idor",
            severity="high",
            evidence_summary="Disposable student token A read order 1002 owned by student B.",
            actor_id=analyst_id,
            actor_email=analyst_email,
        )
        obs_id = obs.id
        assert obs.classification == "hypothesis"
        assert obs.source == "ai_agent"

        # 10. Recorder (analyst) cannot self-confirm own AI hypothesis
        with pytest.raises(ForbiddenError, match="Segregation of duties"):
            await review_redteam_observation(
                db,
                organization_id=org_id,
                observation_id=obs_id,
                decision="confirmed",
                review_note="Attempting to self-confirm my own AI observation",
                actor_id=analyst_id,
                actor_email=analyst_email,
            )

        # 11. Independent reviewer (Security Lead) confirms the hypothesis
        await set_db_context(db, user_id=lead_id, org_id=org_id)
        confirmed = await review_redteam_observation(
            db,
            organization_id=org_id,
            observation_id=obs_id,
            decision="confirmed",
            review_note="Independently reproduced in isolated lab; confirmed BOLA.",
            actor_id=lead_id,
            actor_email=lead_email,
        )
        assert confirmed.classification == "confirmed"
        assert confirmed.reviewed_by == lead_id

        # Cannot re-decide a finalized observation
        with pytest.raises(ConflictError):
            await review_redteam_observation(
                db,
                organization_id=org_id,
                observation_id=obs_id,
                decision="rejected",
                review_note="Trying to flip confirmed back to rejected",
                actor_id=lead_id,
                actor_email=lead_email,
            )

        # 12. Closing session requires cleanup_attested=True
        with pytest.raises(ValidationError, match="cleanup_attested"):
            await complete_or_terminate_redteam_session(
                db,
                organization_id=org_id,
                session_id=session_id,
                final_status="completed",
                cleanup_attested=False,
                actor_id=lead_id,
                actor_email=lead_email,
            )

        closed = await complete_or_terminate_redteam_session(
            db,
            organization_id=org_id,
            session_id=session_id,
            final_status="completed",
            end_reason="Completed bounded BOLA lab exploration",
            cleanup_attested=True,
            cleanup_summary="Wiped /tmp and /home/agent tmpfs and stopped isolated container.",
            actor_id=lead_id,
            actor_email=lead_email,
        )
        assert closed.status == "completed"
        assert closed.cleanup_attested is True

        # 13. Create benchmark comparison
        bench = await create_redteam_benchmark(
            db,
            organization_id=org_id,
            session_id=session_id,
            ground_truth_slugs=["lab-bola-order-read", "lab-sqli-search"],
            ai_detected_slugs=["lab-bola-order-read"],
            zap_detected_slugs=["lab-sqli-search"],
            nuclei_detected_slugs=["lab-sqli-search"],
            actor_id=lead_id,
            actor_email=lead_email,
        )
        assert bench.metrics_json["recall"]["all_engines"] == 1.0
        await db.rollback()


@pytest.mark.asyncio
async def test_phase15_rls_isolation_and_append_only_triggers(
    ph15_env: dict[str, Any],
) -> None:
    factory = ph15_env["session_factory"]
    async with factory() as db:
        org_a, analyst_a, lead_a, _ = await _seed_org_and_users(db)
        org_b, analyst_b, _, _ = await _seed_org_and_users(db)
        org_a_id = org_a.id
        org_b_id = org_b.id
        analyst_a_id = analyst_a.id
        analyst_a_email = analyst_a.email
        lead_a_id = lead_a.id
        lead_a_email = lead_a.email
        analyst_b_id = analyst_b.id

        await set_db_context(db, user_id=analyst_a_id, org_id=org_a_id)
        session = await request_redteam_session(
            db,
            organization_id=org_a_id,
            title="Org A Isolated Session",
            objective="Test RLS and trigger immutability on Phase 15 tables.",
            engine="pentagi",
            tool_allowlist=["http_probe", "note_hypothesis"],
            target_urls=["http://crapi-web:8080"],
            max_duration_seconds=300,
            max_tool_calls=5,
            max_tokens=5000,
            actor_id=analyst_a_id,
            actor_email=analyst_a_email,
        )
        session_id = session.id

        await set_db_context(db, user_id=lead_a_id, org_id=org_a_id)
        await approve_or_reject_redteam_session(
            db,
            organization_id=org_a_id,
            session_id=session_id,
            decision="approve",
            actor_id=lead_a_id,
            actor_email=lead_a_email,
        )
        await start_redteam_session(
            db,
            organization_id=org_a_id,
            session_id=session_id,
            actor_id=lead_a_id,
            actor_email=lead_a_email,
        )
        obs = await record_redteam_observation(
            db,
            organization_id=org_a_id,
            session_id=session_id,
            title="Org A Hypothesis",
            category="auth",
            severity="medium",
            evidence_summary="Redacted evidence summary for trigger test.",
            actor_id=analyst_a_id,
            actor_email=analyst_a_email,
        )
        obs_id = obs.id
        bench = await create_redteam_benchmark(
            db,
            organization_id=org_a_id,
            session_id=session_id,
            ground_truth_slugs=["lab-auth-1"],
            ai_detected_slugs=["lab-auth-1"],
            zap_detected_slugs=[],
            nuclei_detected_slugs=[],
            actor_id=lead_a_id,
            actor_email=lead_a_email,
        )
        bench_id = bench.id
        await db.commit()

    # Cross-tenant RLS check: Tenant B sees zero rows from Tenant A
    async with factory() as db_b:
        await set_db_context(db_b, user_id=analyst_b_id, org_id=org_b_id)
        for table_name in (
            "ai_redteam_sessions",
            "ai_redteam_observations",
            "ai_redteam_events",
            "ai_redteam_benchmarks",
        ):
            cnt = (
                await db_b.execute(
                    text(f"SELECT count(*) FROM {table_name} WHERE organization_id = :oid"),  # noqa: S608
                    {"oid": org_a_id},
                )
            ).scalar_one()
            assert int(cnt) == 0, f"Cross-tenant RLS leak on {table_name}"

    # Trigger checks under Tenant A context:
    # 1. Cannot mutate frozen session fields (tool_allowlist, target_urls, max_tool_calls)
    async with factory() as db_a:
        await set_db_context(db_a, user_id=lead_a_id, org_id=org_a_id)
        with pytest.raises(DBAPIError):
            await db_a.execute(
                text("UPDATE ai_redteam_sessions SET max_tool_calls = 999 WHERE id = :sid"),
                {"sid": session_id},
            )
        await db_a.rollback()

    # 2. Cannot mutate observation evidence_summary or evidence_sha256
    async with factory() as db_a2:
        await set_db_context(db_a2, user_id=lead_a_id, org_id=org_a_id)
        with pytest.raises(DBAPIError):
            await db_a2.execute(
                text(
                    "UPDATE ai_redteam_observations "
                    "SET evidence_summary = 'tampered' WHERE id = :oid"
                ),
                {"oid": obs_id},
            )
        await db_a2.rollback()

    # 3. Append-only events and benchmarks reject DELETE/UPDATE
    async with factory() as db_a3:
        await set_db_context(db_a3, user_id=lead_a_id, org_id=org_a_id)
        with pytest.raises(DBAPIError):
            await db_a3.execute(
                text("DELETE FROM ai_redteam_benchmarks WHERE id = :bid"),
                {"bid": bench_id},
            )
        await db_a3.rollback()


# ---------------------------------------------------------------------------
# 3. Full HTTP API & RBAC / Cross-Tenant Negative Tests
# ---------------------------------------------------------------------------


def _build_auth_headers(ph15_env: dict[str, Any], sub: str, email: str) -> dict[str, str]:
    tok = _make_id_token(
        priv_key=ph15_env["priv_key"],
        kid="ph15-oidc-key-1",
        issuer=ph15_env["issuer"],
        client_id=ph15_env["client_id"],
        sub=sub,
        email=email,
    )
    return {"Authorization": f"Bearer {tok}"}


@pytest.mark.asyncio
async def test_phase15_http_api_workflow_and_rbac_enforcement(
    ph15_env: dict[str, Any],
) -> None:
    factory = ph15_env["session_factory"]
    async with factory() as db:
        org, analyst, lead, viewer = await _seed_org_and_users(db)
        org_b, _, _, _ = await _seed_org_and_users(db)
        org_id = str(org.id)
        org_b_id = str(org_b.id)
        analyst_sub = analyst.oidc_subject
        analyst_email = analyst.email
        lead_sub = lead.oidc_subject
        lead_email = lead.email
        viewer_sub = viewer.oidc_subject
        viewer_email = viewer.email
        await db.commit()

    analyst_hdrs = _build_auth_headers(ph15_env, analyst_sub, analyst_email)
    lead_hdrs = _build_auth_headers(ph15_env, lead_sub, lead_email)
    viewer_hdrs = _build_auth_headers(ph15_env, viewer_sub, viewer_email)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Viewer can GET overview (200) but CANNOT request a session (403)
        ov_resp = await client.get(
            f"/api/v1/organizations/{org_id}/redteam/overview",
            headers=viewer_hdrs,
        )
        assert ov_resp.status_code == 200
        assert ov_resp.json()["sandbox_isolation"]["verified"] is True

        v_create = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions",
            headers=viewer_hdrs,
            json={
                "title": "Viewer Unauthorized Session",
                "objective": "Should be rejected by RBAC",
                "engine": "strix",
                "tool_allowlist": ["http_probe"],
                "target_urls": ["http://crapi-web:8080"],
            },
        )
        assert v_create.status_code == 403

        # Cross-tenant access to Org B by Lead A is denied (403)
        cross_resp = await client.get(
            f"/api/v1/organizations/{org_b_id}/redteam/overview",
            headers=lead_hdrs,
        )
        assert cross_resp.status_code == 403

        # Analyst requests a session (201)
        s_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions",
            headers=analyst_hdrs,
            json={
                "title": "API Lab Assessment Session",
                "objective": "Validate HTTP workflow from request to benchmark.",
                "engine": "strix",
                "tool_allowlist": ["http_probe", "note_hypothesis"],
                "target_urls": ["http://crapi-web:8080"],
                "max_duration_seconds": 600,
                "max_tool_calls": 5,
                "max_tokens": 10000,
            },
        )
        assert s_resp.status_code == 201, s_resp.text
        session_id = s_resp.json()["id"]

        # Analyst CANNOT approve sessions (lacks redteam:approve -> 403)
        a_dec = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/decision",
            headers=analyst_hdrs,
            json={"decision": "approve", "approval_ttl_minutes": 30},
        )
        assert a_dec.status_code == 403

        # Lead approves session (200) and starts it (200)
        l_dec = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/decision",
            headers=lead_hdrs,
            json={"decision": "approve", "approval_ttl_minutes": 30, "reason": "Approved"},
        )
        assert l_dec.status_code == 200
        assert l_dec.json()["status"] == "approved"

        st_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/start",
            headers=analyst_hdrs,
        )
        assert st_resp.status_code == 200
        assert st_resp.json()["status"] == "running"

        # Analyst executes bounded tool call (200) and records hypothesis (201)
        tc_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/tool-calls",
            headers=analyst_hdrs,
            json={
                "tool_name": "http_probe",
                "target_url": "http://crapi-web:8080/api/orders/1002",
                "input_summary": "Probe lab order endpoint",
                "estimated_tokens": 250,
            },
        )
        assert tc_resp.status_code == 200
        assert tc_resp.json()["classification"] == "hypothesis_only"

        obs_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/observations",
            headers=analyst_hdrs,
            json={
                "title": "Lab Order IDOR Hypothesis",
                "category": "bola_idor",
                "severity": "high",
                "evidence_summary": (
                    "Disposable user A read order 1002 belonging to disposable user B."
                ),
            },
        )
        assert obs_resp.status_code == 201
        obs_id = obs_resp.json()["id"]
        assert obs_resp.json()["classification"] == "hypothesis"

        # Negative HTTP check: forbidden tool (shell:exec) returns 403 and persists denied event
        denied_tc = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/tool-calls",
            headers=analyst_hdrs,
            json={
                "tool_name": "shell:exec",
                "input_summary": "id",
                "estimated_tokens": 50,
            },
        )
        assert denied_tc.status_code == 403

        # Negative HTTP check: recorder (analyst) self-confirming own observation returns 403
        sod_rev = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/observations/{obs_id}/review",
            headers=analyst_hdrs,
            json={
                "decision": "confirmed",
                "review_note": "Analyst attempting to self-confirm own observation.",
            },
        )
        assert sod_rev.status_code == 403

        # Lead confirms hypothesis (200), closes session (200), and creates benchmark (201)
        rev_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/observations/{obs_id}/review",
            headers=lead_hdrs,
            json={
                "decision": "confirmed",
                "review_note": "Confirmed in isolated lab workspace by security lead.",
            },
        )
        assert rev_resp.status_code == 200
        assert rev_resp.json()["classification"] == "confirmed"

        cl_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/close",
            headers=lead_hdrs,
            json={
                "final_status": "completed",
                "end_reason": "Completed HTTP test",
                "cleanup_attested": True,
                "cleanup_summary": "Ephemeral sandbox cleaned up.",
            },
        )
        assert cl_resp.status_code == 200
        assert cl_resp.json()["status"] == "completed"

        bm_resp = await client.post(
            f"/api/v1/organizations/{org_id}/redteam/sessions/{session_id}/benchmarks",
            headers=lead_hdrs,
            json={
                "ground_truth_slugs": ["lab-bola-order-read", "lab-sqli-search"],
                "ai_detected_slugs": ["lab-bola-order-read"],
                "zap_detected_slugs": ["lab-sqli-search"],
                "nuclei_detected_slugs": ["lab-sqli-search"],
            },
        )
        assert bm_resp.status_code == 201
        assert bm_resp.json()["metrics_json"]["recall"]["all_engines"] == 1.0

        # Verify denied events (tool_call.denied_tool & observation.review_sod_violation) persisted
        ov_after = await client.get(
            f"/api/v1/organizations/{org_id}/redteam/overview",
            headers=lead_hdrs,
        )
        assert ov_after.status_code == 200
        ev_types = {e["event_type"] for e in ov_after.json()["events"]}
        assert "tool_call.denied_tool" in ev_types
        assert "observation.review_sod_violation" in ev_types
