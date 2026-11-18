"""Phase 8 Comprehensive Test Suite: Canonical Findings, Triage Lifecycle, SLA Tracking,

Risk Exceptions, and Multi-Format Reporting (HTML, PDF, JSON, SARIF).
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.main import app
from vforge.models.domain import AppUser, Membership, Organization, Project
from vforge.models.enums import (
    BusinessPriority,
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    FindingValidationStatus,
    Role,
)
from vforge.models.scanner import (
    Finding,
)
from vforge.security.rate_limit import rate_limiter
from vforge.services.findings import check_and_update_sla_breaches


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _make_rsa_key(kid: str = "ph8-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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
    kid: str = "ph8-oidc-key-1",
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


@pytest_asyncio.fixture
async def ph8_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph8.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key("ph8-oidc-key-1")
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

    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    kek_b64 = base64.urlsafe_b64encode(b"phase8-test-kek-32-bytes-exact!!").decode("ascii")

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
        artifact_root=str(artifact_dir),
        artifact_encryption_key_b64=kek_b64,
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


def _build_auth_headers(
    ph8_env: dict[str, Any],
    subject: str,
    email: str,
) -> dict[str, str]:
    token = _sign_oidc_token(
        ph8_env["priv"],
        issuer=ph8_env["issuer"],
        audience=ph8_env["client_id"],
        subject=subject,
        email=email,
        name=subject,
        nonce="test-nonce",
    )
    return {
        "Authorization": f"Bearer {token}",
        "X-Correlation-ID": uuid.uuid4().hex,
    }


async def _seed_test_org(
    db: AsyncSession,
    *,
    issuer: str,
    org_id: uuid.UUID,
    lead_id: uuid.UUID,
    dev_id: uuid.UUID,
    auditor_id: uuid.UUID,
    viewer_id: uuid.UUID,
    project_id: uuid.UUID,
    admin_id: uuid.UUID | None = None,
) -> None:
    users_info = [
        (
            lead_id,
            f"lead-{lead_id.hex[:6]}",
            f"lead-{lead_id.hex[:6]}@test.internal",
            "Security Lead",
        ),
        (
            dev_id,
            f"dev-{dev_id.hex[:6]}",
            f"dev-{dev_id.hex[:6]}@test.internal",
            "Software Developer",
        ),
        (
            auditor_id,
            f"auditor-{auditor_id.hex[:6]}",
            f"auditor-{auditor_id.hex[:6]}@test.internal",
            "Compliance Auditor",
        ),
        (
            viewer_id,
            f"viewer-{viewer_id.hex[:6]}",
            f"viewer-{viewer_id.hex[:6]}@test.internal",
            "Guest Viewer",
        ),
    ]
    if admin_id is not None:
        users_info.append(
            (
                admin_id,
                f"admin-{admin_id.hex[:6]}",
                f"admin-{admin_id.hex[:6]}@test.internal",
                "Org Admin",
            )
        )
    for uid, sub, email, name in users_info:
        await set_db_context(db, auth_lookup=(issuer, sub))
        u = AppUser(
            id=uid,
            oidc_issuer=issuer,
            oidc_subject=sub,
            email=email,
            display_name=name,
            status="active",
        )
        db.add(u)
        await db.flush()

    await set_db_context(db, org_id=org_id, user_id=lead_id)
    org = Organization(id=org_id, name="Phase 8 Test Org", slug=f"p8-org-{org_id.hex[:6]}")
    db.add(org)
    await db.flush()

    await set_db_context(db, org_id=org_id, user_id=lead_id)
    m_lead = Membership(organization_id=org_id, user_id=lead_id, role=Role.SECURITY_LEAD.value)
    m_dev = Membership(organization_id=org_id, user_id=dev_id, role=Role.DEVELOPER.value)
    m_aud = Membership(organization_id=org_id, user_id=auditor_id, role=Role.AUDITOR.value)
    m_view = Membership(organization_id=org_id, user_id=viewer_id, role=Role.VIEWER.value)
    memberships = [m_lead, m_dev, m_aud, m_view]
    if admin_id is not None:
        memberships.append(
            Membership(organization_id=org_id, user_id=admin_id, role=Role.ADMIN.value)
        )
    proj = Project(
        id=project_id,
        organization_id=org_id,
        name="Target Project",
        slug=f"proj-{project_id.hex[:6]}",
        criticality="high",
    )
    db.add_all([*memberships, proj])
    await db.flush()


@pytest.mark.anyio
async def test_finding_triage_lifecycle_and_audit_events(ph8_env: dict[str, Any]) -> None:
    """Verify finding status update, validation status auto-transitions, and audit event logs."""
    session_factory: async_sessionmaker[AsyncSession] = ph8_env["session_factory"]
    org_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    dev_id = uuid.uuid4()
    auditor_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, org_id=org_id, user_id=lead_id)
        await _seed_test_org(
            sess,
            issuer=ph8_env["issuer"],
            org_id=org_id,
            lead_id=lead_id,
            dev_id=dev_id,
            auditor_id=auditor_id,
            viewer_id=viewer_id,
            project_id=project_id,
            admin_id=admin_id,
        )
        finding = Finding(
            id=finding_id,
            organization_id=org_id,
            project_id=project_id,
            fingerprint="fp-test-lifecycle-" + uuid.uuid4().hex,
            category=FindingCategory.SAST.value,
            scanner_tool_id="opengrep",
            scanner_version="1.33.1",
            rule_id="python.lang.security.injection",
            title="SQL Injection in Auth Handler",
            description="Raw query concatenation detected.",
            severity=FindingSeverity.HIGH.value,
            confidence="high",
            validation_status=FindingValidationStatus.UNVERIFIED.value,
            status=FindingStatus.OPEN.value,
            cwe_ids=["CWE-89"],
            file_path="src/auth.py",
            start_line=42,
            end_line=45,
            business_priority=BusinessPriority.HIGH.value,
            sla_due_at=datetime.now(UTC) + timedelta(days=14),
            sla_breached=False,
            occurrence_count=1,
        )
        sess.add(finding)

    transport = ASGITransport(app=app)
    dev_headers = _build_auth_headers(
        ph8_env,
        f"dev-{dev_id.hex[:6]}",
        f"dev-{dev_id.hex[:6]}@test.internal",
    )

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Update status to IN_PROGRESS and assign to developer
        patch_resp1 = await client.patch(
            f"/api/v1/organizations/{org_id}/findings/{finding_id}",
            json={
                "status": "in_progress",
                "assigned_to": str(dev_id),
                "comment": "Developer investigating code flow.",
            },
            headers=dev_headers,
        )
        assert patch_resp1.status_code == 200, patch_resp1.text
        data1 = patch_resp1.json()
        assert data1["status"] == "in_progress"
        assert data1["assigned_to"] == str(dev_id)
        assert len(data1["events"]) >= 1

        # 2. Update status to RESOLVED -> auto sets fixed and pending_retest
        patch_resp2 = await client.patch(
            f"/api/v1/organizations/{org_id}/findings/{finding_id}",
            json={
                "status": "resolved",
                "remediation_notes": "Replaced with SQLAlchemy parameterized query.",
                "comment": "Fix committed in feature branch.",
            },
            headers=dev_headers,
        )
        assert patch_resp2.status_code == 200, patch_resp2.text
        data2 = patch_resp2.json()
        assert data2["status"] == "resolved"
        assert data2["validation_status"] == "fixed"
        assert data2["retest_status"] == "pending_retest"
        assert data2["remediation_notes"] == "Replaced with SQLAlchemy parameterized query."

        # 3. Retrieve event history
        events_resp = await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding_id}/events",
            headers=dev_headers,
        )
        assert events_resp.status_code == 200
        events_list = events_resp.json()
        assert len(events_list) >= 2
        event_types = [e["event_type"] for e in events_list]
        assert "status_changed" in event_types


@pytest.mark.anyio
async def test_sla_breach_calculation_and_evaluation(ph8_env: dict[str, Any]) -> None:
    """Verify that findings past their SLA deadline get marked breached,
    while resolved are excluded.
    """
    session_factory: async_sessionmaker[AsyncSession] = ph8_env["session_factory"]
    org_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    dev_id = uuid.uuid4()
    auditor_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    project_id = uuid.uuid4()

    f_open_breached_id = uuid.uuid4()
    f_resolved_past_id = uuid.uuid4()
    f_future_id = uuid.uuid4()

    now = datetime.now(UTC)
    past = now - timedelta(days=2)
    future = now + timedelta(days=10)

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, org_id=org_id, user_id=lead_id)
        await _seed_test_org(
            sess,
            issuer=ph8_env["issuer"],
            org_id=org_id,
            lead_id=lead_id,
            dev_id=dev_id,
            auditor_id=auditor_id,
            viewer_id=viewer_id,
            project_id=project_id,
        )
        # Open finding with past due date -> should be marked breached
        f1 = Finding(
            id=f_open_breached_id,
            organization_id=org_id,
            project_id=project_id,
            fingerprint="fp-sla-1-" + uuid.uuid4().hex,
            category=FindingCategory.SAST.value,
            scanner_tool_id="opengrep",
            scanner_version="1.33.1",
            rule_id="rule1",
            title="Overdue Finding",
            severity="critical",
            confidence="high",
            validation_status="unverified",
            status="open",
            business_priority="critical",
            sla_due_at=past,
            sla_breached=False,
            occurrence_count=1,
        )
        # Resolved finding with past due date -> should NOT be marked breached
        f2 = Finding(
            id=f_resolved_past_id,
            organization_id=org_id,
            project_id=project_id,
            fingerprint="fp-sla-2-" + uuid.uuid4().hex,
            category=FindingCategory.SAST.value,
            scanner_tool_id="opengrep",
            scanner_version="1.33.1",
            rule_id="rule2",
            title="Resolved Past Due Finding",
            severity="high",
            confidence="high",
            validation_status="fixed",
            status="resolved",
            business_priority="high",
            sla_due_at=past,
            sla_breached=False,
            occurrence_count=1,
        )
        # Open finding with future due date -> should NOT be marked breached
        f3 = Finding(
            id=f_future_id,
            organization_id=org_id,
            project_id=project_id,
            fingerprint="fp-sla-3-" + uuid.uuid4().hex,
            category=FindingCategory.SAST.value,
            scanner_tool_id="opengrep",
            scanner_version="1.33.1",
            rule_id="rule3",
            title="Future Due Finding",
            severity="medium",
            confidence="high",
            validation_status="unverified",
            status="open",
            business_priority="medium",
            sla_due_at=future,
            sla_breached=False,
            occurrence_count=1,
        )
        sess.add_all([f1, f2, f3])

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, org_id=org_id, user_id=lead_id)
        count = await check_and_update_sla_breaches(sess, org_id=org_id)
        assert count == 1

        f1_check = (
            await sess.execute(select(Finding).where(Finding.id == f_open_breached_id))
        ).scalar_one()
        f2_check = (
            await sess.execute(select(Finding).where(Finding.id == f_resolved_past_id))
        ).scalar_one()
        f3_check = (
            await sess.execute(select(Finding).where(Finding.id == f_future_id))
        ).scalar_one()

        assert f1_check.sla_breached is True
        assert f2_check.sla_breached is False
        assert f3_check.sla_breached is False


@pytest.mark.anyio
async def test_timebound_risk_exception_lifecycle_and_role_gate(ph8_env: dict[str, Any]) -> None:
    """Verify request, approval role-gate (developer denied, security lead allowed),
    and finding transition.
    """
    session_factory: async_sessionmaker[AsyncSession] = ph8_env["session_factory"]
    org_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    dev_id = uuid.uuid4()
    auditor_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, org_id=org_id, user_id=lead_id)
        await _seed_test_org(
            sess,
            issuer=ph8_env["issuer"],
            org_id=org_id,
            lead_id=lead_id,
            dev_id=dev_id,
            auditor_id=auditor_id,
            viewer_id=viewer_id,
            project_id=project_id,
            admin_id=admin_id,
        )
        finding = Finding(
            id=finding_id,
            organization_id=org_id,
            project_id=project_id,
            fingerprint="fp-risk-exc-" + uuid.uuid4().hex,
            category=FindingCategory.SECRET.value,
            scanner_tool_id="gitleaks",
            scanner_version="8.21.2",
            rule_id="generic-api-key",
            title="Exposed Test API Key",
            severity="medium",
            confidence="medium",
            validation_status="unverified",
            status="open",
            business_priority="medium",
            occurrence_count=1,
        )
        sess.add(finding)

    transport = ASGITransport(app=app)
    dev_headers = _build_auth_headers(
        ph8_env,
        f"dev-{dev_id.hex[:6]}",
        f"dev-{dev_id.hex[:6]}@test.internal",
    )
    lead_headers = _build_auth_headers(
        ph8_env,
        f"lead-{lead_id.hex[:6]}",
        f"lead-{lead_id.hex[:6]}@test.internal",
    )
    admin_headers = _build_auth_headers(
        ph8_env,
        f"admin-{admin_id.hex[:6]}",
        f"admin-{admin_id.hex[:6]}@test.internal",
    )

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Developer requests risk exception
        expiry = (datetime.now(UTC) + timedelta(days=30)).isoformat()
        req_resp = await client.post(
            f"/api/v1/organizations/{org_id}/findings/{finding_id}/risk-exceptions",
            json={
                "reason": "Test sandbox credentials with restricted IP and zero production access.",
                "mitigating_controls": (
                    "IP allowlist enforced on test gateway; automated token rotation every 7 days."
                ),
                "expires_at": expiry,
            },
            headers=dev_headers,
        )
        assert req_resp.status_code == 201, req_resp.text
        exc_data = req_resp.json()
        assert exc_data["status"] == "pending"
        assert exc_data["finding_id"] == str(finding_id)
        exception_id = exc_data["id"]

        # 2. Developer tries to approve their own exception -> must be 403 Forbidden
        dev_approve_resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk-exceptions/{exception_id}/review",
            json={
                "approved": True,
                "review_notes": "Self approval attempt should be rejected.",
            },
            headers=dev_headers,
        )
        assert dev_approve_resp.status_code == 403

        # 3. Security Lead reviews and approves the exception
        lead_approve_resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk-exceptions/{exception_id}/review",
            json={
                "approved": True,
                "review_notes": (
                    "Reviewed and approved based on isolated test environment controls."
                ),
            },
            headers=lead_headers,
        )
        assert lead_approve_resp.status_code == 200, lead_approve_resp.text
        approved_data = lead_approve_resp.json()
        assert approved_data["status"] == "approved"
        assert approved_data["reviewed_by"] == str(lead_id)

        # 4. Verify finding status automatically transitioned to risk_accepted
        f_resp = await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding_id}",
            headers=dev_headers,
        )
        assert f_resp.status_code == 200
        f_data = f_resp.json()
        assert f_data["status"] == "risk_accepted"
        assert f_data["validation_status"] == "accepted_risk"
        assert f_data["active_risk_exception"] is not None
        assert f_data["active_risk_exception"]["status"] == "approved"

        # 5. Security Lead requests exception on finding_id_2
        # Verify four-eyes separation of duties: Lead CANNOT approve their own request
        finding_id_2 = uuid.uuid4()
        async with session_factory() as sess, sess.begin():
            await set_db_context(sess, org_id=org_id, user_id=lead_id)
            finding2 = Finding(
                id=finding_id_2,
                organization_id=org_id,
                project_id=project_id,
                fingerprint="fp-risk-exc2-" + uuid.uuid4().hex,
                category=FindingCategory.SAST.value,
                scanner_tool_id="opengrep",
                scanner_version="1.33.1",
                rule_id="command-injection",
                title="Command Injection",
                severity="high",
                confidence="high",
                validation_status="unverified",
                status="open",
                business_priority="high",
                occurrence_count=1,
            )
            sess.add(finding2)

        req_lead_resp = await client.post(
            f"/api/v1/organizations/{org_id}/findings/{finding_id_2}/risk-exceptions",
            json={
                "reason": "Internal test utility, planned for refactor.",
                "mitigating_controls": "Accessible only in test runner sandbox.",
                "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
            },
            headers=lead_headers,
        )
        assert req_lead_resp.status_code == 201
        exc2_id = req_lead_resp.json()["id"]

        # Lead attempts to self-approve -> must be 422 validation_error
        self_approve_resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk-exceptions/{exc2_id}/review",
            json={"approved": True, "review_notes": "Trying to self approve"},
            headers=lead_headers,
        )
        assert self_approve_resp.status_code == 422, self_approve_resp.text
        assert "Self-approval forbidden" in self_approve_resp.json()["detail"]

        # Peer Org Admin approves it -> succeeds
        admin_approve_resp = await client.post(
            f"/api/v1/organizations/{org_id}/risk-exceptions/{exc2_id}/review",
            json={"approved": True, "review_notes": "Approved by peer administrator"},
            headers=admin_headers,
        )
        assert admin_approve_resp.status_code == 200

        # 6. Verify sweep of expired risk exceptions resets finding status to open
        async with session_factory() as sess, sess.begin():
            await set_db_context(sess, org_id=org_id, user_id=lead_id)
            from vforge.models.scanner import RiskException

            exc_row = (
                await sess.execute(
                    select(RiskException).where(RiskException.id == uuid.UUID(exc2_id))
                )
            ).scalar_one()
            exc_row.expires_at = datetime.now(UTC) - timedelta(days=1)
            await sess.flush()

        rate_limiter.reset()
        eval_resp = await client.post(
            f"/api/v1/organizations/{org_id}/findings/evaluate-sla",
            headers=lead_headers,
        )
        assert eval_resp.status_code == 200

        # Verify finding 2 was automatically reopened with retest_status/event logged
        f2_resp = await client.get(
            f"/api/v1/organizations/{org_id}/findings/{finding_id_2}",
            headers=lead_headers,
        )
        assert f2_resp.status_code == 200
        f2_data = f2_resp.json()
        assert f2_data["status"] == "open"
        assert f2_data["validation_status"] == "reopened"


@pytest.mark.anyio
async def test_multi_format_report_generation_and_encrypted_download(
    ph8_env: dict[str, Any],
) -> None:
    """Verify HTML, PDF, JSON, and SARIF report generation, artifact encryption, and download."""
    session_factory: async_sessionmaker[AsyncSession] = ph8_env["session_factory"]
    org_id = uuid.uuid4()
    lead_id = uuid.uuid4()
    admin_id = uuid.uuid4()
    dev_id = uuid.uuid4()
    auditor_id = uuid.uuid4()
    viewer_id = uuid.uuid4()
    project_id = uuid.uuid4()
    finding_id = uuid.uuid4()

    async with session_factory() as sess, sess.begin():
        await set_db_context(sess, org_id=org_id, user_id=lead_id)
        await _seed_test_org(
            sess,
            issuer=ph8_env["issuer"],
            org_id=org_id,
            lead_id=lead_id,
            dev_id=dev_id,
            auditor_id=auditor_id,
            viewer_id=viewer_id,
            project_id=project_id,
            admin_id=admin_id,
        )
        finding = Finding(
            id=finding_id,
            organization_id=org_id,
            project_id=project_id,
            fingerprint="fp-rep-" + uuid.uuid4().hex,
            category=FindingCategory.DAST.value,
            scanner_tool_id="zap",
            scanner_version="2.16.0",
            rule_id="10020",
            title="Missing Anti-Clickjacking Header (X-Frame-Options)",
            description="The response does not include an X-Frame-Options header.",
            severity=FindingSeverity.MEDIUM.value,
            confidence="high",
            validation_status="unverified",
            status="open",
            business_priority="medium",
            cwe_ids=["CWE-1021"],
            remediation=(
                "Add X-Frame-Options: DENY or use Content-Security-Policy frame-ancestors 'none'."
            ),
            occurrence_count=1,
        )
        sess.add(finding)

    transport = ASGITransport(app=app)
    lead_headers = _build_auth_headers(
        ph8_env,
        f"lead-{lead_id.hex[:6]}",
        f"lead-{lead_id.hex[:6]}@test.internal",
    )
    viewer_headers = _build_auth_headers(
        ph8_env,
        f"viewer-{viewer_id.hex[:6]}",
        f"viewer-{viewer_id.hex[:6]}@test.internal",
    )

    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test all 4 formats: html, pdf, json, sarif
        for fmt, expected_mime, check_fn in (
            ("html", "text/html", lambda b: b"<html" in b and b"Missing Anti-Clickjacking" in b),
            ("pdf", "application/pdf", lambda b: b.startswith(b"%PDF-1.4")),
            ("json", "application/json", lambda b: json.loads(b)["summary"]["total_findings"] >= 1),
            ("sarif", "application/sarif+json", lambda b: json.loads(b)["version"] == "2.1.0"),
        ):
            gen_resp = await client.post(
                f"/api/v1/organizations/{org_id}/reports",
                json={
                    "project_id": str(project_id),
                    "report_type": "technical_vapt",
                    "format": fmt,
                    "title": f"Test {fmt.upper()} Assessment Report",
                },
                headers=lead_headers,
            )
            assert gen_resp.status_code == 201, f"{fmt} failed: {gen_resp.text}"
            rep_data = gen_resp.json()
            assert rep_data["format"] == fmt
            assert rep_data["summary"]["total_findings"] >= 1
            report_id = rep_data["id"]

            # Download and verify decryption and content
            dl_resp = await client.get(
                f"/api/v1/organizations/{org_id}/reports/{report_id}/download",
                headers=viewer_headers,  # Viewer can read/download reports
            )
            assert dl_resp.status_code == 200, f"{fmt} download failed"
            assert dl_resp.headers["content-type"].startswith(expected_mime)
            assert check_fn(dl_resp.content) is True

        # Viewer trying to GENERATE a report should be 403 Forbidden
        view_gen_resp = await client.post(
            f"/api/v1/organizations/{org_id}/reports",
            json={
                "project_id": str(project_id),
                "report_type": "executive",
                "format": "html",
            },
            headers=viewer_headers,
        )
        assert view_gen_resp.status_code == 403

        # Viewer trying to trigger SLA evaluation/mutation should be 403 Forbidden (VF-AUDIT-007)
        view_sla_resp = await client.post(
            f"/api/v1/organizations/{org_id}/findings/evaluate-sla",
            headers=viewer_headers,
        )
        assert view_sla_resp.status_code == 403

        # Admin trying to hard-delete a project that has immutable artifacts/reports
        # must receive 409 Conflict rather than a 500 trigger error (VF-AUDIT-008)
        admin_headers = _build_auth_headers(
            ph8_env,
            f"admin-{admin_id.hex[:6]}",
            f"admin-{admin_id.hex[:6]}@test.internal",
        )
        del_proj_resp = await client.delete(
            f"/api/v1/organizations/{org_id}/projects/{project_id}",
            headers=admin_headers,
        )
        assert del_proj_resp.status_code == 409
