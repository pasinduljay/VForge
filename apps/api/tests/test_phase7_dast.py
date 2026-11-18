"""Phase 7 tests: DAST (ZAP, Nuclei, Nmap, testssl), Target Leases, Health Tripwire & RLS."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
import pytest_asyncio
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from vforge_scope import StaticDnsResolver
from httpx import ASGITransport, AsyncClient
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.main import app
from vforge.models.enums import ScanRunStatus, TargetLeaseStatus
from vforge.models.orchestration import OutboxEvent
from vforge.orchestration.service import process_dispatch_message
from vforge.runner_gateway import create_runner_gateway_app
from vforge.security.mtls import generate_runner_ca, issue_signed_runner_cert
from vforge.security.signing import generate_ed25519_keypair_pem


def _make_rsa_key(kid: str = "ph7-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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
    kid: str = "ph7-oidc-key-1",
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
    query = parse_qs(urlsplit(start_resp.json()["authorization_url"]).query)
    state = query["state"][0]
    nonce = query["nonce"][0]

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
            params={"code": f"code-{subject}", "state": state},
            follow_redirects=False,
        )
    finally:
        oidc_client.exchange_code_for_tokens = orig_exchange  # type: ignore[method-assign]

    assert cb.status_code == 302
    me = await client.get("/api/v1/auth/me")
    assert me.status_code == 200
    return str(me.json()["csrf_token"])


@pytest_asyncio.fixture
async def ph7_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph7.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()
    ed_priv, ed_pub = generate_ed25519_keypair_pem()
    merged_keyring: dict[str, Any] = {}
    if base_settings.scope_signing_public_keys_json.strip():
        merged_keyring.update(json.loads(base_settings.scope_signing_public_keys_json))
    merged_keyring["vf-ph7-key"] = {"public_key_pem": ed_pub, "status": "active"}
    keyring_json = json.dumps(merged_keyring)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    kek_b64 = base64.urlsafe_b64encode(b"phase7-test-kek-32-bytes-exact!!").decode("ascii")

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
        scope_signing_key_id="vf-ph7-key",
        scope_signing_private_key_pem=ed_priv,
        scope_signing_public_keys_json=keyring_json,
        require_live_dns_on_approval=False,
        artifact_root=str(artifact_dir),
        artifact_encryption_key_b64=kek_b64,
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.dns_resolver = StaticDnsResolver({"target.ph7.test": ["93.184.216.34"]})
    app.dependency_overrides[get_settings] = lambda: test_settings

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

    yield {
        "settings": test_settings,
        "engine": engine,
        "session_factory": session_factory,
        "priv": priv,
        "issuer": issuer,
        "client_id": client_id,
    }

    app.dependency_overrides.clear()
    app.state.dns_resolver = None
    app.state.snapshot_signer = None
    app.state.opa_client = None
    oidc_client.reset_caches()
    await engine.dispose()


@pytest.mark.asyncio
async def test_phase7_dast_leases_health_monitor_and_rls(
    ph7_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise ZAP/Nuclei DAST, target leases, safety tripwire, secret resolution, and RLS."""
    monkeypatch.setenv("TEST_DAST_BEARER_TOKEN", "super-secret-bearer-token-12345")
    cfg: Settings = ph7_env["settings"]
    session_factory = ph7_env["session_factory"]
    ca_cert_pem, ca_key_pem = generate_runner_ca()

    gateway_app = create_runner_gateway_app(with_lifespan=False)
    gateway_app.state.engine = ph7_env["engine"]
    gateway_app.state.session_factory = session_factory
    gateway_app.dependency_overrides[get_settings] = lambda: cfg

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://api.test") as owner_client,
        AsyncClient(transport=transport, base_url="http://api.test") as lead_client,
        AsyncClient(transport=transport, base_url="http://api.test") as other_client,
    ):
        owner_csrf = await _login_user(
            owner_client,
            priv=ph7_env["priv"],
            issuer=ph7_env["issuer"],
            audience=ph7_env["client_id"],
            subject="ph7-owner",
            email="owner@ph7.test",
            name="Phase 7 Owner",
        )
        lead_csrf = await _login_user(
            lead_client,
            priv=ph7_env["priv"],
            issuer=ph7_env["issuer"],
            audience=ph7_env["client_id"],
            subject="ph7-lead",
            email="lead@ph7.test",
            name="Phase 7 Lead",
        )
        other_csrf = await _login_user(
            other_client,
            priv=ph7_env["priv"],
            issuer=ph7_env["issuer"],
            audience=ph7_env["client_id"],
            subject="ph7-other",
            email="other@ph7.test",
            name="Phase 7 Other Org",
        )

        org_slug = f"ph7-org-{uuid.uuid4().hex[:6]}"
        create_org = await owner_client.post(
            "/api/v1/organizations",
            headers={"X-CSRF-Token": owner_csrf},
            json={"name": "Phase 7 DAST Org", "slug": org_slug},
        )
        assert create_org.status_code == 201, create_org.text
        org_id = create_org.json()["id"]

        await owner_client.post(
            f"/api/v1/organizations/{org_id}/memberships",
            json={
                "oidc_issuer": ph7_env["issuer"],
                "oidc_subject": "ph7-lead",
                "email": "lead@ph7.test",
                "display_name": "Phase 7 Lead",
                "role": "security_lead",
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        await lead_client.post(
            "/api/v1/auth/switch-organization",
            json={"organization_id": org_id},
            headers={"X-CSRF-Token": lead_csrf},
        )
        lead_csrf = (await lead_client.get("/api/v1/auth/me")).json()["csrf_token"]

        other_org_slug = f"ph7-other-{uuid.uuid4().hex[:6]}"
        create_other_org = await other_client.post(
            "/api/v1/organizations",
            headers={"X-CSRF-Token": other_csrf},
            json={"name": "Phase 7 Other Org", "slug": other_org_slug},
        )
        assert create_other_org.status_code == 201
        other_org_id = create_other_org.json()["id"]

        # Create Project & Environment
        proj_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/projects",
            headers={"X-CSRF-Token": owner_csrf},
            json={"name": "DAST Target Project", "slug": "dast-proj"},
        )
        assert proj_resp.status_code == 201
        project_id = proj_resp.json()["id"]

        env_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/projects/{project_id}/environments",
            headers={"X-CSRF-Token": owner_csrf},
            json={"name": "Staging", "environment_type": "staging"},
        )
        assert env_resp.status_code == 201, env_resp.text
        env_id = env_resp.json()["id"]

        # Create AuthProfile with secret manager ref pointing to env var
        auth_prof_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/environments/{env_id}/auth-profiles",
            headers={"X-CSRF-Token": owner_csrf},
            json={
                "name": "Staging API Token",
                "auth_type": "bearer_token_ref",
                "secret_manager_ref": "env-ref://TEST_DAST_BEARER_TOKEN",
            },
        )
        assert auth_prof_resp.status_code == 201, auth_prof_resp.text
        auth_profile_id = auth_prof_resp.json()["id"]
        # Ensure secret value is NOT in API response
        assert "super-secret" not in json.dumps(auth_prof_resp.json())

        # Create Asset, Authorization & Scope Snapshot
        asset_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/environments/{env_id}/assets",
            headers={"X-CSRF-Token": owner_csrf},
            json={
                "asset_type": "web_application",
                "locator": "https://target.ph7.test/api",
            },
        )
        assert asset_resp.status_code == 201, asset_resp.text
        asset_id = asset_resp.json()["id"]

        now = datetime.now(UTC)
        auth_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/authorizations",
            headers={"X-CSRF-Token": owner_csrf},
            json={
                "asset_id": asset_id,
                "approved_testing_scope": {
                    "target_type": "web_application",
                    "target": "https://target.ph7.test/api",
                },
                "approved_activities": [
                    "passive_dast",
                    "active_dast",
                    "network_discovery",
                    "tls_assessment",
                ],
                "permitted_intensity": "medium",
                "authorization_reference": "AUTH-PH7-DAST",
                "valid_from": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(days=2)).isoformat(),
            },
        )
        assert auth_resp.status_code == 201, auth_resp.text
        auth_id = auth_resp.json()["id"]

        # Approve authorization via lead_client (dual-control / separation of duties)
        appr_resp = await lead_client.post(
            f"/api/v1/organizations/{org_id}/authorizations/{auth_id}/approve",
            headers={"X-CSRF-Token": lead_csrf},
            json={"reason": "Authorized for Phase 7 testing"},
        )
        assert appr_resp.status_code == 200, appr_resp.text

        # Fetch signed Scope Snapshot generated upon approval
        snap_resp = await lead_client.get(
            f"/api/v1/organizations/{org_id}/snapshots",
            params={"authorization_id": auth_id},
        )
        assert snap_resp.status_code == 200, snap_resp.text
        snapshot_id = snap_resp.json()["items"][0]["id"]

        # Create Runner Pool & Runner with mTLS Cert
        pool_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/runner-pools",
            headers={"X-CSRF-Token": owner_csrf},
            json={"name": "DAST Pool", "slug": "dast-pool", "pool_type": "dast_egress"},
        )
        assert pool_resp.status_code == 201
        pool_id = pool_resp.json()["id"]

        runner_id = uuid.uuid4()
        runner_cert_pem, _, _ = issue_signed_runner_cert(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            organization_id=uuid.UUID(org_id),
            runner_id=runner_id,
        )
        reg_runner = await owner_client.post(
            f"/api/v1/organizations/{org_id}/runners",
            headers={"X-CSRF-Token": owner_csrf},
            json={
                "pool_id": pool_id,
                "name": "dast-runner-1",
                "certificate_pem": runner_cert_pem,
                "version": "0.1.0",
                "capabilities": {"scanners": ["zap", "nuclei", "nmap", "testssl"]},
            },
        )
        assert reg_runner.status_code == 201, reg_runner.text

        parsed_cert = x509.load_pem_x509_certificate(runner_cert_pem.encode("utf-8"))
        runner_cert_der = parsed_cert.public_bytes(serialization.Encoding.DER)

        async def _mtls_wrapped_gateway(scope: Any, receive: Any, send: Any) -> None:
            scope.setdefault("extensions", {})["vforge.mtls_peer_der"] = runner_cert_der
            await gateway_app(scope, receive, send)

        gw_transport = ASGITransport(app=_mtls_wrapped_gateway)

        # Create DAST Scan Profile with ZAP and Nuclei
        prof_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/scan-profiles",
            headers={"X-CSRF-Token": owner_csrf},
            json={
                "name": "DAST Full Assessment",
                "configuration": {
                    "stages": ["passive_dast", "active_dast"],
                    "passive_only": False,
                    "max_concurrency": 2,
                    "request_rate_limit_rps": 5,
                    "timeout_seconds": 600,
                    "include_paths": ["/api/.*"],
                    "exclude_paths": [],
                    "auth_profile_id": auth_profile_id,
                    "max_rps": 5,
                },
            },
        )
        assert prof_resp.status_code == 201
        scan_profile_id = prof_resp.json()["id"]

        # Launch DAST Scan Run in runner mode
        scan_create = await owner_client.post(
            f"/api/v1/organizations/{org_id}/scans",
            headers={
                "X-CSRF-Token": owner_csrf,
                "Idempotency-Key": f"scan-{uuid.uuid4().hex[:8]}",
            },
            json={
                "project_id": project_id,
                "environment_id": env_id,
                "scan_profile_id": scan_profile_id,
                "authorization_id": auth_id,
                "scope_snapshot_id": snapshot_id,
                "auth_profile_id": auth_profile_id,
                "execution_mode": "runner",
                "target_pool_id": pool_id,
                "revalidate_dns": False,
            },
        )
        assert scan_create.status_code == 201, scan_create.text
        scan_data = scan_create.json()
        scan_id = scan_data["id"]
        assert scan_data["auth_profile_id"] == auth_profile_id

        # Dispatch next job via outbox
        async with session_factory() as s:
            await set_db_context(s, org_id=uuid.UUID(org_id), user_id=uuid.uuid4())
            outbox_rows = (
                (
                    await s.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.scan_run_id == uuid.UUID(scan_id),
                            OutboxEvent.status == "pending",
                        )
                    )
                )
                .scalars()
                .all()
            )
            payloads = [row.payload for row in outbox_rows]
        for p in payloads:
            await process_dispatch_message(
                session_factory,
                p,
                worker_id="ph7-worker",
                settings=cfg,
            )

        # Runner claims job via mTLS
        async with AsyncClient(
            transport=gw_transport,
            base_url="https://gateway.test",
        ) as gw_client:
            claim_resp = await gw_client.post(
                "/api/v1/runner/jobs/claim",
                json={"pool_id": pool_id, "runner_version": "0.1.0"},
            )
            assert claim_resp.status_code == 200, claim_resp.text
            claim_data = claim_resp.json()
            assert claim_data["claimed"] is True
            job_id = claim_data["job_id"]
            exec_id = claim_data["execution_id"]
            attempt = claim_data["attempt_number"]

            # 1. Resolve Target Auth via Runner Gateway
            auth_fetch = await gw_client.get(
                f"/api/v1/runner/jobs/{job_id}/target-auth",
            )
            assert auth_fetch.status_code == 200, auth_fetch.text
            assert auth_fetch.headers.get("Cache-Control") == "no-store, no-cache, must-revalidate"
            auth_details = auth_fetch.json()
            assert auth_details["auth_type"] == "bearer_token_ref"
            assert auth_details["credentials"]["secret_value"] == "super-secret-bearer-token-12345"

            # 2. Record Target Health Probes
            probe_post = await gw_client.post(
                f"/api/v1/runner/jobs/{job_id}/health-probes",
                json={
                    "probe_type": "baseline",
                    "target_url": "https://target.ph7.test/api",
                    "status_code": 200,
                    "latency_ms": 35,
                    "healthy": True,
                },
            )
            assert probe_post.status_code == 201, probe_post.text
            probe_data = probe_post.json()
            assert probe_data["healthy"] is True
            assert probe_data["probe_type"] == "baseline"

            # 3. Simulate Tripwire Abort
            tripwire_post = await gw_client.post(
                f"/api/v1/runner/jobs/{job_id}/health-probes",
                json={
                    "probe_type": "tripwire",
                    "target_url": "https://target.ph7.test/api",
                    "status_code": 503,
                    "latency_ms": 1200,
                    "healthy": False,
                    "error_message": "Consecutive 5xx server errors (5) exceeded safety threshold",
                },
            )
            assert tripwire_post.status_code == 201

            # Runner completes job as failed due to tripwire
            complete_resp = await gw_client.post(
                f"/api/v1/runner/jobs/{job_id}/complete",
                json={
                    "execution_id": exec_id,
                    "attempt_number": attempt,
                    "status": "failed",
                    "error_code": "target_health_tripwire_aborted",
                    "error_message": "Target health safety tripwire breached during active scan",
                    "metrics": {"output_truncated": False},
                },
            )
            assert complete_resp.status_code == 200

        # Verify Scan Run is marked FAILED (never clean pass!)
        scan_detail_resp = await owner_client.get(f"/api/v1/organizations/{org_id}/scans/{scan_id}")
        assert scan_detail_resp.status_code == 200
        scan_detail = scan_detail_resp.json()
        assert scan_detail["status"] == ScanRunStatus.FAILED.value
        assert "Target health safety tripwire breached" in (scan_detail["error_summary"] or "")

        # Verify Target Leases are cleanly released
        leases_resp = await owner_client.get(f"/api/v1/organizations/{org_id}/leases")
        assert leases_resp.status_code == 200
        leases_data = leases_resp.json()
        for lease in leases_data:
            assert lease["status"] in {
                TargetLeaseStatus.RELEASED.value,
                TargetLeaseStatus.EXPIRED.value,
            }

        # Verify Health Probes are readable via API
        probes_api = await owner_client.get(
            f"/api/v1/organizations/{org_id}/scans/{scan_id}/health-probes"
        )
        assert probes_api.status_code == 200
        probes_list = probes_api.json()
        assert len(probes_list) == 2
        p_types = [p["probe_type"] for p in probes_list]
        assert "baseline" in p_types
        assert "tripwire" in p_types

        # Cross-Tenant RLS isolation: other organization cannot read probes or scans
        other_probe_get = await other_client.get(
            f"/api/v1/organizations/{other_org_id}/scans/{scan_id}/health-probes"
        )
        assert other_probe_get.status_code == 200
        assert len(other_probe_get.json()) == 0

        other_scan_get = await other_client.get(
            f"/api/v1/organizations/{other_org_id}/scans/{scan_id}"
        )
        assert other_scan_get.status_code == 404


@pytest.mark.asyncio
async def test_phase7_dast_findings_e2e_normalization(ph7_env: dict[str, Any]) -> None:
    """Verify runner completing jobs with DAST & Network artifacts persists normalized findings."""
    cfg: Settings = ph7_env["settings"]
    session_factory = ph7_env["session_factory"]
    ca_cert_pem, ca_key_pem = generate_runner_ca()

    gateway_app = create_runner_gateway_app(with_lifespan=False)
    gateway_app.state.engine = ph7_env["engine"]
    gateway_app.state.session_factory = session_factory
    gateway_app.dependency_overrides[get_settings] = lambda: cfg

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://api.test") as client,
        AsyncClient(transport=transport, base_url="http://api.test") as lead_client,
    ):
        csrf = await _login_user(
            client,
            priv=ph7_env["priv"],
            issuer=ph7_env["issuer"],
            audience=ph7_env["client_id"],
            subject="ph7-norm-owner",
            email="norm@ph7.test",
            name="Norm Owner",
        )
        lead_csrf = await _login_user(
            lead_client,
            priv=ph7_env["priv"],
            issuer=ph7_env["issuer"],
            audience=ph7_env["client_id"],
            subject="ph7-norm-lead",
            email="norm-lead@ph7.test",
            name="Norm Lead",
        )
        org_resp = await client.post(
            "/api/v1/organizations",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Norm Org", "slug": f"norm-{uuid.uuid4().hex[:6]}"},
        )
        org_id = org_resp.json()["id"]

        await client.post(
            f"/api/v1/organizations/{org_id}/memberships",
            json={
                "oidc_issuer": ph7_env["issuer"],
                "oidc_subject": "ph7-norm-lead",
                "email": "norm-lead@ph7.test",
                "display_name": "Norm Lead",
                "role": "security_lead",
            },
            headers={"X-CSRF-Token": csrf},
        )
        await lead_client.post(
            "/api/v1/auth/switch-organization",
            json={"organization_id": org_id},
            headers={"X-CSRF-Token": lead_csrf},
        )
        lead_csrf = (await lead_client.get("/api/v1/auth/me")).json()["csrf_token"]

        proj_resp = await client.post(
            f"/api/v1/organizations/{org_id}/projects",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Norm Proj", "slug": "norm-proj"},
        )
        project_id = proj_resp.json()["id"]

        env_resp = await client.post(
            f"/api/v1/organizations/{org_id}/projects/{project_id}/environments",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Staging", "environment_type": "staging"},
        )
        env_id = env_resp.json()["id"]

        asset_resp = await client.post(
            f"/api/v1/organizations/{org_id}/environments/{env_id}/assets",
            headers={"X-CSRF-Token": csrf},
            json={
                "asset_type": "web_application",
                "locator": "https://target.ph7.test/api",
            },
        )
        assert asset_resp.status_code == 201, asset_resp.text
        asset_id = asset_resp.json()["id"]

        now = datetime.now(UTC)
        auth_resp = await client.post(
            f"/api/v1/organizations/{org_id}/authorizations",
            headers={"X-CSRF-Token": csrf},
            json={
                "asset_id": asset_id,
                "approved_testing_scope": {
                    "target_type": "web_application",
                    "target": "https://target.ph7.test/api",
                },
                "approved_activities": [
                    "passive_dast",
                    "active_dast",
                    "network_discovery",
                    "tls_assessment",
                ],
                "permitted_intensity": "medium",
                "authorization_reference": "AUTH-NORM",
                "valid_from": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(days=2)).isoformat(),
            },
        )
        assert auth_resp.status_code == 201, auth_resp.text
        auth_id = auth_resp.json()["id"]

        appr_resp = await lead_client.post(
            f"/api/v1/organizations/{org_id}/authorizations/{auth_id}/approve",
            headers={"X-CSRF-Token": lead_csrf},
            json={"reason": "OK"},
        )
        assert appr_resp.status_code == 200, appr_resp.text

        snap_resp = await lead_client.get(
            f"/api/v1/organizations/{org_id}/snapshots",
            params={"authorization_id": auth_id},
        )
        assert snap_resp.status_code == 200, snap_resp.text
        snapshot_id = snap_resp.json()["items"][0]["id"]

        pool_resp = await client.post(
            f"/api/v1/organizations/{org_id}/runner-pools",
            headers={"X-CSRF-Token": csrf},
            json={"name": "Norm Pool", "slug": "norm-pool", "pool_type": "dast_egress"},
        )
        pool_id = pool_resp.json()["id"]

        runner_id = uuid.uuid4()
        runner_cert_pem, _, _ = issue_signed_runner_cert(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            organization_id=uuid.UUID(org_id),
            runner_id=runner_id,
        )
        reg_runner = await client.post(
            f"/api/v1/organizations/{org_id}/runners",
            headers={"X-CSRF-Token": csrf},
            json={
                "pool_id": pool_id,
                "name": "norm-runner",
                "certificate_pem": runner_cert_pem,
                "version": "0.1.0",
                "capabilities": {"scanners": ["zap", "nuclei", "nmap", "testssl"]},
            },
        )
        assert reg_runner.status_code == 201, reg_runner.text

        parsed_cert = x509.load_pem_x509_certificate(runner_cert_pem.encode("utf-8"))
        runner_cert_der = parsed_cert.public_bytes(serialization.Encoding.DER)

        async def _mtls_wrapped_gateway_norm(scope: Any, receive: Any, send: Any) -> None:
            scope.setdefault("extensions", {})["vforge.mtls_peer_der"] = runner_cert_der
            await gateway_app(scope, receive, send)

        gw_transport = ASGITransport(app=_mtls_wrapped_gateway_norm)

        prof_resp = await client.post(
            f"/api/v1/organizations/{org_id}/scan-profiles",
            headers={"X-CSRF-Token": csrf},
            json={
                "name": "Passive DAST Profile",
                "configuration": {
                    "stages": ["passive_dast"],
                    "passive_only": True,
                    "max_concurrency": 1,
                    "request_rate_limit_rps": 2,
                    "timeout_seconds": 300,
                    "include_paths": [],
                    "exclude_paths": [],
                },
            },
        )
        scan_profile_id = prof_resp.json()["id"]

        scan_create = await client.post(
            f"/api/v1/organizations/{org_id}/scans",
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": f"scan-{uuid.uuid4().hex[:8]}"},
            json={
                "project_id": project_id,
                "environment_id": env_id,
                "scan_profile_id": scan_profile_id,
                "authorization_id": auth_id,
                "scope_snapshot_id": snapshot_id,
                "execution_mode": "runner",
                "target_pool_id": pool_id,
                "revalidate_dns": False,
            },
        )
        assert scan_create.status_code == 201
        scan_id = scan_create.json()["id"]

        async with session_factory() as s:
            await set_db_context(s, org_id=uuid.UUID(org_id), user_id=uuid.uuid4())
            outbox_rows = (
                (
                    await s.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.scan_run_id == uuid.UUID(scan_id),
                            OutboxEvent.status == "pending",
                        )
                    )
                )
                .scalars()
                .all()
            )
            payloads = [row.payload for row in outbox_rows]
        for p in payloads:
            await process_dispatch_message(
                session_factory,
                p,
                worker_id="ph7-norm-worker",
                settings=cfg,
            )

        # 1. Runner claims and completes the preflight job
        async with AsyncClient(
            transport=gw_transport,
            base_url="https://gateway.test",
        ) as gw_client:
            claim_resp = await gw_client.post(
                "/api/v1/runner/jobs/claim",
                json={"pool_id": pool_id, "runner_version": "0.1.0"},
            )
            assert claim_resp.status_code == 200, claim_resp.text
            claim_data = claim_resp.json()
            assert claim_data["claimed"] is True
            preflight_job_id = claim_data["job_id"]
            preflight_exec_id = claim_data["execution_id"]
            preflight_attempt = claim_data["attempt_number"]

            comp_preflight = await gw_client.post(
                f"/api/v1/runner/jobs/{preflight_job_id}/complete",
                json={
                    "execution_id": preflight_exec_id,
                    "attempt_number": preflight_attempt,
                    "status": "completed",
                    "metrics": {},
                },
            )
            assert comp_preflight.status_code == 200, comp_preflight.text

        # 2. Dispatch the next stage (passive_dast -> ZAP) via outbox
        async with session_factory() as s:
            await set_db_context(s, org_id=uuid.UUID(org_id), user_id=uuid.uuid4())
            outbox_rows = (
                (
                    await s.execute(
                        select(OutboxEvent).where(
                            OutboxEvent.scan_run_id == uuid.UUID(scan_id),
                            OutboxEvent.status == "pending",
                        )
                    )
                )
                .scalars()
                .all()
            )
            payloads = [row.payload for row in outbox_rows]
        for p in payloads:
            await process_dispatch_message(
                session_factory,
                p,
                worker_id="ph7-norm-worker",
                settings=cfg,
            )

        # 3. Runner claims the ZAP job, uploads report, and completes
        async with AsyncClient(
            transport=gw_transport,
            base_url="https://gateway.test",
        ) as gw_client:
            claim_resp = await gw_client.post(
                "/api/v1/runner/jobs/claim",
                json={"pool_id": pool_id, "runner_version": "0.1.0"},
            )
            assert claim_resp.status_code == 200, claim_resp.text
            claim_data = claim_resp.json()
            assert claim_data["claimed"] is True
            job_id = claim_data["job_id"]
            exec_id = claim_data["execution_id"]
            attempt = claim_data["attempt_number"]

            zap_sample = {
                "site": [
                    {
                        "@name": "https://target.ph7.test",
                        "alerts": [
                            {
                                "pluginid": "10038",
                                "alert": "Content Security Policy (CSP) Header Not Set",
                                "riskcode": "2",
                                "confidence": "3",
                                "desc": "CSP header is not set.",
                                "solution": "Add Content-Security-Policy header.",
                                "cweid": "693",
                                "instances": [
                                    {"uri": "https://target.ph7.test/login", "method": "GET"}
                                ],
                            }
                        ],
                    }
                ]
            }
            zap_bytes = json.dumps(zap_sample).encode("utf-8")
            art_resp = await gw_client.post(
                f"/api/v1/runner/jobs/{job_id}/artifacts",
                json={
                    "execution_id": exec_id,
                    "attempt_number": attempt,
                    "artifact_type": "raw_output",
                    "content_type": "application/json",
                    "sha256": hashlib.sha256(zap_bytes).hexdigest(),
                    "content_b64": base64.b64encode(zap_bytes).decode("ascii"),
                },
            )
            assert art_resp.status_code == 201, art_resp.text

            comp_resp = await gw_client.post(
                f"/api/v1/runner/jobs/{job_id}/complete",
                json={
                    "execution_id": exec_id,
                    "attempt_number": attempt,
                    "status": "completed",
                    "metrics": {"artifacts_uploaded": 1},
                },
            )
            assert comp_resp.status_code == 200, comp_resp.text

        # Verify findings persisted and queryable via Findings API
        findings_resp = await client.get(
            f"/api/v1/organizations/{org_id}/findings?scan_run_id={scan_id}"
        )
        assert findings_resp.status_code == 200
        findings_items = findings_resp.json()["items"]
        assert len(findings_items) == 1
        f = findings_items[0]
        assert f["category"] == "dast"
        assert f["scanner_tool_id"] == "zap"
        assert f["severity"] == "medium"
        assert "CSP" in f["title"]
