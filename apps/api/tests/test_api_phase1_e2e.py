"""End-to-end API, OIDC PKCE, CSRF, session expiry, RBAC, and tenant-isolation tests."""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from httpx import ASGITransport, AsyncClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import text

from vforge.auth.oidc import oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory
from vforge.main import app


def _make_rsa_key(kid: str = "e2e-key-1") -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_jwk = json.loads(RSAAlgorithm.to_jwk(priv.public_key()))
    pub_jwk["kid"] = kid
    pub_jwk["use"] = "sig"
    pub_jwk["alg"] = "RS256"
    return priv, pub_jwk


def _sign_token(
    priv: Any,
    *,
    issuer: str,
    audience: str,
    subject: str,
    email: str,
    name: str,
    nonce: str | None = None,
    kid: str = "e2e-key-1",
) -> str:
    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "email": email,
        "name": name,
        "email_verified": True,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=15)).timestamp()),
    }
    if nonce is not None:
        claims["nonce"] = nonce
    return jwt.encode(claims, priv, algorithm="RS256", headers={"kid": kid})


@pytest.fixture
async def e2e_env() -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.e2e.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()

    test_settings = Settings(
        vforge_env="test",
        database_url=base_settings.effective_database_url,
        cache_url="",  # Use deterministic in-memory rate limit in tests
        opa_url=base_settings.opa_url,
        oidc_enabled=True,
        oidc_issuer=issuer,
        oidc_client_id=client_id,
        oidc_redirect_uri="http://127.0.0.1:3000/api/v1/auth/oidc/callback",
        session_ttl_seconds=3600,
        session_idle_timeout_seconds=1800,
        auth_rate_limit_per_minute=200,
        sensitive_rate_limit_per_minute=500,
    )

    engine = build_engine(test_settings.effective_database_url)
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.dependency_overrides[get_settings] = lambda: test_settings

    # Prime OIDC client caches cleanly for test issuer without network calls
    oidc_client.reset_caches()
    from jwt import PyJWK

    from vforge.auth.oidc import OidcDiscoveryMetadata

    oidc_client._metadata = OidcDiscoveryMetadata(
        issuer=issuer,
        authorization_endpoint=f"{issuer}/protocol/openid-connect/auth",
        token_endpoint=f"{issuer}/protocol/openid-connect/token",
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
    )
    oidc_client._metadata_fetched_at = 10**12
    oidc_client._jwks_keys = {"e2e-key-1": PyJWK.from_dict(pub_jwk)}
    oidc_client._jwks_list = [PyJWK.from_dict(pub_jwk)]
    oidc_client._jwks_fetched_at = 10**12

    yield {
        "settings": test_settings,
        "issuer": issuer,
        "client_id": client_id,
        "priv": priv,
        "engine": engine,
    }

    app.dependency_overrides.clear()
    oidc_client.reset_caches()
    await engine.dispose()


async def test_unauthenticated_requests_rejected(e2e_env: dict[str, Any]) -> None:
    _ = e2e_env
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        assert (await client.get("/api/v1/auth/me")).status_code == 401
        assert (await client.get("/api/v1/organizations")).status_code == 401
        assert (
            await client.post(
                "/api/v1/organizations",
                json={"name": "Anon Org", "slug": "anon-org"},
            )
        ).status_code == 401


async def test_oidc_pkce_cookie_csrf_logout_and_session_expiry(
    e2e_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer: str = e2e_env["issuer"]
    client_id: str = e2e_env["client_id"]
    priv = e2e_env["priv"]
    engine = e2e_env["engine"]
    sub = f"pkce-user-{uuid.uuid4().hex[:8]}"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://127.0.0.1:3000",
        follow_redirects=False,
    ) as client:
        login_resp = await client.get("/api/v1/auth/oidc/login?redirect_path=/organizations")
        assert login_resp.status_code == 302
        auth_url = urlsplit(login_resp.headers["location"])
        qs = parse_qs(auth_url.query)
        assert qs["code_challenge_method"] == ["S256"]
        state = qs["state"][0]
        nonce = qs["nonce"][0]

        id_token = _sign_token(
            priv,
            issuer=issuer,
            audience=client_id,
            subject=sub,
            email=f"{sub}@example.test",
            name="PKCE User",
            nonce=nonce,
        )

        async def fake_exchange(**_kwargs: Any) -> dict[str, Any]:
            return {"id_token": id_token, "access_token": id_token}

        monkeypatch.setattr(oidc_client, "exchange_code_for_tokens", fake_exchange)

        cb_resp = await client.get(f"/api/v1/auth/oidc/callback?code=authcode-1&state={state}")
        assert cb_resp.status_code == 302
        assert "vf_session" in cb_resp.cookies
        assert "vf_csrf" in cb_resp.cookies

        # Replay of same OIDC state must fail
        replay_resp = await client.get(f"/api/v1/auth/oidc/callback?code=authcode-1&state={state}")
        assert replay_resp.status_code == 401

        me_resp = await client.get("/api/v1/auth/me")
        assert me_resp.status_code == 200
        csrf_token = me_resp.json()["csrf_token"]
        assert csrf_token

        # Cookie POST without CSRF token must be rejected 403
        no_csrf = await client.post(
            "/api/v1/organizations",
            json={"name": "No CSRF Org", "slug": f"no-csrf-{uuid.uuid4().hex[:6]}"},
        )
        assert no_csrf.status_code == 403

        # Cookie POST with wrong CSRF token must be rejected 403
        bad_csrf = await client.post(
            "/api/v1/organizations",
            headers={"X-CSRF-Token": "wrong-csrf"},
            json={"name": "Bad CSRF Org", "slug": f"bad-csrf-{uuid.uuid4().hex[:6]}"},
        )
        assert bad_csrf.status_code == 403

        # Cookie POST with valid CSRF token succeeds
        slug = f"pkce-org-{uuid.uuid4().hex[:6]}"
        ok_resp = await client.post(
            "/api/v1/organizations",
            headers={"X-CSRF-Token": csrf_token},
            json={"name": "PKCE Org", "slug": slug},
        )
        assert ok_resp.status_code == 201

        # Expire session in DB (using RLS context for non-owner vforge_app) -> rejected 401
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "SELECT set_config('app.auth_lookup_issuer', :iss, true), "
                    "set_config('app.auth_lookup_subject', :sub, true)"
                ),
                {"iss": issuer, "sub": sub},
            )
            uid_res = await conn.execute(
                text("SELECT id FROM app_users WHERE oidc_issuer = :iss AND oidc_subject = :sub"),
                {"iss": issuer, "sub": sub},
            )
            target_uid = uid_res.scalar_one()
            await conn.execute(
                text("SELECT set_config('app.current_user_id', :uid, true)"),
                {"uid": str(target_uid)},
            )
            upd = await conn.execute(
                text(
                    "UPDATE auth_sessions SET expires_at = now() - interval '1 minute' "
                    "WHERE user_id = :uid"
                ),
                {"uid": target_uid},
            )
            assert upd.rowcount >= 1
        expired_resp = await client.get("/api/v1/auth/me")
        assert expired_resp.status_code == 401


async def test_full_rbac_cross_tenant_isolation_and_workflows(e2e_env: dict[str, Any]) -> None:
    issuer: str = e2e_env["issuer"]
    client_id: str = e2e_env["client_id"]
    priv = e2e_env["priv"]

    run_id = uuid.uuid4().hex[:6]

    def bearer_headers(subject: str, email: str, iss: str = issuer) -> dict[str, str]:
        tok = _sign_token(
            priv,
            issuer=iss,
            audience=client_id,
            subject=subject,
            email=email,
            name=subject,
        )
        return {"Authorization": f"Bearer {tok}"}

    owner_a_hdrs = bearer_headers(f"owner-a-{run_id}", f"ownera-{run_id}@a.test")
    owner_b_hdrs = bearer_headers(f"owner-b-{run_id}", f"ownerb-{run_id}@b.test")
    admin_hdrs = bearer_headers(f"admin-a-{run_id}", f"admina-{run_id}@a.test")
    lead_hdrs = bearer_headers(f"lead-a-{run_id}", f"leada-{run_id}@a.test")
    analyst_hdrs = bearer_headers(f"analyst-a-{run_id}", f"analysta-{run_id}@a.test")
    dev_hdrs = bearer_headers(f"dev-a-{run_id}", f"deva-{run_id}@a.test")
    auditor_hdrs = bearer_headers(f"auditor-a-{run_id}", f"auditora-{run_id}@a.test")
    viewer_hdrs = bearer_headers(f"viewer-a-{run_id}", f"viewera-{run_id}@a.test")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Create Org A and Org B
        org_a = (
            await client.post(
                "/api/v1/organizations",
                headers=owner_a_hdrs,
                json={"name": "Alpha Corp", "slug": f"alpha-{run_id}"},
            )
        ).json()
        org_b = (
            await client.post(
                "/api/v1/organizations",
                headers=owner_b_hdrs,
                json={"name": "Beta Corp", "slug": f"beta-{run_id}"},
            )
        ).json()
        org_a_id = org_a["id"]
        org_b_id = org_b["id"]

        # Duplicate org slug rejected 409
        dup_org = await client.post(
            "/api/v1/organizations",
            headers=owner_a_hdrs,
            json={"name": "Alpha Dup", "slug": f"alpha-{run_id}"},
        )
        assert dup_org.status_code == 409

        # 2. Add members across all remaining 6 roles in Org A
        role_users = [
            (f"admin-a-{run_id}", f"admina-{run_id}@a.test", "admin"),
            (f"lead-a-{run_id}", f"leada-{run_id}@a.test", "security_lead"),
            (f"analyst-a-{run_id}", f"analysta-{run_id}@a.test", "security_analyst"),
            (f"dev-a-{run_id}", f"deva-{run_id}@a.test", "developer"),
            (f"auditor-a-{run_id}", f"auditora-{run_id}@a.test", "auditor"),
            (f"viewer-a-{run_id}", f"viewera-{run_id}@a.test", "viewer"),
        ]
        for subj, email, role_name in role_users:
            m_resp = await client.post(
                f"/api/v1/organizations/{org_a_id}/memberships",
                headers=owner_a_hdrs,
                json={
                    "oidc_issuer": issuer,
                    "oidc_subject": subj,
                    "email": email,
                    "display_name": subj,
                    "role": role_name,
                },
            )
            assert m_resp.status_code == 201

        # Duplicate membership rejected 409
        dup_m = await client.post(
            f"/api/v1/organizations/{org_a_id}/memberships",
            headers=owner_a_hdrs,
            json={
                "oidc_issuer": issuer,
                "oidc_subject": f"dev-a-{run_id}",
                "email": f"deva-{run_id}@a.test",
                "display_name": "dup",
                "role": "developer",
            },
        )
        assert dup_m.status_code == 409

        # Admin cannot escalate someone to owner (403)
        esc_resp = await client.post(
            f"/api/v1/organizations/{org_a_id}/memberships",
            headers=admin_hdrs,
            json={
                "oidc_issuer": issuer,
                "oidc_subject": f"esc-{run_id}",
                "email": f"esc-{run_id}@a.test",
                "display_name": "Esc",
                "role": "owner",
            },
        )
        assert esc_resp.status_code == 403

        # 3. Create project, environment, asset, auth_profile in Org A and Org B
        proj_a = (
            await client.post(
                f"/api/v1/organizations/{org_a_id}/projects",
                headers=dev_hdrs,
                json={"name": "Web Portal", "slug": "web-portal", "criticality": "high"},
            )
        ).json()
        assert proj_a["slug"] == "web-portal"

        # Duplicate project slug rejected 409
        dup_proj = await client.post(
            f"/api/v1/organizations/{org_a_id}/projects",
            headers=dev_hdrs,
            json={"name": "Web Portal 2", "slug": "web-portal"},
        )
        assert dup_proj.status_code == 409

        proj_b = (
            await client.post(
                f"/api/v1/organizations/{org_b_id}/projects",
                headers=owner_b_hdrs,
                json={"name": "Beta API", "slug": "beta-api"},
            )
        ).json()

        env_a = (
            await client.post(
                f"/api/v1/organizations/{org_a_id}/projects/{proj_a['id']}/environments",
                headers=dev_hdrs,
                json={"name": "staging", "environment_type": "staging"},
            )
        ).json()
        env_b = (
            await client.post(
                f"/api/v1/organizations/{org_b_id}/projects/{proj_b['id']}/environments",
                headers=owner_b_hdrs,
                json={"name": "staging", "environment_type": "staging"},
            )
        ).json()

        # Invalid asset rejected 422
        bad_asset = await client.post(
            f"/api/v1/organizations/{org_a_id}/environments/{env_a['id']}/assets",
            headers=dev_hdrs,
            json={"asset_type": "web_application", "locator": "https://user:pass@evil.test"},
        )
        assert bad_asset.status_code == 422

        asset_a = (
            await client.post(
                f"/api/v1/organizations/{org_a_id}/environments/{env_a['id']}/assets",
                headers=dev_hdrs,
                json={
                    "asset_type": "web_application",
                    "locator": "HTTPS://Staging.Alpha.Test:443/app",
                },
            )
        ).json()
        assert asset_a["normalized_locator"] == "https://staging.alpha.test/app"

        asset_b = (
            await client.post(
                f"/api/v1/organizations/{org_b_id}/environments/{env_b['id']}/assets",
                headers=owner_b_hdrs,
                json={"asset_type": "rest_api", "locator": "https://api.beta.test/v1"},
            )
        ).json()

        # Auth profile rejects plaintext token (422) and accepts secret-manager ref (201)
        bad_ap = await client.post(
            f"/api/v1/organizations/{org_a_id}/environments/{env_a['id']}/auth-profiles",
            headers=lead_hdrs,
            json={
                "name": "bad-ap",
                "auth_type": "bearer_token_ref",
                "secret_manager_ref": "Bearer eyJhbGciOiJIUzI1NiJ9.secret",
            },
        )
        assert bad_ap.status_code == 422

        ok_ap = await client.post(
            f"/api/v1/organizations/{org_a_id}/environments/{env_a['id']}/auth-profiles",
            headers=lead_hdrs,
            json={
                "name": "staging-oauth",
                "auth_type": "oauth2_client_credentials",
                "secret_manager_ref": "vault://secret/data/alpha/staging-oauth",
            },
        )
        assert ok_ap.status_code == 201

        # 4. Cross-organization access & UUID manipulation rejected
        assert (
            await client.get(f"/api/v1/organizations/{org_b_id}/projects", headers=dev_hdrs)
        ).status_code == 403
        assert (
            await client.get(
                f"/api/v1/organizations/{org_a_id}/projects/{proj_b['id']}", headers=owner_a_hdrs
            )
        ).status_code == 404
        assert (
            await client.get(
                f"/api/v1/organizations/{org_a_id}/assets/{asset_b['id']}", headers=owner_a_hdrs
            )
        ).status_code == 404
        assert (
            await client.post(
                f"/api/v1/organizations/{org_b_id}/projects",
                headers=owner_a_hdrs,
                json={"name": "Cross", "slug": "cross"},
            )
        ).status_code == 403

        # 5. Authorization workflow: separation of duties, approval, revocation, expiry
        now = datetime.now(UTC)
        auth_req = await client.post(
            f"/api/v1/organizations/{org_a_id}/authorizations",
            headers=lead_hdrs,
            json={
                "asset_id": asset_a["id"],
                "approved_activities": ["passive_dast", "sast"],
                "allowed_ports": [443],
                "authorization_reference": "CHG-1001",
                "valid_from": now.isoformat(),
                "expires_at": (now + timedelta(days=7)).isoformat(),
            },
        )
        assert auth_req.status_code == 201
        auth_id = auth_req.json()["id"]

        # Separation of duties: security_lead who requested CANNOT approve own request (403)
        self_approve = await client.post(
            f"/api/v1/organizations/{org_a_id}/authorizations/{auth_id}/approve",
            headers=lead_hdrs,
            json={"reason": "self-approval attempt"},
        )
        assert self_approve.status_code == 403

        # Developer cannot approve (403)
        dev_approve = await client.post(
            f"/api/v1/organizations/{org_a_id}/authorizations/{auth_id}/approve",
            headers=dev_hdrs,
            json={"reason": "dev attempt"},
        )
        assert dev_approve.status_code == 403

        # Owner (different user) approves -> 200
        owner_approve = await client.post(
            f"/api/v1/organizations/{org_a_id}/authorizations/{auth_id}/approve",
            headers=owner_a_hdrs,
            json={"reason": "verified scope"},
        )
        assert owner_approve.status_code == 200
        assert owner_approve.json()["status"] == "approved"
        assert len(owner_approve.json()["audit_history"]) == 2

        # Security lead revokes -> 200
        rev_resp = await client.post(
            f"/api/v1/organizations/{org_a_id}/authorizations/{auth_id}/revoke",
            headers=lead_hdrs,
            json={"reason": "change window closed"},
        )
        assert rev_resp.status_code == 200
        assert rev_resp.json()["status"] == "revoked"

        # Expired authorization request rejected 422
        exp_req = await client.post(
            f"/api/v1/organizations/{org_a_id}/authorizations",
            headers=dev_hdrs,
            json={
                "asset_id": asset_a["id"],
                "approved_activities": ["sast"],
                "authorization_reference": "CHG-EXPIRED",
                "valid_from": (now - timedelta(days=2)).isoformat(),
                "expires_at": (now - timedelta(days=1)).isoformat(),
            },
        )
        assert exp_req.status_code == 422

        # 6. Scan profile versioning & validation
        sp1 = await client.post(
            f"/api/v1/organizations/{org_a_id}/scan-profiles",
            headers=analyst_hdrs,
            json={
                "name": "standard-web",
                "configuration": {"stages": ["sast", "passive_dast"], "passive_only": True},
            },
        )
        assert sp1.status_code == 201
        assert sp1.json()["version"] == 1

        sp2 = await client.post(
            f"/api/v1/organizations/{org_a_id}/scan-profiles",
            headers=analyst_hdrs,
            json={
                "name": "standard-web",
                "configuration": {
                    "stages": ["sast", "secrets", "passive_dast"],
                    "passive_only": True,
                },
            },
        )
        assert sp2.status_code == 201
        assert sp2.json()["version"] == 2

        # 7. Role checks for Viewer, Auditor, Analyst, Developer
        assert (
            await client.get(f"/api/v1/organizations/{org_a_id}/projects", headers=viewer_hdrs)
        ).status_code == 200
        assert (
            await client.get(f"/api/v1/organizations/{org_a_id}/audit-events", headers=viewer_hdrs)
        ).status_code == 403
        assert (
            await client.get(f"/api/v1/organizations/{org_a_id}/audit-events", headers=dev_hdrs)
        ).status_code == 403
        assert (
            await client.get(f"/api/v1/organizations/{org_a_id}/audit-events", headers=analyst_hdrs)
        ).status_code == 403
        assert (
            await client.post(
                f"/api/v1/organizations/{org_a_id}/projects",
                headers=auditor_hdrs,
                json={"name": "Audit Write", "slug": "audit-write"},
            )
        ).status_code == 403

        audit_resp = await client.get(
            f"/api/v1/organizations/{org_a_id}/audit-events?limit=50",
            headers=auditor_hdrs,
        )
        assert audit_resp.status_code == 200
        actions = {ev["action"] for ev in audit_resp.json()["items"]}
        assert "organization.created" in actions
        assert "membership.created" in actions
        assert "project.created" in actions
        assert "asset.registered" in actions
        assert "authorization.requested" in actions
        assert "authorization.approved" in actions
        assert "authorization.revoked" in actions
        assert "scan_profile.created" in actions


async def test_oidc_logout_revokes_session_clears_id_token_and_builds_safe_logout_url(
    e2e_env: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    issuer: str = e2e_env["issuer"]
    client_id: str = e2e_env["client_id"]
    priv = e2e_env["priv"]
    engine = e2e_env["engine"]
    sub = f"logout-user-{uuid.uuid4().hex[:8]}"

    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://localhost:3000",
        follow_redirects=False,
    ) as client:
        login_resp = await client.get(
            "/api/v1/auth/oidc/login?redirect_path=/organizations&mode=json&prompt=login"
        )
        assert login_resp.status_code == 200
        auth_url = urlsplit(login_resp.json()["authorization_url"])
        qs = parse_qs(auth_url.query)
        assert qs["prompt"] == ["login"]
        state = qs["state"][0]
        nonce = qs["nonce"][0]

        id_token = _sign_token(
            priv,
            issuer=issuer,
            audience=client_id,
            subject=sub,
            email=f"{sub}@example.test",
            name="Logout Tester",
            nonce=nonce,
        )

        async def fake_exchange(**_kwargs: Any) -> dict[str, Any]:
            return {"id_token": id_token, "access_token": id_token}

        monkeypatch.setattr(oidc_client, "exchange_code_for_tokens", fake_exchange)
        cb_resp = await client.get(f"/api/v1/auth/oidc/callback?code=authcode-lo&state={state}")
        assert cb_resp.status_code == 302

        me_resp = await client.get("/api/v1/auth/me")
        assert me_resp.status_code == 200
        csrf_token = me_resp.json()["csrf_token"]

        # Create org and switch org to test id_token_hint preservation across rotation
        org_resp = await client.post(
            "/api/v1/organizations",
            headers={"X-CSRF-Token": csrf_token},
            json={"name": "Logout Org", "slug": f"logout-org-{uuid.uuid4().hex[:6]}"},
        )
        assert org_resp.status_code == 201
        switch_resp = await client.post(
            "/api/v1/auth/switch-organization",
            headers={"X-CSRF-Token": csrf_token},
            json={"organization_id": org_resp.json()["id"]},
        )
        assert switch_resp.status_code == 200
        rotated_csrf = switch_resp.json()["csrf_token"]

        # Mock OIDC metadata with end_session_endpoint and verify spoofed Host is rejected
        from vforge.auth.oidc import OidcDiscoveryMetadata

        monkeypatch.setattr(
            oidc_client,
            "_metadata",
            OidcDiscoveryMetadata(
                issuer=issuer,
                authorization_endpoint=f"{issuer}/auth",
                token_endpoint=f"{issuer}/token",
                jwks_uri=f"{issuer}/certs",
                end_session_endpoint=f"{issuer}/protocol/openid-connect/logout",
            ),
        )
        monkeypatch.setattr(oidc_client, "_metadata_fetched_at", 1e12)

        # Logout without CSRF must still fail 403
        no_csrf_logout = await client.post("/api/v1/auth/logout")
        assert no_csrf_logout.status_code == 403

        # Valid logout returns RP-initiated logout_url with id_token_hint
        # and safe post_logout_redirect_uri
        logout_resp = await client.post(
            "/api/v1/auth/logout",
            headers={
                "X-CSRF-Token": rotated_csrf,
                "X-Forwarded-Host": "evil.attacker.example",
            },
        )
        assert logout_resp.status_code == 200
        body = logout_resp.json()
        assert body["status"] == "logged_out"
        logout_qs = parse_qs(urlsplit(body["logout_url"]).query)
        from vforge.config import get_settings

        expected_fallback = f"{get_settings().frontend_base_url.rstrip('/')}/login"
        assert logout_qs["id_token_hint"] == [id_token]
        assert "evil.attacker.example" not in body["logout_url"]
        assert logout_qs["post_logout_redirect_uri"] == [expected_fallback]

        # Subsequent /auth/me must return 401
        assert (await client.get("/api/v1/auth/me")).status_code == 401

        # All auth_sessions for this user must have oidc_id_token cleared and revoked_at set
        async with engine.begin() as conn:
            await conn.execute(
                text(
                    "SELECT set_config('app.auth_lookup_issuer', :iss, true), "
                    "set_config('app.auth_lookup_subject', :sub, true)"
                ),
                {"iss": issuer, "sub": sub},
            )
            target_uid = (
                await conn.execute(
                    text(
                        "SELECT id FROM app_users WHERE oidc_issuer = :iss AND oidc_subject = :sub"
                    ),
                    {"iss": issuer, "sub": sub},
                )
            ).scalar_one()
            await conn.execute(
                text("SELECT set_config('app.current_user_id', :uid, true)"),
                {"uid": str(target_uid)},
            )
            rows = (
                await conn.execute(
                    text(
                        "SELECT revoked_at, oidc_id_token FROM auth_sessions WHERE user_id = :uid"
                    ),
                    {"uid": target_uid},
                )
            ).all()
            assert rows
            assert all(r.revoked_at is not None and r.oidc_id_token is None for r in rows)
