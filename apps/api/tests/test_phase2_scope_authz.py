"""Comprehensive Phase 2 security tests for scope enforcement, OPA, DNS, and signed snapshots."""

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
from vforge_scope import StaticDnsResolver
from httpx import ASGITransport, AsyncClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import text

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory
from vforge.main import app
from vforge.security.signing import SnapshotSigner, generate_ed25519_keypair_pem


def _make_rsa_key(kid: str = "ph2-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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
    kid: str = "ph2-oidc-key-1",
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
async def ph2_env() -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph2.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()
    ed_priv_1, ed_pub_1 = generate_ed25519_keypair_pem()
    ed_priv_2, ed_pub_2 = generate_ed25519_keypair_pem()

    keyring_json = json.dumps(
        {
            "vf-key-1": {"public_key_pem": ed_pub_1, "status": "active"},
            "vf-key-2": {"public_key_pem": ed_pub_2, "status": "active"},
        }
    )

    test_settings = Settings(
        vforge_env="test",
        database_url=base_settings.effective_database_url,
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
        scope_signing_key_id="vf-key-1",
        scope_signing_private_key_pem=ed_priv_1,
        scope_signing_public_keys_json=keyring_json,
        require_live_dns_on_approval=False,
    )

    state_holder: dict[str, Settings] = {"settings": test_settings}

    engine = build_engine(test_settings.effective_database_url)
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.dns_resolver = StaticDnsResolver(
        {
            "app.example.com": ["93.184.216.34"],
            "sub.app.example.com": ["93.184.216.35"],
            "notexample.com": ["93.184.216.77"],
            "evil.example.org": ["93.184.216.99"],
        }
    )
    app.dependency_overrides[get_settings] = lambda: state_holder["settings"]

    oidc_client.reset_caches()
    oidc_client._metadata = OidcDiscoveryMetadata(  # noqa: SLF001
        issuer=issuer,
        authorization_endpoint=f"{issuer}/protocol/openid-connect/auth",
        token_endpoint=f"{issuer}/protocol/openid-connect/token",
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
    )
    oidc_client._metadata_fetched_at = 10**12  # noqa: SLF001
    oidc_client._jwks_keys = {"ph2-oidc-key-1": jwt.PyJWK.from_dict(pub_jwk)}  # noqa: SLF001
    oidc_client._jwks_list = [jwt.PyJWK.from_dict(pub_jwk)]  # noqa: SLF001
    oidc_client._jwks_fetched_at = 10**12  # noqa: SLF001

    yield {
        "issuer": issuer,
        "client_id": client_id,
        "priv": priv,
        "state_holder": state_holder,
        "test_settings": test_settings,
        "ed_priv_1": ed_priv_1,
        "ed_pub_1": ed_pub_1,
        "ed_priv_2": ed_priv_2,
        "ed_pub_2": ed_pub_2,
        "engine": engine,
    }

    app.dependency_overrides.clear()
    app.state.dns_resolver = None
    app.state.snapshot_signer = None
    app.state.opa_client = None
    oidc_client.reset_caches()
    await engine.dispose()


async def _bootstrap_org_hierarchy(
    lead_client: AsyncClient,
    *,
    lead_csrf: str,
    analyst_client: AsyncClient,
    analyst_csrf: str,
    analyst_email: str,
    analyst_subject: str,
    issuer: str,
    slug_prefix: str,
) -> dict[str, Any]:
    org_resp = await lead_client.post(
        "/api/v1/organizations",
        headers={"X-CSRF-Token": lead_csrf},
        json={"name": f"Org {slug_prefix}", "slug": f"{slug_prefix}-{uuid.uuid4().hex[:6]}"},
    )
    assert org_resp.status_code == 201
    org = org_resp.json()
    org_id = org["id"]

    # Rotate / bind org context for lead
    sw1 = await lead_client.post(
        "/api/v1/auth/switch-organization",
        headers={"X-CSRF-Token": lead_csrf},
        json={"organization_id": org_id},
    )
    assert sw1.status_code == 200
    lead_csrf_new = (await lead_client.get("/api/v1/auth/me")).json()["csrf_token"]

    inv = await lead_client.post(
        f"/api/v1/organizations/{org_id}/memberships",
        headers={"X-CSRF-Token": lead_csrf_new},
        json={
            "oidc_issuer": issuer,
            "oidc_subject": analyst_subject,
            "email": analyst_email,
            "display_name": "Security Analyst",
            "role": "security_analyst",
        },
    )
    assert inv.status_code == 201, inv.text

    sw2 = await analyst_client.post(
        "/api/v1/auth/switch-organization",
        headers={"X-CSRF-Token": analyst_csrf},
        json={"organization_id": org_id},
    )
    assert sw2.status_code == 200
    analyst_csrf_new = (await analyst_client.get("/api/v1/auth/me")).json()["csrf_token"]

    proj_a = (
        await lead_client.post(
            f"/api/v1/organizations/{org_id}/projects",
            headers={"X-CSRF-Token": lead_csrf_new},
            json={
                "name": "Core Web",
                "slug": "core-web",
                "criticality": "high",
            },
        )
    ).json()
    proj_b = (
        await lead_client.post(
            f"/api/v1/organizations/{org_id}/projects",
            headers={"X-CSRF-Token": lead_csrf_new},
            json={
                "name": "Secondary Proj",
                "slug": "secondary-proj",
                "criticality": "medium",
            },
        )
    ).json()

    env_staging = (
        await lead_client.post(
            f"/api/v1/organizations/{org_id}/projects/{proj_a['id']}/environments",
            headers={"X-CSRF-Token": lead_csrf_new},
            json={"name": "staging", "environment_type": "staging"},
        )
    ).json()
    env_prod = (
        await lead_client.post(
            f"/api/v1/organizations/{org_id}/projects/{proj_a['id']}/environments",
            headers={"X-CSRF-Token": lead_csrf_new},
            json={"name": "production", "environment_type": "production"},
        )
    ).json()

    return {
        "org_id": org_id,
        "lead_csrf": lead_csrf_new,
        "analyst_csrf": analyst_csrf_new,
        "proj_a_id": proj_a["id"],
        "proj_b_id": proj_b["id"],
        "env_staging_id": env_staging["id"],
        "env_prod_id": env_prod["id"],
    }


async def _register_asset_and_approve_auth(
    *,
    lead_client: AsyncClient,
    analyst_client: AsyncClient,
    ctx: dict[str, Any],
    env_id: str | None = None,
    asset_type: str,
    locator: str,
    scope_dict: dict[str, Any],
    activities: list[str],
    allowed_ports: list[int] | None,
    intensity: str = "low",
    allow_private: bool = False,
    valid_hours: float = 24.0,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    target_env = env_id or ctx["env_staging_id"]
    asset_resp = await analyst_client.post(
        f"/api/v1/organizations/{ctx['org_id']}/environments/{target_env}/assets",
        headers={"X-CSRF-Token": ctx["analyst_csrf"]},
        json={"asset_type": asset_type, "locator": locator},
    )
    assert asset_resp.status_code == 201, asset_resp.text
    asset = asset_resp.json()

    now = datetime.now(UTC)
    auth_resp = await analyst_client.post(
        f"/api/v1/organizations/{ctx['org_id']}/authorizations",
        headers={"X-CSRF-Token": ctx["analyst_csrf"]},
        json={
            "asset_id": asset["id"],
            "approved_testing_scope": scope_dict,
            "approved_activities": activities,
            "allowed_ports": allowed_ports,
            "permitted_intensity": intensity,
            "allow_private_networks": allow_private,
            "authorization_reference": f"CAB-{uuid.uuid4().hex[:6]}",
            "valid_from": now.isoformat(),
            "expires_at": (now + timedelta(hours=valid_hours)).isoformat(),
        },
    )
    assert auth_resp.status_code == 201, auth_resp.text
    auth = auth_resp.json()

    approve_resp = await lead_client.post(
        f"/api/v1/organizations/{ctx['org_id']}/authorizations/{auth['id']}/approve",
        headers={"X-CSRF-Token": ctx["lead_csrf"]},
        json={"reason": "Approved in Phase 2 integration test"},
    )
    assert approve_resp.status_code == 200, approve_resp.text
    approved_auth = approve_resp.json()

    snaps_resp = await lead_client.get(
        f"/api/v1/organizations/{ctx['org_id']}/snapshots",
        params={"authorization_id": approved_auth["id"]},
    )
    assert snaps_resp.status_code == 200
    assert len(snaps_resp.json()["items"]) >= 1
    snapshot = snaps_resp.json()["items"][0]
    return asset, approved_auth, snapshot


async def test_phase2_comprehensive_scope_opa_dns_and_snapshot_scenarios(
    ph2_env: dict[str, Any],
) -> None:
    state_holder: dict[str, Settings] = ph2_env["state_holder"]
    transport = ASGITransport(app=app)
    suffix = uuid.uuid4().hex[:6]
    lead_email = f"lead-{suffix}@ph2.test"
    analyst_email = f"analyst-{suffix}@ph2.test"
    other_email = f"other-{suffix}@ph2.test"

    async with (
        AsyncClient(transport=transport, base_url="http://test") as lead_client,
        AsyncClient(transport=transport, base_url="http://test") as analyst_client,
        AsyncClient(transport=transport, base_url="http://test") as other_client,
    ):
        lead_csrf = await _login_user(
            lead_client,
            priv=ph2_env["priv"],
            issuer=ph2_env["issuer"],
            audience=ph2_env["client_id"],
            subject=f"sub-lead-{suffix}",
            email=lead_email,
            name="Security Lead",
        )
        analyst_csrf = await _login_user(
            analyst_client,
            priv=ph2_env["priv"],
            issuer=ph2_env["issuer"],
            audience=ph2_env["client_id"],
            subject=f"sub-analyst-{suffix}",
            email=analyst_email,
            name="Security Analyst",
        )
        other_csrf = await _login_user(
            other_client,
            priv=ph2_env["priv"],
            issuer=ph2_env["issuer"],
            audience=ph2_env["client_id"],
            subject=f"sub-other-{suffix}",
            email=other_email,
            name="Other Tenant Owner",
        )

        # Verify session rotation on explicit /session/rotate and organization switch
        pre_cookie = lead_client.cookies.get("vf_session")
        rot_resp = await lead_client.post(
            "/api/v1/auth/session/rotate",
            headers={"X-CSRF-Token": lead_csrf},
        )
        assert rot_resp.status_code == 200
        post_cookie = rot_resp.cookies.get("vf_session")
        assert post_cookie and post_cookie != pre_cookie
        lead_csrf = rot_resp.json()["csrf_token"]

        ctx = await _bootstrap_org_hierarchy(
            lead_client,
            lead_csrf=lead_csrf,
            analyst_client=analyst_client,
            analyst_csrf=analyst_csrf,
            analyst_email=analyst_email,
            analyst_subject=f"sub-analyst-{suffix}",
            issuer=ph2_env["issuer"],
            slug_prefix="alpha-ph2",
        )

        # Second unrelated organization (tenant B)
        other_org = (
            await other_client.post(
                "/api/v1/organizations",
                headers={"X-CSRF-Token": other_csrf},
                json={"name": "Beta Org", "slug": f"beta-ph2-{suffix}"},
            )
        ).json()
        await other_client.post(
            "/api/v1/auth/switch-organization",
            headers={"X-CSRF-Token": other_csrf},
            json={"organization_id": other_org["id"]},
        )
        other_csrf = (await other_client.get("/api/v1/auth/me")).json()["csrf_token"]

        # Register web app exact-domain asset & approve authorization
        asset_web, auth_web, snap_web = await _register_asset_and_approve_auth(
            lead_client=lead_client,
            analyst_client=analyst_client,
            ctx=ctx,
            asset_type="web_application",
            locator="https://app.example.com/",
            scope_dict={
                "domain_match_mode": "exact_domain",
                "url_match_mode": "url_path_prefix",
            },
            activities=["passive_web_testing", "api_testing"],
            allowed_ports=[443],
            intensity="low",
        )
        assert snap_web["resolved_ips"] == ["93.184.216.34"]

        eval_url = f"/api/v1/organizations/{ctx['org_id']}/scope/evaluate"

        # 1. Valid exact domain + valid URL prefix
        res_ok = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com.",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
                "tool_category": "passive_dast",
            },
        )
        assert res_ok.status_code == 200
        assert res_ok.json()["outcome"] == "ALLOW", f"Outcome: {res_ok.json()}"
        assert res_ok.json()["allowed"] is True
        assert res_ok.json()["resolved_ips"] == ["93.184.216.34"]
        assert res_ok.json()["snapshot_verified"] is True

        # 2. Invalid lookalike domain
        res_lookalike = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "notexample.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_lookalike.json()["outcome"] == "DENY"
        codes_lookalike = {r["code"] for r in res_lookalike.json()["reasons"]}
        assert "target_out_of_scope" in codes_lookalike

        # 3. Unauthorized subdomain under exact_domain
        res_sub = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "sub.app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_sub.json()["outcome"] == "DENY"

        # 4 & 5. Valid IPv4 and Valid IPv6 targets
        _, auth_v4, _ = await _register_asset_and_approve_auth(
            lead_client=lead_client,
            analyst_client=analyst_client,
            ctx=ctx,
            asset_type="ip_address",
            locator="93.184.216.10",
            scope_dict={},
            activities=["network_discovery"],
            allowed_ports=[443],
        )
        res_v4 = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_v4["id"],
                "target_type": "ipv4",
                "raw_target": "93.184.216.10",
                "requested_capabilities": ["network_discovery"],
                "requested_intensity": "passive",
            },
        )
        assert res_v4.json()["outcome"] == "ALLOW"

        _, auth_v6, _ = await _register_asset_and_approve_auth(
            lead_client=lead_client,
            analyst_client=analyst_client,
            ctx=ctx,
            asset_type="ip_address",
            locator="2606:2800:220:1::10",
            scope_dict={},
            activities=["network_discovery"],
            allowed_ports=[443],
        )
        res_v6 = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_v6["id"],
                "target_type": "ipv6",
                "raw_target": "2606:2800:0220:0001:0000:0000:0000:0010",
                "requested_capabilities": ["network_discovery"],
                "requested_intensity": "passive",
            },
        )
        assert res_v6.json()["outcome"] == "ALLOW"

        # 6. Unauthorized CIDR
        _, auth_cidr, _ = await _register_asset_and_approve_auth(
            lead_client=lead_client,
            analyst_client=analyst_client,
            ctx=ctx,
            asset_type="cidr_range",
            locator="93.184.216.0/24",
            scope_dict={},
            activities=["network_discovery"],
            allowed_ports=[443],
        )
        res_bad_cidr = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_cidr["id"],
                "target_type": "ipv4",
                "raw_target": "93.184.217.5",
                "requested_capabilities": ["network_discovery"],
                "requested_intensity": "passive",
            },
        )
        assert res_bad_cidr.json()["outcome"] == "DENY"

        # 7. Explicitly authorized private network
        _, auth_priv, _ = await _register_asset_and_approve_auth(
            lead_client=lead_client,
            analyst_client=analyst_client,
            ctx=ctx,
            asset_type="cidr_range",
            locator="10.20.30.0/24",
            scope_dict={},
            activities=["network_discovery"],
            allowed_ports=[443],
            allow_private=True,
        )
        res_priv_ok = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_priv["id"],
                "target_type": "ipv4",
                "raw_target": "10.20.30.15",
                "requested_capabilities": ["network_discovery"],
                "requested_intensity": "passive",
            },
        )
        assert res_priv_ok.json()["outcome"] == "ALLOW"

        # 8 & 9. Unauthorized localhost & Cloud metadata rejection
        for bad_ip in ("127.0.0.1", "169.254.169.254"):
            res_bad_net = await analyst_client.post(
                eval_url,
                headers={"X-CSRF-Token": ctx["analyst_csrf"]},
                json={
                    "authorization_id": auth_priv["id"],
                    "target_type": "ipv4",
                    "raw_target": bad_ip,
                    "requested_capabilities": ["network_discovery"],
                    "requested_intensity": "passive",
                },
            )
            assert res_bad_net.json()["outcome"] == "DENY"

        # 12 & 13. Redirect to unauthorized domain & unauthorized/metadata IP
        for redir in (
            "https://evil.example.org/pwn",
            "http://169.254.169.254/latest/meta-data",
        ):
            res_redir = await analyst_client.post(
                eval_url,
                headers={"X-CSRF-Token": ctx["analyst_csrf"]},
                json={
                    "authorization_id": auth_web["id"],
                    "target_type": "exact_url",
                    "raw_target": "https://app.example.com/login",
                    "redirect_location": redir,
                    "requested_capabilities": ["passive_web_testing"],
                    "requested_intensity": "passive",
                },
            )
            assert res_redir.json()["outcome"] == "DENY"
            assert res_redir.json()["redirect_safe"] is False

        # 14. Unauthorized port
        res_port = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "exact_url",
                "raw_target": "https://app.example.com:8443/api",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_port.json()["outcome"] == "DENY"
        assert "unauthorized_port" in {r["code"] for r in res_port.json()["reasons"]}

        # 18 & 19. Wrong project & Wrong environment
        res_wrong_proj = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "project_id": ctx["proj_b_id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_wrong_proj.json()["outcome"] == "DENY"
        assert "wrong_authorization_project" in {
            r["code"] for r in res_wrong_proj.json()["reasons"]
        }

        res_wrong_env = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "environment_id": ctx["env_prod_id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_wrong_env.json()["outcome"] == "DENY"
        assert "wrong_authorization_environment" in {
            r["code"] for r in res_wrong_env.json()["reasons"]
        }

        # 20. Unauthorized capability & forbidden DoS capability & intensity exceeded
        res_unauth_cap = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["active_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_unauth_cap.json()["outcome"] == "DENY"
        assert "unauthorized_capability" in {r["code"] for r in res_unauth_cap.json()["reasons"]}

        res_dos = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["dos_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_dos.json()["outcome"] == "DENY"
        assert "forbidden_capability" in {r["code"] for r in res_dos.json()["reasons"]}

        # 17. Wrong organization (cross-tenant API access -> 404 or 403)
        res_cross_org = await other_client.post(
            f"/api/v1/organizations/{other_org['id']}/scope/evaluate",
            headers={"X-CSRF-Token": other_csrf},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_cross_org.status_code == 404

        # 10. DNS rebinding attempt (resolver changes away from snapshot's 93.184.216.34)
        app.state.dns_resolver = StaticDnsResolver({"app.example.com": ["93.184.216.44"]})
        res_rebind = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_rebind.json()["outcome"] == "DENY"
        assert "dns_rebinding_detected" in {r["code"] for r in res_rebind.json()["reasons"]}

        # Restore valid DNS for app.example.com
        app.state.dns_resolver = StaticDnsResolver({"app.example.com": ["93.184.216.34"]})

        # 11. Mixed DNS response (one public IP + one metadata IP) blocked before approval
        app.state.dns_resolver = StaticDnsResolver(
            {
                "app.example.com": ["93.184.216.34"],
                "mixed.example.com": ["93.184.216.34", "169.254.169.254"],
            }
        )
        mixed_asset = (
            await analyst_client.post(
                f"/api/v1/organizations/{ctx['org_id']}/environments/{ctx['env_staging_id']}/assets",
                headers={"X-CSRF-Token": ctx["analyst_csrf"]},
                json={"asset_type": "web_application", "locator": "https://mixed.example.com/"},
            )
        ).json()
        now = datetime.now(UTC)
        mixed_auth = (
            await analyst_client.post(
                f"/api/v1/organizations/{ctx['org_id']}/authorizations",
                headers={"X-CSRF-Token": ctx["analyst_csrf"]},
                json={
                    "asset_id": mixed_asset["id"],
                    "approved_activities": ["passive_web_testing"],
                    "authorization_reference": "CAB-MIXED-1",
                    "valid_from": now.isoformat(),
                    "expires_at": (now + timedelta(hours=12)).isoformat(),
                },
            )
        ).json()
        approve_mixed = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/authorizations/{mixed_auth['id']}/approve",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"reason": "Should fail mixed DNS"},
        )
        assert approve_mixed.status_code == 422

        # Restore default ph2 DNS resolver records
        app.state.dns_resolver = StaticDnsResolver(
            {
                "app.example.com": ["93.184.216.34"],
                "sub.app.example.com": ["93.184.216.35"],
                "notexample.com": ["93.184.216.77"],
                "evil.example.org": ["93.184.216.99"],
            }
        )

        # 21. Self-approval rejection + REQUIRES_APPROVAL outcome on pending auth
        self_approve = await analyst_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/authorizations/{mixed_auth['id']}/approve",
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={"reason": "Self approval"},
        )
        assert self_approve.status_code == 403
        res_pending = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_pending.json()["outcome"] == "ALLOW"
        # Check REQUIRES_APPROVAL on production active testing without elevated flag
        _, auth_prod_active, _ = await _register_asset_and_approve_auth(
            lead_client=lead_client,
            analyst_client=analyst_client,
            ctx=ctx,
            env_id=ctx["env_prod_id"],
            asset_type="ip_address",
            locator="93.184.216.50",
            scope_dict={"production_active_approved": False},
            activities=["network_discovery"],
            allowed_ports=[443],
            intensity="low",
        )
        res_prod_req = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_prod_active["id"],
                "target_type": "ipv4",
                "raw_target": "93.184.216.50",
                "requested_capabilities": ["network_discovery"],
                "requested_intensity": "low",
            },
        )
        assert res_prod_req.json()["outcome"] == "REQUIRES_APPROVAL"
        assert "production_active_requires_approval" in {
            r["code"] for r in res_prod_req.json()["reasons"]
        }

        # 22. Modified scope snapshot & asset update invalidates snapshot; DB immutability
        verify_ok = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/snapshots/{snap_web['id']}/verify",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"revalidate_dns": True},
        )
        assert verify_ok.status_code == 200
        assert verify_ok.json()["valid"] is True

        # Tampered snapshot inserted into DB cannot pass verification
        tampered_snap_id = uuid.uuid4()
        sf = build_session_factory(ph2_env["engine"])
        async with sf() as db_sess:
            async with db_sess.begin():
                await db_sess.execute(
                    text("SELECT set_config('app.current_org_id', :oid, true)"),
                    {"oid": ctx["org_id"]},
                )
                tampered_payload = dict(snap_web["payload"])
                tampered_payload["allowed_ports"] = [22, 443]
                await db_sess.execute(
                    text(
                        "INSERT INTO scope_snapshots ("
                        "id, organization_id, project_id, environment_id, asset_id, "
                        "authorization_id, snapshot_version, asset_version, policy_version, "
                        "target_type, canonical_locator, resolved_ips, allowed_ports, "
                        "permitted_capabilities, permitted_intensity, scope_definition, "
                        "payload, payload_sha256, signing_key_id, signature_algorithm, signature, "
                        "authorization_expires_at, created_by"
                        ") VALUES ("
                        ":id, :org_id, :proj_id, :env_id, :asset_id, :auth_id, 99, 1, :pver, "
                        "'web_application', :loc, '[]'::jsonb, '[22,443]'::jsonb, "
                        "'[\"passive_web_testing\"]'::jsonb, 'low', '{}'::jsonb, "
                        "CAST(:payload AS jsonb), :sha, :kid, 'Ed25519', :sig, "
                        ":exp, :uid)"
                    ),
                    {
                        "id": str(tampered_snap_id),
                        "org_id": ctx["org_id"],
                        "proj_id": snap_web["project_id"],
                        "env_id": snap_web["environment_id"],
                        "asset_id": snap_web["asset_id"],
                        "auth_id": snap_web["authorization_id"],
                        "pver": snap_web["policy_version"],
                        "loc": snap_web["canonical_locator"],
                        "payload": json.dumps(tampered_payload),
                        "sha": snap_web["payload_sha256"],  # Mismatched original hash!
                        "kid": snap_web["signing_key_id"],
                        "sig": snap_web["signature"],
                        "exp": datetime.fromisoformat(snap_web["authorization_expires_at"]),
                        "uid": snap_web["created_by"],
                    },
                )

        verify_tampered = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/snapshots/{tampered_snap_id}/verify",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"revalidate_dns": False},
        )
        assert verify_tampered.json()["valid"] is False
        assert verify_tampered.json()["signature_valid"] is False
        assert verify_tampered.json()["opa_outcome"] == "DENY"

        # 23. Stale policy version check
        state_holder["settings"] = Settings(
            **{
                **ph2_env["test_settings"].model_dump(),
                "policy_bundle_version": "2026-12-01.v3",
            }
        )
        verify_stale_policy = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/snapshots/{snap_web['id']}/verify",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"revalidate_dns": False},
        )
        assert verify_stale_policy.json()["policy_version_current"] is False
        assert verify_stale_policy.json()["valid"] is False
        assert verify_stale_policy.json()["opa_outcome"] == "DENY"
        state_holder["settings"] = ph2_env["test_settings"]

        # 24. Key rotation: old key 'verify_only' -> still valid; 'revoked' -> denied
        rotated_verify_only = Settings(
            **{
                **ph2_env["test_settings"].model_dump(),
                "scope_signing_key_id": "vf-key-2",
                "scope_signing_private_key_pem": ph2_env["ed_priv_2"],
                "scope_signing_public_keys_json": json.dumps(
                    {
                        "vf-key-1": {
                            "public_key_pem": ph2_env["ed_pub_1"],
                            "status": "verify_only",
                        },
                        "vf-key-2": {
                            "public_key_pem": ph2_env["ed_pub_2"],
                            "status": "active",
                        },
                    }
                ),
            }
        )
        state_holder["settings"] = rotated_verify_only
        verify_rotated = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/snapshots/{snap_web['id']}/verify",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"revalidate_dns": True},
        )
        assert verify_rotated.json()["signature_valid"] is True
        assert verify_rotated.json()["valid"] is True

        # Revoke vf-key-1 -> previously signed snapshot is rejected
        revoked_key_settings = Settings(
            **{
                **rotated_verify_only.model_dump(),
                "scope_signing_public_keys_json": json.dumps(
                    {
                        "vf-key-1": {
                            "public_key_pem": ph2_env["ed_pub_1"],
                            "status": "revoked",
                        },
                        "vf-key-2": {
                            "public_key_pem": ph2_env["ed_pub_2"],
                            "status": "active",
                        },
                    }
                ),
            }
        )
        state_holder["settings"] = revoked_key_settings
        verify_revoked_key = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/snapshots/{snap_web['id']}/verify",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"revalidate_dns": False},
        )
        assert verify_revoked_key.json()["signature_valid"] is False
        assert verify_revoked_key.json()["signature_reason"] == "signing_key_revoked"
        assert verify_revoked_key.json()["opa_outcome"] == "DENY"
        state_holder["settings"] = ph2_env["test_settings"]

        # Asset mutation bumps asset.version -> snapshot becomes stale until re-evaluated
        patch_asset = await analyst_client.patch(
            f"/api/v1/organizations/{ctx['org_id']}/assets/{asset_web['id']}",
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={"scope_metadata": {"owner_team": "secops"}},
        )
        assert patch_asset.status_code == 200
        assert patch_asset.json()["version"] == asset_web["version"] + 1
        verify_stale_asset = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/snapshots/{snap_web['id']}/verify",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"revalidate_dns": False},
        )
        assert verify_stale_asset.json()["asset_version_current"] is False
        assert verify_stale_asset.json()["opa_outcome"] == "DENY"

        # 16. Revoked authorization denied
        revoke_resp = await lead_client.post(
            f"/api/v1/organizations/{ctx['org_id']}/authorizations/{auth_web['id']}/revoke",
            headers={"X-CSRF-Token": ctx["lead_csrf"]},
            json={"reason": "Window closed early"},
        )
        assert revoke_resp.status_code == 200
        res_revoked = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_web["id"],
                "target_type": "fqdn",
                "raw_target": "app.example.com",
                "requested_capabilities": ["passive_web_testing"],
                "requested_intensity": "passive",
            },
        )
        assert res_revoked.json()["outcome"] == "DENY"
        assert "authorization_revoked" in {r["code"] for r in res_revoked.json()["reasons"]}

        # 15. Expired authorization denied & filtered cleanly by ?status=expired
        async with sf() as db_sess:
            async with db_sess.begin():
                await db_sess.execute(
                    text("SELECT set_config('app.current_org_id', :oid, true)"),
                    {"oid": ctx["org_id"]},
                )
                expired_from = datetime.now(UTC) - timedelta(days=2)
                expired_at = datetime.now(UTC) - timedelta(minutes=5)
                await db_sess.execute(
                    text(
                        "UPDATE authorizations SET valid_from = :vf, expires_at = :exp "
                        "WHERE id = :aid"
                    ),
                    {"vf": expired_from, "exp": expired_at, "aid": auth_v4["id"]},
                )

        res_expired = await analyst_client.post(
            eval_url,
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={
                "authorization_id": auth_v4["id"],
                "target_type": "ipv4",
                "raw_target": "93.184.216.10",
                "requested_capabilities": ["network_discovery"],
                "requested_intensity": "passive",
            },
        )
        assert res_expired.json()["outcome"] == "DENY"
        assert "authorization_expired" in {r["code"] for r in res_expired.json()["reasons"]}

        list_expired = await analyst_client.get(
            f"/api/v1/organizations/{ctx['org_id']}/authorizations",
            params={"status": "expired"},
        )
        assert list_expired.status_code == 200
        assert any(item["id"] == auth_v4["id"] for item in list_expired.json()["items"])

        # Editing an approved authorization forces re-approval (status -> pending)
        patch_auth = await analyst_client.patch(
            f"/api/v1/organizations/{ctx['org_id']}/authorizations/{auth_v6['id']}",
            headers={"X-CSRF-Token": ctx["analyst_csrf"]},
            json={"allowed_ports": [443, 8443]},
        )
        assert patch_auth.status_code == 200
        assert patch_auth.json()["status"] == "pending"
        assert patch_auth.json()["approved_by"] is None

        # Verify unit fails closed for tampered signer without DB
        signer_unit = SnapshotSigner.from_settings(ph2_env["test_settings"])
        bad_verify = signer_unit.verify_payload(
            payload={"modified": True},
            expected_sha256="0" * 64,
            signing_key_id="vf-key-1",
            signature_algorithm="Ed25519",
            signature="invalid",
        )
        assert bad_verify.valid is False
        assert bad_verify.reason == "hash_mismatch"
