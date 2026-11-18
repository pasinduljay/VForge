"""Unit and security tests for OIDC PKCE, JWT validation, and JWKS key rotation."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from vforge.auth.oidc import (
    OidcClient,
    compute_pkce_challenge,
    generate_pkce_verifier,
)
from vforge.config import Settings
from vforge.errors import UnauthorizedError


def _generate_rsa_jwk(kid: str) -> tuple[Any, dict[str, Any]]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_jwk = json.loads(RSAAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = kid
    public_jwk["use"] = "sig"
    public_jwk["alg"] = "RS256"
    return private_key, public_jwk


def _make_settings() -> Settings:
    return Settings(
        vforge_env="test",
        oidc_enabled=True,
        oidc_issuer="https://idp.example.test/realms/vforge",
        oidc_client_id="vforge-api",
        oidc_redirect_uri="http://127.0.0.1:3000/api/v1/auth/oidc/callback",
        oidc_allowed_algorithms=["RS256", "ES256", "EdDSA"],
        oidc_clock_skew_seconds=5,
        oidc_jwks_cache_ttl_seconds=300,
    )


def test_pkce_s256_challenge_matches_rfc7636() -> None:
    verifier = generate_pkce_verifier()
    assert len(verifier) >= 43
    challenge = compute_pkce_challenge(verifier)
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    assert challenge == expected
    assert "=" not in challenge


async def test_valid_jwt_and_jwks_key_rotation() -> None:
    key1_priv, key1_pub = _generate_rsa_jwk("key-1")
    key2_priv, key2_pub = _generate_rsa_jwk("key-2")

    jwks_state = {"keys": [key1_pub]}
    settings = _make_settings()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": settings.oidc_issuer,
                    "authorization_endpoint": f"{settings.oidc_issuer}/auth",
                    "token_endpoint": f"{settings.oidc_issuer}/token",
                    "jwks_uri": f"{settings.oidc_issuer}/certs",
                },
            )
        if request.url.path.endswith("/certs"):
            return httpx.Response(200, json={"keys": jwks_state["keys"]})
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = OidcClient()

    now = datetime.now(UTC)
    claims = {
        "iss": settings.oidc_issuer,
        "sub": "user-123",
        "aud": settings.oidc_client_id,
        "email": "alice@example.test",
        "name": "Alice Security",
        "email_verified": True,
        "nonce": "nonce-abc",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    token1 = jwt.encode(claims, key1_priv, algorithm="RS256", headers={"kid": "key-1"})

    async with httpx.AsyncClient(transport=transport) as http_client:
        identity1 = await client.verify_jwt(
            token=token1,
            settings=settings,
            expected_nonce="nonce-abc",
            http_client=http_client,
        )
        assert identity1.issuer == settings.oidc_issuer
        assert identity1.subject == "user-123"
        assert identity1.email == "alice@example.test"

        # Rotate JWKS to key-2 and sign new token with key-2 while key-1 cache is still warm
        jwks_state["keys"] = [key2_pub]
        token2 = jwt.encode(claims, key2_priv, algorithm="RS256", headers={"kid": "key-2"})
        identity2 = await client.verify_jwt(
            token=token2,
            settings=settings,
            expected_nonce="nonce-abc",
            http_client=http_client,
        )
        assert identity2.subject == "user-123"

        # Unknown kid must fail
        token_unknown = jwt.encode(
            claims, key1_priv, algorithm="RS256", headers={"kid": "unknown-kid"}
        )
        with pytest.raises(UnauthorizedError, match="not found in JWKS"):
            await client.verify_jwt(
                token=token_unknown,
                settings=settings,
                http_client=http_client,
            )


@pytest.mark.parametrize(
    ("claim_override", "expected_msg"),
    [
        ({"exp": int((datetime.now(UTC) - timedelta(minutes=5)).timestamp())}, "expired"),
        (
            {"nbf": int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())},
            "not yet valid",
        ),
        ({"iss": "https://evil.example.test"}, "issuer"),
        ({"aud": "other-client"}, "audience"),
        ({"nonce": "wrong-nonce"}, "nonce"),
    ],
)
async def test_jwt_rejects_expired_immature_wrong_issuer_audience_and_nonce(
    claim_override: dict[str, Any],
    expected_msg: str,
) -> None:
    priv, pub = _generate_rsa_jwk("key-1")
    settings = _make_settings()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": settings.oidc_issuer,
                    "authorization_endpoint": f"{settings.oidc_issuer}/auth",
                    "token_endpoint": f"{settings.oidc_issuer}/token",
                    "jwks_uri": f"{settings.oidc_issuer}/certs",
                },
            )
        return httpx.Response(200, json={"keys": [pub]})

    now = datetime.now(UTC)
    claims: dict[str, Any] = {
        "iss": settings.oidc_issuer,
        "sub": "user-123",
        "aud": settings.oidc_client_id,
        "nonce": "expected-nonce",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()) - 1,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    claims.update(claim_override)
    token = jwt.encode(claims, priv, algorithm="RS256", headers={"kid": "key-1"})

    client = OidcClient()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        with pytest.raises(UnauthorizedError, match=expected_msg):
            await client.verify_jwt(
                token=token,
                settings=settings,
                expected_nonce="expected-nonce",
                http_client=http_client,
            )


async def test_jwt_rejects_disallowed_alg_none_and_hs256_and_tampered_sig() -> None:
    priv, pub = _generate_rsa_jwk("key-1")
    other_priv, _ = _generate_rsa_jwk("key-1")
    settings = _make_settings()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(
                200,
                json={
                    "issuer": settings.oidc_issuer,
                    "authorization_endpoint": f"{settings.oidc_issuer}/auth",
                    "token_endpoint": f"{settings.oidc_issuer}/token",
                    "jwks_uri": f"{settings.oidc_issuer}/certs",
                },
            )
        return httpx.Response(200, json={"keys": [pub]})

    now = datetime.now(UTC)
    claims = {
        "iss": settings.oidc_issuer,
        "sub": "user-123",
        "aud": settings.oidc_client_id,
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    hs_token = jwt.encode(claims, "symmetric-secret-key-at-least-32-bytes", algorithm="HS256")
    none_header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
    none_payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    none_token = f"{none_header}.{none_payload}."
    wrong_sig_token = jwt.encode(claims, other_priv, algorithm="RS256", headers={"kid": "key-1"})

    client = OidcClient()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        for bad_token in (hs_token, none_token, wrong_sig_token, "not-a-jwt"):
            with pytest.raises(UnauthorizedError):
                await client.verify_jwt(
                    token=bad_token,
                    settings=settings,
                    http_client=http_client,
                )


async def test_authorization_prompt_and_rp_initiated_logout_urls() -> None:
    settings = _make_settings()
    discovery_doc: dict[str, Any] = {
        "issuer": settings.oidc_issuer,
        "authorization_endpoint": f"{settings.oidc_issuer}/auth",
        "token_endpoint": f"{settings.oidc_issuer}/token",
        "jwks_uri": f"{settings.oidc_issuer}/certs",
        "end_session_endpoint": f"{settings.oidc_issuer}/logout",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=discovery_doc)
        return httpx.Response(404)

    client = OidcClient()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http_client:
        auth_url = await client.build_authorization_url(
            settings=settings,
            state="st-1",
            nonce="nn-1",
            code_challenge="ch-1",
            prompt="login",
            http_client=http_client,
        )
        assert "prompt=login" in auth_url
        assert "code_challenge_method=S256" in auth_url

        logout_with_hint = await client.build_logout_url(
            settings=settings,
            post_logout_redirect_uri="http://localhost:3000/login",
            id_token_hint="id-tok-xyz",
            http_client=http_client,
        )
        assert logout_with_hint is not None
        assert logout_with_hint.startswith(f"{settings.oidc_issuer}/logout?")
        assert "id_token_hint=id-tok-xyz" in logout_with_hint
        assert "post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Flogin" in logout_with_hint

        logout_no_hint = await client.build_logout_url(
            settings=settings,
            post_logout_redirect_uri="http://127.0.0.1:3000/login",
            http_client=http_client,
        )
        assert logout_no_hint is not None
        assert "client_id=vforge-api" in logout_no_hint
        assert "post_logout_redirect_uri=http%3A%2F%2F127.0.0.1%3A3000%2Flogin" in logout_no_hint

        client.reset_caches()
        discovery_doc.pop("end_session_endpoint")
        assert (
            await client.build_logout_url(
                settings=settings,
                post_logout_redirect_uri="http://localhost:3000/login",
                http_client=http_client,
            )
            is None
        )
