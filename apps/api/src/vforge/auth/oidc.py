"""Production-oriented OIDC Authorization Code + PKCE and JWT/JWKS validation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK

from vforge.config import Settings
from vforge.errors import UnauthorizedError

_FORBIDDEN_ALGORITHMS = frozenset({"none", "HS256", "HS384", "HS512"})


@dataclass(frozen=True)
class OidcDiscoveryMetadata:
    """Validated OIDC provider discovery endpoints."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None


@dataclass(frozen=True)
class OidcIdentity:
    """Verified OIDC user identity anchored to (issuer, subject)."""

    issuer: str
    subject: str
    email: str
    display_name: str
    email_verified: bool


def generate_pkce_verifier() -> str:
    """Generate a high-entropy PKCE code_verifier (RFC 7636)."""
    return secrets.token_urlsafe(64)


def compute_pkce_challenge(code_verifier: str) -> str:
    """Compute S256 PKCE code_challenge without trailing '=' padding."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def hash_oidc_value(value: str) -> str:
    """Return SHA-256 hex digest for storing state/nonce safely."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class OidcClient:
    """OIDC provider client with discovery caching, PKCE, and JWKS rotation support."""

    def __init__(self) -> None:
        self._metadata: OidcDiscoveryMetadata | None = None
        self._metadata_fetched_at: float = 0.0
        self._jwks_keys: dict[str, PyJWK] = {}
        self._jwks_list: list[PyJWK] = []
        self._jwks_fetched_at: float = 0.0

    def reset_caches(self) -> None:
        """Clear cached discovery and JWKS state (useful for tests/config reloads)."""
        self._metadata = None
        self._metadata_fetched_at = 0.0
        self._jwks_keys = {}
        self._jwks_list = []
        self._jwks_fetched_at = 0.0

    @staticmethod
    def _rewrite_internal_url(url: str, settings: Settings) -> str:
        """Map browser-facing issuer URLs to container-internal OIDC URLs when configured."""
        if not settings.oidc_internal_base_url or not settings.oidc_issuer:
            return url
        issuer_base = settings.oidc_issuer.rstrip("/")
        internal_base = settings.oidc_internal_base_url.rstrip("/")
        if url.startswith(issuer_base):
            return f"{internal_base}{url[len(issuer_base) :]}"
        return url

    async def get_metadata(
        self,
        settings: Settings,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> OidcDiscoveryMetadata:
        """Fetch and cache OIDC provider discovery metadata."""
        if not settings.oidc_issuer:
            raise UnauthorizedError("OIDC provider is not configured")

        now = time.monotonic()
        if (
            self._metadata is not None
            and (now - self._metadata_fetched_at) < settings.oidc_jwks_cache_ttl_seconds
        ):
            return self._metadata

        base = (settings.oidc_internal_base_url or settings.oidc_issuer).rstrip("/")
        discovery_url = f"{base}/.well-known/openid-configuration"

        close_client = http_client is None
        client = http_client or httpx.AsyncClient(timeout=5.0)
        try:
            resp = await client.get(discovery_url)
            if resp.status_code != 200:
                raise UnauthorizedError("OIDC discovery endpoint unavailable")
            data = resp.json()
        except httpx.HTTPError as exc:
            raise UnauthorizedError("Failed to contact OIDC discovery endpoint") from exc
        finally:
            if close_client:
                await client.aclose()

        discovered_issuer = str(data.get("issuer", "")).rstrip("/")
        expected_issuer = settings.oidc_issuer.rstrip("/")
        if discovered_issuer != expected_issuer:
            raise UnauthorizedError("OIDC discovery issuer mismatch")

        auth_endpoint = str(data.get("authorization_endpoint", ""))
        token_endpoint = self._rewrite_internal_url(str(data.get("token_endpoint", "")), settings)
        jwks_uri = self._rewrite_internal_url(str(data.get("jwks_uri", "")), settings)
        raw_end_session = data.get("end_session_endpoint")
        end_session_endpoint = (
            raw_end_session.strip()
            if isinstance(raw_end_session, str) and raw_end_session.strip()
            else None
        )
        if not auth_endpoint or not token_endpoint or not jwks_uri:
            raise UnauthorizedError("OIDC discovery metadata incomplete")

        self._metadata = OidcDiscoveryMetadata(
            issuer=expected_issuer,
            authorization_endpoint=auth_endpoint,
            token_endpoint=token_endpoint,
            jwks_uri=jwks_uri,
            end_session_endpoint=end_session_endpoint,
        )
        self._metadata_fetched_at = now
        return self._metadata

    async def _fetch_jwks(
        self,
        jwks_uri: str,
        *,
        http_client: httpx.AsyncClient | None = None,
    ) -> None:
        close_client = http_client is None
        client = http_client or httpx.AsyncClient(timeout=5.0)
        try:
            resp = await client.get(jwks_uri)
            if resp.status_code != 200:
                raise UnauthorizedError("Failed to fetch OIDC JWKS")
            payload = resp.json()
        except httpx.HTTPError as exc:
            raise UnauthorizedError("OIDC JWKS endpoint unreachable") from exc
        finally:
            if close_client:
                await client.aclose()

        raw_keys = payload.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise UnauthorizedError("OIDC JWKS contains no keys")

        key_map: dict[str, PyJWK] = {}
        key_list: list[PyJWK] = []
        for entry in raw_keys:
            if not isinstance(entry, dict):
                continue
            use = entry.get("use")
            if use is not None and use != "sig":
                continue
            jwk_obj = PyJWK.from_dict(entry)
            key_list.append(jwk_obj)
            kid = entry.get("kid")
            if isinstance(kid, str) and kid:
                key_map[kid] = jwk_obj

        if not key_list:
            raise UnauthorizedError("OIDC JWKS contains no signing keys")

        self._jwks_keys = key_map
        self._jwks_list = key_list
        self._jwks_fetched_at = time.monotonic()

    async def _get_signing_key(
        self,
        *,
        kid: str | None,
        settings: Settings,
        http_client: httpx.AsyncClient | None = None,
    ) -> PyJWK:
        metadata = await self.get_metadata(settings, http_client=http_client)
        now = time.monotonic()
        cache_expired = (now - self._jwks_fetched_at) >= settings.oidc_jwks_cache_ttl_seconds

        if not self._jwks_list or cache_expired:
            await self._fetch_jwks(metadata.jwks_uri, http_client=http_client)

        if kid:
            signing_key = self._jwks_keys.get(kid)
            if signing_key is None:
                # Key rotation handling: force immediate JWKS refresh on unknown kid.
                await self._fetch_jwks(metadata.jwks_uri, http_client=http_client)
                signing_key = self._jwks_keys.get(kid)
            if signing_key is None:
                raise UnauthorizedError("Token signing key id not found in JWKS")
            return signing_key

        if len(self._jwks_list) == 1:
            return self._jwks_list[0]
        raise UnauthorizedError("Token missing key id for multi-key JWKS")

    async def build_authorization_url(
        self,
        *,
        settings: Settings,
        state: str,
        nonce: str,
        code_challenge: str,
        prompt: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> str:
        """Build OIDC Authorization Code + PKCE redirect URL."""
        metadata = await self.get_metadata(settings, http_client=http_client)
        query_params: dict[str, str] = {
            "response_type": "code",
            "client_id": settings.oidc_client_id,
            "redirect_uri": settings.oidc_redirect_uri,
            "scope": settings.oidc_scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if prompt:
            query_params["prompt"] = prompt
        params = urlencode(query_params)
        separator = "&" if "?" in metadata.authorization_endpoint else "?"
        return f"{metadata.authorization_endpoint}{separator}{params}"

    async def build_logout_url(
        self,
        *,
        settings: Settings,
        post_logout_redirect_uri: str | None = None,
        id_token_hint: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> str | None:
        """Build OIDC RP-Initiated Logout URL if the provider advertises end_session_endpoint."""
        if not settings.oidc_enabled or not settings.oidc_issuer:
            return None
        metadata = await self.get_metadata(settings, http_client=http_client)
        if not metadata.end_session_endpoint:
            return None
        query_params: dict[str, str] = {}
        if id_token_hint:
            query_params["id_token_hint"] = id_token_hint
        else:
            query_params["client_id"] = settings.oidc_client_id
        if post_logout_redirect_uri:
            query_params["post_logout_redirect_uri"] = post_logout_redirect_uri
        if not query_params:
            return metadata.end_session_endpoint
        params = urlencode(query_params)
        separator = "&" if "?" in metadata.end_session_endpoint else "?"
        return f"{metadata.end_session_endpoint}{separator}{params}"

    async def exchange_code_for_tokens(
        self,
        *,
        settings: Settings,
        code: str,
        code_verifier: str,
        http_client: httpx.AsyncClient | None = None,
    ) -> dict[str, Any]:
        """Exchange authorization code + PKCE code_verifier at token endpoint."""
        metadata = await self.get_metadata(settings, http_client=http_client)
        form_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "client_id": settings.oidc_client_id,
            "code_verifier": code_verifier,
        }
        if settings.oidc_client_secret:
            form_data["client_secret"] = settings.oidc_client_secret

        close_client = http_client is None
        client = http_client or httpx.AsyncClient(timeout=5.0)
        try:
            resp = await client.post(metadata.token_endpoint, data=form_data)
            if resp.status_code != 200:
                raise UnauthorizedError("OIDC token exchange failed")
            payload = resp.json()
        except httpx.HTTPError as exc:
            raise UnauthorizedError("OIDC token endpoint unreachable") from exc
        finally:
            if close_client:
                await client.aclose()

        if not isinstance(payload, dict) or not isinstance(payload.get("id_token"), str):
            raise UnauthorizedError("OIDC token response missing id_token")
        return payload

    async def verify_jwt(
        self,
        *,
        token: str,
        settings: Settings,
        expected_nonce: str | None = None,
        http_client: httpx.AsyncClient | None = None,
    ) -> OidcIdentity:
        """Verify JWT signature, algorithm allowlist, issuer, audience, exp, nbf, and nonce."""
        if not settings.oidc_issuer or not settings.oidc_client_id:
            raise UnauthorizedError("OIDC validation is not configured")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("Malformed JWT header") from exc

        alg = header.get("alg")
        allowed_algs = [
            item for item in settings.oidc_allowed_algorithms if item not in _FORBIDDEN_ALGORITHMS
        ]
        if not isinstance(alg, str) or alg not in allowed_algs:
            raise UnauthorizedError("Disallowed JWT signing algorithm")

        raw_kid = header.get("kid")
        kid = raw_kid if isinstance(raw_kid, str) and raw_kid else None
        signing_key = await self._get_signing_key(
            kid=kid,
            settings=settings,
            http_client=http_client,
        )

        expected_issuer = settings.oidc_issuer.rstrip("/")
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=signing_key.key,
                algorithms=[alg],
                issuer=expected_issuer,
                audience=settings.oidc_client_id,
                leeway=settings.oidc_clock_skew_seconds,
                options={
                    "require": ["exp", "iss", "aud", "sub"],
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iss": True,
                    "verify_aud": True,
                },
            )
        except jwt.ExpiredSignatureError as exc:
            raise UnauthorizedError("Token has expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise UnauthorizedError("Token is not yet valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise UnauthorizedError("Invalid token issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise UnauthorizedError("Invalid token audience") from exc
        except jwt.PyJWTError as exc:
            raise UnauthorizedError("Invalid token signature or claims") from exc

        aud_claim = claims.get("aud")
        if isinstance(aud_claim, list) and len(aud_claim) > 1:
            azp = claims.get("azp")
            if azp != settings.oidc_client_id:
                raise UnauthorizedError("Invalid authorized party (azp) claim")

        if expected_nonce is not None:
            token_nonce = claims.get("nonce")
            if not isinstance(token_nonce, str) or not hmac.compare_digest(
                token_nonce, expected_nonce
            ):
                raise UnauthorizedError("Invalid OIDC nonce")

        subject = str(claims.get("sub", "")).strip()
        if not subject:
            raise UnauthorizedError("Token missing subject claim")

        email = str(claims.get("email") or f"{subject}@oidc.local").strip().lower()
        display_name = str(claims.get("name") or claims.get("preferred_username") or email).strip()[
            :200
        ]
        email_verified = bool(claims.get("email_verified", False))

        return OidcIdentity(
            issuer=expected_issuer,
            subject=subject,
            email=email,
            display_name=display_name or subject[:200],
            email_verified=email_verified,
        )


oidc_client = OidcClient()
