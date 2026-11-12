"""Extensible SecretProvider interface and environment/OpenBao adapters.

Centralizes secret lookup so application services never scatter direct
``os.environ`` reads or bake secrets into source/images. Production deployments
must avoid `.env` files and permanent root tokens.
"""

from __future__ import annotations

import os
import re
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

_PRODUCTION_ENVS = frozenset({"production", "prod", "staging"})


class SecretResolutionError(RuntimeError):
    """Raised when a required secret cannot be resolved without leaking secret values."""


class SecretProviderNotConfiguredError(SecretResolutionError):
    """Raised when a future/enterprise secret backend is selected without runtime wiring."""


@dataclass(frozen=True, slots=True)
class SecretLease:
    """Metadata describing a resolved secret or dynamic credential lease."""

    provider: str
    key: str
    lease_id: str | None = None
    ttl_seconds: int | None = None
    renewable: bool = False
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class DatabaseCredentials:
    """Typed database login bundle returned by a SecretProvider."""

    username: str
    password: str = field(repr=False)
    host: str
    port: int
    database: str
    lease: SecretLease | None = None


class SecretProvider(ABC):
    """Abstract base class for VForge secret providers."""

    provider_name: str

    @abstractmethod
    def get_secret(self, name: str, *, required: bool = True) -> str | None:
        """Resolve a named secret value without logging or exposing plaintext."""

    def get_database_credentials(
        self,
        *,
        username: str,
        password_key: str,
        host: str,
        port: int,
        database: str,
    ) -> DatabaseCredentials:
        """Resolve structured database credentials; overridable for dynamic DB leases."""
        password = self.get_secret(password_key, required=True)
        if not password:
            raise SecretResolutionError(f"Missing required database secret '{password_key}'")
        return DatabaseCredentials(
            username=username,
            password=password,
            host=host,
            port=port,
            database=database,
            lease=SecretLease(provider=self.provider_name, key=password_key),
        )

    @abstractmethod
    def describe_capabilities(self) -> dict[str, Any]:
        """Return non-sensitive provider capabilities and readiness metadata."""


class LocalDevelopmentProvider(SecretProvider):
    """Local development/test secret provider backed by process environment mappings.

    Refuses to initialize in production/staging environments so `.env` or ad-hoc
    host environment secrets cannot silently become production practice.
    """

    provider_name = "local_dev"

    def __init__(
        self,
        *,
        environment: str = "development",
        env_mapping: Mapping[str, str] | None = None,
        allow_in_production: bool = False,
    ) -> None:
        normalized_env = environment.strip().lower()
        if normalized_env in _PRODUCTION_ENVS and not allow_in_production:
            raise SecretResolutionError(
                "LocalDevelopmentProvider is forbidden in production/staging environments"
            )
        self._env: Mapping[str, str] = env_mapping if env_mapping is not None else os.environ

    def get_secret(self, name: str, *, required: bool = True) -> str | None:
        raw = self._env.get(name)
        value = raw.strip() if isinstance(raw, str) else ""
        if not value:
            if required:
                raise SecretResolutionError(
                    f"Required local development secret '{name}' is not set"
                )
            return None
        return value

    def describe_capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "dynamic_credentials": False,
            "lease_renewal": False,
            "production_allowed": False,
        }


class DockerSecretProvider(SecretProvider):
    """File-based secret provider reading mounted secrets (e.g. `/run/secrets/<key>`).

    Validates path containment to prevent path-traversal escapes outside `secrets_dir`.
    Supports `<KEY>_FILE` pointer overrides and optional controlled env fallback.
    """

    provider_name = "docker_secret"

    def __init__(
        self,
        *,
        secrets_dir: str | Path = "/run/secrets",
        env_mapping: Mapping[str, str] | None = None,
        allow_env_fallback: bool = False,
    ) -> None:
        self._secrets_dir = Path(secrets_dir)
        self._env: Mapping[str, str] = env_mapping if env_mapping is not None else os.environ
        self._allow_env_fallback = allow_env_fallback

    def _safe_secret_path(self, name: str) -> Path:
        if not name or "/" in name or "\\" in name or ".." in name or name.startswith("."):
            raise SecretResolutionError(f"Invalid secret identifier '{name}'")
        base = self._secrets_dir.resolve()
        candidate = (base / name).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as exc:
            raise SecretResolutionError(
                f"Secret path for '{name}' escapes configured secrets directory"
            ) from exc
        return candidate

    def _validate_pointer_path(self, pointer_path: str, *, name: str) -> Path:
        raw = Path(pointer_path)
        if ".." in raw.parts:
            raise SecretResolutionError(f"Secret file path for '{name}' contains path traversal")
        candidate = raw.resolve()
        base = self._secrets_dir.resolve()
        run_secrets = Path("/run/secrets").resolve()
        allowed_bases = (base, run_secrets)
        if not any(candidate.is_relative_to(allowed) for allowed in allowed_bases):
            raise SecretResolutionError(
                f"Secret file path for '{name}' escapes configured secrets directory"
            )
        return candidate

    def get_secret(self, name: str, *, required: bool = True) -> str | None:
        pointer_path = self._env.get(f"{name}_FILE", "").strip()
        target_path = (
            self._validate_pointer_path(pointer_path, name=name)
            if pointer_path
            else self._safe_secret_path(name)
        )

        if target_path.is_file():
            content = target_path.read_text(encoding="utf-8").rstrip("\r\n")
            if content:
                return content

        if self._allow_env_fallback:
            env_val = self._env.get(name, "").strip()
            if env_val:
                return env_val

        if required:
            raise SecretResolutionError(
                f"Required Docker/mounted secret '{name}' could not be resolved"
            )
        return None

    def describe_capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "secrets_dir": str(self._secrets_dir),
            "dynamic_credentials": False,
            "lease_renewal": False,
            "production_allowed": True,
        }


@dataclass(frozen=True, slots=True)
class OpenBaoConfig:
    """Non-secret connection and auth metadata for OpenBao readiness."""

    addr: str = ""
    namespace: str = ""
    auth_method: str = "approle"
    auth_role: str = ""
    role_id: str = ""
    secret_id_file: str = ""
    jwt_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    kv_mount: str = "secret"
    db_mount: str = "database"
    db_role: str = "vforge-api"
    valkey_role: str = "vforge-valkey"
    rabbitmq_mount: str = "rabbitmq"
    rabbitmq_role: str = "vforge-api"


_SAFE_BAO_PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_SAFE_BAO_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class OpenBaoProvider(SecretProvider):
    """OpenBao (KV v2 + Database + RabbitMQ + Valkey dynamic leases) runtime provider.

    Enforces least-privilege workload identity (`approle`, `kubernetes`, `jwt`,
    `oidc`), validates OpenBao endpoint scheme/host, keeps short-lived tokens
    strictly in memory (`repr=False`, never logged), and supports dynamic DB/broker
    credential leases plus explicit lease renewal.
    """

    provider_name = "openbao"
    _ALLOWED_AUTH_METHODS = frozenset({"approle", "kubernetes", "jwt", "oidc"})

    def __init__(
        self,
        config: OpenBaoConfig,
        *,
        env_mapping: Mapping[str, str] | None = None,
        environment: str = "development",
        http_transport: httpx.BaseTransport | None = None,
        timeout_seconds: float = 5.0,
    ) -> None:
        env = env_mapping if env_mapping is not None else os.environ
        if env.get("BAO_TOKEN") or env.get("VAULT_TOKEN"):
            raise SecretResolutionError(
                "Static BAO_TOKEN/VAULT_TOKEN tokens are forbidden inside application containers; "
                "use short-lived workload auth (approle/kubernetes/jwt/oidc)"
            )
        if config.auth_method not in self._ALLOWED_AUTH_METHODS:
            raise SecretResolutionError(f"Unsupported OpenBao auth method '{config.auth_method}'")
        self.config = config
        self._environment = environment.strip().lower()
        self._transport = http_transport
        self._timeout = timeout_seconds
        self._token_lock = threading.Lock()
        self._client_token: str | None = None
        self._token_expires_at: float = 0.0

    def __repr__(self) -> str:
        return (
            f"OpenBaoProvider(addr={self.config.addr!r}, "
            f"auth_method={self.config.auth_method!r}, "
            f"authenticated={bool(self._client_token)})"
        )

    def _validated_base_url(self) -> str:
        raw = self.config.addr.strip().rstrip("/")
        if not raw:
            raise SecretProviderNotConfiguredError(
                "OpenBao address is not configured; cannot perform secret operation"
            )
        parsed = urlsplit(raw)
        if parsed.username or parsed.password:
            raise SecretResolutionError("OpenBao URL must not embed credentials")
        if parsed.scheme == "https":
            if not parsed.netloc:
                raise SecretResolutionError("OpenBao HTTPS URL is missing host")
            return raw
        if (
            parsed.scheme == "http"
            and self._environment not in _PRODUCTION_ENVS
            and (parsed.hostname or "") in {"127.0.0.1", "localhost", "openbao"}
        ):
            return raw
        raise SecretResolutionError(
            "OpenBao endpoint must use HTTPS in production/staging "
            "(loopback HTTP allowed only in dev/test)"
        )

    def _build_client(self) -> httpx.Client:
        base_url = self._validated_base_url()
        return httpx.Client(
            base_url=base_url,
            timeout=self._timeout,
            follow_redirects=False,
            transport=self._transport,
        )

    @staticmethod
    def _validate_path(raw: str, *, allow_slash: bool, label: str) -> str:
        clean = raw.strip().strip("/")
        pattern = _SAFE_BAO_PATH_RE if allow_slash else _SAFE_BAO_SEGMENT_RE
        if not clean or ".." in clean or not pattern.match(clean):
            raise SecretResolutionError(f"Invalid OpenBao {label}")
        return clean

    def _authenticate(self, client: httpx.Client, *, force_refresh: bool = False) -> str:
        with self._token_lock:
            if (
                not force_refresh
                and self._client_token
                and time.monotonic() < (self._token_expires_at - 10.0)
            ):
                return self._client_token

            headers: dict[str, str] = {}
            if self.config.namespace:
                headers["X-Vault-Namespace"] = self.config.namespace

            method = self.config.auth_method
            try:
                if method == "approle":
                    if not self.config.role_id.strip():
                        raise SecretProviderNotConfiguredError(
                            "OpenBao AppRole role_id is not configured"
                        )
                    secret_id = ""
                    if self.config.secret_id_file:
                        p = Path(self.config.secret_id_file)
                        if not p.is_file():
                            raise SecretResolutionError("OpenBao secret_id_file does not exist")
                        secret_id = p.read_text(encoding="utf-8").strip()
                    if not secret_id:
                        raise SecretProviderNotConfiguredError(
                            "OpenBao AppRole secret_id_file is not configured or empty"
                        )
                    resp = client.post(
                        "/v1/auth/approle/login",
                        json={"role_id": self.config.role_id.strip(), "secret_id": secret_id},
                        headers=headers,
                    )
                elif method in {"kubernetes", "jwt", "oidc"}:
                    jwt_file = Path(self.config.jwt_path)
                    if not jwt_file.is_file():
                        raise SecretProviderNotConfiguredError(
                            f"OpenBao {method} token file is not present"
                        )
                    jwt_token = jwt_file.read_text(encoding="utf-8").strip()
                    if not jwt_token:
                        raise SecretResolutionError(f"OpenBao {method} token file is empty")
                    auth_role = (self.config.auth_role or self.config.db_role).strip()
                    if not auth_role:
                        raise SecretProviderNotConfiguredError(
                            f"OpenBao {method} auth_role is not configured"
                        )
                    resp = client.post(
                        f"/v1/auth/{method}/login",
                        json={"role": auth_role, "jwt": jwt_token},
                        headers=headers,
                    )
                else:
                    raise SecretResolutionError(f"Unsupported OpenBao auth method '{method}'")
            except httpx.HTTPError as exc:
                raise SecretResolutionError(
                    f"OpenBao authentication request failed ({type(exc).__name__})"
                ) from exc

            if resp.status_code >= 400:
                raise SecretResolutionError(
                    f"OpenBao authentication failed with HTTP {resp.status_code}"
                )
            try:
                payload = resp.json()
            except ValueError as exc:
                raise SecretResolutionError("OpenBao login returned malformed JSON") from exc
            auth_data = payload.get("auth") if isinstance(payload, dict) else None
            if not isinstance(auth_data, dict):
                raise SecretResolutionError("OpenBao login response omitted auth payload")
            token = str(auth_data.get("client_token", "")).strip()
            if not token:
                raise SecretResolutionError("OpenBao login response omitted client_token")
            lease_duration = int(auth_data.get("lease_duration", 300) or 300)
            self._client_token = token
            self._token_expires_at = time.monotonic() + max(lease_duration, 30)
            return token

    def _request_with_reauth(
        self,
        client: httpx.Client,
        method: str,
        path: str,
        *,
        json_body: dict[str, Any] | None = None,
    ) -> httpx.Response:
        token = self._authenticate(client)
        try:
            resp = client.request(
                method,
                path,
                json=json_body,
                headers=self._auth_headers(token),
            )
            if resp.status_code in {401, 403}:
                token = self._authenticate(client, force_refresh=True)
                resp = client.request(
                    method,
                    path,
                    json=json_body,
                    headers=self._auth_headers(token),
                )
        except httpx.HTTPError as exc:
            raise SecretResolutionError(f"OpenBao request failed ({type(exc).__name__})") from exc
        return resp

    def _auth_headers(self, token: str) -> dict[str, str]:
        headers = {"X-Vault-Token": token}
        if self.config.namespace:
            headers["X-Vault-Namespace"] = self.config.namespace
        return headers

    def get_secret(self, name: str, *, required: bool = True) -> str | None:
        if not self.config.addr.strip():
            if not required:
                return None
            raise SecretProviderNotConfiguredError(
                f"OpenBao address is not configured; cannot resolve '{name}'"
            )
        clean_name = self._validate_path(name, allow_slash=True, label="secret key")
        mount = self._validate_path(
            self.config.kv_mount or "secret", allow_slash=False, label="kv_mount"
        )
        with self._build_client() as client:
            resp = self._request_with_reauth(client, "GET", f"/v1/{mount}/data/{clean_name}")
        if resp.status_code == 404 and not required:
            return None
        if resp.status_code >= 400:
            if not required:
                return None
            raise SecretResolutionError(
                f"OpenBao KV read failed for '{clean_name}' with HTTP {resp.status_code}"
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise SecretResolutionError("OpenBao KV read returned malformed JSON") from exc
        data_section = body.get("data", {}).get("data", {}) if isinstance(body, dict) else {}
        if isinstance(data_section, dict):
            if "value" in data_section and str(data_section["value"]):
                return str(data_section["value"])
            if clean_name in data_section and str(data_section[clean_name]):
                return str(data_section[clean_name])
        if required:
            raise SecretResolutionError(f"OpenBao KV secret '{clean_name}' returned empty value")
        return None

    def get_database_credentials(
        self,
        *,
        username: str,
        password_key: str,
        host: str,
        port: int,
        database: str,
    ) -> DatabaseCredentials:
        """Request short-lived dynamic PostgreSQL credentials from OpenBao database engine."""
        if not self.config.addr.strip():
            raise SecretProviderNotConfiguredError(
                "OpenBao dynamic database credentials require openbao_addr configuration"
            )
        mount = self._validate_path(
            self.config.db_mount or "database", allow_slash=False, label="db_mount"
        )
        role = self._validate_path(
            self.config.db_role or "vforge-api", allow_slash=False, label="db_role"
        )
        with self._build_client() as client:
            resp = self._request_with_reauth(client, "GET", f"/v1/{mount}/creds/{role}")
        if resp.status_code >= 400:
            raise SecretResolutionError(
                f"OpenBao dynamic database lease failed with HTTP {resp.status_code}"
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise SecretResolutionError("OpenBao dynamic DB response malformed JSON") from exc
        data = body.get("data", {}) if isinstance(body, dict) else {}
        dyn_user = str(data.get("username") or username).strip()
        dyn_pass = str(data.get("password") or "")
        if not dyn_user or not dyn_pass:
            raise SecretResolutionError("OpenBao dynamic database response lacked credentials")
        lease_id = str(body.get("lease_id") or "") or None
        ttl_raw = body.get("lease_duration")
        ttl_seconds = int(ttl_raw) if ttl_raw is not None else None
        renewable = bool(body.get("renewable", False))
        return DatabaseCredentials(
            username=dyn_user,
            password=dyn_pass,
            host=host,
            port=port,
            database=database,
            lease=SecretLease(
                provider=self.provider_name,
                key=f"{mount}/creds/{role}",
                lease_id=lease_id,
                ttl_seconds=ttl_seconds,
                renewable=renewable,
            ),
        )

    def renew_lease(self, lease_id: str, *, increment_seconds: int = 3600) -> SecretLease:
        """Renew an active dynamic credential lease in OpenBao."""
        clean_id = lease_id.strip()
        if not clean_id:
            raise SecretResolutionError("lease_id is required for lease renewal")
        with self._build_client() as client:
            resp = self._request_with_reauth(
                client,
                "PUT",
                "/v1/sys/leases/renew",
                json_body={"lease_id": clean_id, "increment": increment_seconds},
            )
        if resp.status_code >= 400:
            raise SecretResolutionError(
                f"OpenBao lease renewal failed with HTTP {resp.status_code}"
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise SecretResolutionError("OpenBao lease renewal returned malformed JSON") from exc
        return SecretLease(
            provider=self.provider_name,
            key="sys/leases/renew",
            lease_id=str(body.get("lease_id") or clean_id),
            ttl_seconds=int(body.get("lease_duration") or increment_seconds),
            renewable=bool(body.get("renewable", True)),
        )

    def describe_capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "configured": bool(self.config.addr),
            "auth_method": self.config.auth_method,
            "lease_wiring": "explicit_api_available",
            "pool_auto_rotation_wired": False,
            "engines": {
                "kv_v2": {"mount": self.config.kv_mount, "supported": True},
                "postgres": {
                    "engine": "database",
                    "plugin": "postgresql-database-plugin",
                    "mount": self.config.db_mount,
                    "role": self.config.db_role,
                    "dynamic_credentials": True,
                },
                "valkey": {
                    "engine": "database",
                    "plugin": "valkey-database-plugin",
                    "mount": self.config.db_mount,
                    "role": self.config.valkey_role,
                    "dynamic_credentials": False,
                    "planned_engine": True,
                },
                "rabbitmq": {
                    "engine": "rabbitmq",
                    "mount": self.config.rabbitmq_mount,
                    "role": self.config.rabbitmq_role,
                    "dynamic_credentials": False,
                    "planned_engine": True,
                },
            },
            "lease_renewal": True,
            "production_allowed": True,
        }


class FutureExternalSecretProvider(SecretProvider):
    """Extension hook for cloud/cluster secret managers (aws-sm, gcp-sm, azure-kv, k8s)."""

    provider_name = "external"

    def __init__(self, *, backend_scheme: str = "k8s-secret") -> None:
        self.backend_scheme = backend_scheme

    def get_secret(self, name: str, *, required: bool = True) -> str | None:
        if not required:
            return None
        raise SecretProviderNotConfiguredError(
            f"External secret provider '{self.backend_scheme}' is not enabled in this phase"
        )

    def describe_capabilities(self) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "backend_scheme": self.backend_scheme,
            "dynamic_credentials": False,
            "production_allowed": True,
        }


def build_secret_provider(
    *,
    provider_name: str,
    environment: str,
    docker_secrets_dir: str = "/run/secrets",
    openbao_config: OpenBaoConfig | None = None,
    env_mapping: Mapping[str, str] | None = None,
) -> SecretProvider:
    """Instantiate the configured SecretProvider with fail-closed environment checks."""
    normalized = provider_name.strip().lower() or "local_dev"
    if normalized == "local_dev":
        return LocalDevelopmentProvider(environment=environment, env_mapping=env_mapping)
    if normalized == "docker_secret":
        return DockerSecretProvider(
            secrets_dir=docker_secrets_dir,
            env_mapping=env_mapping,
            allow_env_fallback=environment.strip().lower() not in _PRODUCTION_ENVS,
        )
    if normalized == "openbao":
        return OpenBaoProvider(
            openbao_config or OpenBaoConfig(),
            env_mapping=env_mapping,
            environment=environment,
        )
    if normalized == "external":
        return FutureExternalSecretProvider()
    raise SecretResolutionError(f"Unknown secret provider '{provider_name}'")
