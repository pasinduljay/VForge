"""Application configuration, safe URL construction, and centralized secret resolution."""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Any
from urllib.parse import quote

from pydantic import Field
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from sqlalchemy.engine import URL

from vforge.secrets import (
    OpenBaoConfig,
    SecretProvider,
    SecretResolutionError,
    build_secret_provider,
)

_PRODUCTION_ENVS = frozenset({"production", "prod", "staging"})


def build_postgres_url(
    *,
    username: str,
    password: str,
    host: str,
    port: int,
    database: str,
) -> str:
    """Safely construct a PostgreSQL psycopg3 URL using SQLAlchemy's URL API."""
    if not username or not password or not host or not database:
        raise ValueError("PostgreSQL connection parameters must all be non-empty")
    return URL.create(
        drivername="postgresql+psycopg",
        username=username,
        password=password,
        host=host,
        port=port,
        database=database,
    ).render_as_string(hide_password=False)


def build_amqp_url(
    *,
    username: str,
    password: str,
    host: str,
    port: int,
    vhost: str,
) -> str:
    """Safely construct an AMQP URL with RFC-compliant credential and vhost escaping."""
    if not username or not password or not host:
        raise ValueError("RabbitMQ connection parameters must all be non-empty")
    enc_user = quote(username, safe="")
    enc_pass = quote(password, safe="")
    clean_vhost = vhost if vhost else "/"
    enc_vhost = quote(clean_vhost, safe="")
    return f"amqp://{enc_user}:{enc_pass}@{host}:{port}/{enc_vhost}"


def build_valkey_url(
    *,
    username: str,
    password: str,
    host: str,
    port: int,
    db: int = 0,
) -> str:
    """Safely construct a Valkey/Redis ACL URL with escaped userinfo."""
    if not password or not host:
        raise ValueError("Valkey password and host must be non-empty")
    enc_user = quote(username, safe="") if username else ""
    enc_pass = quote(password, safe="")
    userinfo = f"{enc_user}:{enc_pass}" if enc_user else f":{enc_pass}"
    return f"redis://{userinfo}@{host}:{port}/{db}"


class Settings(BaseSettings):
    """Runtime settings for the VForge control-plane API."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    vforge_env: str = "development"
    log_level: str = "INFO"

    # Secret provider configuration (Phase 3 preflight / OpenBao readiness)
    secret_provider: str = "local_dev"  # noqa: S105
    docker_secrets_dir: str = "/run/secrets"
    openbao_addr: str = ""
    openbao_namespace: str = ""
    openbao_auth_method: str = "approle"
    openbao_auth_role: str = ""
    openbao_role_id: str = ""
    openbao_secret_id_file: str = ""
    openbao_jwt_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    openbao_kv_mount: str = "secret"
    openbao_db_mount: str = "database"
    openbao_db_role: str = "vforge-api"
    openbao_valkey_role: str = "vforge-valkey"
    openbao_rabbitmq_mount: str = "rabbitmq"
    openbao_rabbitmq_role: str = "vforge-api"

    # Legacy/override URL fields (used by unit tests or explicit connection overrides)
    database_url: str = Field(default="", repr=False)
    migration_database_url: str = Field(default="", repr=False)
    rabbitmq_url: str = Field(default="", repr=False)
    cache_url: str = Field(default="", repr=False)

    # Structured runtime connection fields (single source of truth; no URL duplication)
    postgres_host: str = "postgres"
    postgres_port: int = 5432
    postgres_db: str = "vforge"
    postgres_app_user: str = "vforge_app"
    postgres_app_password: str = Field(default="", repr=False)

    # Dedicated migration credentials (MUST NOT be passed to runtime API containers)
    postgres_migrator_user: str = "vforge_migrator"
    postgres_migrator_password: str = Field(default="", repr=False)

    rabbitmq_host: str = "rabbitmq"
    rabbitmq_port: int = 5672
    rabbitmq_vhost: str = "vforge"
    rabbitmq_app_user: str = "vforge_app"
    rabbitmq_app_password: str = Field(default="", repr=False)

    valkey_host: str = "valkey"
    valkey_port: int = 6379
    valkey_db: int = 0
    valkey_app_user: str = "vforge_app"
    valkey_app_password: str = Field(default="", repr=False)

    opa_url: str = "http://opa:8181"
    artifact_root: str = "/var/lib/vforge/artifacts"

    # OIDC & Session Settings (Phase 1)
    oidc_enabled: bool = False
    oidc_issuer: str = ""
    oidc_internal_base_url: str = ""
    oidc_client_id: str = "vforge-api"
    oidc_client_secret: str = Field(default="", repr=False)
    oidc_redirect_uri: str = "http://127.0.0.1:3000/api/v1/auth/oidc/callback"
    oidc_scopes: str = "openid profile email"
    oidc_allowed_algorithms: list[str] = ["RS256", "ES256", "EdDSA"]
    oidc_clock_skew_seconds: int = 30
    oidc_jwks_cache_ttl_seconds: int = 300

    session_cookie_name: str = "vf_session"
    session_csrf_cookie_name: str = "vf_csrf"
    session_ttl_seconds: int = 28800  # 8 hours
    session_idle_timeout_seconds: int = 3600  # 1 hour
    session_cookie_secure: bool | None = None
    session_cookie_samesite: str = "lax"

    cors_allowed_origins: list[str] = ["http://127.0.0.1:3000", "http://localhost:3000"]
    frontend_base_url: str = "http://127.0.0.1:3000"
    auth_rate_limit_per_minute: int = 20
    sensitive_rate_limit_per_minute: int = 60

    # Phase 2: OPA & Scope Snapshot Signing
    opa_timeout_seconds: float = 5.0
    policy_bundle_version: str = "2026-11-12.v2"
    scope_signing_key_id: str = "vf-scope-dev-1"
    scope_signing_private_key_path: str = ""
    scope_signing_private_key_pem: str = Field(default="", repr=False)
    scope_signing_public_keys_json: str = ""
    require_live_dns_on_approval: bool = False

    # Phase 4: Runner mTLS Gateway, Signed Manifests & Artifact Envelope Encryption
    runner_mtls_ca_cert_path: str = ""
    runner_gateway_cert_path: str = ""
    runner_gateway_key_path: str = ""
    runner_manifest_ttl_seconds: int = 1800
    runner_heartbeat_online_window_seconds: int = 120
    runner_max_artifact_bytes: int = 26_214_400  # 25 MiB per artifact
    opengrep_image_digest: str = (
        "vforge-opengrep:1.33.1@sha256:"
        "a92cb260fea66c388fdf32924ae67ae933be6f13473e3e5c945182c1e4c01365"
    )
    gitleaks_image_digest: str = (
        "zricethezav/gitleaks@sha256:"
        "2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176"
    )
    syft_image_digest: str = (
        "anchore/syft@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060"
    )
    grype_image_digest: str = (
        "anchore/grype@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887"
    )
    checkov_image_digest: str = (
        "bridgecrew/checkov@sha256:ccead19bd9201d43872ceb7e78bb5868eabfc0d3960d3756fc75f4896067372a"
    )
    zap_image_digest: str = (
        "ghcr.io/zaproxy/zaproxy@sha256:"
        "391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908"
    )
    nuclei_image_digest: str = (
        "projectdiscovery/nuclei@sha256:"
        "582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb"
    )
    nmap_image_digest: str = (
        "instrumentisto/nmap@sha256:"
        "96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827"
    )
    testssl_image_digest: str = (
        "drwetter/testssl.sh@sha256:"
        "e42cb1ba9445ea861e8b6eec96b97f6f293ce4e5908eebc75c28bdd96d66108e"
    )
    source_snapshot_max_archive_bytes: int = 20_971_520  # 20 MiB
    source_snapshot_max_extracted_bytes: int = 52_428_800  # 50 MiB
    source_snapshot_max_files: int = 5000
    runner_allowed_image_digests: list[str] = [
        "vforge/dummy-scanner@sha256:0000000000000000000000000000000000000000000000000000000000000001",
        "vforge-opengrep:1.33.1@sha256:a92cb260fea66c388fdf32924ae67ae933be6f13473e3e5c945182c1e4c01365",
        "zricethezav/gitleaks@sha256:2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176",
        "anchore/syft@sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060",
        "anchore/grype@sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887",
        "bridgecrew/checkov@sha256:ccead19bd9201d43872ceb7e78bb5868eabfc0d3960d3756fc75f4896067372a",
        "ghcr.io/zaproxy/zaproxy@sha256:391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908",
        "projectdiscovery/nuclei@sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb",
        "instrumentisto/nmap@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827",
        "drwetter/testssl.sh@sha256:e42cb1ba9445ea861e8b6eec96b97f6f293ce4e5908eebc75c28bdd96d66108e",
    ]
    artifact_encryption_key_id: str = "vf-artifact-dev-1"
    artifact_encryption_key_b64: str = Field(default="", repr=False)
    artifact_encryption_keyring_json: str = Field(default="", repr=False)
    backup_encryption_key_id: str = "vf-backup-dev-1"
    backup_encryption_key_b64: str = Field(default="", repr=False)
    runner_cert_expiry_warning_days: int = 30
    metrics_enabled: bool = True
    metrics_bearer_token_required: bool = False
    metrics_bearer_token: str = Field(default="", repr=False)
    platform_admin_emails: list[str] = Field(default_factory=list)

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        """Ignore `.env` files completely in production and staging environments."""
        env_name = os.environ.get("VFORGE_ENV", "development").strip().lower()
        if env_name in _PRODUCTION_ENVS:
            return (init_settings, env_settings, file_secret_settings)
        return (init_settings, env_settings, dotenv_settings, file_secret_settings)

    def get_secret_provider(self) -> SecretProvider:
        """Return the configured SecretProvider for runtime credential resolution."""
        return build_secret_provider(
            provider_name=self.secret_provider,
            environment=self.vforge_env,
            docker_secrets_dir=self.docker_secrets_dir,
            openbao_config=OpenBaoConfig(
                addr=self.openbao_addr,
                namespace=self.openbao_namespace,
                auth_method=self.openbao_auth_method,
                auth_role=self.openbao_auth_role,
                role_id=self.openbao_role_id,
                secret_id_file=self.openbao_secret_id_file,
                jwt_path=self.openbao_jwt_path,
                kv_mount=self.openbao_kv_mount,
                db_mount=self.openbao_db_mount,
                db_role=self.openbao_db_role,
                valkey_role=self.openbao_valkey_role,
                rabbitmq_mount=self.openbao_rabbitmq_mount,
                rabbitmq_role=self.openbao_rabbitmq_role,
            ),
        )

    def _resolve_secret(self, inline_value: str, secret_key: str) -> str:
        if inline_value:
            return inline_value
        if self.vforge_env.strip().lower() == "test":
            return ""
        try:
            provider = self.get_secret_provider()
            return provider.get_secret(secret_key, required=False) or ""
        except SecretResolutionError:
            return ""

    @property
    def effective_database_url(self) -> str:
        """Return runtime PostgreSQL URL constructed safely from non-owner credentials."""
        if self.database_url:
            return self.database_url
        password = self._resolve_secret(self.postgres_app_password, "POSTGRES_APP_PASSWORD")
        if not password:
            return ""
        return build_postgres_url(
            username=self.postgres_app_user,
            password=password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @property
    def effective_migration_database_url(self) -> str:
        """Return explicit migration-owner DB URL; never falls back to runtime DB URL."""
        if self.migration_database_url:
            return self.migration_database_url
        password = self._resolve_secret(
            self.postgres_migrator_password, "POSTGRES_MIGRATOR_PASSWORD"
        )
        if not password:
            return ""
        return build_postgres_url(
            username=self.postgres_migrator_user,
            password=password,
            host=self.postgres_host,
            port=self.postgres_port,
            database=self.postgres_db,
        )

    @property
    def effective_rabbitmq_url(self) -> str:
        """Return runtime RabbitMQ AMQP URL constructed safely from app credentials."""
        if self.rabbitmq_url:
            return self.rabbitmq_url
        password = self._resolve_secret(self.rabbitmq_app_password, "RABBITMQ_APP_PASSWORD")
        if not password:
            return ""
        return build_amqp_url(
            username=self.rabbitmq_app_user,
            password=password,
            host=self.rabbitmq_host,
            port=self.rabbitmq_port,
            vhost=self.rabbitmq_vhost,
        )

    @property
    def effective_cache_url(self) -> str:
        """Return runtime Valkey ACL URL constructed safely from app credentials."""
        if self.cache_url:
            return self.cache_url
        password = self._resolve_secret(self.valkey_app_password, "VALKEY_APP_PASSWORD")
        if not password:
            return ""
        return build_valkey_url(
            username=self.valkey_app_user,
            password=password,
            host=self.valkey_host,
            port=self.valkey_port,
            db=self.valkey_db,
        )

    @property
    def effective_cookie_secure(self) -> bool:
        """Default to Secure=True outside local development unless explicitly set."""
        if self.session_cookie_secure is not None:
            return self.session_cookie_secure
        return self.vforge_env not in {"development", "test"}

    def validate_startup_configuration(self) -> None:
        """Fail closed on missing runtime secrets or unsafe role/provider configuration."""
        env_name = self.vforge_env.strip().lower()
        if env_name in _PRODUCTION_ENVS:
            if self.secret_provider.strip().lower() == "local_dev":
                raise RuntimeError(
                    "SECRET_PROVIDER=local_dev is forbidden in production/staging environments"
                )
            if os.environ.get("BAO_TOKEN") or os.environ.get("VAULT_TOKEN"):
                raise RuntimeError(
                    "Static BAO_TOKEN/VAULT_TOKEN is forbidden inside production containers"
                )
            if not self.scope_signing_private_key_path.strip():
                raise RuntimeError(
                    "SCOPE_SIGNING_PRIVATE_KEY_PATH is required in production/staging"
                )

        if env_name != "test" and (self.migration_database_url or self.postgres_migrator_password):
            raise RuntimeError("Migration credentials must not be exposed to runtime API services")

        # Instantiate provider to verify provider-specific invariants
        self.get_secret_provider()

        missing: list[str] = []
        if not self.effective_database_url:
            missing.append("POSTGRES_APP_PASSWORD / DATABASE_URL")
        if not self.effective_rabbitmq_url:
            missing.append("RABBITMQ_APP_PASSWORD / RABBITMQ_URL")
        if not self.effective_cache_url:
            missing.append("VALKEY_APP_PASSWORD / CACHE_URL")
        if missing:
            joined = ", ".join(missing)
            raise RuntimeError(f"Missing required runtime connection credentials: {joined}")

        if env_name in _PRODUCTION_ENVS:
            from vforge.security.envelope import resolve_backup_kek, resolve_kek

            resolve_kek(self)
            resolve_backup_kek(self)
            if self.metrics_enabled and self.metrics_bearer_token_required:
                tok = self._resolve_secret(self.metrics_bearer_token, "METRICS_BEARER_TOKEN")
                if not tok:
                    raise RuntimeError(
                        "METRICS_BEARER_TOKEN is required when metrics_bearer_token_required=True"
                    )

    def redacted_summary(self) -> dict[str, Any]:
        """Return non-sensitive configuration metadata safe for diagnostics."""
        return {
            "vforge_env": self.vforge_env,
            "secret_provider": self.secret_provider,
            "postgres_host": self.postgres_host,
            "postgres_port": self.postgres_port,
            "postgres_db": self.postgres_db,
            "postgres_app_user": self.postgres_app_user,
            "rabbitmq_host": self.rabbitmq_host,
            "rabbitmq_port": self.rabbitmq_port,
            "rabbitmq_vhost": self.rabbitmq_vhost,
            "rabbitmq_app_user": self.rabbitmq_app_user,
            "valkey_host": self.valkey_host,
            "valkey_port": self.valkey_port,
            "valkey_db": self.valkey_db,
            "valkey_app_user": self.valkey_app_user,
            "opa_url": self.opa_url,
            "oidc_enabled": self.oidc_enabled,
            "database_configured": bool(self.effective_database_url),
            "rabbitmq_configured": bool(self.effective_rabbitmq_url),
            "valkey_configured": bool(self.effective_cache_url),
        }

    def __repr__(self) -> str:
        return (
            f"Settings(vforge_env={self.vforge_env!r}, "
            f"secret_provider={self.secret_provider!r}, "
            f"postgres_app_user={self.postgres_app_user!r}, "
            f"rabbitmq_app_user={self.rabbitmq_app_user!r}, "
            f"valkey_app_user={self.valkey_app_user!r})"
        )

    def __str__(self) -> str:
        return self.__repr__()


@lru_cache
def get_settings() -> Settings:
    """Return cached settings instance."""
    return Settings()
