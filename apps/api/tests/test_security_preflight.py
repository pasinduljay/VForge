"""Security preflight acceptance tests for secret handling, role separation, and ACLs."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from unittest.mock import AsyncMock

import aio_pika
import pytest
import valkey.asyncio as valkey_async
from pamqp.exceptions import PAMQPException
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.ext.asyncio import create_async_engine
from valkey.exceptions import NoPermissionError

from vforge.config import (
    Settings,
    build_amqp_url,
    build_postgres_url,
    build_valkey_url,
)
from vforge.db import verify_runtime_db_identity
from vforge.logging import redact_text, sanitize_exception_message
from vforge.secrets import (
    DockerSecretProvider,
    LocalDevelopmentProvider,
    OpenBaoConfig,
    OpenBaoProvider,
    SecretProviderNotConfiguredError,
    SecretResolutionError,
)


def _find_repo_root() -> Path | None:
    candidates = [Path("/workspace"), *Path(__file__).resolve().parents]
    for candidate in candidates:
        if (candidate / "docker-compose.yml").is_file() and (candidate / ".env.example").is_file():
            return candidate
    return None


def test_safe_url_builders_escape_special_characters() -> None:
    special_pw = "p@ss:w/rd?#%+=&!"
    pg_url = build_postgres_url(
        username="vforge_app",
        password=special_pw,
        host="postgres",
        port=5432,
        database="vforge",
    )
    parsed_pg = make_url(pg_url)
    assert parsed_pg.username == "vforge_app"
    assert parsed_pg.password == special_pw
    assert parsed_pg.host == "postgres"

    amqp_url = build_amqp_url(
        username="vforge_app",
        password=special_pw,
        host="rabbitmq",
        port=5672,
        vhost="vforge",
    )
    assert "p%40ss%3Aw%2Frd%3F%23%25%2B%3D%26%21@rabbitmq:5672/vforge" in amqp_url

    valkey_url = build_valkey_url(
        username="vforge_app",
        password=special_pw,
        host="valkey",
        port=6379,
        db=0,
    )
    assert valkey_url.startswith("redis://vforge_app:p%40ss%3Aw%2Frd%3F%23%25%2B%3D%26%21@")


def test_redaction_covers_empty_user_valkey_urls_basic_auth_and_exceptions() -> None:
    samples = [
        "redis://:ValkeySecret99@valkey:6379/0",
        "redis://vforge_app:ValkeySecret99@valkey:6379/0",
        "amqp://vforge_app:RmqSecret88@rabbitmq:5672/vforge",
        "postgresql+psycopg://vforge_app:PgSecret77@postgres:5432/vforge",
        "Authorization: Basic dXNlcjpwYXNzd29yZA==",
        "REDISCLI_AUTH=CliSecret66 client_secret=OidcSecret55",
    ]
    for sample in samples:
        redacted = redact_text(sample)
        for secret in (
            "ValkeySecret99",
            "RmqSecret88",
            "PgSecret77",
            "dXNlcjpwYXNzd29yZA==",
            "CliSecret66",
            "OidcSecret55",
        ):
            assert secret not in redacted

    exc = RuntimeError("connect failed to redis://:HiddenPass123@valkey:6379/0")
    safe_exc = sanitize_exception_message(exc)
    assert "HiddenPass123" not in safe_exc
    assert "[REDACTED]" in safe_exc


def test_settings_repr_and_summary_never_expose_credentials() -> None:
    secret = "SuperSecretValue_XYZ_987"
    s = Settings(
        vforge_env="test",
        postgres_app_password=secret,
        rabbitmq_app_password=secret,
        valkey_app_password=secret,
        oidc_client_secret=secret,
        scope_signing_private_key_pem=secret,
    )
    assert secret not in repr(s)
    assert secret not in str(s)
    assert secret not in json.dumps(s.redacted_summary())
    assert s.effective_migration_database_url == ""


def test_startup_validation_fails_on_missing_secrets_and_unsafe_prod_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for var_name in (
        "POSTGRES_APP_PASSWORD",
        "RABBITMQ_APP_PASSWORD",
        "VALKEY_APP_PASSWORD",
        "DATABASE_URL",
        "RABBITMQ_URL",
        "CACHE_URL",
    ):
        monkeypatch.delenv(var_name, raising=False)

    empty_settings = Settings(
        vforge_env="test",
        postgres_app_password="",
        rabbitmq_app_password="",
        valkey_app_password="",
        database_url="",
        rabbitmq_url="",
        cache_url="",
    )
    with pytest.raises(RuntimeError, match="Missing required runtime connection credentials"):
        empty_settings.validate_startup_configuration()

    # Migration credentials must never be exposed to ordinary API runtime
    leak_settings = Settings(
        vforge_env="development",
        postgres_app_password="app-pw-value",
        rabbitmq_app_password="rmq-pw-value",
        valkey_app_password="vk-pw-value",
        postgres_migrator_password="migrator-pw-value",
    )
    with pytest.raises(RuntimeError, match="Migration credentials must not be exposed"):
        leak_settings.validate_startup_configuration()

    # Production forbids local_dev provider and static OpenBao root tokens
    prod_local = Settings(
        vforge_env="production",
        secret_provider="local_dev",
        postgres_app_password="app-pw-value",
        rabbitmq_app_password="rmq-pw-value",
        valkey_app_password="vk-pw-value",
        scope_signing_private_key_path="/run/secrets/scope.pem",
    )
    with pytest.raises(RuntimeError, match="forbidden in production/staging"):
        prod_local.validate_startup_configuration()

    monkeypatch.setenv("VAULT_TOKEN", "root-token-forbidden")
    prod_token = Settings(
        vforge_env="production",
        secret_provider="openbao",
        postgres_app_password="app-pw-value",
        rabbitmq_app_password="rmq-pw-value",
        valkey_app_password="vk-pw-value",
        scope_signing_private_key_path="/run/secrets/scope.pem",
    )
    with pytest.raises(RuntimeError, match="VAULT_TOKEN is forbidden"):
        prod_token.validate_startup_configuration()


def test_secret_providers_docker_and_openbao_readiness(tmp_path: Path) -> None:
    secret_file = tmp_path / "POSTGRES_APP_PASSWORD"
    secret_file.write_text("mounted-secret-value\n", encoding="utf-8")

    docker_provider = DockerSecretProvider(secrets_dir=tmp_path)
    assert docker_provider.get_secret("POSTGRES_APP_PASSWORD") == "mounted-secret-value"
    with pytest.raises(SecretResolutionError, match="Invalid secret identifier"):
        docker_provider.get_secret("../escape")

    with pytest.raises(SecretResolutionError, match="forbidden in production"):
        LocalDevelopmentProvider(environment="production")

    with pytest.raises(SecretResolutionError, match="Static BAO_TOKEN/VAULT_TOKEN"):
        OpenBaoProvider(
            OpenBaoConfig(addr="https://bao.internal:8200"),
            env_mapping={"BAO_TOKEN": "x"},
        )

    bao = OpenBaoProvider(OpenBaoConfig(addr="https://bao.internal:8200", auth_method="approle"))
    caps = bao.describe_capabilities()
    assert caps["engines"]["postgres"]["plugin"] == "postgresql-database-plugin"
    assert caps["engines"]["valkey"]["plugin"] == "valkey-database-plugin"
    assert caps["engines"]["rabbitmq"]["engine"] == "rabbitmq"
    with pytest.raises(SecretProviderNotConfiguredError):
        bao.get_secret("POSTGRES_APP_PASSWORD")


async def test_verify_runtime_db_identity_rejects_privileged_roles() -> None:
    mock_conn = AsyncMock()
    mock_res = AsyncMock()
    mock_res.one = lambda: ("vforge", True, True, True, True, True, True)
    mock_conn.execute = AsyncMock(return_value=mock_res)

    class _Ctx:
        async def __aenter__(self) -> AsyncMock:
            return mock_conn

        async def __aexit__(self, *_args: object) -> None:
            return None

    class _FakeEngine:
        def connect(self) -> _Ctx:
            return _Ctx()

    with pytest.raises(RuntimeError, match="Unsafe PostgreSQL runtime identity 'vforge'"):
        await verify_runtime_db_identity(_FakeEngine())  # type: ignore[arg-type]


def test_api_runtime_environment_excludes_migration_and_admin_secrets() -> None:
    forbidden_runtime_env_vars = (
        "MIGRATION_DATABASE_URL",
        "POSTGRES_MIGRATOR_PASSWORD",
        "POSTGRES_PASSWORD",
        "RABBITMQ_ADMIN_PASSWORD",
        "VALKEY_ADMIN_PASSWORD",
        "VALKEY_HEALTH_PASSWORD",
    )
    for var_name in forbidden_runtime_env_vars:
        assert not os.environ.get(var_name), f"{var_name} must not exist in runtime API env"


async def test_live_postgres_rabbitmq_and_valkey_hardening() -> None:
    settings = Settings()
    if not settings.effective_database_url:
        pytest.skip("Runtime control-plane credentials not configured")

    # 1. PostgreSQL least-privilege identity & privilege escalation denial
    pg_engine = create_async_engine(settings.effective_database_url, pool_size=1, max_overflow=0)
    try:
        identity = await verify_runtime_db_identity(pg_engine)
        assert identity["role"] == "vforge_app"
        assert identity["rolsuper"] is False
        assert identity["rolbypassrls"] is False
        assert identity["rolcreaterole"] is False
        assert identity["owns_tables"] is False

        for target_role in ("vforge", "vforge_migrator"):
            async with pg_engine.begin() as conn:
                with pytest.raises(ProgrammingError):
                    await conn.execute(text(f"SET LOCAL ROLE {target_role}"))
    finally:
        await pg_engine.dispose()

    # 2. RabbitMQ restricted vhost and publish/consume verification
    amqp_url = settings.effective_rabbitmq_url
    assert amqp_url
    conn = await aio_pika.connect_robust(amqp_url, timeout=5.0)
    try:
        channel = await conn.channel()
        queue_name = f"vforge.preflight.{uuid.uuid4().hex[:8]}"
        queue = await channel.declare_queue(
            queue_name,
            durable=False,
            exclusive=True,
            auto_delete=True,
        )
        await channel.default_exchange.publish(
            aio_pika.Message(body=b"preflight-ok"),
            routing_key=queue_name,
        )
        msg = await queue.get(timeout=3.0)
        assert msg.body == b"preflight-ok"
        await msg.ack()
        await queue.delete(if_unused=False, if_empty=False)
    finally:
        await conn.close()

    # Verify RabbitMQ runtime user cannot access root vhost '/'
    root_vhost_url = build_amqp_url(
        username=settings.rabbitmq_app_user,
        password=settings.rabbitmq_app_password,
        host=settings.rabbitmq_host,
        port=settings.rabbitmq_port,
        vhost="/",
    )
    with pytest.raises((aio_pika.AMQPException, PAMQPException, OSError)):
        bad_conn = await aio_pika.connect_robust(root_vhost_url, timeout=3.0)
        await bad_conn.close()

    # 3. Valkey ACL enforcement: allowed vf:* ops vs denied commands/keys
    valkey_url = settings.effective_cache_url
    assert valkey_url
    vk = valkey_async.from_url(valkey_url, socket_timeout=2.0)  # type: ignore[no-untyped-call]
    test_key = f"vf:preflight:{uuid.uuid4().hex[:8]}"
    try:
        assert await vk.ping() is True
        assert await vk.incr(test_key) == 1
        assert await vk.expire(test_key, 5) is True
        assert await vk.ttl(test_key) >= 1

        with pytest.raises(NoPermissionError):
            await vk.incr("other:forbidden:key")
        with pytest.raises(NoPermissionError):
            await vk.keys("*")
        with pytest.raises(NoPermissionError):
            await vk.config_get("*")
        with pytest.raises(NoPermissionError):
            await vk.acl_list()
    finally:
        await vk.aclose()


def test_repo_config_and_image_lock_hygiene_when_repo_present() -> None:
    repo_root = _find_repo_root()
    if repo_root is None:
        pytest.skip("Repo root files not mounted in container")

    env_example = (repo_root / ".env.example").read_text(encoding="utf-8")
    for line in env_example.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, val = stripped.split("=", 1)
        if key != "SECRET_PROVIDER" and any(tok in key for tok in ("PASSWORD", "SECRET")):
            assert val == "" or val.startswith("CHANGE_ME_"), f"Unsafe placeholder for {key}"

    gitignore = (repo_root / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gitignore
    assert ".secrets/" in gitignore

    compose = (repo_root / "docker-compose.yml").read_text(encoding="utf-8")
    assert ":latest" not in compose
    assert "--requirepass" not in compose

    lock = json.loads(
        (repo_root / "lifecycle/image-lock/phase2-images.json").read_text(encoding="utf-8")
    )
    required_fields = {
        "toolName",
        "toolVersion",
        "role",
        "updateChannel",
        "repository",
        "tag",
        "digest",
        "reference",
        "architecture",
        "sourceRepository",
        "releaseSource",
        "signatureProvenance",
        "sbomReference",
        "approvalState",
        "lastVerifiedAt",
    }
    for img in lock["images"]:
        assert required_fields.issubset(img.keys())
        assert img["tag"] != "latest"
        assert "@sha256:" in img["reference"]


def test_docker_secret_provider_rejects_file_pointer_traversal(tmp_path: Path) -> None:
    secrets_dir = tmp_path / "secrets"
    secrets_dir.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("leaked", encoding="utf-8")

    provider_escape = DockerSecretProvider(
        secrets_dir=secrets_dir,
        env_mapping={"TEST_SECRET_FILE": str(outside)},
    )
    with pytest.raises(SecretResolutionError):
        provider_escape.get_secret("TEST_SECRET")

    provider_dots = DockerSecretProvider(
        secrets_dir=secrets_dir,
        env_mapping={"TEST_SECRET_FILE": f"{secrets_dir}/../outside.txt"},
    )
    with pytest.raises(SecretResolutionError):
        provider_dots.get_secret("TEST_SECRET")
