"""Comprehensive Phase 14 security, key rotation, OpenBao, mTLS, DR, fuzzing & API tests."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
import time
import uuid
import zipfile
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import jwt
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric import rsa
from vforge_scanners.adapters.nmap import _safe_parse_nmap_xml_text
from vforge_scanners.archive import UnsafeArchiveError, canonicalize_source_archive
from httpx import ASGITransport, AsyncClient
from hypothesis import given
from hypothesis import settings as hyp_settings
from hypothesis import strategies as st
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.ai_gateway.providers import validate_provider_endpoint_url
from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.errors import ForbiddenError, RateLimitExceededError, ValidationError
from vforge.hardening.service import (
    create_encrypted_backup_manifest,
    evaluate_hardening_action_with_opa,
    get_hardening_overview,
    register_or_rotate_key_record,
    run_backup_restore_drill,
)
from vforge.main import app
from vforge.models import (
    AppUser,
    BackupManifest,
    EncryptionKeyRecord,
    Membership,
    Organization,
    RestoreDrillRecord,
    Runner,
    RunnerPool,
)
from vforge.models.enums import Role
from vforge.observability.metrics import PrometheusMetricsRegistry, normalize_route_label
from vforge.secrets.provider import (
    OpenBaoConfig,
    OpenBaoProvider,
    SecretResolutionError,
)
from vforge.security.envelope import (
    decrypt_artifact_with_keyring,
    encrypt_artifact_bytes,
    evaluate_crypto_agility,
    rewrap_artifact_dek,
)
from vforge.security.mtls import (
    generate_runner_ca,
    inspect_pem_cert_expiry,
    inspect_runner_certificate_health,
    issue_signed_runner_cert,
)
from vforge.security.rate_limit import RateLimiter, rate_limiter
from vforge.studio.validators import validate_native_rule_content


def _make_rsa_key(kid: str = "ph14-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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


def _b64_key(seed: bytes) -> str:
    digest = hashlib.sha256(seed).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii")


def _db_available(settings: Settings) -> bool:
    return bool(settings.effective_database_url)


@pytest_asyncio.fixture
async def ph14_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base = get_settings()
    if not _db_available(base):
        pytest.skip("PostgreSQL runtime URL not configured for Phase 14 DB tests")

    priv_key, pub_jwk = _make_rsa_key()
    issuer = "https://auth.vforge.test/realms/vforge"
    client_id = "vforge-ph14-test"

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
        oidc_client_secret="ph14-oidc-test-secret",
        session_cookie_secure=False,
        artifact_encryption_key_id="vf-artifact-ph14-v1",
        artifact_encryption_key_b64=_b64_key(b"ph14-artifact-kek-v1"),
        backup_encryption_key_id="vf-backup-ph14-v1",
        backup_encryption_key_b64=_b64_key(b"ph14-backup-kek-v1"),
        auth_rate_limit_per_minute=10000,
        sensitive_rate_limit_per_minute=10000,
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    async with engine.connect() as conn:
        res = await conn.execute(text("SELECT version_num FROM alembic_version"))
        ver = res.scalar_one_or_none()
        if ver not in {"0015_phase14_hardening_dr", "0016_phase15_ai_redteam"}:
            await engine.dispose()
            pytest.skip(f"DB migration head is '{ver}', expected Phase 14/15 head")

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


async def _seed_org_and_user(
    session: AsyncSession,
    *,
    role: Role,
    email: str,
    subject: str,
) -> tuple[Organization, AppUser]:
    suffix = uuid.uuid4().hex[:8]
    issuer = "https://auth.vforge.test/realms/vforge"
    org_id = uuid.uuid4()
    user_id = uuid.uuid4()

    await set_db_context(session, auth_lookup=(issuer, subject))
    user = AppUser(
        id=user_id,
        oidc_issuer=issuer,
        oidc_subject=subject,
        email=email,
        display_name=f"User {suffix}",
    )
    session.add(user)
    await session.flush()

    await set_db_context(session, user_id=user.id, org_id=org_id)
    org = Organization(id=org_id, name=f"Phase14 Org {suffix}", slug=f"ph14-{suffix}")
    session.add(org)
    await session.flush()
    session.add(Membership(organization_id=org.id, user_id=user.id, role=role.value))
    await session.flush()
    return org, user


# ---------------------------------------------------------------------------
# 1. Envelope Encryption Multi-KEK Rotation & Recovery Tests
# ---------------------------------------------------------------------------


def test_envelope_multi_kek_rotation_rewrap_and_fail_closed(tmp_path: Path) -> None:
    kek_v1 = hashlib.sha256(b"kek-epoch-1").digest()
    kek_v2 = hashlib.sha256(b"kek-epoch-2").digest()
    payload = b"sensitive scanner sarif report bytes"
    aad = b"vf:v1|org-1|run-1|job-1|digest"

    sealed = encrypt_artifact_bytes(
        plaintext=payload,
        kek_id="vf-kek-v1",
        kek_bytes=kek_v1,
        aad=aad,
    )
    # Historical KEK v1 decrypts while v2 is active
    recovered_v1 = decrypt_artifact_with_keyring(
        ciphertext=sealed.ciphertext,
        expected_plaintext_sha256=sealed.plaintext_sha256,
        expected_ciphertext_sha256=sealed.ciphertext_sha256,
        encryption_key_id="vf-kek-v1",
        keyring={"vf-kek-v1": kek_v1, "vf-kek-v2": kek_v2},
        wrapped_dek_b64=sealed.wrapped_dek_b64,
        nonce_b64=sealed.nonce_b64,
        aad_b64=sealed.aad_b64,
    )
    assert recovered_v1 == payload

    # Re-wrap DEK onto v2 without altering ciphertext
    rewrapped = rewrap_artifact_dek(
        old_kek_id="vf-kek-v1",
        old_kek_bytes=kek_v1,
        new_kek_id="vf-kek-v2",
        new_kek_bytes=kek_v2,
        wrapped_dek_b64=sealed.wrapped_dek_b64,
        aad_b64=sealed.aad_b64,
    )
    assert rewrapped.roundtrip_verified is True
    assert rewrapped.new_kek_id == "vf-kek-v2"

    # Decrypt under v2 only (v1 completely decommissioned)
    recovered_v2 = decrypt_artifact_with_keyring(
        ciphertext=sealed.ciphertext,
        expected_plaintext_sha256=sealed.plaintext_sha256,
        expected_ciphertext_sha256=sealed.ciphertext_sha256,
        encryption_key_id="vf-kek-v2",
        keyring={"vf-kek-v2": kek_v2},
        wrapped_dek_b64=rewrapped.wrapped_dek_b64,
        nonce_b64=sealed.nonce_b64,
        aad_b64=sealed.aad_b64,
    )
    assert recovered_v2 == payload

    # Revoked KEK or tampered ciphertext must fail closed
    with pytest.raises(ValueError, match="revoked"):
        decrypt_artifact_with_keyring(
            ciphertext=sealed.ciphertext,
            expected_plaintext_sha256=sealed.plaintext_sha256,
            expected_ciphertext_sha256=sealed.ciphertext_sha256,
            encryption_key_id="vf-kek-v2",
            keyring={"vf-kek-v2": kek_v2},
            wrapped_dek_b64=rewrapped.wrapped_dek_b64,
            nonce_b64=sealed.nonce_b64,
            aad_b64=sealed.aad_b64,
            revoked_key_ids=frozenset({"vf-kek-v2"}),
        )

    tampered = bytearray(sealed.ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(ValueError, match="integrity verification failed"):
        decrypt_artifact_with_keyring(
            ciphertext=bytes(tampered),
            expected_plaintext_sha256=sealed.plaintext_sha256,
            expected_ciphertext_sha256=sealed.ciphertext_sha256,
            encryption_key_id="vf-kek-v2",
            keyring={"vf-kek-v2": kek_v2},
            wrapped_dek_b64=rewrapped.wrapped_dek_b64,
            nonce_b64=sealed.nonce_b64,
            aad_b64=sealed.aad_b64,
        )

    agility = evaluate_crypto_agility(Settings(vforge_env="test", artifact_root=str(tmp_path)))
    assert agility["fips_validated_claim"] is False
    assert agility["pqc_hybrid_live_enabled"] is False
    assert agility["custom_hybrid_protocol_allowed"] is False


# ---------------------------------------------------------------------------
# 2. OpenBao AppRole, Dynamic Leases, Renewal & Zero-Secret-Leak Tests
# ---------------------------------------------------------------------------


def test_openbao_workload_login_dynamic_lease_renewal_and_no_leak(tmp_path: Path) -> None:
    secret_id_file = tmp_path / "bao_secret_id"
    secret_id_file.write_text("ephemeral-role-secret-id\n", encoding="utf-8")
    token_value = "hvs.CAESIFakeShortLivedWorkloadToken123"
    seen_calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_calls.append((request.method, request.url.path))
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(
                200,
                json={"auth": {"client_token": token_value, "lease_duration": 600}},
            )
        if request.headers.get("X-Vault-Token") != token_value:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if request.url.path == "/v1/secret/data/OIDC_CLIENT_SECRET":
            return httpx.Response(200, json={"data": {"data": {"value": "resolved-oidc-secret"}}})
        if request.url.path == "/v1/database/creds/vforge-api":
            return httpx.Response(
                200,
                json={
                    "lease_id": "database/creds/vforge-api/abc123",
                    "lease_duration": 1800,
                    "renewable": True,
                    "data": {"username": "v-approle-dyn", "password": "dyn-password-32bytes"},
                },
            )
        if request.url.path == "/v1/sys/leases/renew":
            return httpx.Response(
                200,
                json={
                    "lease_id": "database/creds/vforge-api/abc123",
                    "lease_duration": 3600,
                    "renewable": True,
                },
            )
        return httpx.Response(404, json={})

    provider = OpenBaoProvider(
        OpenBaoConfig(
            addr="https://openbao.internal:8200",
            auth_method="approle",
            role_id="role-vforge-api",
            secret_id_file=str(secret_id_file),
        ),
        environment="production",
        http_transport=httpx.MockTransport(handler),
    )

    assert provider.get_secret("OIDC_CLIENT_SECRET") == "resolved-oidc-secret"
    creds = provider.get_database_credentials(
        username="vforge_app",
        password_key="POSTGRES_APP_PASSWORD",
        host="postgres",
        port=5432,
        database="vforge",
    )
    assert creds.username == "v-approle-dyn"
    assert creds.lease is not None
    assert creds.lease.lease_id == "database/creds/vforge-api/abc123"
    assert creds.lease.ttl_seconds == 1800

    renewed = provider.renew_lease(creds.lease.lease_id or "", increment_seconds=3600)
    assert renewed.ttl_seconds == 3600

    # Zero token or password leaks in repr / str
    assert token_value not in repr(provider)
    assert token_value not in str(provider)
    assert "dyn-password-32bytes" not in repr(creds)

    # HTTP non-loopback in production fails closed
    bad_prod = OpenBaoProvider(
        OpenBaoConfig(
            addr="http://openbao.internal:8200",
            auth_method="approle",
            role_id="r",
            secret_id_file=str(secret_id_file),
        ),
        environment="production",
        http_transport=httpx.MockTransport(handler),
    )
    with pytest.raises(SecretResolutionError, match="HTTPS in production"):
        bad_prod.get_secret("OIDC_CLIENT_SECRET")


# ---------------------------------------------------------------------------
# 3. mTLS Certificate Expiry Monitoring & Revocation Posture Tests
# ---------------------------------------------------------------------------


def test_mtls_certificate_expiry_and_revocation_monitoring(tmp_path: Path) -> None:
    ca_pem, ca_key = generate_runner_ca()
    ca_file = tmp_path / "runner-ca.pem"
    ca_file.write_text(ca_pem, encoding="utf-8")

    ca_info = inspect_pem_cert_expiry(ca_file, label="runner_mtls_ca", warning_days=30)
    assert ca_info["status"] == "healthy"
    assert ca_info["days_remaining"] >= 360

    org_id = uuid.uuid4()
    runner_id = uuid.uuid4()
    _leaf_pem, _leaf_key, claims = issue_signed_runner_cert(
        ca_cert_pem=ca_pem,
        ca_key_pem=ca_key,
        organization_id=org_id,
        runner_id=runner_id,
        valid_days=10,
    )
    soon = inspect_runner_certificate_health(
        runner_id=str(runner_id),
        runner_name="runner-soon",
        runner_status="active",
        cert_sha256=claims.cert_sha256,
        cert_expires_at=claims.expires_at,
        warning_days=30,
    )
    assert soon["cert_health"] == "expiring_soon"

    revoked = inspect_runner_certificate_health(
        runner_id=str(runner_id),
        runner_name="runner-revoked",
        runner_status="revoked",
        cert_sha256=claims.cert_sha256,
        cert_expires_at=datetime.now(UTC) + timedelta(days=90),
        warning_days=30,
    )
    assert revoked["cert_health"] == "revoked"

    expired = inspect_runner_certificate_health(
        runner_id=str(runner_id),
        runner_name="runner-expired",
        runner_status="active",
        cert_sha256=claims.cert_sha256,
        cert_expires_at=datetime.now(UTC) - timedelta(hours=1),
        warning_days=30,
    )
    assert expired["cert_health"] == "expired"


# ---------------------------------------------------------------------------
# 4. SSRF, Abuse Rate-Limiting & PII-Scrubbed Metrics Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "blocked_url",
    [
        "http://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1:8080/v1/chat",
        "https://10.0.0.5/v1/chat",
        "https://postgres:5432/",
        "https://user:pass@api.openai.com/v1/responses",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
    ],
)
def test_ssrf_blocked_across_external_provider_urls(blocked_url: str) -> None:
    with pytest.raises((ValidationError, ForbiddenError)):
        validate_provider_endpoint_url(
            blocked_url,
            provider_class="hosted_openai",
            resolve_dns=False,
        )


async def test_rate_limiter_enforces_abuse_threshold_and_metrics_scrub_pii() -> None:
    rl = RateLimiter()
    cfg = Settings(vforge_env="test", cache_url="")
    for _ in range(3):
        await rl.check_limit(settings=cfg, bucket="auth", key="ip:198.51.100.1", limit=3)
    with pytest.raises(RateLimitExceededError) as exc_info:
        await rl.check_limit(settings=cfg, bucket="auth", key="ip:198.51.100.1", limit=3)
    assert exc_info.value.retry_after >= 1

    # Metrics normalize UUIDs & strip query strings
    org_uuid = str(uuid.uuid4())
    route = normalize_route_label(f"/api/v1/organizations/{org_uuid}/hardening/overview?token=abc")
    assert org_uuid not in route
    assert "token=abc" not in route
    assert route == "/api/v1/organizations/{id}/hardening/overview"

    reg = PrometheusMetricsRegistry()
    reg.observe_http_request(
        method="GET",
        path=f"/api/v1/organizations/{org_uuid}/hardening/overview?secret=xyz",
        status_code=429,
        duration_seconds=0.012,
    )
    reg.record_dr_drill(passed=True)
    text_out = reg.render_prometheus_text(phase=14)
    assert org_uuid not in text_out
    assert "secret=xyz" not in text_out
    assert "vforge_rate_limit_hits_total 1" in text_out
    assert 'vforge_dr_drills_total{outcome="passed"} 1' in text_out


# ---------------------------------------------------------------------------
# 5. Hypothesis Fuzz Testing Suite (Archives, XML Parsers, YAML/Rule Parsers)
# ---------------------------------------------------------------------------


@hyp_settings(max_examples=40, deadline=None, database=None)
@given(member_name=st.text(min_size=1, max_size=80))
def test_fuzz_archive_canonicalizer_rejects_unsafe_or_arbitrary_tar(member_name: str) -> None:
    buf = io.BytesIO()
    data = b"fuzz"
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo(name=member_name)
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    raw_bytes = buf.getvalue()

    try:
        res = canonicalize_source_archive(raw_bytes, source_type="archive_tar_gz")
        assert res.file_count <= 1
    except UnsafeArchiveError:
        pass


@hyp_settings(max_examples=30, deadline=None, database=None)
@given(entry_name=st.text(min_size=1, max_size=60), body=st.binary(max_size=256))
def test_fuzz_zip_archive_traversal_and_corrupt_bytes(entry_name: str, body: bytes) -> None:
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr(f"../../{entry_name}", body)
    with pytest.raises(UnsafeArchiveError):
        canonicalize_source_archive(zbuf.getvalue(), source_type="archive_zip")

    with pytest.raises(UnsafeArchiveError):
        canonicalize_source_archive(b"not-a-valid-zip" + body, source_type="archive_zip")


@hyp_settings(max_examples=40, deadline=None, database=None)
@given(xml_payload=st.text(max_size=500))
def test_fuzz_nmap_xml_parser_blocks_xxe_and_never_crashes_unhandled(xml_payload: str) -> None:
    import xml.etree.ElementTree as ET

    try:
        _safe_parse_nmap_xml_text(xml_payload)
    except (ValueError, ET.ParseError):
        pass

    xxe = (
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun/>'
    )
    with pytest.raises(ValueError, match="forbidden DOCTYPE or ENTITY"):
        _safe_parse_nmap_xml_text(xxe)


@hyp_settings(max_examples=40, deadline=None, database=None)
@given(yaml_content=st.text(max_size=400))
def test_fuzz_native_rule_yaml_validator_never_crashes_unhandled(yaml_content: str) -> None:
    outcome = validate_native_rule_content(
        engine="opengrep",
        native_format="yaml",
        native_content=yaml_content,
    )
    assert isinstance(outcome.passed, bool)
    assert isinstance(outcome.errors, list)


# ---------------------------------------------------------------------------
# 6. OPA Hardening Policy + PostgreSQL RLS & Immutable Triggers Tests
# ---------------------------------------------------------------------------


async def test_phase14_opa_hardening_policy_honesty_and_fail_closed() -> None:
    def fake_opa(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8"))["input"]
        if body["resource"].get("fips_validated_claim") is True:
            return httpx.Response(200, json={"result": False})
        if body["subject"]["role"] == "viewer":
            return httpx.Response(200, json={"result": False})
        return httpx.Response(200, json={"result": True})

    cfg = Settings(vforge_env="test", opa_url="http://opa.test:8181")
    allowed, _ = await evaluate_hardening_action_with_opa(
        settings=cfg,
        organization_id=uuid.uuid4(),
        actor_id=uuid.uuid4(),
        actor_role="admin",
        action="hardening:manage",
        transport=httpx.MockTransport(fake_opa),
    )
    assert allowed is True

    denied_fips, _ = await evaluate_hardening_action_with_opa(
        settings=cfg,
        organization_id=uuid.uuid4(),
        actor_id=uuid.uuid4(),
        actor_role="owner",
        action="hardening:manage",
        fips_validated_claim=True,
        transport=httpx.MockTransport(fake_opa),
    )
    assert denied_fips is False

    # Network failure must fail closed
    def broken_opa(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("opa offline")

    denied_err, reason = await evaluate_hardening_action_with_opa(
        settings=cfg,
        organization_id=uuid.uuid4(),
        actor_id=uuid.uuid4(),
        actor_role="owner",
        action="hardening:manage",
        transport=httpx.MockTransport(broken_opa),
    )
    assert denied_err is False
    assert "failed closed" in reason


async def test_phase14_rls_isolation_dr_backup_and_append_only_triggers(
    ph14_env: dict[str, Any],
) -> None:
    session_factory = ph14_env["session_factory"]
    settings: Settings = ph14_env["settings"]

    async with session_factory() as db_a:
        org_a, user_a = await _seed_org_and_user(
            db_a,
            role=Role.ADMIN,
            email=f"admin-a-{uuid.uuid4().hex[:6]}@vforge.test",
            subject=f"sub-a-{uuid.uuid4().hex[:6]}",
        )
        org_a_id, user_a_id = org_a.id, user_a.id
        key_rec = await register_or_rotate_key_record(
            db_a,
            organization_id=org_a_id,
            key_id=f"vf-kek-{uuid.uuid4().hex[:6]}",
            purpose="artifact_envelope",
            algorithm_suite="aes-256-gcm-v1",
            pqc_readiness_status="hybrid_planned",
            cryptoperiod_days=90,
            key_fingerprint_sha256="a" * 64,
            actor_id=user_a_id,
            actor_email=user_a.email,
        )
        key_rec_id = key_rec.id
        manifest = await create_encrypted_backup_manifest(
            db_a,
            organization_id=org_a_id,
            backup_scope="postgres_tenant_snapshot",
            rpo_target_minutes=60,
            rto_target_minutes=30,
            actor_id=user_a_id,
            actor_email=user_a.email,
            actor_role=Role.ADMIN.value,
            settings=settings,
        )
        manifest_id = manifest.id
        drill = await run_backup_restore_drill(
            db_a,
            organization_id=org_a_id,
            manifest_id=manifest_id,
            drill_mode="isolated_checksum_decrypt",
            actor_id=user_a_id,
            actor_email=user_a.email,
            actor_role=Role.ADMIN.value,
            settings=settings,
        )
        drill_id = drill.id
        assert drill.status == "passed"
        assert drill.integrity_verified is True
        assert drill.decryption_verified is True
        await db_a.commit()

        # Verify immutability (trigger or REVOKE) blocks UPDATE/DELETE on audit tables
        await set_db_context(db_a, user_id=user_a_id, org_id=org_a_id)
        with pytest.raises(DBAPIError, match="append-only|permission denied"):
            await db_a.execute(
                text("UPDATE dr_restore_drills SET status = 'failed' WHERE id = :id"),
                {"id": drill_id},
            )
        await db_a.rollback()

        await set_db_context(db_a, user_id=user_a_id, org_id=org_a_id)
        with pytest.raises(DBAPIError, match="append-only|permission denied"):
            await db_a.execute(
                text("DELETE FROM hardening_audit_events WHERE organization_id = :org"),
                {"org": org_a_id},
            )
        await db_a.rollback()

        # Verify tenant B context cannot read tenant A's keys, manifests, drills, or audits
        org_b, user_b = await _seed_org_and_user(
            db_a,
            role=Role.OWNER,
            email=f"owner-b-{uuid.uuid4().hex[:6]}@vforge.test",
            subject=f"sub-b-{uuid.uuid4().hex[:6]}",
        )
        org_b_id, user_b_id = org_b.id, user_b.id
        await db_a.commit()

        await set_db_context(db_a, user_id=user_b_id, org_id=org_b_id)
        assert await db_a.get(EncryptionKeyRecord, key_rec_id) is None
        assert await db_a.get(BackupManifest, manifest_id) is None
        assert await db_a.get(RestoreDrillRecord, drill_id) is None
        ov_b = await get_hardening_overview(db_a, organization_id=org_b_id, settings=settings)
        assert ov_b["keys"] == []
        assert ov_b["backup_manifests"] == []
        assert ov_b["restore_drills"] == []
        assert ov_b["audit_events"] == []


# ---------------------------------------------------------------------------
# 7. Full HTTP API Workflow, RBAC, Key Re-Wrap, DR Drill & /metrics Tests
# ---------------------------------------------------------------------------


def _build_auth_headers(ph14_env: dict[str, Any], sub: str, email: str) -> dict[str, str]:
    tok = _make_id_token(
        priv_key=ph14_env["priv_key"],
        kid="ph14-oidc-key-1",
        issuer=ph14_env["issuer"],
        client_id=ph14_env["client_id"],
        sub=sub,
        email=email,
    )
    return {"Authorization": f"Bearer {tok}"}


async def test_phase14_http_api_rbac_dr_rewrap_and_metrics(ph14_env: dict[str, Any]) -> None:
    session_factory = ph14_env["session_factory"]
    suffix = uuid.uuid4().hex[:8]
    viewer_sub = f"ph14-viewer-{suffix}"
    admin_sub = f"ph14-admin-{suffix}"

    async with session_factory() as db:
        org_id = uuid.uuid4()
        viewer_id = uuid.uuid4()
        admin_id = uuid.uuid4()
        await set_db_context(db, auth_lookup=(ph14_env["issuer"], viewer_sub))
        viewer = AppUser(
            id=viewer_id,
            oidc_issuer=ph14_env["issuer"],
            oidc_subject=viewer_sub,
            email=f"viewer-{suffix}@vforge.test",
            display_name="Ph14 Viewer",
        )
        db.add(viewer)
        await db.flush()

        await set_db_context(db, auth_lookup=(ph14_env["issuer"], admin_sub))
        admin = AppUser(
            id=admin_id,
            oidc_issuer=ph14_env["issuer"],
            oidc_subject=admin_sub,
            email=f"admin-{suffix}@vforge.test",
            display_name="Ph14 Admin",
        )
        db.add(admin)
        await db.flush()

        await set_db_context(db, user_id=admin.id, org_id=org_id)
        org = Organization(id=org_id, name=f"Ph14 API Org {suffix}", slug=f"ph14-api-{suffix}")
        db.add(org)
        await db.flush()
        db.add_all(
            [
                Membership(organization_id=org.id, user_id=viewer.id, role=Role.VIEWER.value),
                Membership(organization_id=org.id, user_id=admin.id, role=Role.ADMIN.value),
            ]
        )
        # Seed a runner with near-expiry cert for cert posture endpoint verification
        pool = RunnerPool(organization_id=org.id, name="ph14-pool", slug="ph14-pool")
        db.add(pool)
        await db.flush()
        db.add(
            Runner(
                organization_id=org.id,
                pool_id=pool.id,
                name="ph14-expiring-runner",
                runner_identity=f"spiffe://vforge/org/{org.id}/runner/{uuid.uuid4()}",
                cert_sha256=uuid.uuid4().hex + uuid.uuid4().hex,
                cert_subject="CN=ph14-expiring-runner",
                cert_expires_at=datetime.now(UTC) + timedelta(days=5),
                status="active",
                version="0.1.0",
            )
        )
        await db.commit()

    viewer_hdrs = _build_auth_headers(ph14_env, viewer_sub, f"viewer-{suffix}@vforge.test")
    admin_hdrs = _build_auth_headers(ph14_env, admin_sub, f"admin-{suffix}@vforge.test")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Meta & Metrics endpoints
        meta = await client.get("/api/v1/meta")
        assert meta.status_code == 200
        assert meta.json()["phase"] >= 14
        assert meta.json()["hardening_enabled"] is True
        assert meta.json()["observability_enabled"] is True

        # 2. Viewer denied on hardening:read & hardening:manage
        v_resp = await client.get(
            f"/api/v1/organizations/{org.id}/hardening/overview",
            headers=viewer_hdrs,
        )
        assert v_resp.status_code == 403

        # 3. Admin reads overview (sees expiring runner cert & honest FIPS=false)
        ov_resp = await client.get(
            f"/api/v1/organizations/{org.id}/hardening/overview",
            headers=admin_hdrs,
        )
        assert ov_resp.status_code == 200, ov_resp.text
        ov = ov_resp.json()
        assert ov["crypto_agility"]["fips_validated_claim"] is False
        assert ov["certificate_posture"]["expiring_soon_count"] == 1

        # 4. Register key v1 then rotate to v2
        k1 = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/keys",
            headers=admin_hdrs,
            json={
                "key_id": f"vf-art-v1-{suffix}",
                "purpose": "artifact_envelope",
                "algorithm_suite": "aes-256-gcm-v1",
                "pqc_readiness_status": "classical_active",
                "cryptoperiod_days": 90,
                "key_fingerprint_sha256": "1" * 64,
            },
        )
        assert k1.status_code == 201, k1.text
        k2 = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/keys",
            headers=admin_hdrs,
            json={
                "key_id": f"vf-art-v2-{suffix}",
                "purpose": "artifact_envelope",
                "algorithm_suite": "aes-256-gcm-v1",
                "pqc_readiness_status": "hybrid_planned",
                "cryptoperiod_days": 90,
                "key_fingerprint_sha256": "2" * 64,
            },
        )
        assert k2.status_code == 201, k2.text
        assert k2.json()["version"] == 2

        # Reject false FIPS claim at schema/service/OPA level
        bad_fips = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/keys",
            headers=admin_hdrs,
            json={
                "key_id": f"vf-fips-bad-{suffix}",
                "purpose": "artifact_envelope",
                "algorithm_suite": "aes-256-gcm-v1",
                "pqc_readiness_status": "classical_active",
                "cryptoperiod_days": 90,
                "key_fingerprint_sha256": "3" * 64,
                "fips_validated_claim": True,
            },
        )
        assert bad_fips.status_code in {400, 403, 422}

        # 5. Live AES-256-GCM DEK re-wrap drill
        rewrap = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/keys/rewrap-drill",
            headers=admin_hdrs,
            json={"new_kek_id": f"vf-kek-rot-{suffix}"},
        )
        assert rewrap.status_code == 200, rewrap.text
        assert rewrap.json()["rewrap_verified"] is True
        assert rewrap.json()["decrypt_recovery_verified"] is True

        # 6. Encrypted DR backup & restore verification drill
        bkp = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/backups",
            headers=admin_hdrs,
            json={
                "backup_scope": "postgres_tenant_snapshot",
                "rpo_target_minutes": 30,
                "rto_target_minutes": 15,
            },
        )
        assert bkp.status_code == 201, bkp.text
        manifest_id = bkp.json()["id"]

        drill = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/drills",
            headers=admin_hdrs,
            json={"manifest_id": manifest_id, "drill_mode": "isolated_checksum_decrypt"},
        )
        assert drill.status_code == 201, drill.text
        assert drill.json()["status"] == "passed"
        assert drill.json()["integrity_verified"] is True
        assert drill.json()["decryption_verified"] is True

        # 7. Prometheus /metrics endpoint scrubbed of tenant UUID
        m_resp = await client.get("/metrics")
        assert m_resp.status_code == 200
        assert "vforge_build_info" in m_resp.text
        assert str(org.id) not in m_resp.text

        # Reject custom PQC protocol flag over HTTP
        bad_pqc = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/keys",
            headers=admin_hdrs,
            json={
                "key_id": f"vf-pqc-bad-{suffix}",
                "purpose": "artifact_envelope",
                "algorithm_suite": "custom-lattice-v1",
                "pqc_readiness_status": "hybrid_planned",
                "cryptoperiod_days": 90,
                "key_fingerprint_sha256": "4" * 64,
                "pqc_experimental_custom_protocol": True,
            },
        )
        assert bad_pqc.status_code in {400, 403, 422}

        # Re-wrap persisted DEKs across rotated backup KEK
        old_backup_id = ph14_env["settings"].backup_encryption_key_id
        old_backup_b64 = ph14_env["settings"].backup_encryption_key_b64
        new_backup_b64 = base64.b64encode(b"\x5a" * 32).decode("ascii")
        rotated_settings = Settings(
            **{
                **ph14_env["settings"].model_dump(),
                "backup_encryption_key_id": f"vf-backup-v2-{suffix}",
                "backup_encryption_key_b64": new_backup_b64,
                "artifact_encryption_keyring_json": json.dumps({old_backup_id: old_backup_b64}),
            }
        )
        app.dependency_overrides[get_settings] = lambda: rotated_settings
        rewrap_persisted = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/keys/rewrap-persisted",
            headers=admin_hdrs,
            json={"source_key_id": old_backup_id},
        )
        assert rewrap_persisted.status_code == 200, rewrap_persisted.text
        assert rewrap_persisted.json()["backup_manifests_rewrapped"] >= 1

        # Verify restore drill still succeeds after removing old KEK from keyring
        clean_new_settings = Settings(
            **{
                **ph14_env["settings"].model_dump(),
                "backup_encryption_key_id": f"vf-backup-v2-{suffix}",
                "backup_encryption_key_b64": new_backup_b64,
                "artifact_encryption_keyring_json": "",
            }
        )
        app.dependency_overrides[get_settings] = lambda: clean_new_settings
        post_rewrap_drill = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/drills",
            headers=admin_hdrs,
            json={"manifest_id": manifest_id, "drill_mode": "isolated_checksum_decrypt"},
        )
        assert post_rewrap_drill.status_code == 201, post_rewrap_drill.text
        assert post_rewrap_drill.json()["status"] == "passed"
        app.dependency_overrides[get_settings] = lambda: ph14_env["settings"]

        # Auditor gets 200 on read-only endpoints and 403 on mutations
        auditor_sub = f"ph14-auditor-{suffix}"
        auditor_email = f"auditor-{suffix}@vforge.test"
        other_sub = f"ph14-other-org-{suffix}"
        other_email = f"other-org-{suffix}@vforge.test"
        async with session_factory() as db:
            await set_db_context(db, auth_lookup=(ph14_env["issuer"], auditor_sub))
            auditor = AppUser(
                oidc_issuer=ph14_env["issuer"],
                oidc_subject=auditor_sub,
                email=auditor_email,
                display_name="Auditor",
            )
            db.add(auditor)
            await db.flush()

            await set_db_context(db, auth_lookup=(ph14_env["issuer"], other_sub))
            other_user = AppUser(
                oidc_issuer=ph14_env["issuer"],
                oidc_subject=other_sub,
                email=other_email,
                display_name="Other Owner",
            )
            db.add(other_user)
            await db.flush()

            other_org_id = uuid.uuid4()
            await set_db_context(db, user_id=other_user.id, org_id=other_org_id)
            other_org = Organization(
                id=other_org_id, name=f"Other-{suffix}", slug=f"other-{suffix}"
            )
            db.add(other_org)
            await db.flush()
            db.add(
                Membership(
                    organization_id=other_org.id,
                    user_id=other_user.id,
                    role=Role.OWNER.value,
                )
            )
            await db.flush()

            await set_db_context(db, user_id=auditor.id, org_id=org.id)
            db.add(
                Membership(
                    organization_id=org.id,
                    user_id=auditor.id,
                    role=Role.AUDITOR.value,
                )
            )
            await db.commit()

        auditor_hdrs = _build_auth_headers(ph14_env, auditor_sub, auditor_email)
        other_hdrs = _build_auth_headers(ph14_env, other_sub, other_email)

        auditor_get = await client.get(
            f"/api/v1/organizations/{org.id}/hardening/certs/posture",
            headers=auditor_hdrs,
        )
        assert auditor_get.status_code == 200
        auditor_mut = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/backups",
            headers=auditor_hdrs,
            json={"backup_scope": "postgres_tenant_snapshot"},
        )
        assert auditor_mut.status_code == 403

        # Cross-tenant HTTP IDOR rejection
        idor_get = await client.get(
            f"/api/v1/organizations/{org.id}/hardening/overview",
            headers=other_hdrs,
        )
        assert idor_get.status_code == 403

        # Missing/deleted backup blob must surface explicit failed drill (never clean pass)
        async with session_factory() as db:
            await set_db_context(db, user_id=admin.id, org_id=org.id)
            m_row = await db.get(BackupManifest, uuid.UUID(manifest_id))
            assert m_row is not None
            blob_file = Path(ph14_env["settings"].artifact_root) / m_row.storage_key
            if blob_file.exists():
                blob_file.unlink()
        failed_drill = await client.post(
            f"/api/v1/organizations/{org.id}/hardening/drills",
            headers=admin_hdrs,
            json={"manifest_id": manifest_id, "drill_mode": "isolated_checksum_decrypt"},
        )
        assert failed_drill.status_code == 201
        assert failed_drill.json()["status"] == "failed"
        assert failed_drill.json()["decryption_verified"] is False


async def test_phase14_metrics_bearer_token_and_cardinality_cap(ph14_env: dict[str, Any]) -> None:
    reg = PrometheusMetricsRegistry(max_route_labels=10)
    for i in range(25):
        reg.observe_http_request(
            method="GET", path=f"/probe-{i}", status_code=404, duration_seconds=0.01
        )
    text_out = reg.render_prometheus_text(phase=14)
    assert "__overflow__" in text_out

    # Test /metrics bearer token gating & disabled 404
    base_settings: Settings = ph14_env["settings"]
    try:
        disabled_cfg = Settings(**{**base_settings.model_dump(), "metrics_enabled": False})
        app.dependency_overrides[get_settings] = lambda: disabled_cfg
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r_off = await client.get("/metrics")
            assert r_off.status_code == 404

        unconfigured_cfg = Settings(
            **{
                **base_settings.model_dump(),
                "metrics_enabled": True,
                "metrics_bearer_token_required": True,
                "metrics_bearer_token": "",
            }
        )
        app.dependency_overrides[get_settings] = lambda: unconfigured_cfg
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            r_503 = await client.get("/metrics")
            assert r_503.status_code == 503

        token_cfg = Settings(
            **{
                **base_settings.model_dump(),
                "metrics_enabled": True,
                "metrics_bearer_token_required": True,
                "metrics_bearer_token": "prom-scrape-secret-1234",
            }
        )
        app.dependency_overrides[get_settings] = lambda: token_cfg
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            assert (await client.get("/metrics")).status_code == 401
            assert (
                await client.get("/metrics", headers={"Authorization": "Bearer wrong"})
            ).status_code == 401
            r_ok = await client.get(
                "/metrics", headers={"Authorization": "Bearer prom-scrape-secret-1234"}
            )
            assert r_ok.status_code == 200
            assert "vforge_build_info" in r_ok.text
            # Probe random unmatched path and confirm raw path is never leaked to /metrics
            await client.get("/never-matched-secret-slug-999")
            r_ok2 = await client.get(
                "/metrics", headers={"Authorization": "Bearer prom-scrape-secret-1234"}
            )
            assert "never-matched-secret-slug-999" not in r_ok2.text
    finally:
        app.dependency_overrides[get_settings] = lambda: base_settings
