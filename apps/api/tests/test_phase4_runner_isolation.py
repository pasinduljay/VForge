"""Phase 4 tests: TLS 1.3 mTLS gateway, signed manifests, envelope encryption, & RLS."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import socket
import ssl
import threading
import time
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
import uvicorn
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import rsa
from vforge_scope import StaticDnsResolver
from httpx import ASGITransport, AsyncClient
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select, text
from sqlalchemy.exc import ProgrammingError

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.main import app
from vforge.models.enums import (
    RunnerJobStatus,
    RunnerPoolType,
    RunnerStatus,
    ScanRunStatus,
)
from vforge.models.orchestration import RunnerJob, ScanStage
from vforge.models.runner import (
    Artifact,
    Runner,
    RunnerEvent,
    RunnerHeartbeat,
    RunnerPool,
    ToolExecution,
)
from vforge.orchestration.manifest import verify_execution_manifest
from vforge.orchestration.service import process_dispatch_message
from vforge.runner_gateway import (
    create_mtls_uvicorn_config,
    create_runner_gateway_app,
)
from vforge.security.envelope import (
    build_artifact_aad,
    decrypt_artifact_bytes,
    encrypt_artifact_bytes,
    resolve_kek,
)
from vforge.security.mtls import (
    generate_runner_ca,
    issue_signed_gateway_cert,
    issue_signed_runner_cert,
)
from vforge.security.signing import SnapshotSigner, generate_ed25519_keypair_pem


def _make_rsa_key(kid: str = "ph4-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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
    kid: str = "ph4-oidc-key-1",
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


def test_envelope_encryption_and_aad_binding() -> None:
    settings = Settings(vforge_env="test", artifact_encryption_key_b64="")
    kek_id, kek_bytes = resolve_kek(settings)
    org_id = str(uuid.uuid4())
    scan_run_id = str(uuid.uuid4())
    job_id = str(uuid.uuid4())
    plaintext = b'{"finding":"none","tool":"dummy"}\n'
    sha = hashlib.sha256(plaintext).hexdigest()
    aad = build_artifact_aad(
        organization_id=org_id,
        scan_run_id=scan_run_id,
        runner_job_id=job_id,
        plaintext_sha256=sha,
    )

    enc = encrypt_artifact_bytes(
        plaintext=plaintext,
        kek_id=kek_id,
        kek_bytes=kek_bytes,
        aad=aad,
    )
    assert plaintext not in enc.ciphertext
    assert enc.plaintext_sha256 == sha

    decrypted = decrypt_artifact_bytes(
        ciphertext=enc.ciphertext,
        expected_plaintext_sha256=enc.plaintext_sha256,
        expected_ciphertext_sha256=enc.ciphertext_sha256,
        kek_bytes=kek_bytes,
        wrapped_dek_b64=enc.wrapped_dek_b64,
        nonce_b64=enc.nonce_b64,
        aad_b64=enc.aad_b64,
    )
    assert decrypted == plaintext

    # Wrong AAD (cross-tenant/cross-job swap) must fail authentication
    wrong_aad = build_artifact_aad(
        organization_id=str(uuid.uuid4()),
        scan_run_id=scan_run_id,
        runner_job_id=job_id,
        plaintext_sha256=sha,
    )
    with pytest.raises(InvalidTag):
        decrypt_artifact_bytes(
            ciphertext=enc.ciphertext,
            expected_plaintext_sha256=enc.plaintext_sha256,
            expected_ciphertext_sha256=enc.ciphertext_sha256,
            kek_bytes=kek_bytes,
            wrapped_dek_b64=enc.wrapped_dek_b64,
            nonce_b64=enc.nonce_b64,
            aad_b64=base64.b64encode(wrong_aad).decode("ascii"),
        )


def test_execution_manifest_signing_and_tamper_rejection() -> None:
    ed_priv, ed_pub = generate_ed25519_keypair_pem()
    keyring_json = json.dumps({"vf-ph4-key": {"public_key_pem": ed_pub, "status": "active"}})
    settings = Settings(
        vforge_env="test",
        scope_signing_key_id="vf-ph4-key",
        scope_signing_private_key_pem=ed_priv,
        scope_signing_public_keys_json=keyring_json,
    )
    signer = SnapshotSigner.from_settings(settings)
    approved_image = "vforge/dummy-scanner@sha256:" + ("a" * 64)

    manifest = {
        "apiVersion": "vforge.io/v1alpha1",
        "kind": "ExecutionManifest",
        "metadata": {
            "jobId": str(uuid.uuid4()),
            "scanRunId": str(uuid.uuid4()),
            "organizationId": str(uuid.uuid4()),
            "expiresAt": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
        },
        "execution": {
            "image": approved_image,
            "toolId": "vforge-dummy-scanner",
        },
        "security": {
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "noNewPrivileges": True,
            "dropCapabilities": ["ALL"],
        },
    }
    bundle = signer.sign_payload(manifest)
    ok, reason = verify_execution_manifest(
        manifest=manifest,
        expected_sha256=bundle.payload_sha256,
        signing_key_id="vf-ph4-key",
        signature=bundle.signature,
        public_keyring_json=keyring_json,
        allowed_image_digests=[approved_image],
    )
    assert ok is True
    assert reason == "valid"

    tampered = json.loads(json.dumps(manifest))
    tampered["execution"]["image"] = "evil/image:latest"
    bad_ok, bad_reason = verify_execution_manifest(
        manifest=tampered,
        expected_sha256=bundle.payload_sha256,
        signing_key_id="vf-ph4-key",
        signature=bundle.signature,
        public_keyring_json=keyring_json,
        allowed_image_digests=[approved_image],
    )
    assert bad_ok is False
    assert bad_reason == "hash_mismatch"


@pytest.fixture
async def ph4_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph4.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()
    ed_priv, ed_pub = generate_ed25519_keypair_pem()
    merged_keyring: dict[str, Any] = {}
    if base_settings.scope_signing_public_keys_json.strip():
        merged_keyring.update(json.loads(base_settings.scope_signing_public_keys_json))
    merged_keyring["vf-ph4-key"] = {"public_key_pem": ed_pub, "status": "active"}
    keyring_json = json.dumps(merged_keyring)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    kek_b64 = base64.urlsafe_b64encode(b"phase4-test-kek-32-bytes-exact!!").decode("ascii")

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
        scope_signing_key_id="vf-ph4-key",
        scope_signing_private_key_pem=ed_priv,
        scope_signing_public_keys_json=keyring_json,
        require_live_dns_on_approval=False,
        artifact_root=str(artifact_dir),
        artifact_encryption_key_b64=kek_b64,
        runner_allowed_image_digests=["vforge/dummy-scanner@sha256:" + ("0" * 63) + "1"],
    )

    engine = build_engine(test_settings.effective_database_url)
    session_factory = build_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.dns_resolver = StaticDnsResolver({"app.example.com": ["93.184.216.34"]})
    app.dependency_overrides[get_settings] = lambda: test_settings

    oidc_client.reset_caches()
    oidc_client._metadata = OidcDiscoveryMetadata(  # noqa: SLF001
        issuer=issuer,
        authorization_endpoint=f"{issuer}/protocol/openid-connect/auth",
        token_endpoint=f"{issuer}/protocol/openid-connect/token",
        jwks_uri=f"{issuer}/protocol/openid-connect/certs",
    )
    oidc_client._metadata_fetched_at = 10**12  # noqa: SLF001
    oidc_client._jwks_keys = {"ph4-oidc-key-1": jwt.PyJWK.from_dict(pub_jwk)}  # noqa: SLF001
    oidc_client._jwks_list = [jwt.PyJWK.from_dict(pub_jwk)]  # noqa: SLF001
    oidc_client._jwks_fetched_at = 10**12  # noqa: SLF001

    yield {
        "issuer": issuer,
        "priv": priv,
        "settings": test_settings,
        "engine": engine,
        "session_factory": session_factory,
        "artifact_dir": artifact_dir,
        "tmp_path": tmp_path,
    }

    app.dependency_overrides.clear()
    app.state.dns_resolver = None
    app.state.snapshot_signer = None
    app.state.opa_client = None
    oidc_client.reset_caches()
    await engine.dispose()


async def _bootstrap_org_asset_profile(
    client: AsyncClient,
    *,
    csrf: str,
    priv: Any,
    issuer: str,
    slug_prefix: str,
) -> dict[str, Any]:
    org_resp = await client.post(
        "/api/v1/organizations",
        json={"name": f"{slug_prefix} Org", "slug": f"{slug_prefix}-{uuid.uuid4().hex[:6]}"},
        headers={"X-CSRF-Token": csrf},
    )
    assert org_resp.status_code == 201, org_resp.text
    org_id = org_resp.json()["id"]

    analyst_sub = f"ph4-analyst-{uuid.uuid4().hex[:8]}"
    analyst_email = f"{analyst_sub}@example.com"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as analyst:
        a_csrf = await _login_user(
            analyst,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject=analyst_sub,
            email=analyst_email,
            name="Phase 4 Analyst",
        )
        inv = await client.post(
            f"/api/v1/organizations/{org_id}/memberships",
            json={
                "oidc_issuer": issuer,
                "oidc_subject": analyst_sub,
                "email": analyst_email,
                "display_name": "Phase 4 Analyst",
                "role": "security_analyst",
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert inv.status_code == 201, inv.text
        sw = await analyst.post(
            "/api/v1/auth/switch-organization",
            json={"organization_id": org_id},
            headers={"X-CSRF-Token": a_csrf},
        )
        assert sw.status_code == 200
        a_csrf = (await analyst.get("/api/v1/auth/me")).json()["csrf_token"]

        proj = await client.post(
            f"/api/v1/organizations/{org_id}/projects",
            json={"name": "Portal", "slug": "portal", "criticality": "high"},
            headers={"X-CSRF-Token": csrf},
        )
        assert proj.status_code == 201
        env = await client.post(
            f"/api/v1/organizations/{org_id}/projects/{proj.json()['id']}/environments",
            json={"name": "prod", "environment_type": "production"},
            headers={"X-CSRF-Token": csrf},
        )
        assert env.status_code == 201
        asset = await client.post(
            f"/api/v1/organizations/{org_id}/environments/{env.json()['id']}/assets",
            json={
                "asset_type": "web_application",
                "locator": "https://app.example.com",
                "scope_metadata": {"owner": "sec"},
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert asset.status_code == 201
        asset_id = asset.json()["id"]

        profile = await client.post(
            f"/api/v1/organizations/{org_id}/scan-profiles",
            json={
                "name": f"ph4-prof-{uuid.uuid4().hex[:6]}",
                "configuration": {
                    "stages": ["passive_dast"],
                    "passive_only": True,
                    "max_concurrency": 1,
                    "request_rate_limit_rps": 5,
                    "timeout_seconds": 300,
                },
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert profile.status_code == 201, profile.text
        now = datetime.now(UTC)
        authz = await analyst.post(
            f"/api/v1/organizations/{org_id}/authorizations",
            json={
                "asset_id": asset_id,
                "approved_testing_scope": {
                    "target_type": "exact_url",
                    "target": "https://app.example.com",
                    "allowed_hosts": ["app.example.com"],
                },
                "approved_activities": ["passive_dast"],
                "allowed_ports": [443],
                "permitted_intensity": "passive",
                "allow_private_networks": False,
                "authorization_reference": f"AUTH-{uuid.uuid4().hex[:6]}",
                "valid_from": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(days=7)).isoformat(),
            },
            headers={"X-CSRF-Token": a_csrf},
        )
        assert authz.status_code == 201, authz.text
        authz_id = authz.json()["id"]
        appr = await client.post(
            f"/api/v1/organizations/{org_id}/authorizations/{authz_id}/approve",
            json={"reason": "Phase 4 dual control approval"},
            headers={"X-CSRF-Token": csrf},
        )
        assert appr.status_code == 200, appr.text

        snaps = await client.get(
            f"/api/v1/organizations/{org_id}/snapshots",
            params={"authorization_id": authz_id},
        )
        assert snaps.status_code == 200, snaps.text
        snapshot_id = snaps.json()["items"][0]["id"]

    return {
        "org_id": org_id,
        "project_id": proj.json()["id"],
        "environment_id": env.json()["id"],
        "asset_id": asset_id,
        "profile_id": profile.json()["id"],
        "authorization_id": authz_id,
        "snapshot_id": snapshot_id,
    }


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.asyncio
async def test_live_tls13_mtls_gateway_revocation_and_e2e_encrypted_artifacts(
    ph4_env: dict[str, Any],
) -> None:
    priv = ph4_env["priv"]
    issuer = ph4_env["issuer"]
    test_settings: Settings = ph4_env["settings"]
    session_factory = ph4_env["session_factory"]
    artifact_dir: Path = ph4_env["artifact_dir"]
    cert_dir: Path = ph4_env["tmp_path"] / "certs"
    await asyncio.to_thread(cert_dir.mkdir, parents=True, exist_ok=True)

    # 1) Create dedicated Runner CA, gateway cert, valid runner cert, and rogue CA cert
    ca_cert_pem, ca_key_pem = generate_runner_ca()
    gw_cert_pem, gw_key_pem = issue_signed_gateway_cert(
        ca_cert_pem=ca_cert_pem,
        ca_key_pem=ca_key_pem,
        dns_names=["localhost"],
        ip_addresses=["127.0.0.1"],
    )
    ca_cert_path = cert_dir / "ca.crt"
    gw_cert_path = cert_dir / "gateway.crt"
    gw_key_path = cert_dir / "gateway.key"
    ca_cert_path.write_text(ca_cert_pem, encoding="utf-8")
    gw_cert_path.write_text(gw_cert_pem, encoding="utf-8")
    gw_key_path.write_text(gw_key_pem, encoding="utf-8")

    rogue_ca_pem, rogue_ca_key = generate_runner_ca(common_name="Rogue CA")

    # 2) Admin creates org, runner pool, and registers valid runner cert
    admin_sub = f"ph4-admin-{uuid.uuid4().hex[:8]}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin:
        csrf = await _login_user(
            admin,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject=admin_sub,
            email=f"{admin_sub}@example.com",
            name="Phase 4 Admin",
        )
        ctx = await _bootstrap_org_asset_profile(
            admin,
            csrf=csrf,
            priv=priv,
            issuer=issuer,
            slug_prefix="ph4-e2e",
        )
        org_id = uuid.UUID(ctx["org_id"])
        pool_resp = await admin.post(
            f"/api/v1/organizations/{org_id}/runner-pools",
            json={
                "name": "Default Isolated Pool",
                "slug": f"pool-{uuid.uuid4().hex[:6]}",
                "pool_type": RunnerPoolType.DAST_EGRESS.value,
                "max_concurrent_jobs": 2,
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert pool_resp.status_code == 201, pool_resp.text
        pool_id = pool_resp.json()["id"]

        runner_id = uuid.uuid4()
        runner_cert_pem, runner_key_pem, _ = issue_signed_runner_cert(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            organization_id=org_id,
            runner_id=runner_id,
        )
        r_cert_path = cert_dir / "runner.crt"
        r_key_path = cert_dir / "runner.key"
        r_cert_path.write_text(runner_cert_pem, encoding="utf-8")
        r_key_path.write_text(runner_key_pem, encoding="utf-8")

        reg_resp = await admin.post(
            f"/api/v1/organizations/{org_id}/runners",
            json={
                "pool_id": pool_id,
                "name": "linux-isolated-01",
                "certificate_pem": runner_cert_pem,
                "version": "0.1.0",
                "capabilities": {"network_profiles": ["none", "scoped-http-egress"]},
            },
            headers={"X-CSRF-Token": csrf},
        )
        assert reg_resp.status_code == 201, reg_resp.text
        assert reg_resp.json()["id"] == str(runner_id)

        # Verify honest /api/v1/meta runner status before & after activity
        rogue_cert_pem, rogue_key_pem, _ = issue_signed_runner_cert(
            ca_cert_pem=rogue_ca_pem,
            ca_key_pem=rogue_ca_key,
            organization_id=org_id,
            runner_id=uuid.uuid4(),
        )
        rogue_cert_path = cert_dir / "rogue.crt"
        rogue_key_path = cert_dir / "rogue.key"
        rogue_cert_path.write_text(rogue_cert_pem, encoding="utf-8")
        rogue_key_path.write_text(rogue_key_pem, encoding="utf-8")

        # 3) Create and dispatch runner-mode ScanRun + sign ExecutionManifest
        scan_resp = await admin.post(
            f"/api/v1/organizations/{org_id}/scans",
            json={
                "project_id": ctx["project_id"],
                "environment_id": ctx["environment_id"],
                "scan_profile_id": ctx["profile_id"],
                "authorization_id": ctx["authorization_id"],
                "scope_snapshot_id": ctx["snapshot_id"],
                "execution_mode": "runner",
                "target_pool_id": pool_id,
                "revalidate_dns": False,
            },
            headers={"X-CSRF-Token": csrf, "Idempotency-Key": str(uuid.uuid4())},
        )
        assert scan_resp.status_code == 201, scan_resp.text
        scan_run_id = uuid.UUID(scan_resp.json()["id"])

    # Run orchestrator dispatch handler directly against DB (signs ExecutionManifest & sets LEASED)
    async with session_factory() as db_session:
        async with db_session.begin():
            await set_db_context(db_session, org_id=org_id)
            preflight_job = (
                await db_session.execute(
                    select(RunnerJob)
                    .join(ScanStage, RunnerJob.scan_stage_id == ScanStage.id)
                    .where(
                        RunnerJob.scan_run_id == scan_run_id,
                        ScanStage.stage_order == 0,
                    )
                )
            ).scalar_one()
    await process_dispatch_message(
        session_factory,
        {
            "organization_id": str(org_id),
            "scan_run_id": str(scan_run_id),
            "scan_stage_id": str(preflight_job.scan_stage_id),
            "runner_job_id": str(preflight_job.id),
        },
        worker_id="ph4-test-worker",
        settings=test_settings,
    )

    # 4) Launch real TLS 1.3 + CERT_REQUIRED runner gateway in background thread
    gw_app = create_runner_gateway_app(with_lifespan=False)
    gw_app.state.engine = ph4_env["engine"]
    gw_app.state.session_factory = session_factory
    gw_app.dependency_overrides[get_settings] = lambda: test_settings

    port = _find_free_port()
    uv_config = create_mtls_uvicorn_config(
        gw_app,
        host="127.0.0.1",
        port=port,
        certfile=str(gw_cert_path),
        keyfile=str(gw_key_path),
        ca_certs=str(ca_cert_path),
        log_level="warning",
    )
    server = uvicorn.Server(uv_config)
    server_thread = threading.Thread(target=server.run, daemon=True)
    server_thread.start()
    try:
        deadline = time.monotonic() + 10.0
        while not server.started:
            assert time.monotonic() < deadline, "mTLS gateway server failed to start"
            await asyncio.sleep(0.05)

        gateway_base = f"https://127.0.0.1:{port}"

        # 4a) Client without certificate is rejected at TLS handshake
        no_cert_ctx = ssl.create_default_context(cafile=str(ca_cert_path))
        async with httpx.AsyncClient(base_url=gateway_base, verify=no_cert_ctx) as no_cert_client:
            with pytest.raises(
                (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, ssl.SSLError)
            ):
                await no_cert_client.post("/api/v1/runner/jobs/claim", json={})

        # 4b) Client with untrusted CA certificate is rejected at TLS handshake
        rogue_ctx = ssl.create_default_context(cafile=str(ca_cert_path))
        rogue_ctx.load_cert_chain(certfile=str(rogue_cert_path), keyfile=str(rogue_key_path))
        async with httpx.AsyncClient(base_url=gateway_base, verify=rogue_ctx) as rogue_client:
            with pytest.raises(
                (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError, ssl.SSLError)
            ):
                await rogue_client.post("/api/v1/runner/jobs/claim", json={})

        # 4c) Valid TLS 1.3 mTLS runner claims signed manifest & runs lifecycle
        valid_ctx = ssl.create_default_context(cafile=str(ca_cert_path))
        valid_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        valid_ctx.load_cert_chain(certfile=str(r_cert_path), keyfile=str(r_key_path))
        async with httpx.AsyncClient(base_url=gateway_base, verify=valid_ctx) as runner_client:
            # Claim and complete preflight stage first, which unlocks stage_1_passive_dast
            pre_claim = await runner_client.post(
                "/api/v1/runner/jobs/claim",
                json={"pool_id": pool_id, "runner_version": "0.1.0", "active_containers": 0},
            )
            assert pre_claim.status_code == 200, pre_claim.text
            pre_data = pre_claim.json()
            assert pre_data["claimed"] is True
            pre_comp = await runner_client.post(
                f"/api/v1/runner/jobs/{pre_data['job_id']}/complete",
                json={
                    "execution_id": pre_data["execution_id"],
                    "attempt_number": pre_data["attempt_number"],
                    "status": "completed",
                    "exit_code": 0,
                    "metrics": {"stage": "preflight"},
                },
            )
            assert pre_comp.status_code == 200, pre_comp.text
            assert pre_comp.json()["scan_run_status"] == ScanRunStatus.RUNNING.value

            # Dispatch unlocked passive_dast job
            async with session_factory() as db_session:
                async with db_session.begin():
                    await set_db_context(db_session, org_id=org_id)
                    stage_job = (
                        await db_session.execute(
                            select(RunnerJob)
                            .join(ScanStage, RunnerJob.scan_stage_id == ScanStage.id)
                            .where(
                                RunnerJob.scan_run_id == scan_run_id,
                                ScanStage.stage_order == 1,
                            )
                        )
                    ).scalar_one()
            await process_dispatch_message(
                session_factory,
                {
                    "organization_id": str(org_id),
                    "scan_run_id": str(scan_run_id),
                    "scan_stage_id": str(stage_job.scan_stage_id),
                    "runner_job_id": str(stage_job.id),
                },
                worker_id="ph4-test-worker",
                settings=test_settings,
            )

            claim_resp = await runner_client.post(
                "/api/v1/runner/jobs/claim",
                json={"pool_id": pool_id, "runner_version": "0.1.0", "active_containers": 0},
            )
            assert claim_resp.status_code == 200, claim_resp.text
            claim_data = claim_resp.json()
            assert claim_data["claimed"] is True
            claimed_job_id = claim_data["job_id"]
            execution_id = claim_data["execution_id"]
            attempt_number = claim_data["attempt_number"]

            # Verify signed manifest using public keyring
            v_ok, v_reason = verify_execution_manifest(
                manifest=claim_data["manifest"],
                expected_sha256=claim_data["manifest_sha256"],
                signing_key_id=claim_data["manifest_signing_key_id"],
                signature=claim_data["manifest_signature"],
                public_keyring_json=claim_data["public_keyring_json"],
                allowed_image_digests=test_settings.runner_allowed_image_digests,
            )
            assert v_ok is True
            assert v_reason == "valid"

            # Heartbeat updates runner telemetry and reports online in /api/v1/meta
            hb_resp = await runner_client.post(
                f"/api/v1/runner/jobs/{claimed_job_id}/heartbeat",
                json={
                    "attempt_number": attempt_number,
                    "status": "online",
                    "cpu_percent": 12,
                    "memory_mb": 128,
                    "active_containers": 1,
                    "metrics": {"phase": "running"},
                },
            )
            assert hb_resp.status_code == 200, hb_resp.text
            assert hb_resp.json()["cancel_requested"] is False

            # Upload artifact with bad SHA-256 -> rejected
            raw_artifact = b'{"secret_marker":"CANARY_PLAINTEXT_MUST_BE_ENCRYPTED","ok":true}\n'
            bad_upload = await runner_client.post(
                f"/api/v1/runner/jobs/{claimed_job_id}/artifacts",
                json={
                    "execution_id": execution_id,
                    "attempt_number": attempt_number,
                    "artifact_type": "raw_output",
                    "content_type": "application/json",
                    "sha256": "0" * 64,
                    "content_b64": base64.b64encode(raw_artifact).decode("ascii"),
                },
            )
            assert bad_upload.status_code == 422

            # Upload valid artifact -> AES-256-GCM encrypted on disk
            good_sha = hashlib.sha256(raw_artifact).hexdigest()
            good_upload = await runner_client.post(
                f"/api/v1/runner/jobs/{claimed_job_id}/artifacts",
                json={
                    "execution_id": execution_id,
                    "attempt_number": attempt_number,
                    "artifact_type": "raw_output",
                    "content_type": "application/json",
                    "sha256": good_sha,
                    "content_b64": base64.b64encode(raw_artifact).decode("ascii"),
                },
            )
            assert good_upload.status_code == 201, good_upload.text
            artifact_id = good_upload.json()["id"]

            # Prove ciphertext on disk contains no plaintext
            stored_files = await asyncio.to_thread(lambda: list(artifact_dir.rglob("*.enc")))
            assert len(stored_files) == 1
            raw_enc = await asyncio.to_thread(stored_files[0].read_bytes)
            assert b"CANARY_PLAINTEXT_MUST_BE_ENCRYPTED" not in raw_enc

            # Complete job
            comp_resp = await runner_client.post(
                f"/api/v1/runner/jobs/{claimed_job_id}/complete",
                json={
                    "execution_id": execution_id,
                    "attempt_number": attempt_number,
                    "status": "completed",
                    "exit_code": 0,
                    "metrics": {"artifacts_uploaded": 1},
                },
            )
            assert comp_resp.status_code == 200, comp_resp.text
            assert comp_resp.json()["scan_run_status"] == ScanRunStatus.COMPLETED.value

            # Operator revokes runner -> immediate 403 rejection on next mTLS request
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as admin2:
                await _login_user(
                    admin2,
                    priv=priv,
                    issuer=issuer,
                    audience="vforge-api",
                    subject=admin_sub,
                    email=f"{admin_sub}@example.com",
                    name="Phase 4 Admin",
                )
                me_csrf = (await admin2.get("/api/v1/auth/me")).json()["csrf_token"]
                # Verify /api/v1/meta reflects active phase >= 4 & live runner_connected
                meta = await admin2.get("/api/v1/meta")
                assert meta.status_code == 200
                assert meta.json()["phase"] >= 4
                assert meta.json()["runner_connected"] is True

                # Verify artifact listing and decrypted download roundtrip
                art_list = await admin2.get(
                    f"/api/v1/organizations/{org_id}/scans/{scan_run_id}/artifacts"
                )
                assert art_list.status_code == 200
                assert len(art_list.json()) == 1
                dl = await admin2.get(
                    f"/api/v1/organizations/{org_id}/scans/{scan_run_id}/artifacts/{artifact_id}/download"
                )
                assert dl.status_code == 200
                assert dl.content == raw_artifact
                assert dl.headers["X-VForge-Artifact-SHA256"] == good_sha

                rev = await admin2.post(
                    f"/api/v1/organizations/{org_id}/runners/{runner_id}/revoke",
                    json={"reason": "Key rotation test"},
                    headers={"X-CSRF-Token": me_csrf},
                )
                assert rev.status_code == 200
                assert rev.json()["status"] == RunnerStatus.REVOKED.value

            revoked_claim = await runner_client.post("/api/v1/runner/jobs/claim", json={})
            assert revoked_claim.status_code == 403
    finally:
        server.should_exit = True
        server_thread.join(timeout=5.0)
        gw_app.dependency_overrides.clear()


@pytest.mark.asyncio
async def test_phase4_cancellation_immutability_and_cross_tenant_rls_isolation(
    ph4_env: dict[str, Any],
) -> None:
    priv = ph4_env["priv"]
    issuer = ph4_env["issuer"]
    test_settings: Settings = ph4_env["settings"]
    session_factory = ph4_env["session_factory"]

    ca_cert_pem, ca_key_pem = generate_runner_ca()

    # Org A creates pool, runner, scan, leases job, cancels -> heartbeat sees cancel_requested
    org_a_sub = f"ph4-orga-{uuid.uuid4().hex[:8]}"
    org_b_sub = f"ph4-orgb-{uuid.uuid4().hex[:8]}"
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin_a:
        csrf_a = await _login_user(
            admin_a,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject=org_a_sub,
            email=f"{org_a_sub}@example.com",
            name="Org A Admin",
        )
        ctx_a = await _bootstrap_org_asset_profile(
            admin_a,
            csrf=csrf_a,
            priv=priv,
            issuer=issuer,
            slug_prefix="ph4-rls-a",
        )
        org_a_id = uuid.UUID(ctx_a["org_id"])
        pool_a = await admin_a.post(
            f"/api/v1/organizations/{org_a_id}/runner-pools",
            json={
                "name": "Pool A",
                "slug": f"pool-a-{uuid.uuid4().hex[:6]}",
                "pool_type": RunnerPoolType.DAST_EGRESS.value,
            },
            headers={"X-CSRF-Token": csrf_a},
        )
        assert pool_a.status_code == 201
        pool_a_id = pool_a.json()["id"]
        runner_a_id = uuid.uuid4()
        r_cert_pem, _, claims = issue_signed_runner_cert(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            organization_id=org_a_id,
            runner_id=runner_a_id,
        )
        reg_a = await admin_a.post(
            f"/api/v1/organizations/{org_a_id}/runners",
            json={
                "pool_id": pool_a_id,
                "name": "runner-a",
                "version": "0.1.0",
                "certificate_pem": r_cert_pem,
            },
            headers={"X-CSRF-Token": csrf_a},
        )
        assert reg_a.status_code == 201

        scan_a = await admin_a.post(
            f"/api/v1/organizations/{org_a_id}/scans",
            json={
                "project_id": ctx_a["project_id"],
                "environment_id": ctx_a["environment_id"],
                "scan_profile_id": ctx_a["profile_id"],
                "authorization_id": ctx_a["authorization_id"],
                "scope_snapshot_id": ctx_a["snapshot_id"],
                "execution_mode": "runner",
                "target_pool_id": pool_a_id,
                "revalidate_dns": False,
            },
            headers={"X-CSRF-Token": csrf_a, "Idempotency-Key": str(uuid.uuid4())},
        )
        assert scan_a.status_code == 201
        scan_a_id = uuid.UUID(scan_a.json()["id"])

    async with session_factory() as db_session:
        async with db_session.begin():
            await set_db_context(db_session, org_id=org_a_id)
            job_a = (
                await db_session.execute(
                    select(RunnerJob)
                    .join(ScanStage, RunnerJob.scan_stage_id == ScanStage.id)
                    .where(
                        RunnerJob.scan_run_id == scan_a_id,
                        ScanStage.stage_order == 0,
                    )
                )
            ).scalar_one()
    await process_dispatch_message(
        session_factory,
        {
            "organization_id": str(org_a_id),
            "scan_run_id": str(scan_a_id),
            "scan_stage_id": str(job_a.scan_stage_id),
            "runner_job_id": str(job_a.id),
        },
        worker_id="ph4-test-worker",
        settings=test_settings,
    )

    # Claim via gateway ASGI app using direct scope extension to test claim/cancel/immutability
    gw_app = create_runner_gateway_app(with_lifespan=False)
    gw_app.state.engine = ph4_env["engine"]
    gw_app.state.session_factory = session_factory
    gw_app.dependency_overrides[get_settings] = lambda: test_settings

    # Claim directly through service inside DB context
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    from vforge.schemas import (
        RunnerHeartbeatRequest,
        RunnerJobClaimRequest,
        RunnerJobCompleteRequest,
    )
    from vforge.services.runners import (
        authenticate_mtls_runner,
        claim_next_runner_job,
        complete_runner_job,
        record_runner_heartbeat,
    )

    cert_der = x509.load_pem_x509_certificate(r_cert_pem.encode("utf-8")).public_bytes(
        serialization.Encoding.DER
    )
    from vforge.security.mtls import verify_runner_cert_der

    verified_claims = verify_runner_cert_der(cert_der)
    assert verified_claims.cert_sha256 == claims.cert_sha256

    async with session_factory() as db_session:
        async with db_session.begin():
            await set_db_context(db_session, org_id=org_a_id)
            runner_obj = await authenticate_mtls_runner(db_session, claims=verified_claims)
            claimed = await claim_next_runner_job(
                db_session,
                runner=runner_obj,
                payload=RunnerJobClaimRequest(pool_id=uuid.UUID(pool_a_id)),
                settings=test_settings,
            )
            assert claimed.claimed is True
            exec_id = claimed.execution_id
            assert exec_id is not None

    # Operator cancels run -> heartbeat sees cancel_requested -> completes as cancelled
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin_a2:
        await _login_user(
            admin_a2,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject=org_a_sub,
            email=f"{org_a_sub}@example.com",
            name="Org A Admin",
        )
        csrf_a2 = (await admin_a2.get("/api/v1/auth/me")).json()["csrf_token"]
        cancel_resp = await admin_a2.post(
            f"/api/v1/organizations/{org_a_id}/scans/{scan_a_id}/cancel",
            headers={"X-CSRF-Token": csrf_a2},
        )
        assert cancel_resp.status_code == 200
        assert cancel_resp.json()["status"] == ScanRunStatus.CANCELLING.value

    async with session_factory() as db_session:
        async with db_session.begin():
            await set_db_context(db_session, org_id=org_a_id)
            runner_obj = await authenticate_mtls_runner(db_session, claims=verified_claims)
            hb = await record_runner_heartbeat(
                db_session,
                runner=runner_obj,
                job_id=job_a.id,
                payload=RunnerHeartbeatRequest(attempt_number=1, active_containers=1),
            )
            assert hb.cancel_requested is True
            done = await complete_runner_job(
                db_session,
                runner=runner_obj,
                job_id=job_a.id,
                payload=RunnerJobCompleteRequest(
                    execution_id=exec_id,
                    attempt_number=1,
                    status="cancelled",
                    error_code="cancelled_by_operator",
                    error_message="Stopped by operator",
                ),
            )
            assert done.job_status == RunnerJobStatus.CANCELLED.value
            assert done.scan_run_status == ScanRunStatus.CANCELLED.value
            # Mark test runner revoked so ephemeral test telemetry never leaks into /api/v1/meta
            runner_obj.status = RunnerStatus.REVOKED.value
            runner_obj.revoked_at = datetime.now(UTC)
            runner_obj.revocation_reason = "Phase 4 test cleanup"

    # Append-only immutability on runner_events
    with pytest.raises(ProgrammingError):
        async with session_factory() as db_session:
            async with db_session.begin():
                await set_db_context(db_session, org_id=org_a_id)
                await db_session.execute(
                    text("DELETE FROM runner_events WHERE organization_id = :oid"),
                    {"oid": str(org_a_id)},
                )

    # Cross-tenant RLS & HTTP API isolation (Org B sees 0 rows across all 6 new tables & 403 HTTP)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as admin_b:
        csrf_b = await _login_user(
            admin_b,
            priv=priv,
            issuer=issuer,
            audience="vforge-api",
            subject=org_b_sub,
            email=f"{org_b_sub}@example.com",
            name="Org B Admin",
        )
        org_b_resp = await admin_b.post(
            "/api/v1/organizations",
            json={"name": "Org B", "slug": f"ph4-rls-b-{uuid.uuid4().hex[:6]}"},
            headers={"X-CSRF-Token": csrf_b},
        )
        assert org_b_resp.status_code == 201
        org_b_id = uuid.UUID(org_b_resp.json()["id"])

        cross_list = await admin_b.get(f"/api/v1/organizations/{org_a_id}/runners")
        assert cross_list.status_code == 403

    async with session_factory() as db_session:
        async with db_session.begin():
            await set_db_context(db_session, org_id=org_b_id)
            assert (await db_session.execute(select(RunnerPool))).scalars().all() == []
            assert (await db_session.execute(select(Runner))).scalars().all() == []
            assert (await db_session.execute(select(RunnerHeartbeat))).scalars().all() == []
            assert (await db_session.execute(select(RunnerEvent))).scalars().all() == []
            assert (await db_session.execute(select(ToolExecution))).scalars().all() == []
            assert (await db_session.execute(select(Artifact))).scalars().all() == []
