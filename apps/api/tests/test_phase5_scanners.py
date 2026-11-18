"""Phase 5 tests: source snapshots, partial coverage, findings normalization & redaction."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import tarfile
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
from vforge.models.runner import Artifact
from vforge.orchestration.service import process_dispatch_message
from vforge.runner_gateway import create_runner_gateway_app
from vforge.security.mtls import (
    generate_runner_ca,
    issue_signed_runner_cert,
)
from vforge.security.signing import generate_ed25519_keypair_pem


def _make_rsa_key(kid: str = "ph5-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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
    kid: str = "ph5-oidc-key-1",
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


def _make_tar_gz(files: dict[str, bytes], *, symlinks: dict[str, str] | None = None) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        for sym_path, target in (symlinks or {}).items():
            sinfo = tarfile.TarInfo(name=sym_path)
            sinfo.type = tarfile.SYMTYPE
            sinfo.linkname = target
            tf.addfile(sinfo)
    return buf.getvalue()


@pytest.fixture
async def ph5_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph5.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()
    ed_priv, ed_pub = generate_ed25519_keypair_pem()
    merged_keyring: dict[str, Any] = {}
    if base_settings.scope_signing_public_keys_json.strip():
        merged_keyring.update(json.loads(base_settings.scope_signing_public_keys_json))
    merged_keyring["vf-ph5-key"] = {"public_key_pem": ed_pub, "status": "active"}
    keyring_json = json.dumps(merged_keyring)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    kek_b64 = base64.urlsafe_b64encode(b"phase5-test-kek-32-bytes-exact!!").decode("ascii")

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
        scope_signing_key_id="vf-ph5-key",
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
    app.state.dns_resolver = StaticDnsResolver({"app.example.com": ["93.184.216.34"]})
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
        "artifact_dir": artifact_dir,
    }

    app.dependency_overrides.clear()
    app.state.dns_resolver = None
    app.state.snapshot_signer = None
    app.state.opa_client = None
    oidc_client.reset_caches()
    await engine.dispose()


@pytest.mark.asyncio
async def test_phase5_source_snapshot_partial_coverage_and_findings_dedup(
    ph5_env: dict[str, Any],
) -> None:
    """Exercise snapshot safety, partial coverage honesty, SAST+Secrets normalization & dedup."""
    cfg: Settings = ph5_env["settings"]
    session_factory = ph5_env["session_factory"]
    ca_cert_pem, ca_key_pem = generate_runner_ca()

    gateway_app = create_runner_gateway_app(with_lifespan=False)
    gateway_app.state.engine = ph5_env["engine"]
    gateway_app.state.session_factory = session_factory
    gateway_app.dependency_overrides[get_settings] = lambda: cfg

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://api.test") as owner_client,
        AsyncClient(transport=transport, base_url="http://api.test") as lead_client,
    ):
        owner_csrf = await _login_user(
            owner_client,
            priv=ph5_env["priv"],
            issuer=ph5_env["issuer"],
            audience=ph5_env["client_id"],
            subject="ph5-owner",
            email="owner-ph5@vforge.test",
            name="Phase5 Owner",
        )
        lead_csrf = await _login_user(
            lead_client,
            priv=ph5_env["priv"],
            issuer=ph5_env["issuer"],
            audience=ph5_env["client_id"],
            subject="ph5-lead",
            email="lead-ph5@vforge.test",
            name="Phase5 Lead",
        )

        org_resp = await owner_client.post(
            "/api/v1/organizations",
            json={"name": f"Ph5 Org {uuid.uuid4().hex[:6]}", "slug": f"ph5-{uuid.uuid4().hex[:8]}"},
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert org_resp.status_code == 201, org_resp.text
        org_id = org_resp.json()["id"]

        add_member = await owner_client.post(
            f"/api/v1/organizations/{org_id}/memberships",
            json={
                "oidc_issuer": ph5_env["issuer"],
                "oidc_subject": "ph5-lead",
                "email": "lead-ph5@vforge.test",
                "display_name": "Phase5 Lead",
                "role": "security_lead",
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert add_member.status_code == 201, add_member.text
        sw_lead = await lead_client.post(
            "/api/v1/auth/switch-organization",
            json={"organization_id": org_id},
            headers={"X-CSRF-Token": lead_csrf},
        )
        assert sw_lead.status_code == 200, sw_lead.text
        lead_csrf = (await lead_client.get("/api/v1/auth/me")).json()["csrf_token"]

        proj_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/projects",
            json={"name": "Repo Service", "slug": f"repo-{uuid.uuid4().hex[:6]}"},
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert proj_resp.status_code == 201
        project_id = proj_resp.json()["id"]

        env_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/projects/{project_id}/environments",
            json={"name": "Staging", "environment_type": "staging"},
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert env_resp.status_code == 201
        env_id = env_resp.json()["id"]

        asset_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/environments/{env_id}/assets",
            json={
                "asset_type": "source_repository",
                "locator": "https://git.example.com/acme/repo-service.git",
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert asset_resp.status_code == 201, asset_resp.text
        asset_id = asset_resp.json()["id"]

        # 1. Negative test: reject symlink / path traversal inside source snapshot
        evil_tar = _make_tar_gz(
            {"app.py": b"print('hi')\n"},
            symlinks={"escape": "/etc/passwd"},
        )
        bad_snap = await owner_client.post(
            f"/api/v1/organizations/{org_id}/projects/{project_id}/source-snapshots",
            json={
                "asset_id": asset_id,
                "source_type": "archive_tar_gz",
                "content_b64": base64.b64encode(evil_tar).decode("ascii"),
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert bad_snap.status_code == 422

        # 2. Positive snapshot: Python + unsupported Solidity (forces honest partial coverage)
        secret_plaintext = "ghp_Phase5TestSecretTokenValue1234567890"  # noqa: S105
        good_tar = _make_tar_gz(
            {
                "app.py": b"import subprocess\nsubprocess.run('id', shell=True, check=False)\n",
                "Contract.sol": b"pragma solidity ^0.8.0;\n",
                "config.py": f'TOKEN = "{secret_plaintext}"\n'.encode(),
            }
        )
        snap_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/projects/{project_id}/source-snapshots",
            json={
                "asset_id": asset_id,
                "source_type": "archive_tar_gz",
                "content_b64": base64.b64encode(good_tar).decode("ascii"),
                "commit_sha": "deadbeef1234",
                "branch": "main",
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert snap_resp.status_code == 201, snap_resp.text
        snap_data = snap_resp.json()
        snapshot_id = snap_data["id"]
        assert snap_data["coverage_report"]["assessment_coverage_status"] == "partial"
        assert "solidity" in snap_data["coverage_report"]["unsupported_languages"]
        assert "python" in snap_data["coverage_report"]["supported_languages"]

        # 3. Authorization & signed scope snapshot for sast + secrets
        now = datetime.now(UTC)
        auth_req = await owner_client.post(
            f"/api/v1/organizations/{org_id}/authorizations",
            json={
                "asset_id": asset_id,
                "approved_testing_scope": {
                    "target_type": "source_repository",
                    "target": "https://git.example.com/acme/repo-service.git",
                },
                "approved_activities": ["sast", "secrets"],
                "permitted_intensity": "passive",
                "authorization_reference": "CHG-PH5-001",
                "valid_from": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(days=7)).isoformat(),
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert auth_req.status_code == 201, auth_req.text
        auth_id = auth_req.json()["id"]

        auth_app = await lead_client.post(
            f"/api/v1/organizations/{org_id}/authorizations/{auth_id}/approve",
            json={"reason": "Approved Phase 5 repo SAST+Secrets"},
            headers={"X-CSRF-Token": lead_csrf},
        )
        assert auth_app.status_code == 200, auth_app.text

        snaps_resp = await lead_client.get(
            f"/api/v1/organizations/{org_id}/snapshots",
            params={"authorization_id": auth_id},
        )
        assert snaps_resp.status_code == 200, snaps_resp.text
        scope_snapshot_id = snaps_resp.json()["items"][0]["id"]

        profile_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/scan-profiles",
            json={
                "name": "Phase5 SAST Secrets",
                "configuration": {
                    "passive_only": True,
                    "stages": ["sast", "secrets"],
                    "timeout_seconds": 120,
                },
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert profile_resp.status_code == 201, profile_resp.text
        profile_id = profile_resp.json()["id"]

        pool_resp = await owner_client.post(
            f"/api/v1/organizations/{org_id}/runner-pools",
            json={
                "name": "Ph5 Pool",
                "slug": f"ph5-pool-{uuid.uuid4().hex[:6]}",
                "pool_type": "standard",
                "max_concurrent_jobs": 2,
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert pool_resp.status_code == 201, pool_resp.text
        pool_id = pool_resp.json()["id"]

        runner_id = uuid.uuid4()
        runner_cert_pem, _runner_key_pem, _ = issue_signed_runner_cert(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            organization_id=uuid.UUID(org_id),
            runner_id=runner_id,
        )
        runner_reg = await owner_client.post(
            f"/api/v1/organizations/{org_id}/runners",
            json={
                "pool_id": pool_id,
                "name": "ph5-runner-1",
                "certificate_pem": runner_cert_pem,
                "version": "0.1.0",
                "capabilities": {"scanners": ["opengrep", "gitleaks"]},
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert runner_reg.status_code == 201, runner_reg.text

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        parsed_runner_cert = x509.load_pem_x509_certificate(runner_cert_pem.encode("utf-8"))
        runner_cert_der = parsed_runner_cert.public_bytes(serialization.Encoding.DER)

        async def _mtls_wrapped_gateway(scope: Any, receive: Any, send: Any) -> None:
            scope.setdefault("extensions", {})["vforge.mtls_peer_der"] = runner_cert_der
            await gateway_app(scope, receive, send)

        mtls_transport = ASGITransport(app=_mtls_wrapped_gateway)

        async def _execute_run_via_mtls(idemp_key: str) -> str:
            create_scan = await owner_client.post(
                f"/api/v1/organizations/{org_id}/scans",
                json={
                    "project_id": project_id,
                    "environment_id": env_id,
                    "scan_profile_id": profile_id,
                    "authorization_id": auth_id,
                    "scope_snapshot_id": scope_snapshot_id,
                    "source_snapshot_id": snapshot_id,
                    "execution_mode": "runner",
                    "target_pool_id": pool_id,
                },
                headers={"X-CSRF-Token": owner_csrf, "Idempotency-Key": idemp_key},
            )
            assert create_scan.status_code == 201, create_scan.text
            run_id = create_scan.json()["id"]

            # Fetch outbox dispatch helper for all 3 jobs (preflight -> sast -> secrets)
            from vforge.models.orchestration import OutboxEvent, RunnerJob

            async def _dispatch_next_pending() -> None:
                async with session_factory() as s:
                    await set_db_context(s, org_id=uuid.UUID(org_id), user_id=uuid.uuid4())
                    outbox_rows = (
                        (
                            await s.execute(
                                select(OutboxEvent).where(
                                    OutboxEvent.scan_run_id == uuid.UUID(run_id),
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
                        worker_id="ph5-test-worker",
                        settings=cfg,
                    )

            async def _claim_and_complete_next() -> bool:
                await _dispatch_next_pending()
                async with httpx.AsyncClient(
                    transport=mtls_transport, base_url="https://runner.local"
                ) as gw_client:
                    claim_resp = await gw_client.post(
                        "/api/v1/runner/jobs/claim",
                        json={"pool_id": pool_id, "runner_version": "0.1.0"},
                    )
                    assert claim_resp.status_code == 200, claim_resp.text
                    claimed = claim_resp.json()
                    if not claimed.get("claimed"):
                        return False
                    job_id = claimed["job_id"]
                    exec_id = claimed["execution_id"]
                    attempt_num = claimed["attempt_number"]
                    tool_id = claimed["manifest"]["execution"]["toolId"]

                    if tool_id in {"opengrep", "gitleaks"}:
                        snap_stream = await gw_client.get(
                            f"/api/v1/runner/jobs/{job_id}/source-snapshot"
                        )
                        assert snap_stream.status_code == 200
                        assert (
                            hashlib.sha256(snap_stream.content).hexdigest()
                            == claimed["manifest"]["inputs"]["sourceSnapshotSha256"]
                        )

                    artifacts_payload: list[tuple[str, str, bytes]] = []
                    if tool_id == "opengrep":
                        og_raw = json.dumps(
                            {
                                "version": "1.33.1",
                                "results": [
                                    {
                                        "check_id": (
                                            "opt.opengrep.rules.python.subprocess-shell-true"
                                        ),
                                        "path": "/work/in/source/app.py",
                                        "start": {"line": 2, "col": 1},
                                        "end": {"line": 2, "col": 45},
                                        "extra": {
                                            "severity": "ERROR",
                                            "message": "Shell injection via shell=True",
                                            "lines": (
                                                "subprocess.run('id', shell=True, check=False)"
                                            ),
                                            "metadata": {"cwe": ["CWE-78"], "confidence": "HIGH"},
                                        },
                                    }
                                ],
                            }
                        ).encode("utf-8")
                        artifacts_payload.append(("raw_output", "application/json", og_raw))
                    elif tool_id == "gitleaks":
                        gl_raw = json.dumps(
                            [
                                {
                                    "RuleID": "github-pat",
                                    "Description": "GitHub Personal Access Token",
                                    "File": "/work/in/source/config.py",
                                    "StartLine": 1,
                                    "EndLine": 1,
                                    "Secret": secret_plaintext,
                                    "Match": f'TOKEN = "{secret_plaintext}"',
                                    "Entropy": 4.5,
                                }
                            ]
                        ).encode("utf-8")
                        artifacts_payload.append(("raw_output", "application/json", gl_raw))

                    for a_type, c_type, a_bytes in artifacts_payload:
                        up_resp = await gw_client.post(
                            f"/api/v1/runner/jobs/{job_id}/artifacts",
                            json={
                                "execution_id": exec_id,
                                "attempt_number": attempt_num,
                                "artifact_type": a_type,
                                "content_type": c_type,
                                "sha256": hashlib.sha256(a_bytes).hexdigest(),
                                "content_b64": base64.b64encode(a_bytes).decode("ascii"),
                            },
                        )
                        assert up_resp.status_code == 201, up_resp.text

                    comp_resp = await gw_client.post(
                        f"/api/v1/runner/jobs/{job_id}/complete",
                        json={
                            "execution_id": exec_id,
                            "attempt_number": attempt_num,
                            "status": "completed",
                            "exit_code": 10 if tool_id == "gitleaks" else 0,
                            "metrics": {"findings_raw": len(artifacts_payload)},
                        },
                    )
                    assert comp_resp.status_code == 200, comp_resp.text
                    _ = RunnerJob
                    return True

            # Stage 0 (preflight), Stage 1 (opengrep), Stage 2 (gitleaks)
            assert await _claim_and_complete_next() is True
            assert await _claim_and_complete_next() is True
            assert await _claim_and_complete_next() is True
            assert await _claim_and_complete_next() is False
            return run_id

        # Execute Scan 1
        run1_id = await _execute_run_via_mtls(f"ph5-run1-{uuid.uuid4().hex}")
        scan1 = await owner_client.get(f"/api/v1/organizations/{org_id}/scans/{run1_id}")
        assert scan1.status_code == 200
        assert scan1.json()["status"] == "completed"
        assert scan1.json()["coverage_status"] == "partial"

        # Verify findings persisted & secret completely redacted
        findings_resp = await owner_client.get(f"/api/v1/organizations/{org_id}/findings")
        assert findings_resp.status_code == 200, findings_resp.text
        assert findings_resp.json()["total"] == 2
        assert secret_plaintext not in findings_resp.text

        # Execute deterministic rescan of identical snapshot
        run2_id = await _execute_run_via_mtls(f"ph5-run2-{uuid.uuid4().hex}")
        assert run2_id != run1_id

        findings_after = await owner_client.get(f"/api/v1/organizations/{org_id}/findings")
        assert findings_after.status_code == 200
        assert findings_after.json()["total"] == 2
        for f_item in findings_after.json()["items"]:
            assert f_item["occurrence_count"] == 2
            detail = await owner_client.get(
                f"/api/v1/organizations/{org_id}/findings/{f_item['id']}"
            )
            assert detail.status_code == 200
            assert len(detail.json()["occurrences"]) == 2
            assert secret_plaintext not in detail.text

        cov_resp = await owner_client.get(f"/api/v1/organizations/{org_id}/scanner-coverage")
        assert cov_resp.status_code == 200
        assert cov_resp.json()["phase"] >= 5
        assert cov_resp.json()["scanners_enabled"] is True
        _ = Artifact
