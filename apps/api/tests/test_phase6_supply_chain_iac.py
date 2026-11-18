"""Phase 6 tests: Syft SBOM, offline Grype SCA, Checkov IaC, provenance, and tenant RLS."""

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
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from vforge_scanners import CheckovAdapter, GrypeAdapter, SyftAdapter
from vforge_scope import StaticDnsResolver
from httpx import ASGITransport, AsyncClient
from jwt import PyJWK
from jwt.algorithms import RSAAlgorithm
from sqlalchemy import select

from vforge.auth.oidc import OidcDiscoveryMetadata, oidc_client
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, set_db_context
from vforge.main import app
from vforge.models.domain import Asset, ScanProfile
from vforge.models.enums import ScanProfileStatus
from vforge.models.orchestration import OutboxEvent
from vforge.orchestration.planner import build_declarative_scan_plan
from vforge.orchestration.service import process_dispatch_message
from vforge.runner_gateway import create_runner_gateway_app
from vforge.security.mtls import generate_runner_ca, issue_signed_runner_cert
from vforge.security.signing import generate_ed25519_keypair_pem


def _make_rsa_key(kid: str = "ph6-oidc-key-1") -> tuple[Any, dict[str, Any]]:
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
    kid: str = "ph6-oidc-key-1",
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


def _make_tar_gz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, data in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
async def ph6_env(tmp_path: Path) -> AsyncIterator[dict[str, Any]]:
    base_settings = get_settings()
    if not base_settings.effective_database_url:
        pytest.skip("Runtime database credentials not configured")

    issuer = "https://idp.ph6.test/realms/vforge"
    client_id = "vforge-api"
    priv, pub_jwk = _make_rsa_key()
    ed_priv, ed_pub = generate_ed25519_keypair_pem()
    merged_keyring: dict[str, Any] = {}
    if base_settings.scope_signing_public_keys_json.strip():
        merged_keyring.update(json.loads(base_settings.scope_signing_public_keys_json))
    merged_keyring["vf-ph6-key"] = {"public_key_pem": ed_pub, "status": "active"}
    keyring_json = json.dumps(merged_keyring)
    artifact_dir = tmp_path / "artifacts"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    kek_b64 = base64.urlsafe_b64encode(b"phase6-test-kek-32-bytes-exact!!").decode("ascii")

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
        scope_signing_key_id="vf-ph6-key",
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
    }

    app.dependency_overrides.clear()
    app.state.dns_resolver = None
    app.state.snapshot_signer = None
    app.state.opa_client = None
    oidc_client.reset_caches()
    await engine.dispose()


@pytest.mark.asyncio
async def test_phase6_sbom_sca_iac_provenance_and_rls(ph6_env: dict[str, Any]) -> None:
    """Exercise Syft CycloneDX/SPDX -> /sbom-input -> Grype DB snapshot + Checkov IaC + RLS."""
    cfg: Settings = ph6_env["settings"]
    session_factory = ph6_env["session_factory"]
    ca_cert_pem, ca_key_pem = generate_runner_ca()

    gateway_app = create_runner_gateway_app(with_lifespan=False)
    gateway_app.state.engine = ph6_env["engine"]
    gateway_app.state.session_factory = session_factory
    gateway_app.dependency_overrides[get_settings] = lambda: cfg

    transport = ASGITransport(app=app)
    async with (
        AsyncClient(transport=transport, base_url="http://api.test") as owner_client,
        AsyncClient(transport=transport, base_url="http://api.test") as lead_client,
        AsyncClient(transport=transport, base_url="http://api.test") as other_client,
    ):
        owner_csrf = await _login_user(
            owner_client,
            priv=ph6_env["priv"],
            issuer=ph6_env["issuer"],
            audience=ph6_env["client_id"],
            subject="ph6-owner",
            email="owner-ph6@vforge.test",
            name="Phase6 Owner",
        )
        lead_csrf = await _login_user(
            lead_client,
            priv=ph6_env["priv"],
            issuer=ph6_env["issuer"],
            audience=ph6_env["client_id"],
            subject="ph6-lead",
            email="lead-ph6@vforge.test",
            name="Phase6 Lead",
        )
        other_csrf = await _login_user(
            other_client,
            priv=ph6_env["priv"],
            issuer=ph6_env["issuer"],
            audience=ph6_env["client_id"],
            subject="ph6-other",
            email="other-ph6@vforge.test",
            name="Other Tenant Owner",
        )

        org1 = (
            await owner_client.post(
                "/api/v1/organizations",
                json={
                    "name": f"Ph6 Org1 {uuid.uuid4().hex[:6]}",
                    "slug": f"ph6-1-{uuid.uuid4().hex[:6]}",
                },
                headers={"X-CSRF-Token": owner_csrf},
            )
        ).json()["id"]
        org2 = (
            await other_client.post(
                "/api/v1/organizations",
                json={
                    "name": f"Ph6 Org2 {uuid.uuid4().hex[:6]}",
                    "slug": f"ph6-2-{uuid.uuid4().hex[:6]}",
                },
                headers={"X-CSRF-Token": other_csrf},
            )
        ).json()["id"]

        await owner_client.post(
            f"/api/v1/organizations/{org1}/memberships",
            json={
                "oidc_issuer": ph6_env["issuer"],
                "oidc_subject": "ph6-lead",
                "email": "lead-ph6@vforge.test",
                "display_name": "Phase6 Lead",
                "role": "security_lead",
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        await lead_client.post(
            "/api/v1/auth/switch-organization",
            json={"organization_id": org1},
            headers={"X-CSRF-Token": lead_csrf},
        )
        lead_csrf = (await lead_client.get("/api/v1/auth/me")).json()["csrf_token"]

        proj_id = (
            await owner_client.post(
                f"/api/v1/organizations/{org1}/projects",
                json={"name": "Supply Chain App", "slug": f"sca-app-{uuid.uuid4().hex[:6]}"},
                headers={"X-CSRF-Token": owner_csrf},
            )
        ).json()["id"]
        env_id = (
            await owner_client.post(
                f"/api/v1/organizations/{org1}/projects/{proj_id}/environments",
                json={"name": "Prod", "environment_type": "production"},
                headers={"X-CSRF-Token": owner_csrf},
            )
        ).json()["id"]
        asset_id = (
            await owner_client.post(
                f"/api/v1/organizations/{org1}/environments/{env_id}/assets",
                json={
                    "asset_type": "source_repository",
                    "locator": "https://git.example.com/acme/supply-chain-app.git",
                },
                headers={"X-CSRF-Token": owner_csrf},
            )
        ).json()["id"]

        snap_tar = _make_tar_gz(
            {
                "requirements.txt": b"requests==2.19.1\nurllib3==1.26.5\n",
                "main.tf": (
                    b'resource "aws_s3_bucket" "data_lake" {\n  bucket = "acme-untagged-lake"\n}\n'
                ),
            }
        )
        src_snap = await owner_client.post(
            f"/api/v1/organizations/{org1}/projects/{proj_id}/source-snapshots",
            json={
                "asset_id": asset_id,
                "source_type": "archive_tar_gz",
                "content_b64": base64.b64encode(snap_tar).decode("ascii"),
                "commit_sha": "cafe6666",
                "branch": "main",
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert src_snap.status_code == 201, src_snap.text
        source_snapshot_id = src_snap.json()["id"]

        now = datetime.now(UTC)
        auth_resp = await owner_client.post(
            f"/api/v1/organizations/{org1}/authorizations",
            json={
                "asset_id": asset_id,
                "approved_testing_scope": {
                    "target_type": "source_repository",
                    "target": "https://git.example.com/acme/supply-chain-app.git",
                },
                "approved_activities": ["sbom", "sca", "iac"],
                "permitted_intensity": "passive",
                "authorization_reference": "CHG-PH6-001",
                "valid_from": (now - timedelta(minutes=5)).isoformat(),
                "expires_at": (now + timedelta(days=7)).isoformat(),
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert auth_resp.status_code == 201, auth_resp.text
        auth_id = auth_resp.json()["id"]
        assert (
            await lead_client.post(
                f"/api/v1/organizations/{org1}/authorizations/{auth_id}/approve",
                json={"reason": "Approved Phase 6 supply chain + IaC"},
                headers={"X-CSRF-Token": lead_csrf},
            )
        ).status_code == 200

        scope_snapshot_id = (
            await lead_client.get(
                f"/api/v1/organizations/{org1}/snapshots",
                params={"authorization_id": auth_id},
            )
        ).json()["items"][0]["id"]

        # Request ["sca", "iac"] without "sbom" to verify automatic upstream Syft planning
        profile_resp = await owner_client.post(
            f"/api/v1/organizations/{org1}/scan-profiles",
            json={
                "name": "Phase6 Supply Chain & IaC",
                "configuration": {
                    "passive_only": True,
                    "stages": ["sca", "iac"],
                    "enable_custom_policies": True,
                    "timeout_seconds": 180,
                },
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        assert profile_resp.status_code == 201, profile_resp.text
        profile_id = profile_resp.json()["id"]

        pool_id = (
            await owner_client.post(
                f"/api/v1/organizations/{org1}/runner-pools",
                json={
                    "name": "Ph6 Pool",
                    "slug": f"ph6-pool-{uuid.uuid4().hex[:6]}",
                    "pool_type": "standard",
                    "max_concurrent_jobs": 2,
                },
                headers={"X-CSRF-Token": owner_csrf},
            )
        ).json()["id"]

        runner_id = uuid.uuid4()
        runner_cert_pem, _, _ = issue_signed_runner_cert(
            ca_cert_pem=ca_cert_pem,
            ca_key_pem=ca_key_pem,
            organization_id=uuid.UUID(org1),
            runner_id=runner_id,
        )
        await owner_client.post(
            f"/api/v1/organizations/{org1}/runners",
            json={
                "pool_id": pool_id,
                "name": "ph6-runner-1",
                "certificate_pem": runner_cert_pem,
                "version": "0.1.0",
                "capabilities": {"scanners": ["syft", "grype", "checkov"]},
            },
            headers={"X-CSRF-Token": owner_csrf},
        )
        parsed_cert = x509.load_pem_x509_certificate(runner_cert_pem.encode("utf-8"))
        runner_cert_der = parsed_cert.public_bytes(serialization.Encoding.DER)

        async def _mtls_wrapped_gateway(scope: Any, receive: Any, send: Any) -> None:
            scope.setdefault("extensions", {})["vforge.mtls_peer_der"] = runner_cert_der
            await gateway_app(scope, receive, send)

        mtls_transport = ASGITransport(app=_mtls_wrapped_gateway)

        scan_resp = await owner_client.post(
            f"/api/v1/organizations/{org1}/scans",
            json={
                "project_id": proj_id,
                "environment_id": env_id,
                "scan_profile_id": profile_id,
                "authorization_id": auth_id,
                "scope_snapshot_id": scope_snapshot_id,
                "source_snapshot_id": source_snapshot_id,
                "execution_mode": "runner",
                "target_pool_id": pool_id,
            },
            headers={"X-CSRF-Token": owner_csrf, "Idempotency-Key": f"ph6-{uuid.uuid4().hex}"},
        )
        assert scan_resp.status_code == 201, scan_resp.text
        run_id = scan_resp.json()["id"]

        cdx_doc = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:66666666-6666-4666-8666-666666666666",
            "components": [
                {
                    "name": "requests",
                    "version": "2.19.1",
                    "purl": "pkg:pypi/requests@2.19.1",
                    "type": "library",
                    "properties": [
                        {"name": "syft:package:type", "value": "python"},
                        {"name": "syft:location:0:path", "value": "requirements.txt"},
                    ],
                },
                {
                    "name": "urllib3",
                    "version": "1.26.5",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "type": "library",
                },
            ],
        }
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "documentNamespace": "https://vforge.local/spdx/ph6",
            "packages": [
                {
                    "name": "requests",
                    "versionInfo": "2.19.1",
                    "externalRefs": [
                        {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.19.1",
                        }
                    ],
                }
            ],
        }
        grype_report = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "GHSA-x84v-xcm2-53pg",
                        "severity": "Critical",
                        "description": "Improper handling of Proxy-Authorization in requests",
                        "fix": {"state": "fixed", "versions": ["2.20.0"]},
                        "cwes": [{"cwe": "CWE-522"}],
                    },
                    "relatedVulnerabilities": [{"id": "CVE-2018-18074"}],
                    "artifact": {
                        "name": "requests",
                        "version": "2.19.1",
                        "purl": "pkg:pypi/requests@2.19.1",
                        "locations": [{"path": "requirements.txt"}],
                    },
                }
            ],
            "descriptor": {
                "db": {
                    "status": {
                        "schemaVersion": "v6.1.10",
                        "built": "2026-11-12T06:20:58Z",
                        "from": (
                            "https://grype.anchore.io/databases/v6/"
                            "vulnerability-db_v6.1.10_2026-11-12.tar.zst"
                            "?checksum=sha256:abcdef0123456789abcdef0123456789"
                            "abcdef0123456789abcdef0123456789"
                        ),
                        "valid": True,
                    },
                    "providers": {"nvd": {"captured": "2026-11-12T05:00:00Z"}},
                }
            },
        }
        checkov_report = [
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV2_VF_CUSTOM_1",
                            "check_name": "Ensure S3 bucket enforces DataClassification tag",
                            "file_abs_path": "/work/in/source/main.tf",
                            "file_line_range": [1, 3],
                            "resource": "aws_s3_bucket.data_lake",
                            "code_block": [
                                [1, 'resource "aws_s3_bucket" "data_lake" {'],
                                [2, '  bucket = "acme-untagged-lake"'],
                                [3, "}"],
                            ],
                        }
                    ]
                },
            }
        ]

        seen_tools: list[str] = []
        comp_results: list[dict[str, Any]] = []

        async def _claim_and_complete_next(
            target_run_id: str | None = None,
            *,
            skip_upload: bool = False,
        ) -> bool:
            active_run_id = target_run_id or run_id
            async with session_factory() as s:
                await set_db_context(s, org_id=uuid.UUID(org1), user_id=uuid.uuid4())
                outbox_rows = (
                    (
                        await s.execute(
                            select(OutboxEvent).where(
                                OutboxEvent.scan_run_id == uuid.UUID(active_run_id),
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
                    session_factory, p, worker_id="ph6-worker", settings=cfg
                )

            async with httpx.AsyncClient(
                transport=mtls_transport, base_url="https://runner.local"
            ) as gw_client:
                claim = (
                    await gw_client.post(
                        "/api/v1/runner/jobs/claim",
                        json={"pool_id": pool_id, "runner_version": "0.1.0"},
                    )
                ).json()
                if not claim.get("claimed"):
                    return False

                job_id = claim["job_id"]
                exec_id = claim["execution_id"]
                attempt = claim["attempt_number"]
                tool_id = claim["manifest"]["execution"]["toolId"]
                seen_tools.append(tool_id)

                uploads: list[tuple[str, str, bytes]] = []
                if tool_id == "syft":
                    snap_dl = await gw_client.get(f"/api/v1/runner/jobs/{job_id}/source-snapshot")
                    assert snap_dl.status_code == 200
                    # Non-grype jobs must be denied from /sbom-input
                    bad_sbom_req = await gw_client.get(f"/api/v1/runner/jobs/{job_id}/sbom-input")
                    assert bad_sbom_req.status_code == 422
                    uploads.append(
                        (
                            "raw_output",
                            "application/vnd.cyclonedx+json",
                            json.dumps(cdx_doc).encode("utf-8"),
                        )
                    )
                    uploads.append(
                        (
                            "raw_output",
                            "application/spdx+json",
                            json.dumps(spdx_doc).encode("utf-8"),
                        )
                    )
                elif tool_id == "grype":
                    assert claim["manifest"]["execution"]["requiresSbomInput"] is True
                    sbom_in = await gw_client.get(f"/api/v1/runner/jobs/{job_id}/sbom-input")
                    assert sbom_in.status_code == 200, sbom_in.text
                    assert json.loads(sbom_in.content.decode("utf-8")) == cdx_doc
                    assert (
                        sbom_in.headers["X-SBOM-SHA256"]
                        == hashlib.sha256(sbom_in.content).hexdigest()
                    )
                    uploads.append(
                        ("raw_output", "application/json", json.dumps(grype_report).encode("utf-8"))
                    )
                elif tool_id == "checkov":
                    assert claim["manifest"]["execution"]["enableCustomPolicies"] is True
                    snap_dl = await gw_client.get(f"/api/v1/runner/jobs/{job_id}/source-snapshot")
                    assert snap_dl.status_code == 200
                    uploads.append(
                        (
                            "raw_output",
                            "application/json",
                            json.dumps(checkov_report).encode("utf-8"),
                        )
                    )

                if not skip_upload:
                    for a_type, c_type, raw_bytes in uploads:
                        up = await gw_client.post(
                            f"/api/v1/runner/jobs/{job_id}/artifacts",
                            json={
                                "execution_id": exec_id,
                                "attempt_number": attempt,
                                "artifact_type": a_type,
                                "content_type": c_type,
                                "sha256": hashlib.sha256(raw_bytes).hexdigest(),
                                "content_b64": base64.b64encode(raw_bytes).decode("ascii"),
                            },
                        )
                        assert up.status_code == 201, up.text

                comp = await gw_client.post(
                    f"/api/v1/runner/jobs/{job_id}/complete",
                    json={
                        "execution_id": exec_id,
                        "attempt_number": attempt,
                        "status": "completed",
                        "exit_code": 0,
                        "metrics": {"uploaded": 0 if skip_upload else len(uploads)},
                    },
                )
                assert comp.status_code == 200, comp.text
                comp_results.append(comp.json())
                return True

        # Order: preflight -> checkov -> syft -> grype (stages sort alphabetically)
        for _ in range(4):
            assert await _claim_and_complete_next() is True
        assert await _claim_and_complete_next() is False
        assert seen_tools == ["vforge-dummy-scanner", "checkov", "syft", "grype"]

        # Verify scan completed and SBOM + VulnerabilityDB + Findings are traceable
        sboms_resp = await owner_client.get(f"/api/v1/organizations/{org1}/sboms")
        assert sboms_resp.status_code == 200, sboms_resp.text
        assert sboms_resp.json()["total"] == 2
        cdx_meta = next(
            item for item in sboms_resp.json()["items"] if item["sbom_format"] == "cyclonedx-json"
        )
        sbom_detail = await owner_client.get(f"/api/v1/organizations/{org1}/sboms/{cdx_meta['id']}")
        assert sbom_detail.status_code == 200
        assert any(
            c["purl"] == "pkg:pypi/requests@2.19.1"
            for c in sbom_detail.json()["components_summary"]
        )

        db_snaps = await owner_client.get(
            f"/api/v1/organizations/{org1}/vulnerability-db-snapshots"
        )
        assert db_snaps.status_code == 200, db_snaps.text
        assert db_snaps.json()["total"] == 1
        db_snap_item = db_snaps.json()["items"][0]
        assert db_snap_item["schema_version"] == "v6.1.10"
        assert db_snap_item["db_archive_sha256"] == ("abcdef0123456789" * 4)

        sca_findings = await owner_client.get(
            f"/api/v1/organizations/{org1}/findings",
            params={"purl": "pkg:pypi/requests@2.19.1"},
        )
        assert sca_findings.status_code == 200, sca_findings.text
        assert sca_findings.json()["total"] == 1
        sca_item = sca_findings.json()["items"][0]
        assert sca_item["category"] == "sca"
        assert sca_item["cve_id"] == "CVE-2018-18074"
        assert sca_item["fixed_version"] == "2.20.0"
        assert sca_item["sbom_document_id"] == cdx_meta["id"]
        assert sca_item["vulnerability_db_snapshot_id"] == db_snap_item["id"]

        iac_findings = await owner_client.get(
            f"/api/v1/organizations/{org1}/findings",
            params={"category": "iac"},
        )
        assert iac_findings.status_code == 200
        assert iac_findings.json()["total"] == 1
        iac_item = iac_findings.json()["items"][0]
        assert iac_item["rule_id"] == "CKV2_VF_CUSTOM_1"
        assert iac_item["file_path"] == "main.tf"
        assert iac_item["start_line"] == 1
        assert iac_item["iac_resource"] == "aws_s3_bucket.data_lake"

        # Verify /scanner-coverage reflects Phase 6 tools
        cov = await owner_client.get(f"/api/v1/organizations/{org1}/scanner-coverage")
        assert cov.status_code == 200
        assert cov.json()["phase"] >= 6
        assert {
            "opengrep",
            "gitleaks",
            "syft",
            "grype",
            "checkov",
        }.issubset({t["tool_id"] for t in cov.json()["tools"]})

        # Verify strict cross-tenant RLS isolation on org2 vs org1
        assert (await other_client.get(f"/api/v1/organizations/{org2}/sboms")).json()["total"] == 0
        assert (
            await other_client.get(f"/api/v1/organizations/{org2}/vulnerability-db-snapshots")
        ).json()["total"] == 0
        assert (
            await other_client.get(f"/api/v1/organizations/{org2}/sboms/{cdx_meta['id']}")
        ).status_code == 404
        assert (await other_client.get(f"/api/v1/organizations/{org1}/sboms")).status_code == 403

        # Honesty invariant: Syft completing without uploading CycloneDX SBOM must fail closed
        bad_scan_resp = await owner_client.post(
            f"/api/v1/organizations/{org1}/scans",
            json={
                "project_id": proj_id,
                "environment_id": env_id,
                "scan_profile_id": profile_id,
                "authorization_id": auth_id,
                "scope_snapshot_id": scope_snapshot_id,
                "source_snapshot_id": source_snapshot_id,
                "execution_mode": "runner",
                "target_pool_id": pool_id,
            },
            headers={"X-CSRF-Token": owner_csrf, "Idempotency-Key": f"ph6-bad-{uuid.uuid4().hex}"},
        )
        assert bad_scan_resp.status_code == 201, bad_scan_resp.text
        bad_run_id = bad_scan_resp.json()["id"]
        assert await _claim_and_complete_next(bad_run_id) is True  # preflight
        assert await _claim_and_complete_next(bad_run_id, skip_upload=True) is True  # syft w/o SBOM
        assert comp_results[-1]["job_status"] == "failed"
        assert comp_results[-1]["execution_status"] == "failed"
        assert comp_results[-1]["scan_run_status"] == "failed"

        # Silence unused adapter imports while pinning adapter availability
        _ = (SyftAdapter, GrypeAdapter, CheckovAdapter)


def test_phase6_planner_orders_sbom_before_unnormalized_sca() -> None:
    """Ensure planner prepends sbom upstream of sca even if raw profile lists ['sca', 'sbom']."""
    org_id = uuid.uuid4()
    profile = ScanProfile(
        id=uuid.uuid4(),
        organization_id=org_id,
        name="Unnormalized Sca Sbom",
        version=1,
        status=ScanProfileStatus.ACTIVE.value,
        configuration={"stages": ["sca", "sbom"], "timeout_seconds": 300},
    )
    asset = Asset(
        id=uuid.uuid4(),
        organization_id=org_id,
        environment_id=uuid.uuid4(),
        asset_type="source_repository",
        normalized_locator="https://github.com/acme/app-repo",
    )
    plan = build_declarative_scan_plan(
        profile=profile,
        asset=asset,
        execution_mode="runner",
        source_snapshot_present=True,
    )
    tool_order = [stage.jobs[0].tool_id for stage in plan.stages]
    assert tool_order == ["vforge-dummy-scanner", "syft", "grype"]
    assert plan.stages[1].stage_key.endswith("_sbom")
    assert plan.stages[2].stage_key.endswith("_sca")
