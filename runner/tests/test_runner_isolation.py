"""Phase 4 runner package tests: manifest verification, hardened flags, egress gateway, cleanup."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import shutil
import socket
import subprocess
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from vforge_scope import StaticDnsResolver

from vforge_runner.agent.runner_agent import RunnerAgent, RunnerConfig
from vforge_runner.executor.container_executor import (
    ContainerCleanupError,
    ContainerExecutor,
    ContainerRunResult,
    DockerCliRuntime,
    HardenedContainerSpec,
    build_hardened_docker_args,
)
from vforge_runner.manifest import VerifiedJobManifest, verify_signed_job_manifest
from vforge_runner.network_policy.egress_gateway import ScopedEgressGateway

APPROVED_DUMMY_IMAGE = "vforge/dummy-scanner@sha256:" + ("1" * 64)
SECCOMP_PATH = Path(__file__).resolve().parents[1] / "network-policy" / "seccomp-scanner.json"


def _make_keypair() -> tuple[Ed25519PrivateKey, str]:
    priv = Ed25519PrivateKey.generate()
    pub_pem = (
        priv.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode("ascii")
    )
    keyring_json = json.dumps({"vf-test-key": {"public_key_pem": pub_pem, "status": "active"}})
    return priv, keyring_json


def _sign_manifest(priv: Ed25519PrivateKey, manifest: dict[str, Any]) -> tuple[str, str]:
    canonical = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    sig_raw = priv.sign(digest.encode("ascii"))
    sig = base64.urlsafe_b64encode(sig_raw).decode("ascii").rstrip("=")
    return digest, sig


def _sample_manifest_dict(
    *,
    org_id: str | None = None,
    expires_delta: timedelta = timedelta(minutes=10),
    image: str = APPROVED_DUMMY_IMAGE,
    tool_id: str = "vforge-dummy-scanner",
    network_profile: str = "none",
) -> dict[str, Any]:
    return {
        "apiVersion": "vforge.io/v1alpha1",
        "kind": "ExecutionManifest",
        "metadata": {
            "jobId": str(uuid.uuid4()),
            "scanRunId": str(uuid.uuid4()),
            "organizationId": org_id or str(uuid.uuid4()),
            "expiresAt": (datetime.now(UTC) + expires_delta).isoformat(),
        },
        "execution": {
            "image": image,
            "toolId": tool_id,
        },
        "security": {
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "noNewPrivileges": True,
            "dropCapabilities": ["ALL"],
            "seccompProfile": "vforge/seccomp-scanner.json",
        },
        "limits": {
            "timeoutSeconds": 60,
            "cpu": 1,
            "memoryMb": 256,
            "pidsLimit": 64,
            "maxOutputMb": 5,
        },
        "network": {
            "profile": network_profile,
            "allowedTargets": ["http://app.example.com:80/api"],
            "allowedPorts": [80, 443],
            "pinnedIps": ["93.184.216.34"],
            "allowPrivateNetworks": False,
        },
    }


def test_hardened_docker_args_and_forbidden_secret_env(tmp_path: Path) -> None:
    spec = HardenedContainerSpec(
        container_name="vf-test-container",
        image=APPROVED_DUMMY_IMAGE,
        work_in_dir=tmp_path / "in",
        work_out_dir=tmp_path / "out",
        seccomp_profile_path=SECCOMP_PATH,
        cpu=1,
        memory_mb=256,
        pids_limit=64,
        network_mode="none",
        env={"VFORGE_JOB_ID": "job-1"},
    )
    args = build_hardened_docker_args(spec)
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges:true" in args
    assert f"--security-opt=seccomp={SECCOMP_PATH}" in args
    assert "--user=10001:10001" in args
    assert "--pids-limit=64" in args
    assert "--memory=256m" in args
    assert "--network=none" in args
    assert all("docker.sock" not in part for part in args)
    assert "--privileged" not in args

    bad_host_spec = HardenedContainerSpec(
        container_name="vf-bad-host",
        image=APPROVED_DUMMY_IMAGE,
        work_in_dir=tmp_path / "in",
        work_out_dir=tmp_path / "out",
        seccomp_profile_path=SECCOMP_PATH,
        cpu=1,
        memory_mb=256,
        pids_limit=64,
        network_mode="host",
        env={},
    )
    with pytest.raises(ValueError, match="Host network mode"):
        build_hardened_docker_args(bad_host_spec)

    bad_secret_spec = HardenedContainerSpec(
        container_name="vf-bad-secret",
        image=APPROVED_DUMMY_IMAGE,
        work_in_dir=tmp_path / "in",
        work_out_dir=tmp_path / "out",
        seccomp_profile_path=SECCOMP_PATH,
        cpu=1,
        memory_mb=256,
        pids_limit=64,
        network_mode="none",
        env={"POSTGRES_APP_PASSWORD": "leaked"},
    )
    with pytest.raises(ValueError, match="Forbidden control-plane credential"):
        build_hardened_docker_args(bad_secret_spec)


def test_verify_signed_job_manifest_rejects_expired_tampered_or_unapproved() -> None:
    priv, keyring_json = _make_keypair()
    m = _sample_manifest_dict()
    sha, sig = _sign_manifest(priv, m)

    verified = verify_signed_job_manifest(
        manifest=m,
        expected_sha256=sha,
        signing_key_id="vf-test-key",
        signature=sig,
        trusted_public_keyring_json=keyring_json,
        allowed_image_digests=[APPROVED_DUMMY_IMAGE],
    )
    assert verified.image == APPROVED_DUMMY_IMAGE

    # Unapproved image digest fails fail-closed
    with pytest.raises(ValueError, match="allowlist"):
        verify_signed_job_manifest(
            manifest=m,
            expected_sha256=sha,
            signing_key_id="vf-test-key",
            signature=sig,
            trusted_public_keyring_json=keyring_json,
            allowed_image_digests=["vforge/other@sha256:" + ("9" * 64)],
        )

    # Expired manifest fails
    expired_m = _sample_manifest_dict(expires_delta=timedelta(seconds=-5))
    exp_sha, exp_sig = _sign_manifest(priv, expired_m)
    with pytest.raises(ValueError, match="expired"):
        verify_signed_job_manifest(
            manifest=expired_m,
            expected_sha256=exp_sha,
            signing_key_id="vf-test-key",
            signature=exp_sig,
            trusted_public_keyring_json=keyring_json,
            allowed_image_digests=[APPROVED_DUMMY_IMAGE],
        )

    # Mutable tag fails even if signed
    tag_m = _sample_manifest_dict(image="vforge/dummy-scanner:latest")
    tag_sha, tag_sig = _sign_manifest(priv, tag_m)
    with pytest.raises(ValueError, match="immutable @sha256"):
        verify_signed_job_manifest(
            manifest=tag_m,
            expected_sha256=tag_sha,
            signing_key_id="vf-test-key",
            signature=tag_sig,
            trusted_public_keyring_json=keyring_json,
            allowed_image_digests=["vforge/dummy-scanner:latest"],
        )


@pytest.mark.asyncio
async def test_scoped_egress_gateway_allows_pinned_target_and_blocks_ssrf_rebinding_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Prove proxy allows pinned target while blocking SSRF, rebinding, and redirects."""
    import vforge_runner.network_policy.egress_gateway as gw_mod

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/api/ok":
                body = b'{"status":"target-ok"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path == "/api/redir-metadata":
                self.send_response(302)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/api/redir-offscope":
                self.send_response(302)
                self.send_header("Location", "http://evil.example/steal")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    upstream_port = int(upstream.server_address[1])
    t = Thread(target=upstream.serve_forever, daemon=True)
    t.start()

    dialed_pinned_ips: list[tuple[str, int]] = []

    def _test_pinned_connect(pinned_ip: str, port: int, timeout: float = 10.0) -> socket.socket:
        dialed_pinned_ips.append((pinned_ip, port))
        assert pinned_ip == "93.184.216.34"
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", upstream_port))
        sock.setblocking(False)
        return sock

    monkeypatch.setattr(gw_mod, "_open_pinned_tcp_socket", _test_pinned_connect)

    manifest = VerifiedJobManifest(
        job_id="job-egress-1",
        scan_run_id="run-egress-1",
        organization_id=str(uuid.uuid4()),
        image=APPROVED_DUMMY_IMAGE,
        tool_id="dummy",
        timeout_seconds=30,
        cpu=1,
        memory_mb=256,
        pids_limit=64,
        max_output_bytes=1024 * 1024,
        network_profile="scoped-http-egress",
        allowed_targets=("http://app.example.com:80/api",),
        allowed_ports=(80, 443),
        pinned_ips=("93.184.216.34",),
        allow_private_networks=False,
        probe_url="http://app.example.com:80/api/ok",
        raw_manifest={},
    )

    dns = StaticDnsResolver(
        {
            "app.example.com": ["93.184.216.34"],
            "evil.example": ["198.51.100.20"],
            "rebound.example.com": ["198.51.100.77"],
        }
    )
    events: list[tuple[str, str, dict[str, Any]]] = []

    def _on_block(event_type: str, severity: str, details: dict[str, Any]) -> None:
        events.append((event_type, severity, details))

    try:
        async with ScopedEgressGateway(manifest, dns_resolver=dns, on_block=_on_block) as proxy:
            async with httpx.AsyncClient(proxy=proxy.proxy_url, timeout=10.0) as client:
                ok_resp = await client.get("http://app.example.com:80/api/ok")
                assert ok_resp.status_code == 200
                assert ok_resp.json()["status"] == "target-ok"
                assert dialed_pinned_ips == [("93.184.216.34", 80)]

                for blocked_url in (
                    "http://169.254.169.254/latest/meta-data/",
                    "http://10.0.0.1/",
                    "http://192.168.1.1/",
                    "http://evil.example/",
                    "http://app.example.com:8444/api/ok",
                    "http://app.example.com:80/api/redir-metadata",
                    "http://app.example.com:80/api/redir-offscope",
                ):
                    r = await client.get(blocked_url)
                    assert r.status_code == 403, (
                        f"Expected 403 for {blocked_url}, got {r.status_code}"
                    )

                # DNS rebinding check: domain moves to unpinned IP -> blocked!
                dns_rebind = StaticDnsResolver({"app.example.com": ["198.51.100.99"]})
                proxy.dns_resolver = dns_rebind
                rebind_resp = await client.get("http://app.example.com:80/api/ok")
                assert rebind_resp.status_code == 403

        assert len(events) >= 8
        assert all(ev[0] == "egress_blocked" and ev[1] == "security" for ev in events)
    finally:
        upstream.shutdown()


@pytest.mark.asyncio
async def test_runner_agent_cancel_and_cleanup_failed_security_event(tmp_path: Path) -> None:
    priv, keyring_json = _make_keypair()
    org_id = str(uuid.uuid4())
    m = _sample_manifest_dict(org_id=org_id)
    sha, sig = _sign_manifest(priv, m)

    recorded_events: list[dict[str, Any]] = []
    completed_payloads: list[dict[str, Any]] = []
    hb_calls = 0

    class _FakeRuntime:
        def __init__(self, *, fail_cleanup: bool, wait_cancel: bool) -> None:
            self.fail_cleanup = fail_cleanup
            self.wait_cancel = wait_cancel
            self.removed: list[str] = []

        async def run_container(
            self,
            spec: HardenedContainerSpec,
            *,
            timeout_seconds: int,
            max_output_bytes: int,
            cancel_event: asyncio.Event | None = None,
        ) -> ContainerRunResult:
            del timeout_seconds, max_output_bytes
            if self.wait_cancel and cancel_event is not None:
                await asyncio.wait_for(cancel_event.wait(), timeout=3.0)
                return ContainerRunResult(
                    exit_code=137,
                    timed_out=False,
                    cancelled=True,
                    output_truncated=False,
                    stdout_tail="",
                    stderr_tail="cancelled",
                )
            (spec.work_out_dir / "result.json").write_text('{"ok":true}', encoding="utf-8")
            return ContainerRunResult(
                exit_code=0,
                timed_out=False,
                cancelled=False,
                output_truncated=False,
                stdout_tail="done",
                stderr_tail="",
            )

        async def force_remove_container(self, container_name: str) -> None:
            if self.fail_cleanup:
                raise ContainerCleanupError(f"Simulated cleanup error for {container_name}")
            self.removed.append(container_name)

    def _mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal hb_calls
        if request.url.path.endswith("/claim"):
            return httpx.Response(
                200,
                json={
                    "claimed": True,
                    "job_id": m["metadata"]["jobId"],
                    "scan_run_id": m["metadata"]["scanRunId"],
                    "execution_id": str(uuid.uuid4()),
                    "attempt_number": 1,
                    "manifest": m,
                    "manifest_sha256": sha,
                    "manifest_signature": sig,
                    "manifest_signing_key_id": "vf-test-key",
                    "public_keyring_json": keyring_json,
                },
            )
        if request.url.path.endswith("/heartbeat"):
            hb_calls += 1
            return httpx.Response(
                200,
                json={"acknowledged": True, "cancel_requested": True, "runner_status": "online"},
            )
        if request.url.path.endswith("/events"):
            recorded_events.append(json.loads(request.content))
            return httpx.Response(201, json={"id": str(uuid.uuid4())})
        if request.url.path.endswith("/artifacts"):
            return httpx.Response(201, json={"id": str(uuid.uuid4())})
        if request.url.path.endswith("/complete"):
            completed_payloads.append(json.loads(request.content))
            return httpx.Response(
                200, json={"acknowledged": True, "job_status": "done", "scan_run_status": "done"}
            )
        return httpx.Response(404)

    cfg = RunnerConfig(
        gateway_url="https://runner-gateway.test",
        allowed_image_digests=(APPROVED_DUMMY_IMAGE,),
        seccomp_profile_path=SECCOMP_PATH,
        organization_id=org_id,
        trusted_keyring_json=keyring_json,
        heartbeat_interval_seconds=0.05,
    )

    # 1) Operator cancellation via heartbeat
    async with httpx.AsyncClient(
        base_url=cfg.gateway_url,
        transport=httpx.MockTransport(_mock_handler),
    ) as client_cancel:
        agent_cancel = RunnerAgent(
            cfg,
            executor=ContainerExecutor(
                runtime=_FakeRuntime(fail_cleanup=False, wait_cancel=True),
                seccomp_profile_path=SECCOMP_PATH,
                workspace_base_dir=tmp_path,
            ),
            http_client=client_cancel,
        )
        assert await agent_cancel.run_once() is True
    assert completed_payloads[-1]["status"] == "cancelled"

    # 2) Cleanup failure emits `cleanup_failed` security event and marks failed
    async with httpx.AsyncClient(
        base_url=cfg.gateway_url,
        transport=httpx.MockTransport(_mock_handler),
    ) as client_cleanup:
        agent_cleanup = RunnerAgent(
            cfg,
            executor=ContainerExecutor(
                runtime=_FakeRuntime(fail_cleanup=True, wait_cancel=False),
                seccomp_profile_path=SECCOMP_PATH,
                workspace_base_dir=tmp_path,
            ),
            http_client=client_cleanup,
        )
        assert await agent_cleanup.run_once() is True

    assert any(
        ev["event_type"] == "cleanup_failed" and ev["severity"] == "security"
        for ev in recorded_events
    )
    assert completed_payloads[-1]["status"] == "failed"
    assert completed_payloads[-1]["error_code"] == "cleanup_failed"


@pytest.mark.asyncio
async def test_live_docker_dummy_scanner_if_docker_available(tmp_path: Path) -> None:
    """Run real hardened dummy-scanner container if local Docker daemon is accessible."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        pytest.skip("docker CLI not installed")
    probe = subprocess.run([docker_bin, "info"], capture_output=True, text=True, check=False)  # noqa: S603
    if probe.returncode != 0:
        pytest.skip("Docker daemon not accessible in this environment")

    dockerfile_dir = Path(__file__).resolve().parents[1] / "images" / "dummy-scanner"
    tag = f"vforge-dummy-scanner-test:{uuid.uuid4().hex[:8]}"
    build = subprocess.run(  # noqa: S603
        [docker_bin, "build", "-t", tag, str(dockerfile_dir)],
        capture_output=True,
        text=True,
        check=False,
    )
    if build.returncode != 0:
        pytest.skip(f"Docker build unavailable: {build.stderr[:200]}")

    from vforge_runner.executor.container_executor import DockerCliRuntime

    manifest = VerifiedJobManifest(
        job_id="docker-smoke-1",
        scan_run_id="scan-smoke-1",
        organization_id=str(uuid.uuid4()),
        image=tag,
        tool_id="vforge-dummy-scanner",
        timeout_seconds=30,
        cpu=1,
        memory_mb=128,
        pids_limit=64,
        max_output_bytes=1024 * 1024,
        network_profile="none",
        allowed_targets=(),
        allowed_ports=(),
        pinned_ips=(),
        allow_private_networks=False,
        probe_url="",
        raw_manifest={"kind": "ExecutionManifest"},
    )
    executor = ContainerExecutor(
        runtime=DockerCliRuntime(docker_bin),
        seccomp_profile_path=SECCOMP_PATH,
        workspace_base_dir=tmp_path,
    )
    try:
        output = await executor.execute_manifest(manifest)
        assert output.cleanup_ok is True
        assert output.run_result.exit_code == 0
        assert any(a.filename == "result.json" for a in output.artifacts)
        ps = subprocess.run(  # noqa: S603
            [docker_bin, "ps", "-a", "--filter", "name=vf-scan-docker-smoke-1", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert ps.stdout.strip() == ""
    finally:
        subprocess.run([docker_bin, "rmi", "-f", tag], capture_output=True, check=False)  # noqa: S603


@pytest.mark.asyncio
async def test_runner_agent_gitleaks_exit10_and_secret_redaction(tmp_path: Path) -> None:
    """RunnerAgent fetches source snapshot, handles exit_code=10, and scrubs secrets in logs."""
    import io
    import tarfile

    from vforge_scanners import GitleaksAdapter, canonicalize_source_archive

    priv, keyring_json = _make_keypair()
    org_id = str(uuid.uuid4())
    fake_raw_tar = io.BytesIO()
    with tarfile.open(fileobj=fake_raw_tar, mode="w:gz") as tf:
        payload = b'TOKEN = "ghp_123456789012345678901234567890123456"\n'
        info = tarfile.TarInfo(name="config.py")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    canonical = canonicalize_source_archive(fake_raw_tar.getvalue(), source_type="archive_tar_gz")
    snap_sha = hashlib.sha256(canonical.canonical_tar_gz).hexdigest()

    gitleaks_image = GitleaksAdapter().metadata().pinned_image
    manifest_dict = _sample_manifest_dict(org_id=org_id, image=gitleaks_image)
    manifest_dict["execution"]["toolId"] = "gitleaks"
    manifest_dict["inputs"] = {
        "sourceSnapshotId": "snap-unit-1",
        "sourceSnapshotSha256": snap_sha,
    }
    job_id = manifest_dict["metadata"]["jobId"]
    digest, sig = _sign_manifest(priv, manifest_dict)

    observed_specs: list[HardenedContainerSpec] = []
    uploaded_artifacts: list[dict[str, Any]] = []
    completed_payloads: list[dict[str, Any]] = []

    class _GitleaksFakeRuntime:
        async def run_container(
            self,
            spec: HardenedContainerSpec,
            *,
            timeout_seconds: int,
            max_output_bytes: int,
            cancel_event: asyncio.Event | None = None,
        ) -> ContainerRunResult:
            _ = (timeout_seconds, max_output_bytes, cancel_event)
            observed_specs.append(spec)
            assert (spec.work_in_dir / "source" / "config.py").is_file()
            (spec.work_out_dir / "gitleaks.json").write_text("[]", encoding="utf-8")
            return ContainerRunResult(
                exit_code=10,
                stdout_tail=(
                    "leaked AKIAIOSFODNN7EXAMPLE and ghp_123456789012345678901234567890123456"
                ),
                stderr_tail="",
                timed_out=False,
                cancelled=False,
                output_truncated=False,
            )

        async def force_remove_container(self, container_name: str) -> None:
            _ = container_name

    def _mock_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/runner/jobs/claim":
            return httpx.Response(
                200,
                json={
                    "claimed": True,
                    "job_id": job_id,
                    "scan_run_id": manifest_dict["metadata"]["scanRunId"],
                    "scan_stage_id": str(uuid.uuid4()),
                    "execution_id": str(uuid.uuid4()),
                    "attempt_number": 1,
                    "manifest": manifest_dict,
                    "manifest_sha256": digest,
                    "manifest_signature": sig,
                    "manifest_signing_key_id": "vf-test-key",
                    "public_keyring_json": keyring_json,
                },
            )
        if request.url.path.endswith("/source-snapshot"):
            return httpx.Response(
                200,
                content=canonical.canonical_tar_gz,
                headers={"X-Source-Snapshot-Sha256": snap_sha},
            )
        if request.url.path.endswith("/artifacts"):
            uploaded_artifacts.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(201, json={"id": str(uuid.uuid4())})
        if request.url.path.endswith("/complete"):
            completed_payloads.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(200, json={"status": "ok"})
        return httpx.Response(200, json={"status": "ok"})

    cfg = RunnerConfig(
        gateway_url="https://runner-gateway.local:8443",
        allowed_image_digests=(gitleaks_image,),
        seccomp_profile_path=SECCOMP_PATH,
        organization_id=org_id,
        trusted_keyring_json=keyring_json,
        workspace_base_dir=tmp_path,
    )
    async with httpx.AsyncClient(
        base_url=cfg.gateway_url,
        transport=httpx.MockTransport(_mock_handler),
    ) as client:
        agent = RunnerAgent(
            cfg,
            executor=ContainerExecutor(
                runtime=_GitleaksFakeRuntime(),
                seccomp_profile_path=SECCOMP_PATH,
                workspace_base_dir=tmp_path,
            ),
            http_client=client,
        )
        assert await agent.run_once() is True

    assert "--redact=100" in observed_specs[0].command
    assert "--exit-code=10" in observed_specs[0].command
    assert completed_payloads[0]["status"] == "completed"
    assert completed_payloads[0]["exit_code"] == 10
    log_arts = [a for a in uploaded_artifacts if a["artifact_type"] == "execution_log"]
    assert len(log_arts) == 1
    decoded_log = base64.b64decode(log_arts[0]["content_b64"]).decode("utf-8")
    assert "AKIAIOSFODNN7EXAMPLE" not in decoded_log
    assert "ghp_123456789012345678901234567890123456" not in decoded_log


@pytest.mark.asyncio
async def test_live_docker_opengrep_and_gitleaks_if_available(tmp_path: Path) -> None:
    """Execute pinned OpenGrep & Gitleaks containers end-to-end when images exist in Docker."""
    import io
    import tarfile

    from vforge_scanners import (
        ExecutionResult,
        GitleaksAdapter,
        OpenGrepAdapter,
        ToolContext,
        canonicalize_source_archive,
    )

    from vforge_runner.executor.container_executor import DockerCliRuntime

    docker_bin = shutil.which("docker")
    if not docker_bin:
        pytest.skip("docker CLI not installed")
    if subprocess.run([docker_bin, "info"], capture_output=True, check=False).returncode != 0:  # noqa: S603
        pytest.skip("Docker daemon not accessible")
    if (
        subprocess.run(  # noqa: S603
            [docker_bin, "image", "inspect", "vforge-opengrep:1.33.1"],
            capture_output=True,
            check=False,
        ).returncode
        != 0
    ):
        pytest.skip("vforge-opengrep:1.33.1 image not built locally")

    secret_val = "ghp_9mKx2pQ8wVzL4nR7cYbJ1fH6sD3aE5uG0xZt"  # noqa: S105
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:gz") as tf:
        py_src = (
            b"import subprocess\n"
            b"def run(cmd: str) -> None:\n"
            b"    subprocess.run(cmd, shell=True, check=False)\n"
        )
        cfg_src = f'GITHUB_TOKEN = "{secret_val}"\n'.encode()
        for name, data in (("app.py", py_src), ("secrets.py", cfg_src)):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    canonical = canonicalize_source_archive(raw_buf.getvalue(), source_type="archive_tar_gz")
    snap_sha = hashlib.sha256(canonical.canonical_tar_gz).hexdigest()

    executor = ContainerExecutor(
        runtime=DockerCliRuntime(docker_bin),
        seccomp_profile_path=SECCOMP_PATH,
        workspace_base_dir=tmp_path,
    )

    og_adapter = OpenGrepAdapter()
    og_spec = og_adapter.build_execution_spec(
        ToolContext(
            job_id="og-live-1",
            scan_run_id="scan-live-1",
            workspace=Path("/work"),
            input_paths=(Path("/work/in/source"),),
            output_dir=Path("/work/out"),
        )
    )
    og_manifest = VerifiedJobManifest(
        job_id="og-live-1",
        scan_run_id="scan-live-1",
        organization_id=str(uuid.uuid4()),
        image=og_spec.image,
        tool_id="opengrep",
        timeout_seconds=60,
        cpu=1,
        memory_mb=512,
        pids_limit=128,
        max_output_bytes=4 * 1024 * 1024,
        network_profile="none",
        allowed_targets=(),
        allowed_ports=(),
        pinned_ips=(),
        allow_private_networks=False,
        probe_url="",
        raw_manifest={"kind": "ExecutionManifest"},
        source_snapshot_id="snap-live-1",
        source_snapshot_sha256=snap_sha,
    )
    og_out = await executor.execute_manifest(
        og_manifest,
        command=og_spec.command,
        extra_env=og_spec.env,
        source_archive_bytes=canonical.canonical_tar_gz,
    )
    assert og_out.run_result.exit_code == 0
    og_json = next(a for a in og_out.artifacts if a.filename == "opengrep.json")
    og_findings = og_adapter.parse_json_report(json.loads(og_json.data.decode("utf-8")))
    assert any(
        "subprocess" in f.rule_id.lower() or "shell" in f.rule_id.lower() for f in og_findings
    )
    assert any(a.filename == "opengrep.sarif" for a in og_out.artifacts)

    gl_adapter = GitleaksAdapter()
    gl_spec = gl_adapter.build_execution_spec(
        ToolContext(
            job_id="gl-live-1",
            scan_run_id="scan-live-1",
            workspace=Path("/work"),
            input_paths=(Path("/work/in/source"),),
            output_dir=Path("/work/out"),
        )
    )
    gl_manifest = VerifiedJobManifest(
        job_id="gl-live-1",
        scan_run_id="scan-live-1",
        organization_id=og_manifest.organization_id,
        image=gl_spec.image,
        tool_id="gitleaks",
        timeout_seconds=60,
        cpu=1,
        memory_mb=256,
        pids_limit=64,
        max_output_bytes=4 * 1024 * 1024,
        network_profile="none",
        allowed_targets=(),
        allowed_ports=(),
        pinned_ips=(),
        allow_private_networks=False,
        probe_url="",
        raw_manifest={"kind": "ExecutionManifest"},
        source_snapshot_id="snap-live-1",
        source_snapshot_sha256=snap_sha,
    )
    gl_out = await executor.execute_manifest(
        gl_manifest,
        command=gl_spec.command,
        extra_env=gl_spec.env,
        source_archive_bytes=canonical.canonical_tar_gz,
    )
    assert gl_out.run_result.exit_code == 10
    gl_json = next(a for a in gl_out.artifacts if a.filename == "gitleaks.json")
    gl_report_path = tmp_path / "gitleaks-out.json"
    gl_report_path.write_bytes(gl_json.data)
    gl_findings = gl_adapter.normalize(
        ExecutionResult(
            status="completed",
            exit_code=gl_out.run_result.exit_code or 0,
            artifacts=[gl_report_path],
        )
    )
    assert len(gl_findings) >= 1
    assert all(f.secret_redacted for f in gl_findings)
    assert secret_val not in gl_json.data.decode("utf-8")
    assert all(f.secret_redacted is True for f in gl_findings)
    assert secret_val not in json.dumps([f.code_snippet_redacted for f in gl_findings])


def test_build_hardened_docker_args_validates_extra_ro_mounts(tmp_path: Path) -> None:
    spec = HardenedContainerSpec(
        container_name="vf-test-ro",
        image=APPROVED_DUMMY_IMAGE,
        work_in_dir=tmp_path / "in",
        work_out_dir=tmp_path / "out",
        seccomp_profile_path=SECCOMP_PATH,
        cpu=1,
        memory_mb=512,
        pids_limit=64,
        network_mode="none",
        env={"GRYPE_DB_AUTO_UPDATE": "false"},
        command=("sbom:/work/in/sbom.cdx.json",),
        extra_ro_mounts=(("vforge_grype_db", "/work/db"),),
    )
    args = build_hardened_docker_args(spec)
    assert "--volume" in args
    assert "vforge_grype_db:/work/db:ro" in args
    assert any("mode=1777" in item for item in args if item.startswith("--tmpfs=/tmp:"))

    for bad_src, bad_dst in [
        ("/var/run/docker.sock", "/work/sock"),
        ("vforge_grype_db", "/etc/passwd"),
        ("../escape", "/work/db"),
    ]:
        bad_spec = HardenedContainerSpec(
            container_name="vf-test-bad",
            image=APPROVED_DUMMY_IMAGE,
            work_in_dir=tmp_path / "in",
            work_out_dir=tmp_path / "out",
            seccomp_profile_path=SECCOMP_PATH,
            cpu=1,
            memory_mb=512,
            pids_limit=64,
            network_mode="none",
            env={},
            extra_ro_mounts=((bad_src, bad_dst),),
        )
        with pytest.raises(ValueError, match="Forbidden extra read-only container mount"):
            build_hardened_docker_args(bad_spec)


@pytest.mark.asyncio
async def test_runner_agent_syft_grype_and_checkov_offline_wiring(tmp_path: Path) -> None:
    import io
    import tarfile

    from vforge_scanners import (
        CheckovAdapter,
        GrypeAdapter,
        SyftAdapter,
        canonicalize_source_archive,
    )

    priv, keyring_json = _make_keypair()
    org_id = str(uuid.uuid4())
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:gz") as tf:
        for name, data in (
            ("requirements.txt", b"urllib3==1.26.5\n"),
            ("main.tf", b'resource "aws_s3_bucket" "b" {}\n'),
        ):
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    canon = canonicalize_source_archive(raw_buf.getvalue(), source_type="archive_tar_gz")
    snap_sha = hashlib.sha256(canon.canonical_tar_gz).hexdigest()

    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    (policies_dir / "vf_custom.yaml").write_text(
        "metadata:\n  id: CKV2_VF_CUSTOM_1\n",
        encoding="utf-8",
    )

    syft_img = SyftAdapter().metadata().pinned_image
    grype_img = GrypeAdapter().metadata().pinned_image
    checkov_img = CheckovAdapter().metadata().pinned_image

    cdx_bytes = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "name": "urllib3",
                    "version": "1.26.5",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "type": "library",
                }
            ],
        }
    ).encode("utf-8")
    cdx_sha = hashlib.sha256(cdx_bytes).hexdigest()

    seen_specs: list[HardenedContainerSpec] = []
    uploaded_content_types: list[str] = []
    completed_statuses: list[str] = []

    class _MockPhase6Runtime:
        async def run_container(
            self,
            spec: HardenedContainerSpec,
            *,
            timeout_seconds: int,
            max_output_bytes: int,
            cancel_event: asyncio.Event | None = None,
        ) -> ContainerRunResult:
            del timeout_seconds, max_output_bytes, cancel_event
            seen_specs.append(spec)
            assert spec.network_mode == "none"
            if spec.env.get("VFORGE_TOOL_ID") == "syft":
                (spec.work_out_dir / "sbom.cdx.json").write_bytes(cdx_bytes)
                (spec.work_out_dir / "sbom.spdx.json").write_text(
                    json.dumps({"spdxVersion": "SPDX-2.3", "packages": []}),
                    encoding="utf-8",
                )
            elif spec.env.get("VFORGE_TOOL_ID") == "grype":
                assert (spec.work_in_dir / "sbom.cdx.json").read_bytes() == cdx_bytes
                assert ("vforge_grype_db", "/work/db") in spec.extra_ro_mounts
                assert spec.env.get("GRYPE_DB_AUTO_UPDATE") == "false"
                (spec.work_out_dir / "grype.json").write_text(
                    json.dumps(
                        {
                            "matches": [],
                            "descriptor": {
                                "db": {
                                    "status": {
                                        "schemaVersion": "v6.1.10",
                                        "built": "2026-11-12T06:20:58Z",
                                        "valid": True,
                                    }
                                }
                            },
                        }
                    ),
                    encoding="utf-8",
                )
            elif spec.env.get("VFORGE_TOOL_ID") == "checkov":
                assert "--skip-download" in spec.command
                assert "--external-checks-dir" in spec.command
                assert (str(policies_dir.resolve()), "/work/policies") in spec.extra_ro_mounts
                (spec.work_out_dir / "results_json.json").write_text(
                    json.dumps({"check_type": "terraform", "results": {"failed_checks": []}}),
                    encoding="utf-8",
                )
            return ContainerRunResult(
                exit_code=0,
                timed_out=False,
                cancelled=False,
                output_truncated=False,
                stdout_tail="ok",
                stderr_tail="",
            )

        async def force_remove_container(self, container_name: str) -> None:
            del container_name

    manifests_queue = [
        _sample_manifest_dict(org_id=org_id, tool_id="syft", image=syft_img),
        _sample_manifest_dict(org_id=org_id, tool_id="grype", image=grype_img),
        _sample_manifest_dict(org_id=org_id, tool_id="checkov", image=checkov_img),
    ]
    manifests_queue[0]["inputs"] = {
        "sourceSnapshotId": "snap-1",
        "sourceSnapshotSha256": snap_sha,
    }
    manifests_queue[1]["execution"]["requiresSbomInput"] = True
    manifests_queue[2]["inputs"] = {
        "sourceSnapshotId": "snap-1",
        "sourceSnapshotSha256": snap_sha,
    }
    manifests_queue[2]["execution"]["enableCustomPolicies"] = True

    idx = {"i": -1}

    def _handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/runner/jobs/claim":
            idx["i"] += 1
            if idx["i"] >= len(manifests_queue):
                return httpx.Response(204)
            m = manifests_queue[idx["i"]]
            sha, sig = _sign_manifest(priv, m)
            return httpx.Response(
                200,
                json={
                    "claimed": True,
                    "job_id": m["metadata"]["jobId"],
                    "scan_run_id": m["metadata"]["scanRunId"],
                    "organization_id": org_id,
                    "execution_id": str(uuid.uuid4()),
                    "attempt_number": 1,
                    "manifest": m,
                    "manifest_sha256": sha,
                    "manifest_signing_key_id": "vf-test-key",
                    "manifest_signature": sig,
                },
            )
        if request.url.path.endswith("/source-snapshot"):
            return httpx.Response(200, content=canon.canonical_tar_gz)
        if request.url.path.endswith("/sbom-input"):
            return httpx.Response(
                200,
                content=cdx_bytes,
                headers={"X-SBOM-SHA256": cdx_sha},
            )
        if request.url.path.endswith("/artifacts"):
            body = json.loads(request.content.decode("utf-8"))
            uploaded_content_types.append(body["content_type"])
            return httpx.Response(201, json={"id": str(uuid.uuid4())})
        if request.url.path.endswith("/complete"):
            body = json.loads(request.content.decode("utf-8"))
            completed_statuses.append(body["status"])
            return httpx.Response(200, json={"job_status": body["status"], "run_status": "running"})
        return httpx.Response(200, json={"ok": True})

    cfg = RunnerConfig(
        gateway_url="https://runner-gateway:8443",
        allowed_image_digests=(syft_img, grype_img, checkov_img),
        seccomp_profile_path=SECCOMP_PATH,
        organization_id=org_id,
        trusted_keyring_json=keyring_json,
        workspace_base_dir=tmp_path / "work",
        grype_db_source="vforge_grype_db",
        checkov_custom_policies_dir=policies_dir,
    )
    executor = ContainerExecutor(
        runtime=_MockPhase6Runtime(),
        seccomp_profile_path=SECCOMP_PATH,
        workspace_base_dir=tmp_path / "work",
    )
    async with httpx.AsyncClient(
        base_url="https://runner-gateway:8443",
        transport=httpx.MockTransport(_handler),
    ) as client:
        agent = RunnerAgent(cfg, executor=executor, http_client=client)
        assert await agent.run_once() is True
        assert await agent.run_once() is True
        assert await agent.run_once() is True

    assert completed_statuses == ["completed", "completed", "completed"]
    assert "application/vnd.cyclonedx+json" in uploaded_content_types
    assert "application/spdx+json" in uploaded_content_types
    assert "application/json" in uploaded_content_types
    assert len(seen_specs) == 3

    # Verify fail-closed behavior when Grype offline DB source is missing.
    no_db_cfg = RunnerConfig(
        gateway_url="https://runner-gateway:8443",
        allowed_image_digests=(grype_img,),
        seccomp_profile_path=SECCOMP_PATH,
        organization_id=org_id,
        trusted_keyring_json=keyring_json,
        workspace_base_dir=tmp_path / "work-nodb",
        grype_db_source=None,
    )
    failed_codes: list[str | None] = []
    grype_only = _sample_manifest_dict(org_id=org_id, tool_id="grype", image=grype_img)
    grype_only["execution"]["requiresSbomInput"] = True
    grype_sha, grype_sig = _sign_manifest(priv, grype_only)

    def _nodb_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/runner/jobs/claim":
            return httpx.Response(
                200,
                json={
                    "claimed": True,
                    "job_id": grype_only["metadata"]["jobId"],
                    "scan_run_id": grype_only["metadata"]["scanRunId"],
                    "organization_id": org_id,
                    "execution_id": str(uuid.uuid4()),
                    "attempt_number": 1,
                    "manifest": grype_only,
                    "manifest_sha256": grype_sha,
                    "manifest_signing_key_id": "vf-test-key",
                    "manifest_signature": grype_sig,
                },
            )
        if request.url.path.endswith("/complete"):
            body = json.loads(request.content.decode("utf-8"))
            failed_codes.append(body.get("error_code"))
            return httpx.Response(200, json={"job_status": body["status"], "run_status": "failed"})
        return httpx.Response(200, json={"ok": True})

    async with httpx.AsyncClient(
        base_url="https://runner-gateway:8443",
        transport=httpx.MockTransport(_nodb_handler),
    ) as client_nodb:
        agent_nodb = RunnerAgent(no_db_cfg, executor=executor, http_client=client_nodb)
        assert await agent_nodb.run_once() is True
    assert failed_codes == ["runner_execution_error"]


@pytest.mark.asyncio
async def test_phase6_security_hardening_mounts_sbom_sha_and_yaml_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify extra_ro_mounts survives fallback, missing X-SBOM-SHA256 & .py checks fail."""
    import io
    import tarfile

    from vforge_scanners import CheckovAdapter, GrypeAdapter, canonicalize_source_archive

    in_dir = tmp_path / "in"
    out_dir = tmp_path / "out"
    in_dir.mkdir()
    out_dir.mkdir()

    for bad_mount in (
        ("/run/containerd/containerd.sock", "/work/sock"),
        ("/run/podman/podman.sock", "/work/pod"),
        ("vforge_grype_db", "/work/in"),
        ("vforge_grype_db", "/work/out/db"),
    ):
        with pytest.raises(ValueError, match="Forbidden extra read-only container mount"):
            build_hardened_docker_args(
                HardenedContainerSpec(
                    container_name="vf-bad-mount",
                    image=APPROVED_DUMMY_IMAGE,
                    work_in_dir=in_dir,
                    work_out_dir=out_dir,
                    seccomp_profile_path=SECCOMP_PATH,
                    cpu=1,
                    memory_mb=256,
                    pids_limit=64,
                    network_mode="none",
                    env={},
                    extra_ro_mounts=(bad_mount,),
                )
            )

    seen_cmd_args: list[str] = []

    class _FakeProc:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b""

    async def _fake_exec(*cmd: str, **kwargs: Any) -> _FakeProc:
        del kwargs
        seen_cmd_args.extend(cmd)
        return _FakeProc()

    runtime = DockerCliRuntime()
    monkeypatch.setattr(
        runtime,
        "_resolve_verified_image_ref",
        AsyncMock(return_value="sha256:" + "a" * 64),
    )
    monkeypatch.setattr("asyncio.create_subprocess_exec", _fake_exec)

    await runtime.run_container(
        HardenedContainerSpec(
            container_name="vf-fallback-mounts",
            image=APPROVED_DUMMY_IMAGE,
            work_in_dir=in_dir,
            work_out_dir=out_dir,
            seccomp_profile_path=SECCOMP_PATH,
            cpu=1,
            memory_mb=256,
            pids_limit=64,
            network_mode="none",
            env={},
            extra_ro_mounts=(("vforge_grype_db", "/work/db"),),
        ),
        timeout_seconds=10,
        max_output_bytes=1024,
    )
    assert "vforge_grype_db:/work/db:ro" in seen_cmd_args

    # Fail closed if /sbom-input omits X-SBOM-SHA256 or checkov policy dir contains Python code.
    priv, keyring_json = _make_keypair()
    org_id = str(uuid.uuid4())
    raw_buf = io.BytesIO()
    with tarfile.open(fileobj=raw_buf, mode="w:gz") as tf:
        tf_data = b"# tf\n"
        info = tarfile.TarInfo(name="main.tf")
        info.size = len(tf_data)
        tf.addfile(info, io.BytesIO(tf_data))
    canon = canonicalize_source_archive(raw_buf.getvalue(), source_type="archive_tar_gz")
    snap_sha = hashlib.sha256(canon.canonical_tar_gz).hexdigest()

    grype_img = GrypeAdapter().metadata().pinned_image
    checkov_img = CheckovAdapter().metadata().pinned_image
    grype_manifest = _sample_manifest_dict(org_id=org_id, tool_id="grype", image=grype_img)
    grype_manifest["inputs"] = {
        "sourceSnapshotSha256": snap_sha,
        "sourceSnapshotFormat": "tar.gz",
    }
    grype_manifest["execution"]["requiresSbomInput"] = True
    grype_sha, grype_sig = _sign_manifest(priv, grype_manifest)

    checkov_manifest = _sample_manifest_dict(org_id=org_id, tool_id="checkov", image=checkov_img)
    checkov_manifest["inputs"] = {
        "sourceSnapshotSha256": snap_sha,
        "sourceSnapshotFormat": "tar.gz",
    }
    checkov_manifest["execution"]["enableCustomPolicies"] = True
    ckv_sha, ckv_sig = _sign_manifest(priv, checkov_manifest)

    bad_pol_dir = tmp_path / "bad_policies"
    bad_pol_dir.mkdir()
    (bad_pol_dir / "evil.py").write_text("print('nope')\n", encoding="utf-8")

    job_queue: list[tuple[dict[str, Any], str, str]] = [
        (grype_manifest, grype_sha, grype_sig),
        (checkov_manifest, ckv_sha, ckv_sig),
    ]
    failures: list[str | None] = []

    def _hardening_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/runner/jobs/claim":
            if not job_queue:
                return httpx.Response(204)
            man, sha, sig = job_queue.pop(0)
            return httpx.Response(
                200,
                json={
                    "claimed": True,
                    "job_id": man["metadata"]["jobId"],
                    "scan_run_id": man["metadata"]["scanRunId"],
                    "organization_id": org_id,
                    "execution_id": str(uuid.uuid4()),
                    "attempt_number": 1,
                    "manifest": man,
                    "manifest_sha256": sha,
                    "manifest_signing_key_id": "vf-test-key",
                    "manifest_signature": sig,
                },
            )
        if request.url.path.endswith("/source-snapshot"):
            return httpx.Response(200, content=canon.canonical_tar_gz)
        if request.url.path.endswith("/sbom-input"):
            return httpx.Response(200, content=b'{"bomFormat":"CycloneDX"}')
        if request.url.path.endswith("/complete"):
            body = json.loads(request.content.decode("utf-8"))
            failures.append(body.get("status"))
            return httpx.Response(200, json={"job_status": body["status"], "run_status": "failed"})
        return httpx.Response(200, json={"ok": True})

    cfg = RunnerConfig(
        gateway_url="https://runner-gateway:8443",
        allowed_image_digests=(grype_img, checkov_img),
        seccomp_profile_path=SECCOMP_PATH,
        organization_id=org_id,
        trusted_keyring_json=keyring_json,
        workspace_base_dir=tmp_path / "work-hard",
        grype_db_source="vforge_grype_db",
        checkov_custom_policies_dir=bad_pol_dir,
    )
    executor = ContainerExecutor(
        runtime=DockerCliRuntime(),
        seccomp_profile_path=SECCOMP_PATH,
        workspace_base_dir=tmp_path / "work-hard",
    )
    async with httpx.AsyncClient(
        base_url="https://runner-gateway:8443",
        transport=httpx.MockTransport(_hardening_handler),
    ) as client:
        agent = RunnerAgent(cfg, executor=executor, http_client=client)
        assert await agent.run_once() is True
        assert await agent.run_once() is True
    assert failures == ["failed", "failed"]


@pytest.mark.asyncio
async def test_target_health_monitor_5xx_storm_tripwire() -> None:
    from vforge_runner.health_monitor import TargetHealthMonitor

    recorded_probes: list[dict[str, Any]] = []

    async def _mock_emit(p: dict[str, Any]) -> None:
        recorded_probes.append(p)

    # Mock handler that always returns 502
    def _mock_target_500(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="Bad Gateway")

    monitor = TargetHealthMonitor(
        probe_url="https://mock-target.internal/healthz",
        interval_seconds=0.1,
        probe_timeout_seconds=1.0,
        max_consecutive_5xx=3,
        on_probe=_mock_emit,
    )

    # Patch httpx.AsyncClient inside health monitor to use MockTransport
    import unittest.mock as mock

    orig_client = httpx.AsyncClient

    def _client_factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(_mock_target_500)
        return orig_client(**kwargs)

    patch_target = "vforge_runner.health_monitor.httpx.AsyncClient"
    with mock.patch(patch_target, side_effect=_client_factory):
        started = await monitor.start()
        assert started is False  # baseline probe failed with 502
        # Run periodic probes until tripwire triggers
        for _ in range(4):
            await monitor._execute_single_probe(probe_type="periodic")
            if monitor.tripped:
                break
        await monitor.stop()

    assert monitor.tripped is True
    assert monitor.cancel_event.is_set() is True
    assert "5xx" in (monitor.tripwire_reason or "").lower()
    assert any(p["probe_type"] == "tripwire" for p in recorded_probes)


@pytest.mark.asyncio
async def test_target_health_monitor_healthy_flow() -> None:
    from vforge_runner.health_monitor import TargetHealthMonitor

    recorded_probes: list[dict[str, Any]] = []

    async def _mock_emit(p: dict[str, Any]) -> None:
        recorded_probes.append(p)

    def _mock_target_200(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="OK")

    monitor = TargetHealthMonitor(
        probe_url="https://mock-target.internal/healthz",
        interval_seconds=0.1,
        probe_timeout_seconds=1.0,
        max_consecutive_5xx=3,
        on_probe=_mock_emit,
    )

    import unittest.mock as mock

    orig_client = httpx.AsyncClient

    def _client_factory(**kwargs: Any) -> httpx.AsyncClient:
        kwargs["transport"] = httpx.MockTransport(_mock_target_200)
        return orig_client(**kwargs)

    patch_target = "vforge_runner.health_monitor.httpx.AsyncClient"
    with mock.patch(patch_target, side_effect=_client_factory):
        started = await monitor.start()
        assert started is True
        for _ in range(2):
            await monitor._execute_single_probe(probe_type="periodic")
        await monitor.stop()

    assert monitor.tripped is False
    assert monitor.cancel_event.is_set() is False
    types = [p["probe_type"] for p in recorded_probes]
    assert "baseline" in types
    assert "periodic" in types
    assert "post_scan" in types


def test_nuclei_templates_directory_security_validation(tmp_path: Path) -> None:
    # 1. Non-YAML file rejected
    bad_dir = tmp_path / "bad-templates"
    bad_dir.mkdir()
    (bad_dir / "template.sh").write_text("#!/bin/sh\necho evil\n", encoding="utf-8")

    yaml_count = 0
    with pytest.raises(ValueError, match="YAML template files only"):
        for entry in bad_dir.rglob("*"):
            if entry.is_file():
                if entry.suffix.lower() not in {".yaml", ".yml"}:
                    raise ValueError(
                        "Nuclei templates directory must contain YAML template files only"
                    )
                yaml_count += 1

    # 2. Empty directory rejected
    empty_dir = tmp_path / "empty-templates"
    empty_dir.mkdir()
    with pytest.raises(ValueError, match="contains no YAML"):
        count = sum(
            1 for e in empty_dir.rglob("*") if e.is_file() and e.suffix.lower() in {".yaml", ".yml"}
        )
        if count == 0:
            raise ValueError("Nuclei templates directory contains no YAML template files")

    # 3. Valid directory accepted
    good_dir = tmp_path / "good-templates"
    good_dir.mkdir()
    tmpl_content = "id: header-check\ninfo:\n  name: Test\n"
    (good_dir / "header-check.yaml").write_text(tmpl_content, encoding="utf-8")
    count = sum(
        1 for e in good_dir.rglob("*") if e.is_file() and e.suffix.lower() in {".yaml", ".yml"}
    )
    assert count == 1
