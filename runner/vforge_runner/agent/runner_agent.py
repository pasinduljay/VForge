"""Dedicated Runner Agent daemon communicating strictly via TLS 1.3 mTLS."""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import logging
import os
import signal
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from vforge_scanners import (
    CheckovAdapter,
    GitleaksAdapter,
    GrypeAdapter,
    NmapAdapter,
    NucleiAdapter,
    OpenGrepAdapter,
    ScannerAdapter,
    SyftAdapter,
    TestsslAdapter,
    ToolContext,
    ZAPAdapter,
    build_zap_automation_plan,
    redact_text_secrets,
)
from vforge_scope import DnsResolver

from vforge_runner.executor.container_executor import (
    CollectedArtifact,
    ContainerCleanupError,
    ContainerExecutor,
    DockerCliRuntime,
)
from vforge_runner.health_monitor import TargetHealthMonitor
from vforge_runner.manifest import (
    VerifiedJobManifest,
    verify_signed_allowlist,
    verify_signed_job_manifest,
)
from vforge_runner.network_policy.egress_gateway import ScopedEgressGateway

logger = logging.getLogger("vforge_runner.agent")


@dataclass(frozen=True, slots=True)
class RunnerConfig:
    """Configuration for the isolated Runner Agent process."""

    gateway_url: str
    allowed_image_digests: tuple[str, ...]
    seccomp_profile_path: Path
    organization_id: str | None = None
    pool_id: str | None = None
    runner_version: str = "0.1.0"
    ca_cert_path: Path | None = None
    client_cert_path: Path | None = None
    client_key_path: Path | None = None
    trusted_keyring_json: str | None = None
    poll_interval_seconds: float = 3.0
    heartbeat_interval_seconds: float = 5.0
    egress_network_name: str = "none"
    egress_bind_host: str = "127.0.0.1"
    workspace_base_dir: Path | None = None
    grype_db_source: str | None = "vforge_grype_db"
    checkov_custom_policies_dir: Path | None = None
    nuclei_templates_dir: Path | None = None


def build_mtls_client_ssl_context(
    *,
    ca_cert_path: Path,
    client_cert_path: Path,
    client_key_path: Path,
) -> ssl.SSLContext:
    """Build strict TLS 1.3 client SSLContext presenting runner identity certificate."""
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(ca_cert_path))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.check_hostname = True
    ctx.load_cert_chain(certfile=str(client_cert_path), keyfile=str(client_key_path))
    return ctx


class RunnerAgent:
    """Polls mTLS runner gateway, verifies signed manifests, and runs isolated containers."""

    def __init__(
        self,
        config: RunnerConfig,
        *,
        executor: ContainerExecutor | None = None,
        http_client: httpx.AsyncClient | None = None,
        dns_resolver: DnsResolver | None = None,
    ) -> None:
        self.config = config
        self.executor = executor or ContainerExecutor(
            runtime=DockerCliRuntime(),
            seccomp_profile_path=config.seccomp_profile_path,
            egress_network_name=config.egress_network_name,
            workspace_base_dir=config.workspace_base_dir,
        )
        self._external_client = http_client
        self._dns_resolver = dns_resolver

    def _build_client(self) -> httpx.AsyncClient:
        if self._external_client is not None:
            return self._external_client
        verify: bool | ssl.SSLContext = True
        if (
            self.config.ca_cert_path is not None
            and self.config.client_cert_path is not None
            and self.config.client_key_path is not None
        ):
            verify = build_mtls_client_ssl_context(
                ca_cert_path=self.config.ca_cert_path,
                client_cert_path=self.config.client_cert_path,
                client_key_path=self.config.client_key_path,
            )
        return httpx.AsyncClient(
            base_url=self.config.gateway_url.rstrip("/"),
            verify=verify,
            timeout=30.0,
        )

    async def _post_event(
        self,
        client: httpx.AsyncClient,
        job_id: str,
        event_type: str,
        severity: str,
        details: dict[str, Any],
    ) -> None:
        try:
            await client.post(
                f"/api/v1/runner/jobs/{job_id}/events",
                json={
                    "event_type": event_type,
                    "severity": severity,
                    "details": details,
                },
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to post runner event %s: %s", event_type, type(exc).__name__)

    async def run_once(self) -> bool:
        """Claim and execute at most one job. Returns True if a job was claimed."""
        client = self._build_client()
        owns_client = self._external_client is None
        try:
            claim_payload: dict[str, Any] = {
                "runner_version": self.config.runner_version,
                "active_containers": 0,
            }
            if self.config.pool_id:
                claim_payload["pool_id"] = self.config.pool_id

            resp = await client.post("/api/v1/runner/jobs/claim", json=claim_payload)
            resp.raise_for_status()
            claim_data = resp.json()
            if not claim_data.get("claimed"):
                return False

            job_id = str(claim_data["job_id"])
            execution_id = str(claim_data["execution_id"])
            attempt_number = int(claim_data.get("attempt_number", 1))
            raw_manifest = claim_data["manifest"]
            keyring_json = self.config.trusted_keyring_json or str(
                claim_data.get("public_keyring_json", "")
            )
            effective_allowlist = list(self.config.allowed_image_digests)

            try:
                signed_allowlist = claim_data.get("signed_allowlist_payload")
                if isinstance(signed_allowlist, dict):
                    verified_dynamic = verify_signed_allowlist(
                        payload=signed_allowlist,
                        expected_sha256=str(claim_data.get("allowlist_sha256", "")),
                        signing_key_id=str(claim_data.get("allowlist_signing_key_id", "")),
                        signature=str(claim_data.get("allowlist_signature", "")),
                        trusted_public_keyring_json=keyring_json,
                    )
                    for item in verified_dynamic:
                        if item not in effective_allowlist:
                            effective_allowlist.append(item)
                verified = verify_signed_job_manifest(
                    manifest=raw_manifest,
                    expected_sha256=str(claim_data["manifest_sha256"]),
                    signing_key_id=str(claim_data["manifest_signing_key_id"]),
                    signature=str(claim_data["manifest_signature"]),
                    trusted_public_keyring_json=keyring_json,
                    allowed_image_digests=effective_allowlist,
                    expected_organization_id=self.config.organization_id,
                )
            except Exception as exc:  # noqa: BLE001
                await self._post_event(
                    client,
                    job_id,
                    "manifest_rejected",
                    "security",
                    {"error": str(exc)},
                )
                await client.post(
                    f"/api/v1/runner/jobs/{job_id}/complete",
                    json={
                        "execution_id": execution_id,
                        "attempt_number": attempt_number,
                        "status": "failed",
                        "exit_code": None,
                        "error_code": "manifest_verification_failed",
                        "error_message": str(exc),
                        "metrics": {},
                    },
                )
                return True

            await self._execute_verified_job(
                client=client,
                verified=verified,
                execution_id=execution_id,
                attempt_number=attempt_number,
            )
            return True
        finally:
            if owns_client:
                await client.aclose()

    async def _execute_verified_job(
        self,
        *,
        client: httpx.AsyncClient,
        verified: VerifiedJobManifest,
        execution_id: str,
        attempt_number: int,
    ) -> None:
        cancel_event = asyncio.Event()
        stop_heartbeat = asyncio.Event()

        async def _heartbeat_loop() -> None:
            while not stop_heartbeat.is_set():
                try:
                    hb_resp = await client.post(
                        f"/api/v1/runner/jobs/{verified.job_id}/heartbeat",
                        json={
                            "attempt_number": attempt_number,
                            "status": "online",
                            "active_containers": 1,
                            "metrics": {"tool_id": verified.tool_id},
                        },
                    )
                    if hb_resp.status_code == 200:
                        hb_data = hb_resp.json()
                        if hb_data.get("cancel_requested"):
                            cancel_event.set()
                            return
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Runner heartbeat failed: %s", type(exc).__name__)
                try:
                    await asyncio.wait_for(
                        stop_heartbeat.wait(),
                        timeout=self.config.heartbeat_interval_seconds,
                    )
                except TimeoutError:
                    continue

        async def _on_event(event_type: str, severity: str, details: dict[str, Any]) -> None:
            await self._post_event(client, verified.job_id, event_type, severity, details)

        hb_task = asyncio.create_task(_heartbeat_loop())
        egress_gateway: ScopedEgressGateway | None = None
        proxy_url: str | None = None

        try:
            if verified.network_profile == "scoped-http-egress":
                egress_gateway = ScopedEgressGateway(
                    verified,
                    dns_resolver=self._dns_resolver,
                    on_block=_on_event,
                    bind_host=self.config.egress_bind_host,
                )
                await egress_gateway.start()
                proxy_url = egress_gateway.proxy_url

            command: tuple[str, ...] = ()
            extra_env: dict[str, str] | None = None
            allowed_exit_codes: tuple[int, ...] = (0,)
            source_archive_bytes: bytes | None = None
            extra_input_files: dict[str, bytes] = {}
            extra_ro_mounts: list[tuple[str, str]] = []

            adapter: ScannerAdapter | None = None
            if verified.tool_id == "opengrep":
                adapter = OpenGrepAdapter(pinned_image=verified.image)
            elif verified.tool_id == "gitleaks":
                adapter = GitleaksAdapter(pinned_image=verified.image)
            elif verified.tool_id == "syft":
                adapter = SyftAdapter(pinned_image=verified.image)
            elif verified.tool_id == "grype":
                adapter = GrypeAdapter(pinned_image=verified.image)
            elif verified.tool_id == "checkov":
                adapter = CheckovAdapter(pinned_image=verified.image)
            elif verified.tool_id == "zap":
                adapter = ZAPAdapter(pinned_image=verified.image)
            elif verified.tool_id == "nuclei":
                adapter = NucleiAdapter(pinned_image=verified.image)
            elif verified.tool_id == "nmap":
                adapter = NmapAdapter(pinned_image=verified.image)
            elif verified.tool_id == "testssl":
                adapter = TestsslAdapter(pinned_image=verified.image)

            needs_source_snapshot = verified.tool_id in {"opengrep", "gitleaks", "syft", "checkov"}
            if verified.source_snapshot_id or needs_source_snapshot:
                if not verified.source_snapshot_id:
                    raise ValueError(
                        f"Tool '{verified.tool_id}' requires sourceSnapshotId in manifest"
                    )
                snap_resp = await client.get(
                    f"/api/v1/runner/jobs/{verified.job_id}/source-snapshot"
                )
                snap_resp.raise_for_status()
                source_archive_bytes = snap_resp.content

            tool_input_paths: tuple[Path, ...] = (Path("/work/in/source"),)
            tool_config: dict[str, Any] = {}
            if verified.tool_id == "grype" or verified.requires_sbom_input:
                if not (self.config.grype_db_source or "").strip():
                    raise ValueError(
                        "Offline Grype DB source is not configured; refusing online fallback"
                    )
                sbom_resp = await client.get(f"/api/v1/runner/jobs/{verified.job_id}/sbom-input")
                sbom_resp.raise_for_status()
                sbom_bytes = sbom_resp.content
                declared_sha = (sbom_resp.headers.get("X-SBOM-SHA256") or "").strip().lower()
                if (
                    len(declared_sha) != 64
                    or not all(ch in "0123456789abcdef" for ch in declared_sha)
                    or hashlib.sha256(sbom_bytes).hexdigest() != declared_sha
                ):
                    raise ValueError(
                        "Downloaded SBOM input is missing or failed X-SBOM-SHA256 verification"
                    )
                extra_input_files["sbom.cdx.json"] = sbom_bytes
                tool_input_paths = (Path("/work/in/sbom.cdx.json"),)
                extra_ro_mounts.append((str(self.config.grype_db_source).strip(), "/work/db"))
            elif verified.tool_id == "checkov" and verified.enable_custom_policies:
                policies_dir = self.config.checkov_custom_policies_dir
                if policies_dir is None or not policies_dir.is_dir():
                    raise ValueError(
                        "Checkov custom policies enabled without configured policy directory"
                    )
                yaml_count = 0
                for policy_entry in policies_dir.rglob("*"):
                    if policy_entry.is_symlink():
                        raise ValueError(
                            "Checkov custom policies directory must not contain symlinks"
                        )
                    if policy_entry.is_file():
                        if policy_entry.suffix.lower() not in {".yaml", ".yml"}:
                            raise ValueError(
                                "Checkov custom policies directory must contain YAML files only"
                            )
                        yaml_count += 1
                if yaml_count == 0:
                    raise ValueError(
                        "Checkov custom policies directory contains no YAML policy files"
                    )
                tool_config["enable_custom_policies"] = True
                extra_ro_mounts.append((str(policies_dir.resolve()), "/work/policies"))

            health_monitor: TargetHealthMonitor | None = None
            if verified.tool_id == "zap":
                target_url = verified.probe_url or (
                    verified.allowed_targets[0] if verified.allowed_targets else "http://target"
                )
                if verified.has_openapi_spec:
                    spec_resp = await client.get(
                        f"/api/v1/runner/jobs/{verified.job_id}/openapi-spec"
                    )
                    spec_resp.raise_for_status()
                    extra_input_files["openapi.json"] = spec_resp.content

                stage_key = verified.raw_manifest.get("metadata", {}).get("stageKey", "")
                is_active = (stage_key == "active_dast") or (verified.dast_tool == "zap")
                zap_yaml = build_zap_automation_plan(
                    target_url=target_url,
                    active_scan=is_active,
                    has_openapi_spec=verified.has_openapi_spec,
                    max_rps=verified.max_requests_per_second,
                )
                extra_input_files["zap.yaml"] = zap_yaml.encode("utf-8")
                props: list[str] = []
                if proxy_url:
                    parsed_proxy = urlsplit(proxy_url)
                    props.append("connection.proxyChain.enabled=true")
                    props.append(f"connection.proxyChain.hostName={parsed_proxy.hostname}")
                    props.append(f"connection.proxyChain.port={parsed_proxy.port}")
                if verified.auth_profile_id:
                    auth_resp = await client.get(
                        f"/api/v1/runner/jobs/{verified.job_id}/target-auth"
                    )
                    auth_resp.raise_for_status()
                    auth_payload = auth_resp.json()
                    secret_val = auth_payload.get("credentials", {}).get("secret_value", "")
                    if secret_val:
                        hdr = (
                            secret_val
                            if ":" in secret_val
                            else f"Authorization: Bearer {secret_val}"
                        )
                        hdr_parts = [part.strip() for part in hdr.split(":", 1)]
                        hdr_name = hdr_parts[0]
                        hdr_val = hdr_parts[1] if len(hdr_parts) > 1 else ""
                        props.append("replacer.full_list(0).description=AuthHeader")
                        props.append("replacer.full_list(0).enabled=true")
                        props.append("replacer.full_list(0).matchtype=REQ_HEADER")
                        props.append(f"replacer.full_list(0).matchstr={hdr_name}")
                        props.append("replacer.full_list(0).regex=false")
                        props.append(f"replacer.full_list(0).replacement={hdr_val}")
                if props:
                    extra_input_files["zap-runtime.prop"] = "\n".join(props).encode("utf-8")
                    tool_config["has_config_properties"] = True
                tool_config["target_url"] = target_url

            elif verified.tool_id == "nuclei":
                target_url = verified.probe_url or (
                    verified.allowed_targets[0] if verified.allowed_targets else "http://target"
                )
                templates_dir = self.config.nuclei_templates_dir
                if templates_dir is None or not templates_dir.is_dir():
                    default_tmpl = Path("/opt/runner/nuclei-templates")
                    if default_tmpl.is_dir():
                        templates_dir = default_tmpl
                    else:
                        raise ValueError(
                            "Nuclei templates directory is not configured or does not exist"
                        )
                yaml_count = 0
                for tmpl_entry in templates_dir.rglob("*"):
                    if tmpl_entry.is_symlink():
                        raise ValueError("Nuclei templates directory must not contain symlinks")
                    if tmpl_entry.is_file():
                        if tmpl_entry.suffix.lower() not in {".yaml", ".yml"}:
                            raise ValueError(
                                "Nuclei templates directory must contain YAML template files only"
                            )
                        yaml_count += 1
                if yaml_count == 0:
                    raise ValueError("Nuclei templates directory contains no YAML template files")
                extra_ro_mounts.append((str(templates_dir.resolve()), "/work/in/templates"))
                tool_config["target_url"] = target_url
                tool_config["templates_path"] = "/work/in/templates"
                tool_config["max_rps"] = verified.max_requests_per_second
                if verified.auth_profile_id:
                    auth_resp = await client.get(
                        f"/api/v1/runner/jobs/{verified.job_id}/target-auth"
                    )
                    auth_resp.raise_for_status()
                    auth_payload = auth_resp.json()
                    secret_val = auth_payload.get("credentials", {}).get("secret_value", "")
                    if secret_val:
                        tool_config["auth_header"] = (
                            secret_val
                            if ":" in secret_val
                            else f"Authorization: Bearer {secret_val}"
                        )

            elif verified.tool_id == "nmap":
                raw_target = verified.target_locator or (
                    verified.allowed_targets[0] if verified.allowed_targets else "127.0.0.1"
                )
                tool_config["target_locator"] = raw_target
                if verified.allowed_ports:
                    tool_config["ports"] = ",".join(str(p) for p in verified.allowed_ports)

            elif verified.tool_id == "testssl":
                raw_target = verified.probe_url or (
                    verified.allowed_targets[0] if verified.allowed_targets else "localhost:443"
                )
                tool_config["target_url"] = raw_target

            if verified.tool_id in {"zap", "nuclei"} and verified.probe_url:

                async def _on_health_probe(probe_payload: dict[str, Any]) -> None:
                    try:
                        await client.post(
                            f"/api/v1/runner/jobs/{verified.job_id}/health-probes",
                            json=probe_payload,
                        )
                    except Exception as probe_err:  # noqa: BLE001
                        logger.warning("Failed to record health probe: %s", probe_err)

                health_monitor = TargetHealthMonitor(
                    probe_url=verified.probe_url,
                    proxy_url=proxy_url,
                    cancel_event=cancel_event,
                    on_probe=_on_health_probe,
                )
                started = await health_monitor.start()
                if not started:
                    cancel_event.set()

            if adapter is not None:
                tool_ctx = ToolContext(
                    job_id=verified.job_id,
                    scan_run_id=verified.scan_run_id,
                    workspace=Path("/work"),
                    input_paths=tool_input_paths,
                    output_dir=Path("/work/out"),
                    config=tool_config,
                    limits={
                        "timeout_seconds": verified.timeout_seconds,
                        "max_requests_per_second": verified.max_requests_per_second,
                    },
                    approved_scope={"allowed_ports": verified.allowed_ports},
                )
                exec_spec = adapter.build_execution_spec(tool_ctx)
                command = exec_spec.command
                extra_env = dict(exec_spec.env)
                allowed_exit_codes = exec_spec.allowed_exit_codes

            try:
                output = await self.executor.execute_manifest(
                    verified,
                    cancel_event=cancel_event,
                    on_security_event=_on_event,
                    proxy_url=proxy_url,
                    command=command,
                    extra_env=extra_env,
                    source_archive_bytes=source_archive_bytes,
                    extra_input_files=extra_input_files or None,
                    extra_ro_mounts=tuple(extra_ro_mounts),
                )
            finally:
                if health_monitor is not None:
                    await health_monitor.stop()

            artifacts_to_upload = list(output.artifacts)
            log_text = redact_text_secrets(
                _format_process_logs(output.run_result.stdout_tail, output.run_result.stderr_tail)
            )
            if log_text:
                log_bytes = log_text.encode("utf-8")
                artifacts_to_upload.append(
                    CollectedArtifact(
                        filename="runner-stdout.log",
                        artifact_type="execution_log",
                        content_type="text/plain",
                        sha256=hashlib.sha256(log_bytes).hexdigest(),
                        data=log_bytes,
                    )
                )

            for artifact in artifacts_to_upload:
                art_resp = await client.post(
                    f"/api/v1/runner/jobs/{verified.job_id}/artifacts",
                    json={
                        "execution_id": execution_id,
                        "attempt_number": attempt_number,
                        "artifact_type": artifact.artifact_type,
                        "content_type": artifact.content_type,
                        "sha256": artifact.sha256,
                        "content_b64": base64.b64encode(artifact.data).decode("ascii"),
                    },
                )
                art_resp.raise_for_status()

            final_status: str
            error_code: str | None = None
            error_message: str | None = None
            if health_monitor and health_monitor.tripped:
                final_status = "failed"
                error_code = "target_health_tripwire_aborted"
                error_message = health_monitor.tripwire_reason or "Target health tripwire aborted"
            elif output.run_result.cancelled:
                final_status = "cancelled"
                error_code = "cancelled_by_operator"
                error_message = "Job cancelled by operator signal"
            elif output.run_result.timed_out:
                final_status = "timed_out"
                error_code = "execution_timed_out"
                error_message = f"Container exceeded timeout ({verified.timeout_seconds}s)"
            elif output.run_result.exit_code in allowed_exit_codes:
                final_status = "completed"
            else:
                final_status = "failed"
                error_code = "container_non_zero_exit"
                error_message = f"Container exited with code {output.run_result.exit_code}"

            await client.post(
                f"/api/v1/runner/jobs/{verified.job_id}/complete",
                json={
                    "execution_id": execution_id,
                    "attempt_number": attempt_number,
                    "status": final_status,
                    "exit_code": output.run_result.exit_code,
                    "error_code": error_code,
                    "error_message": error_message,
                    "metrics": {
                        "artifacts_uploaded": len(artifacts_to_upload),
                        "output_truncated": output.run_result.output_truncated,
                        "egress_blocked_count": (
                            len(egress_gateway.blocked_events) if egress_gateway else 0
                        ),
                    },
                },
            )
        except ContainerCleanupError as exc:
            await client.post(
                f"/api/v1/runner/jobs/{verified.job_id}/complete",
                json={
                    "execution_id": execution_id,
                    "attempt_number": attempt_number,
                    "status": "failed",
                    "exit_code": None,
                    "error_code": "cleanup_failed",
                    "error_message": redact_text_secrets(str(exc)),
                    "metrics": {},
                },
            )
        except Exception as exc:  # noqa: BLE001
            await client.post(
                f"/api/v1/runner/jobs/{verified.job_id}/complete",
                json={
                    "execution_id": execution_id,
                    "attempt_number": attempt_number,
                    "status": "failed",
                    "exit_code": None,
                    "error_code": "runner_execution_error",
                    "error_message": redact_text_secrets(f"{type(exc).__name__}: {exc}"),
                    "metrics": {},
                },
            )
        finally:
            stop_heartbeat.set()
            if not hb_task.done():
                hb_task.cancel()
            try:
                await hb_task
            except asyncio.CancelledError:
                logger.debug("Runner heartbeat task cancelled cleanly")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Runner heartbeat task exited with error: %s", type(exc).__name__)
            if egress_gateway is not None:
                await egress_gateway.stop()

    async def serve_forever(self, stop_event: asyncio.Event | None = None) -> None:
        """Continuously poll for jobs until stopped cleanly."""
        halt = stop_event or asyncio.Event()
        while not halt.is_set():
            try:
                claimed = await self.run_once()
            except Exception as exc:  # noqa: BLE001
                logger.warning("Runner claim loop error: %s", type(exc).__name__)
                claimed = False
            if not claimed:
                try:
                    await asyncio.wait_for(halt.wait(), timeout=self.config.poll_interval_seconds)
                except TimeoutError:
                    continue


def _format_process_logs(stdout_tail: str, stderr_tail: str) -> str:
    parts: list[str] = []
    if stdout_tail:
        parts.append("=== STDOUT ===\n" + stdout_tail)
    if stderr_tail:
        parts.append("=== STDERR ===\n" + stderr_tail)
    return "\n".join(parts)


async def _run_cli(args: argparse.Namespace) -> None:
    allowed = tuple(
        item.strip()
        for item in os.environ.get("RUNNER_ALLOWED_IMAGE_DIGESTS", "").split(",")
        if item.strip()
    )
    keyring_path = os.environ.get("RUNNER_TRUSTED_KEYRING_PATH", "").strip()
    keyring_json = Path(keyring_path).read_text(encoding="utf-8") if keyring_path else None

    config = RunnerConfig(
        gateway_url=os.environ.get("RUNNER_GATEWAY_URL", args.gateway_url),
        allowed_image_digests=allowed,
        seccomp_profile_path=Path(
            os.environ.get("RUNNER_SECCOMP_PROFILE", str(args.seccomp_profile))
        ),
        organization_id=os.environ.get("RUNNER_ORGANIZATION_ID") or None,
        pool_id=os.environ.get("RUNNER_POOL_ID") or None,
        ca_cert_path=Path(os.environ["RUNNER_CA_CERT_PATH"])
        if os.environ.get("RUNNER_CA_CERT_PATH")
        else None,
        client_cert_path=Path(os.environ["RUNNER_CLIENT_CERT_PATH"])
        if os.environ.get("RUNNER_CLIENT_CERT_PATH")
        else None,
        client_key_path=Path(os.environ["RUNNER_CLIENT_KEY_PATH"])
        if os.environ.get("RUNNER_CLIENT_KEY_PATH")
        else None,
        trusted_keyring_json=keyring_json,
        poll_interval_seconds=float(os.environ.get("RUNNER_POLL_INTERVAL_SECONDS", "3.0")),
        heartbeat_interval_seconds=float(
            os.environ.get("RUNNER_HEARTBEAT_INTERVAL_SECONDS", "5.0")
        ),
        egress_network_name=os.environ.get("RUNNER_EGRESS_NETWORK", "none"),
        egress_bind_host=os.environ.get("RUNNER_EGRESS_BIND_HOST", "127.0.0.1"),
        grype_db_source=os.environ.get("RUNNER_GRYPE_DB_SOURCE", "vforge_grype_db") or None,
        checkov_custom_policies_dir=(
            Path(os.environ["RUNNER_CHECKOV_CUSTOM_POLICIES_DIR"])
            if os.environ.get("RUNNER_CHECKOV_CUSTOM_POLICIES_DIR")
            else None
        ),
        nuclei_templates_dir=(
            Path(os.environ["RUNNER_NUCLEI_TEMPLATES_DIR"])
            if os.environ.get("RUNNER_NUCLEI_TEMPLATES_DIR")
            else None
        ),
    )
    agent = RunnerAgent(config)
    if args.once:
        await agent.run_once()
        return

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except NotImplementedError:
            pass
    await agent.serve_forever(stop_event)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(description="VForge Isolated Runner Agent")
    parser.add_argument("--gateway-url", default="https://127.0.0.1:8443")
    parser.add_argument(
        "--seccomp-profile",
        default="/opt/runner/network-policy/seccomp-scanner.json",
    )
    parser.add_argument("--once", action="store_true", help="Claim and execute at most one job")
    args = parser.parse_args()
    asyncio.run(_run_cli(args))


if __name__ == "__main__":
    main()
