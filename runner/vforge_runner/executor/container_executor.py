"""Isolated ephemeral container runner enforcing least privilege and mandatory cleanup."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from vforge_scanners import safe_extract_archive_bytes

from vforge_runner.manifest import VerifiedJobManifest

SecurityEventCallback = Callable[[str, str, dict[str, Any]], Awaitable[None] | None]

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]")
_FORBIDDEN_CONTAINER_ENV_PREFIXES = (
    "POSTGRES_",
    "RABBITMQ_",
    "VALKEY_",
    "OPENBAO_",
    "SCOPE_SIGNING_",
    "RUNNER_ARTIFACT_",
    "ARTIFACT_KEK",
    "DATABASE_URL",
)


class ContainerCleanupError(RuntimeError):
    """Raised when an ephemeral container or scratch directory fails cleanup."""


@dataclass(frozen=True, slots=True)
class HardenedContainerSpec:
    """Declarative hardened Docker container execution specification."""

    container_name: str
    image: str
    work_in_dir: Path
    work_out_dir: Path
    seccomp_profile_path: Path
    cpu: int
    memory_mb: int
    pids_limit: int
    network_mode: str
    env: dict[str, str]
    command: tuple[str, ...] = ()
    extra_ro_mounts: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class ContainerRunResult:
    """Raw outcome from container runtime execution."""

    exit_code: int | None
    timed_out: bool
    cancelled: bool
    output_truncated: bool
    stdout_tail: str
    stderr_tail: str


@dataclass(frozen=True, slots=True)
class CollectedArtifact:
    """Verified regular file produced inside `/work/out`."""

    filename: str
    artifact_type: str
    content_type: str
    sha256: str
    data: bytes


@dataclass(frozen=True, slots=True)
class ExecutedContainerOutput:
    """Complete execution outcome including bounded artifacts and cleanup status."""

    run_result: ContainerRunResult
    artifacts: tuple[CollectedArtifact, ...]
    cleanup_ok: bool


class ContainerRuntime(Protocol):
    """Pluggable container execution backend (Docker CLI or mock runtime for tests)."""

    async def run_container(
        self,
        spec: HardenedContainerSpec,
        *,
        timeout_seconds: int,
        max_output_bytes: int,
        cancel_event: asyncio.Event | None = None,
    ) -> ContainerRunResult:
        """Start container, wait for completion/timeout/cancel, and capture bounded logs."""
        ...

    async def force_remove_container(self, container_name: str) -> None:
        """Force-remove container and raise `ContainerCleanupError` if cleanup fails."""
        ...


def build_hardened_docker_args(spec: HardenedContainerSpec) -> list[str]:
    """Build hardened `docker run` CLI flags with zero privilege or docker.sock mounts."""
    if spec.network_mode == "host":
        raise ValueError("Host network mode is permanently forbidden for scanner containers")
    for env_key in spec.env:
        if env_key.startswith(_FORBIDDEN_CONTAINER_ENV_PREFIXES):
            raise ValueError(f"Forbidden control-plane credential env var in container: {env_key}")

    args: list[str] = [
        "run",
        "--name",
        spec.container_name,
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges:true",
        f"--security-opt=seccomp={spec.seccomp_profile_path}",
        "--user=10001:10001",
        f"--pids-limit={spec.pids_limit}",
        f"--memory={spec.memory_mb}m",
        f"--memory-swap={spec.memory_mb}m",
        f"--cpus={spec.cpu}",
        "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        f"--network={spec.network_mode}",
        "--volume",
        f"{spec.work_in_dir.resolve()}:/work/in:ro",
        "--volume",
        f"{spec.work_out_dir.resolve()}:/work/out:rw",
    ]
    for source_ref, target_path in spec.extra_ro_mounts:
        clean_src = str(source_ref).strip()
        clean_dst = str(target_path).strip()
        if (
            not clean_src
            or any(sock in clean_src for sock in ("docker.sock", "containerd.sock", "podman.sock"))
            or ".." in clean_src
            or ":" in clean_src
            or not clean_dst.startswith("/work/")
            or clean_dst in ("/work/in", "/work/out")
            or clean_dst.startswith("/work/in/")
            or clean_dst.startswith("/work/out/")
            or ".." in clean_dst
            or ":" in clean_dst
        ):
            raise ValueError(
                f"Forbidden extra read-only container mount: {clean_src} -> {clean_dst}"
            )
        args.extend(["--volume", f"{clean_src}:{clean_dst}:ro"])
    for key, value in sorted(spec.env.items()):
        args.extend(["--env", f"{key}={value}"])
    args.append(spec.image)
    args.extend(spec.command)
    return args


class DockerCliRuntime:
    """Executes hardened ephemeral containers via local `docker` CLI without privileged flags."""

    def __init__(self, docker_bin: str = "docker") -> None:
        self.docker_bin = docker_bin

    async def _resolve_verified_image_ref(self, image_ref: str) -> str:
        """Resolve tag+digest refs against local Docker cache while verifying exact SHA-256."""
        if "@sha256:" not in image_ref:
            return image_ref
        proc = await asyncio.create_subprocess_exec(
            self.docker_bin,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            image_ref,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await proc.communicate()
        if proc.returncode == 0:
            return image_ref

        repo_part, _, expected_digest = image_ref.partition("@")
        tail = repo_part.rsplit("/", 1)[-1]
        if ":" not in tail:
            return image_ref

        tag_proc = await asyncio.create_subprocess_exec(
            self.docker_bin,
            "image",
            "inspect",
            "--format",
            "{{.Id}}",
            repo_part,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        tag_stdout, _ = await tag_proc.communicate()
        actual_id = tag_stdout.decode("utf-8", errors="replace").strip().lower()
        if tag_proc.returncode == 0 and actual_id == expected_digest.lower():
            return expected_digest
        raise RuntimeError(f"Pinned container image digest mismatch for '{image_ref}'")

    async def run_container(
        self,
        spec: HardenedContainerSpec,
        *,
        timeout_seconds: int,
        max_output_bytes: int,
        cancel_event: asyncio.Event | None = None,
    ) -> ContainerRunResult:
        resolved_image = await self._resolve_verified_image_ref(spec.image)
        effective_spec = (
            spec
            if resolved_image == spec.image
            else HardenedContainerSpec(
                container_name=spec.container_name,
                image=resolved_image,
                work_in_dir=spec.work_in_dir,
                work_out_dir=spec.work_out_dir,
                seccomp_profile_path=spec.seccomp_profile_path,
                cpu=spec.cpu,
                memory_mb=spec.memory_mb,
                pids_limit=spec.pids_limit,
                network_mode=spec.network_mode,
                env=spec.env,
                command=spec.command,
                extra_ro_mounts=spec.extra_ro_mounts,
            )
        )
        args = build_hardened_docker_args(effective_spec)
        proc = await asyncio.create_subprocess_exec(
            self.docker_bin,
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        timed_out = False
        cancelled = False

        async def _watch_cancel() -> None:
            if cancel_event is None:
                return
            await cancel_event.wait()
            if proc.returncode is None:
                nonlocal cancelled
                cancelled = True
                proc.terminate()
                await self._kill_container(spec.container_name)

        cancel_task = asyncio.create_task(_watch_cancel()) if cancel_event is not None else None
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                proc.communicate(),
                timeout=float(timeout_seconds),
            )
        except TimeoutError:
            timed_out = True
            proc.kill()
            await self._kill_container(spec.container_name)
            stdout_bytes, stderr_bytes = await proc.communicate()
        finally:
            if cancel_task is not None and not cancel_task.done():
                cancel_task.cancel()
                try:
                    await cancel_task
                except asyncio.CancelledError:
                    pass

        cap = max(1024, max_output_bytes)
        output_truncated = (len(stdout_bytes) + len(stderr_bytes)) > cap
        stdout_slice = stdout_bytes[: cap // 2]
        stderr_slice = stderr_bytes[: cap // 2]
        return ContainerRunResult(
            exit_code=proc.returncode,
            timed_out=timed_out,
            cancelled=cancelled,
            output_truncated=output_truncated,
            stdout_tail=stdout_slice.decode("utf-8", errors="replace"),
            stderr_tail=stderr_slice.decode("utf-8", errors="replace"),
        )

    async def _kill_container(self, container_name: str) -> None:
        kill_proc = await asyncio.create_subprocess_exec(
            self.docker_bin,
            "kill",
            container_name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await kill_proc.communicate()

    async def force_remove_container(self, container_name: str) -> None:
        proc = await asyncio.create_subprocess_exec(
            self.docker_bin,
            "rm",
            "-f",
            container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await proc.communicate()
        err_text = stderr.decode("utf-8", errors="replace").strip()
        if proc.returncode != 0 and "No such container" not in err_text:
            raise ContainerCleanupError(
                f"Failed to remove container '{container_name}': {err_text or proc.returncode}"
            )


class ContainerExecutor:
    """Manages job scratch workspace, hardened container invocation, and guaranteed cleanup."""

    def __init__(
        self,
        *,
        runtime: ContainerRuntime,
        seccomp_profile_path: Path,
        egress_network_name: str = "none",
        workspace_base_dir: Path | None = None,
    ) -> None:
        self.runtime = runtime
        self.seccomp_profile_path = seccomp_profile_path
        self.egress_network_name = egress_network_name
        self.workspace_base_dir = workspace_base_dir

    async def execute_manifest(
        self,
        manifest: VerifiedJobManifest,
        *,
        cancel_event: asyncio.Event | None = None,
        on_security_event: SecurityEventCallback | None = None,
        proxy_url: str | None = None,
        command: tuple[str, ...] = (),
        extra_env: dict[str, str] | None = None,
        source_archive_bytes: bytes | None = None,
        extra_input_files: dict[str, bytes] | None = None,
        extra_ro_mounts: tuple[tuple[str, str], ...] = (),
    ) -> ExecutedContainerOutput:
        safe_job = _SAFE_NAME_RE.sub("-", manifest.job_id)[:36] or "job"
        container_name = f"vf-scan-{safe_job}-{os.urandom(3).hex()}"

        if manifest.source_snapshot_id and source_archive_bytes is None:
            raise ValueError("Manifest requires source snapshot archive bytes before execution")
        if source_archive_bytes is not None and manifest.source_snapshot_sha256:
            actual_src_sha = hashlib.sha256(source_archive_bytes).hexdigest()
            if actual_src_sha != manifest.source_snapshot_sha256.lower():
                raise ValueError("Source snapshot archive SHA-256 verification failed")

        if self.workspace_base_dir is not None:
            self.workspace_base_dir.mkdir(parents=True, exist_ok=True)
        scratch_dir = Path(
            tempfile.mkdtemp(
                prefix=f"vf-{safe_job}-",
                dir=str(self.workspace_base_dir) if self.workspace_base_dir else None,
            )
        )
        work_in = scratch_dir / "in"
        work_out = scratch_dir / "out"
        work_in.mkdir(parents=True, exist_ok=True)
        work_out.mkdir(parents=True, exist_ok=True)

        # Extract source snapshot strictly read-only into /work/in/source before chmod/run.
        if source_archive_bytes is not None:
            source_dir = work_in / "source"
            safe_extract_archive_bytes(
                source_archive_bytes,
                source_dir,
                source_type="archive_tar_gz",
                read_only=True,
            )

        for rel_name, payload_bytes in (extra_input_files or {}).items():
            clean_name = Path(rel_name).name
            if (
                not clean_name
                or clean_name != rel_name
                or clean_name in {".", "..", "manifest.json", "source"}
                or "/" in rel_name
                or "\\" in rel_name
            ):
                raise ValueError(f"Invalid extra input filename: {rel_name!r}")
            extra_path = work_in / clean_name
            extra_path.write_bytes(payload_bytes)
            try:
                os.chmod(extra_path, 0o444)
            except OSError:
                pass

        # Ensure container UID 10001 can read input manifest and write bounded artifacts.
        try:
            os.chmod(scratch_dir, 0o755)  # noqa: S103
            os.chmod(work_in, 0o755)  # noqa: S103
            os.chmod(work_out, 0o777)  # noqa: S103
            manifest_path = work_in / "manifest.json"
            manifest_path.write_text(
                json.dumps(manifest.raw_manifest, sort_keys=True, indent=2),
                encoding="utf-8",
            )
            os.chmod(manifest_path, 0o444)
        except OSError:
            pass

        network_mode = (
            "none" if manifest.network_profile == "none" else (self.egress_network_name or "none")
        )
        env: dict[str, str] = dict(extra_env or {})
        env.update(
            {
                "VFORGE_JOB_ID": manifest.job_id,
                "VFORGE_SCAN_RUN_ID": manifest.scan_run_id,
                "VFORGE_TOOL_ID": manifest.tool_id,
                "VFORGE_NETWORK_PROFILE": manifest.network_profile,
            }
        )
        if manifest.probe_url:
            env["VFORGE_PROBE_URL"] = manifest.probe_url
        if manifest.network_profile == "scoped-http-egress" and proxy_url:
            env["HTTP_PROXY"] = proxy_url
            env["HTTPS_PROXY"] = proxy_url
            env["http_proxy"] = proxy_url
            env["https_proxy"] = proxy_url

        spec = HardenedContainerSpec(
            container_name=container_name,
            image=manifest.image,
            work_in_dir=work_in,
            work_out_dir=work_out,
            seccomp_profile_path=self.seccomp_profile_path,
            cpu=manifest.cpu,
            memory_mb=manifest.memory_mb,
            pids_limit=manifest.pids_limit,
            network_mode=network_mode,
            env=env,
            command=command,
            extra_ro_mounts=extra_ro_mounts,
        )

        run_result: ContainerRunResult | None = None
        artifacts: tuple[CollectedArtifact, ...] = ()
        cleanup_ok = True
        cleanup_error: Exception | None = None

        try:
            run_result = await self.runtime.run_container(
                spec,
                timeout_seconds=manifest.timeout_seconds,
                max_output_bytes=manifest.max_output_bytes,
                cancel_event=cancel_event,
            )
            artifacts = _collect_work_out_artifacts(
                work_out, max_total_bytes=manifest.max_output_bytes
            )
        finally:
            try:
                await self.runtime.force_remove_container(container_name)
            except Exception as exc:  # noqa: BLE001
                cleanup_ok = False
                cleanup_error = exc
                await _emit_security_event(
                    on_security_event,
                    "cleanup_failed",
                    {
                        "container_name": container_name,
                        "job_id": manifest.job_id,
                        "stage": "container_rm",
                        "error": str(exc),
                    },
                )
            try:
                if scratch_dir.exists():
                    for child in scratch_dir.rglob("*"):
                        try:
                            os.chmod(child, 0o700)
                        except OSError:
                            pass
                    shutil.rmtree(scratch_dir)
            except Exception as exc:  # noqa: BLE001
                cleanup_ok = False
                if cleanup_error is None:
                    cleanup_error = exc
                await _emit_security_event(
                    on_security_event,
                    "cleanup_failed",
                    {
                        "container_name": container_name,
                        "job_id": manifest.job_id,
                        "stage": "workspace_rmtree",
                        "error": str(exc),
                    },
                )

        if cleanup_error is not None:
            raise ContainerCleanupError(str(cleanup_error)) from cleanup_error

        assert run_result is not None
        return ExecutedContainerOutput(
            run_result=run_result,
            artifacts=artifacts,
            cleanup_ok=cleanup_ok,
        )


def _collect_work_out_artifacts(
    work_out: Path, *, max_total_bytes: int
) -> tuple[CollectedArtifact, ...]:
    collected: list[CollectedArtifact] = []
    total_bytes = 0
    if not work_out.exists():
        return ()

    for entry in sorted(work_out.iterdir(), key=lambda p: p.name):
        if entry.is_symlink() or not entry.is_file():
            continue
        raw = entry.read_bytes()
        total_bytes += len(raw)
        if total_bytes > max_total_bytes:
            raise ValueError(
                f"Container output artifacts exceed maxOutputMb limit ({max_total_bytes} bytes)"
            )
        digest = hashlib.sha256(raw).hexdigest()
        lower_name = entry.name.lower()
        suffix = entry.suffix.lower()
        if lower_name.endswith(".cdx.json"):
            artifact_type = "raw_output"
            content_type = "application/vnd.cyclonedx+json"
        elif lower_name.endswith(".spdx.json"):
            artifact_type = "raw_output"
            content_type = "application/spdx+json"
        elif suffix == ".json":
            artifact_type = "raw_output"
            content_type = "application/json"
        elif suffix == ".sarif":
            artifact_type = "raw_output"
            content_type = "application/sarif+json"
        else:
            artifact_type = "execution_log"
            content_type = "text/plain"
        collected.append(
            CollectedArtifact(
                filename=entry.name,
                artifact_type=artifact_type,
                content_type=content_type,
                sha256=digest,
                data=raw,
            )
        )
    return tuple(collected)


async def _emit_security_event(
    callback: SecurityEventCallback | None,
    event_type: str,
    details: dict[str, Any],
) -> None:
    if callback is None:
        return
    res = callback(event_type, "security", details)
    if asyncio.iscoroutine(res):
        await res
