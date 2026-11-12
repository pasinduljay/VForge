"""FastAPI entry point for the VForge control-plane API."""

from __future__ import annotations

import asyncio
import hmac
import logging
import os
import re
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from vforge import __version__
from vforge.api.routers import (
    ai_gateway,
    audit,
    auth,
    findings,
    governance,
    hardening,
    intel,
    lab,
    organizations,
    projects,
    redteam,
    reports,
    runners,
    scanners,
    scans,
    scope,
    studio,
    updates,
)
from vforge.config import Settings, get_settings
from vforge.db import build_engine, build_session_factory, verify_runtime_db_identity
from vforge.errors import VForgeError, RateLimitExceededError
from vforge.health import run_readiness_checks
from vforge.logging import configure_logging, correlation_id_var
from vforge.observability.metrics import metrics_registry

logger = logging.getLogger("vforge.api")
_CORR_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.validate_startup_configuration()
    db_url = settings.effective_database_url
    engine = build_engine(db_url) if db_url else None
    if engine is not None:
        identity = await verify_runtime_db_identity(engine)
        logger.info("verified_runtime_db_identity role=%s", identity["role"])
    application.state.engine = engine
    application.state.session_factory = build_session_factory(engine) if engine else None
    try:
        yield
    finally:
        if engine is not None:
            await engine.dispose()


app = FastAPI(
    title="VForge Control-Plane API",
    version=__version__,
    description="Phase 1 control-plane domain, OIDC auth, RBAC, and tenant isolation API.",
    lifespan=lifespan,
)

_settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=_settings.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "X-CSRF-Token",
        "X-Correlation-ID",
        "Idempotency-Key",
        "X-VForge-Actor-Type",
    ],
    expose_headers=["X-Correlation-ID"],
)


@app.middleware("http")
async def correlation_and_security_headers(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    incoming = request.headers.get("x-correlation-id", "").strip()
    corr_id = incoming if _CORR_ID_RE.match(incoming) else uuid.uuid4().hex
    token = correlation_id_var.set(corr_id)
    started = time.monotonic()
    try:
        response = await call_next(request)
    finally:
        correlation_id_var.reset(token)

    matched_route = request.scope.get("route")
    route_template = getattr(matched_route, "path", None)
    metrics_registry.observe_http_request(
        method=request.method,
        path=str(route_template) if isinstance(route_template, str) else "__unmatched__",
        status_code=response.status_code,
        duration_seconds=time.monotonic() - started,
    )

    response.headers["X-Correlation-ID"] = corr_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.url.path.startswith("/api/v1/auth"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.exception_handler(VForgeError)
async def handle_vforge_error(_request: Request, exc: VForgeError) -> JSONResponse:
    headers: dict[str, str] = {}
    if isinstance(exc, RateLimitExceededError):
        headers["Retry-After"] = str(exc.retry_after)
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "detail": exc.message,
            "correlation_id": correlation_id_var.get(),
        },
        headers=headers,
    )


@app.exception_handler(RequestValidationError)
async def handle_validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    sanitized_errors = [
        {
            "loc": err.get("loc"),
            "msg": err.get("msg"),
            "type": err.get("type"),
        }
        for err in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={
            "error": "validation_error",
            "detail": "Request validation failed",
            "errors": sanitized_errors,
            "correlation_id": correlation_id_var.get(),
        },
    )


@app.exception_handler(Exception)
async def handle_unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
    logger.error("unhandled_api_exception: %s", type(exc).__name__)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_error",
            "detail": "An unexpected internal error occurred.",
            "correlation_id": correlation_id_var.get(),
        },
    )


app.include_router(auth.router)
app.include_router(organizations.router)
app.include_router(projects.router)
app.include_router(governance.router)
app.include_router(audit.router)
app.include_router(scope.router)
app.include_router(scans.router)
app.include_router(runners.router)
app.include_router(scanners.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(intel.intel_router)
app.include_router(intel.org_intel_router)
app.include_router(updates.platform_updates_router)
app.include_router(updates.org_updates_router)
app.include_router(studio.router)
app.include_router(ai_gateway.router)
app.include_router(lab.router)
app.include_router(hardening.router)
app.include_router(redteam.router)


@app.get("/metrics", include_in_schema=False)
async def prometheus_metrics(
    request: Request,
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    """Expose Prometheus v0.0.4 metrics scrubbed of PII, tenant IDs, and secrets."""
    if not settings.metrics_enabled:
        return Response(status_code=status.HTTP_404_NOT_FOUND)
    if settings.metrics_bearer_token_required or (
        settings.vforge_env.strip().lower() in {"production", "prod", "staging"}
    ):
        expected_token = settings._resolve_secret(
            settings.metrics_bearer_token, "METRICS_BEARER_TOKEN"
        )
        if not expected_token:
            return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            return Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )
        presented = auth_header.removeprefix("Bearer ").strip()
        if not hmac.compare_digest(presented.encode("utf-8"), expected_token.encode("utf-8")):
            return Response(
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )
    return Response(
        content=metrics_registry.render_prometheus_text(phase=15),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )


@app.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict[str, str]:
    """Liveness probe — verifies the API process is responsive."""
    return {
        "status": "ok",
        "service": "vforge-api",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/ready")
async def ready(
    response: Response,
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> dict[str, Any]:
    """Readiness probe — verifies Postgres migrations, RabbitMQ, Valkey, and OPA."""
    checks = await run_readiness_checks(settings)
    all_ok = all(item.status == "ok" for item in checks.values())
    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if all_ok else "degraded",
        "service": "vforge-api",
        "timestamp": datetime.now(UTC).isoformat(),
        "dependencies": {
            name: {"status": check.status, "detail": check.detail} for name, check in checks.items()
        },
    }


@app.get("/api/v1/meta", status_code=status.HTTP_200_OK)
async def meta(
    request: Request,
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> dict[str, Any]:
    """Honest Phase 4 platform metadata — explicitly reports live runner connectivity & caps."""
    docker_socket_present = await asyncio.to_thread(lambda: Path("/var/run/docker.sock").exists())
    runner_connected = False
    session_factory = getattr(request.app.state, "session_factory", None)
    if session_factory is not None:
        cutoff = datetime.now(UTC) - timedelta(
            seconds=settings.runner_heartbeat_online_window_seconds
        )
        try:
            async with session_factory() as session:
                count_res = await session.execute(
                    text("SELECT public.count_online_runners(:cutoff)"),
                    {"cutoff": cutoff},
                )
                runner_connected = int(count_res.scalar_one() or 0) > 0
        except Exception:  # noqa: BLE001
            runner_connected = False

    return {
        "platform": "VForge",
        "version": __version__,
        "environment": settings.vforge_env,
        "phase": 15,
        "phase_name": (
            "Optional Isolated AI Red-Team Sandbox & Release Candidate Readiness "
            "(Strix/PentAGI Sandbox, Per-Session Human Approval, Hypothesis Review & Benchmarks)"
        ),
        "scanners_enabled": True,
        "supply_chain_enabled": True,
        "dast_enabled": True,
        "findings_management_enabled": True,
        "reporting_enabled": True,
        "threat_intel_enabled": True,
        "updates_enabled": True,
        "rule_studio_enabled": True,
        "ai_gateway_enabled": True,
        "learning_lab_enabled": True,
        "hardening_enabled": True,
        "observability_enabled": settings.metrics_enabled,
        "ai_redteam_governance_enabled": True,
        "ai_redteam_sandbox_enabled": bool(os.getenv("REDTEAM_AGENT_IMAGE", "").strip()),
        "ai_redteam_sandbox_profile": "opt_in_disabled_by_default",
        "ai_redteam_execution_mode": "isolated_lab_only_human_approved",
        "ai_execution_mode": "offline_deterministic_unless_endpoint_configured",
        "runner_connected": runner_connected,
        "docker_socket_mounted": docker_socket_present,
        "oidc_enabled": settings.oidc_enabled,
        "policy_bundle_version": settings.policy_bundle_version,
        "implemented_capabilities": [
            "control-plane-health",
            "control-plane-readiness",
            "alembic-migrations",
            "opa-rbac-baseline",
            "multi-tenant-rls",
            "oidc-pkce-auth",
            "rbac-authorization-workflows",
            "append-only-audit-events",
            "scope-validation-engine",
            "opa-scope-policy",
            "signed-scope-snapshots",
            "declarative-scan-planner",
            "orchestrator-state-machine",
            "orchestration-outbox-leases",
            "runner-mtls-gateway",
            "signed-job-manifests",
            "ephemeral-container-executor",
            "scoped-egress-gateway",
            "envelope-encrypted-artifacts",
            "scanner-adapter-sdk",
            "polyglot-language-coverage",
            "immutable-source-snapshots",
            "opengrep-sast",
            "gitleaks-secrets",
            "canonical-finding-deduplication",
            "syft-sbom",
            "grype-sca",
            "checkov-iac",
            "zap-dast",
            "nuclei-dast",
            "nmap-network",
            "testssl-tls",
            "exclusive-target-leases",
            "target-health-tripwire",
            "canonical-finding-correlation",
            "finding-triage-lifecycle",
            "finding-audit-events",
            "timebound-risk-exceptions",
            "sla-tracking-and-breaches",
            "multi-format-reporting-html",
            "multi-format-reporting-pdf",
            "multi-format-reporting-json",
            "multi-format-reporting-sarif",
            "threat-intelligence-connectors",
            "cisa-kev-exploitation-feed",
            "first-epss-probability-scoring",
            "nvd-cve-catalog-2.0",
            "osv-package-advisories",
            "exploit-db-reference-catalog",
            "gated-threat-intel-privacy",
            "finding-threat-enrichment",
            "immutable-threat-snapshots",
            "four-stream-update-lifecycle",
            "digest-pinned-release-monitor",
            "update-validation-gates",
            "canary-and-stable-promotion",
            "emergency-security-updates",
            "zero-rebuild-rollback",
            "immutable-scan-tool-pins",
            "rule-and-skill-studio",
            "native-rule-format-validation",
            "positive-negative-nearmiss-fixtures",
            "ed25519-signed-rule-packs",
            "constrained-assessment-skills",
            "ai-provider-gateway",
            "pre-egress-data-classification",
            "prompt-injection-mitigation",
            "hosted-retention-consent-gate",
            "multi-agent-rbac-tool-broker",
            "tenant-isolated-rag-knowledge",
            "ai-model-evaluation-harness",
            "learning-lab-isolated",
            "learning-lab-tracks",
            "self-scan-verification",
            "openbao-workload-identity",
            "multi-kek-envelope-rotation",
            "pqc-crypto-agility-registry",
            "mtls-cert-expiry-monitoring",
            "encrypted-dr-backup-restore-drills",
            "prometheus-metrics-observability",
            "parser-archive-fuzz-suite",
            "optional-ai-redteam-sandbox",
            "redteam-per-session-human-approval",
            "redteam-hypothesis-vs-confirmed-review",
            "redteam-zap-nuclei-benchmark-harness",
        ],
        "planned_capabilities": [],
    }
