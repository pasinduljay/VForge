"""Unit and negative security tests for Phase 0 API health and readiness."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from vforge.config import Settings, get_settings
from vforge.health import DependencyCheck
from vforge.main import app


@pytest.fixture
def override_settings() -> Settings:
    settings = Settings(
        vforge_env="test",
        database_url="postgresql+psycopg://user:secretpass@postgres:5432/vforge",
        rabbitmq_url="amqp://user:secretpass@rabbitmq:5672/%2F",
        cache_url="redis://:secretpass@valkey:6379/0",
        opa_url="http://opa:8181",
    )
    app.dependency_overrides[get_settings] = lambda: settings
    yield settings
    app.dependency_overrides.clear()


async def test_health_endpoint_returns_ok() -> None:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["service"] == "vforge-api"
    assert "timestamp" in body


async def test_ready_returns_200_when_all_dependencies_healthy(
    override_settings: Settings,
) -> None:
    mock_checks = {
        "postgres": DependencyCheck(status="ok", detail="alembic:0001_phase0_foundation"),
        "rabbitmq": DependencyCheck(status="ok", detail="amqp_connected"),
        "valkey": DependencyCheck(status="ok", detail="pong"),
        "opa": DependencyCheck(status="ok", detail="healthy"),
    }
    with patch("vforge.main.run_readiness_checks", new=AsyncMock(return_value=mock_checks)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ready")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["dependencies"]["postgres"]["status"] == "ok"
    assert "secretpass" not in resp.text


async def test_ready_returns_503_when_dependency_degraded_without_secret_leak(
    override_settings: Settings,
) -> None:
    mock_checks = {
        "postgres": DependencyCheck(status="ok", detail="alembic:0001_phase0_foundation"),
        "rabbitmq": DependencyCheck(status="error", detail="connection_failed"),
        "valkey": DependencyCheck(status="ok", detail="pong"),
        "opa": DependencyCheck(status="ok", detail="healthy"),
    }
    with patch("vforge.main.run_readiness_checks", new=AsyncMock(return_value=mock_checks)):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/ready")

    assert resp.status_code == 503
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["dependencies"]["rabbitmq"]["status"] == "error"
    assert "secretpass" not in resp.text


async def test_meta_reports_honest_phase15_status(override_settings: Settings) -> None:
    prev_factory = getattr(app.state, "session_factory", None)
    app.state.session_factory = None
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            resp = await client.get("/api/v1/meta")
    finally:
        app.state.session_factory = prev_factory

    assert resp.status_code == 200
    body = resp.json()
    assert body["phase"] == 15
    assert body["scanners_enabled"] is True
    assert body["supply_chain_enabled"] is True
    assert body["dast_enabled"] is True
    assert body["findings_management_enabled"] is True
    assert body["reporting_enabled"] is True
    assert body["threat_intel_enabled"] is True
    assert body["updates_enabled"] is True
    assert body["rule_studio_enabled"] is True
    assert body["ai_gateway_enabled"] is True
    assert body["learning_lab_enabled"] is True
    assert body["hardening_enabled"] is True
    assert body["observability_enabled"] is True
    assert body["ai_redteam_governance_enabled"] is True
    assert body["ai_redteam_sandbox_enabled"] is False
    assert body["ai_redteam_sandbox_profile"] == "opt_in_disabled_by_default"
    assert body["ai_redteam_execution_mode"] == "isolated_lab_only_human_approved"
    assert body["runner_connected"] is False
    assert body["docker_socket_mounted"] is False
    assert "optional-ai-redteam-sandbox" in body["implemented_capabilities"]
    assert "redteam-per-session-human-approval" in body["implemented_capabilities"]
    assert "redteam-hypothesis-vs-confirmed-review" in body["implemented_capabilities"]
    assert "redteam-zap-nuclei-benchmark-harness" in body["implemented_capabilities"]
    assert "openbao-workload-identity" in body["implemented_capabilities"]
    assert "multi-kek-envelope-rotation" in body["implemented_capabilities"]
    assert "encrypted-dr-backup-restore-drills" in body["implemented_capabilities"]
    assert "prometheus-metrics-observability" in body["implemented_capabilities"]
    assert "learning-lab-isolated" in body["implemented_capabilities"]
    assert "learning-lab-tracks" in body["implemented_capabilities"]
    assert "self-scan-verification" in body["implemented_capabilities"]
    assert "ai-provider-gateway" in body["implemented_capabilities"]
    assert "pre-egress-data-classification" in body["implemented_capabilities"]
    assert "rule-and-skill-studio" in body["implemented_capabilities"]
    assert "positive-negative-nearmiss-fixtures" in body["implemented_capabilities"]
    assert "ed25519-signed-rule-packs" in body["implemented_capabilities"]
    assert "four-stream-update-lifecycle" in body["implemented_capabilities"]
    assert "zero-rebuild-rollback" in body["implemented_capabilities"]
    assert "first-epss-probability-scoring" in body["implemented_capabilities"]
    assert "nvd-cve-catalog-2.0" in body["implemented_capabilities"]
    assert "finding-threat-enrichment" in body["implemented_capabilities"]
    assert "immutable-threat-snapshots" in body["implemented_capabilities"]
    assert "runner-mtls-gateway" in body["implemented_capabilities"]
    assert "scoped-egress-gateway" in body["implemented_capabilities"]
    assert "opengrep-sast" in body["implemented_capabilities"]
    assert "gitleaks-secrets" in body["implemented_capabilities"]
    assert "syft-sbom" in body["implemented_capabilities"]
    assert "grype-sca" in body["implemented_capabilities"]
    assert "checkov-iac" in body["implemented_capabilities"]
    assert "zap-dast" in body["implemented_capabilities"]
    assert "nuclei-dast" in body["implemented_capabilities"]
    assert "nmap-network" in body["implemented_capabilities"]
    assert "testssl-tls" in body["implemented_capabilities"]
    assert "exclusive-target-leases" in body["implemented_capabilities"]
    assert "target-health-tripwire" in body["implemented_capabilities"]
    assert "canonical-finding-correlation" in body["implemented_capabilities"]
    assert "finding-triage-lifecycle" in body["implemented_capabilities"]
    assert "multi-format-reporting-html" in body["implemented_capabilities"]
    assert "multi-format-reporting-pdf" in body["implemented_capabilities"]
    assert "multi-format-reporting-json" in body["implemented_capabilities"]
    assert "multi-format-reporting-sarif" in body["implemented_capabilities"]
