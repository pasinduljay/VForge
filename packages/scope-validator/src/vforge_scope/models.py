"""Domain models and capability taxonomy for VForge scope validation."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ScopeStrictModel(BaseModel):
    """Strict Pydantic base model rejecting unknown fields."""

    model_config = ConfigDict(extra="forbid")


class TargetType(StrEnum):
    FQDN = "fqdn"
    DOMAIN_AND_SUBDOMAINS = "domain_and_subdomains"
    EXACT_URL = "exact_url"
    URL_PATH_PREFIX = "url_path_prefix"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR_RANGE = "cidr_range"
    NETWORK_SERVICE = "network_service"
    REST_API = "rest_api"
    SOURCE_REPOSITORY = "source_repository"
    CONTAINER_IMAGE = "container_image"
    INFRASTRUCTURE_DEFINITION = "infrastructure_definition"


class Capability(StrEnum):
    PASSIVE_WEB_TESTING = "passive_web_testing"
    ACTIVE_WEB_TESTING = "active_web_testing"
    API_TESTING = "api_testing"
    AUTHENTICATED_TESTING = "authenticated_testing"
    NETWORK_DISCOVERY = "network_discovery"
    TLS_ASSESSMENT = "tls_assessment"
    CONTAINER_ASSESSMENT = "container_assessment"
    SOURCE_CODE_ANALYSIS = "source_code_analysis"
    INFRASTRUCTURE_ANALYSIS = "infrastructure_analysis"
    APPROVED_EXPLOIT_VALIDATION = "approved_exploit_validation"


FORBIDDEN_CAPABILITIES: frozenset[str] = frozenset(
    {
        "dos_testing",
        "denial_of_service",
        "destructive_testing",
        "unrestricted_exploitation",
        "lateral_movement",
        "persistence",
        "exfiltration",
        "credential_stuffing",
    }
)

LEGACY_ACTIVITY_TO_CAPABILITY: dict[str, Capability] = {
    "sast": Capability.SOURCE_CODE_ANALYSIS,
    "secrets": Capability.SOURCE_CODE_ANALYSIS,
    "sbom": Capability.CONTAINER_ASSESSMENT,
    "sca": Capability.CONTAINER_ASSESSMENT,
    "iac": Capability.INFRASTRUCTURE_ANALYSIS,
    "passive_dast": Capability.PASSIVE_WEB_TESTING,
    "active_dast": Capability.ACTIVE_WEB_TESTING,
    "network_discovery": Capability.NETWORK_DISCOVERY,
    "tls_assessment": Capability.TLS_ASSESSMENT,
}


def normalize_capabilities(raw_items: list[str]) -> list[Capability]:
    """Normalize Phase 1 activity names and Phase 2 capability names into canonical Capabilities."""
    resolved: list[Capability] = []
    seen: set[Capability] = set()
    for raw in raw_items:
        cleaned = raw.strip().lower()
        if not cleaned:
            continue
        if cleaned in FORBIDDEN_CAPABILITIES:
            raise ValueError(f"Capability '{cleaned}' is permanently forbidden by policy")
        if cleaned in LEGACY_ACTIVITY_TO_CAPABILITY:
            cap = LEGACY_ACTIVITY_TO_CAPABILITY[cleaned]
        else:
            try:
                cap = Capability(cleaned)
            except ValueError as exc:
                raise ValueError(f"Unsupported testing capability: '{cleaned}'") from exc
        if cap not in seen:
            seen.add(cap)
            resolved.append(cap)
    return sorted(resolved, key=lambda c: c.value)


class IntensityLevel(StrEnum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


INTENSITY_ORDER: dict[IntensityLevel, int] = {
    IntensityLevel.PASSIVE: 0,
    IntensityLevel.LOW: 1,
    IntensityLevel.MEDIUM: 2,
    IntensityLevel.HIGH: 3,
}


class DomainMatchMode(StrEnum):
    EXACT_DOMAIN = "exact_domain"
    DOMAIN_AND_SUBDOMAINS = "domain_and_subdomains"


class UrlMatchMode(StrEnum):
    EXACT_URL = "exact_url"
    URL_PATH_PREFIX = "url_path_prefix"


class CanonicalTarget(ScopeStrictModel):
    """Canonicalized representation of a proposed target."""

    target_type: TargetType
    raw: str
    normalized: str
    scheme: str | None = None
    host: str | None = None
    port: int | None = None
    path: str | None = None
    query: str | None = None
    ip_address: str | None = None
    cidr: str | None = None
    is_ip: bool = False
    is_domain: bool = False


class ScopeDefinition(ScopeStrictModel):
    """Explicit target scope derived from a registered asset and authorization."""

    exact_domains: list[str] = Field(default_factory=list)
    domain_and_subdomains: list[str] = Field(default_factory=list)
    exact_urls: list[str] = Field(default_factory=list)
    url_path_prefixes: list[str] = Field(default_factory=list)
    allowed_ips: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)
    allowed_repositories: list[str] = Field(default_factory=list)
    allowed_container_images: list[str] = Field(default_factory=list)
    allowed_infrastructure_paths: list[str] = Field(default_factory=list)
    allow_private_networks: bool = False
    allow_loopback: bool = False
    pinned_dns_resolution: dict[str, list[str]] = Field(default_factory=dict)


class ScopeReason(ScopeStrictModel):
    """Structured explanation for a scope or policy validation finding."""

    code: str
    message: str
    field: str | None = None


class DnsResolutionResult(ScopeStrictModel):
    """Result of resolving and validating A/AAAA records for a hostname."""

    hostname: str
    resolved_ips: list[str] = Field(default_factory=list)
    allowed: bool
    reasons: list[ScopeReason] = Field(default_factory=list)


class ScopeValidationResult(ScopeStrictModel):
    """Outcome of target canonicalization, scope matching, and network security checks."""

    allowed: bool
    canonical_target: CanonicalTarget | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    reasons: list[ScopeReason] = Field(default_factory=list)
    pre_flight_facts: dict[str, Any] = Field(default_factory=dict)


class RedirectEvaluationResult(ScopeStrictModel):
    """Outcome of evaluating an HTTP redirect hop against target scope and SSRF rules."""

    allowed: bool
    source_url: str
    location: str
    resolved_url: str | None = None
    resolved_ips: list[str] = Field(default_factory=list)
    reasons: list[ScopeReason] = Field(default_factory=list)
