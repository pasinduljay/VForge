"""High-level target-scope and pre-flight evaluation for API, OPA, and Runner Agents."""

from __future__ import annotations

from typing import Any

from vforge_scope.canonicalize import (
    ScopeValidationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_port,
    canonicalize_target,
    canonicalize_url,
)
from vforge_scope.models import (
    ScopeDefinition,
    ScopeReason,
    ScopeValidationResult,
    TargetType,
)
from vforge_scope.network import (
    DnsResolver,
    SystemDnsResolver,
    evaluate_redirect_destination,
    resolve_and_validate_host,
    target_matches_scope,
    validate_ip_safety_and_scope,
)


def build_scope_definition_from_asset(
    *,
    asset_type: str,
    normalized_locator: str,
    approved_testing_scope: dict[str, Any],
    allowed_ports: list[int] | None,
    allow_private_networks: bool = False,
    allow_loopback: bool = False,
    pinned_dns_resolution: dict[str, list[str]] | None = None,
) -> ScopeDefinition:
    """Construct a normalized `ScopeDefinition` from an asset and authorization record."""
    exact_domains: list[str] = []
    domain_and_subdomains: list[str] = []
    exact_urls: list[str] = []
    url_path_prefixes: list[str] = []
    allowed_ips: list[str] = []
    allowed_cidrs: list[str] = []
    allowed_repositories: list[str] = []
    allowed_container_images: list[str] = []
    allowed_infrastructure_paths: list[str] = []

    if asset_type in {"web_application", "rest_api"}:
        url_target = canonicalize_url(normalized_locator, target_type=TargetType.EXACT_URL)
        url_mode = str(approved_testing_scope.get("url_match_mode", "url_path_prefix")).lower()
        if url_mode == "exact_url":
            exact_urls.append(url_target.normalized)
        else:
            url_path_prefixes.append(url_target.normalized)

        domain_mode = str(approved_testing_scope.get("domain_match_mode", "exact_domain")).lower()
        if url_target.is_domain and url_target.host:
            if domain_mode == "domain_and_subdomains":
                domain_and_subdomains.append(url_target.host)
            else:
                exact_domains.append(url_target.host)
        elif url_target.is_ip and url_target.ip_address:
            allowed_ips.append(url_target.ip_address)
    elif asset_type == "ip_address":
        allowed_ips.append(canonicalize_ip(normalized_locator).compressed)
    elif asset_type == "cidr_range":
        allowed_cidrs.append(canonicalize_cidr(normalized_locator).compressed)
    elif asset_type == "network_service":
        svc = canonicalize_target(TargetType.NETWORK_SERVICE, normalized_locator)
        if svc.is_ip and svc.ip_address:
            allowed_ips.append(svc.ip_address)
        elif svc.is_domain and svc.host:
            exact_domains.append(svc.host)
    elif asset_type == "source_repository":
        allowed_repositories.append(
            canonicalize_target(TargetType.SOURCE_REPOSITORY, normalized_locator).normalized
        )
    elif asset_type == "container_image":
        allowed_container_images.append(
            canonicalize_target(TargetType.CONTAINER_IMAGE, normalized_locator).normalized
        )
    elif asset_type == "infrastructure_definition":
        allowed_infrastructure_paths.append(
            canonicalize_target(TargetType.INFRASTRUCTURE_DEFINITION, normalized_locator).normalized
        )

    # Merge explicit scope extensions from approved_testing_scope
    for raw_dom in approved_testing_scope.get("exact_domains", []) or []:
        exact_domains.append(canonicalize_domain(str(raw_dom), allow_wildcard=False))

    for raw_sub in approved_testing_scope.get("domain_and_subdomains", []) or []:
        cleaned = str(raw_sub).strip()
        if cleaned.startswith("*."):
            cleaned = cleaned[2:]
        domain_and_subdomains.append(canonicalize_domain(cleaned, allow_wildcard=False))

    for raw_url in approved_testing_scope.get("exact_urls", []) or []:
        exact_urls.append(
            canonicalize_url(str(raw_url), target_type=TargetType.EXACT_URL).normalized
        )

    for raw_prefix in approved_testing_scope.get("url_path_prefixes", []) or []:
        url_path_prefixes.append(
            canonicalize_url(str(raw_prefix), target_type=TargetType.URL_PATH_PREFIX).normalized
        )

    for raw_ip in approved_testing_scope.get("allowed_ips", []) or []:
        allowed_ips.append(canonicalize_ip(str(raw_ip)).compressed)

    for raw_cidr in approved_testing_scope.get("allowed_cidrs", []) or []:
        allowed_cidrs.append(canonicalize_cidr(str(raw_cidr)).compressed)

    ports = [canonicalize_port(p) for p in (allowed_ports or [])]
    if not ports and asset_type == "network_service":
        svc = canonicalize_target(TargetType.NETWORK_SERVICE, normalized_locator)
        if svc.port is not None:
            ports = [svc.port]

    return ScopeDefinition(
        exact_domains=sorted(set(exact_domains)),
        domain_and_subdomains=sorted(set(domain_and_subdomains)),
        exact_urls=sorted(set(exact_urls)),
        url_path_prefixes=sorted(set(url_path_prefixes)),
        allowed_ips=sorted(set(allowed_ips)),
        allowed_cidrs=sorted(set(allowed_cidrs)),
        allowed_ports=sorted(set(ports)),
        allowed_repositories=sorted(set(allowed_repositories)),
        allowed_container_images=sorted(set(allowed_container_images)),
        allowed_infrastructure_paths=sorted(set(allowed_infrastructure_paths)),
        allow_private_networks=bool(
            allow_private_networks or approved_testing_scope.get("allow_private_networks", False)
        ),
        allow_loopback=bool(allow_loopback or approved_testing_scope.get("allow_loopback", False)),
        pinned_dns_resolution=pinned_dns_resolution or {},
    )


def evaluate_target_scope(
    *,
    target_type: TargetType,
    raw_target: str,
    scope: ScopeDefinition,
    dns_resolver: DnsResolver | None = None,
    resolve_dns: bool = True,
    redirect_location: str | None = None,
    redirect_hop_count: int = 1,
    max_redirects: int = 5,
) -> ScopeValidationResult:
    """Validate a target (and optional redirect destination) against scope and SSRF rules."""
    try:
        canonical = canonicalize_target(target_type, raw_target)
    except ScopeValidationError as exc:
        return ScopeValidationResult(
            allowed=False,
            canonical_target=None,
            resolved_ips=[],
            reasons=[ScopeReason(code=exc.code, message=exc.message, field="target")],
            pre_flight_facts={
                "canonical_valid": False,
                "scope_matched": False,
                "port_allowed": False,
                "dns_safe": False,
                "redirect_safe": redirect_location is None,
            },
        )

    reasons = target_matches_scope(canonical, scope)
    scope_matched = len(reasons) == 0
    port_allowed = not any(r.code == "unauthorized_port" for r in reasons)

    resolved_ips: list[str] = []
    dns_safe = True

    if canonical.is_ip and canonical.ip_address:
        ip_obj = canonicalize_ip(canonical.ip_address)
        ip_reasons = validate_ip_safety_and_scope(
            ip_obj,
            scope,
            require_explicit_ip_match=target_type in {TargetType.IPV4, TargetType.IPV6},
        )
        if ip_reasons:
            dns_safe = False
            for r in ip_reasons:
                if r not in reasons:
                    reasons.append(r)
        resolved_ips = [ip_obj.compressed]
    elif (
        resolve_dns
        and canonical.is_domain
        and canonical.host
        and target_type
        in {
            TargetType.FQDN,
            TargetType.EXACT_URL,
            TargetType.URL_PATH_PREFIX,
            TargetType.REST_API,
            TargetType.NETWORK_SERVICE,
        }
    ):
        resolver = dns_resolver or SystemDnsResolver()
        dns_res = resolve_and_validate_host(
            canonical.host,
            scope,
            resolver,
            require_explicit_ip_match=False,
        )
        resolved_ips = dns_res.resolved_ips
        if not dns_res.allowed:
            dns_safe = False
            reasons.extend(dns_res.reasons)

    redirect_safe = True
    if redirect_location is not None:
        if target_type not in {
            TargetType.EXACT_URL,
            TargetType.URL_PATH_PREFIX,
            TargetType.REST_API,
        }:
            redirect_safe = False
            reasons.append(
                ScopeReason(
                    code="redirect_invalid_target_type",
                    message="Redirect evaluation applies only to HTTP/HTTPS URL targets",
                    field="redirect_location",
                )
            )
        else:
            redir_res = evaluate_redirect_destination(
                source_url=canonical.normalized,
                location=redirect_location,
                scope=scope,
                dns_resolver=dns_resolver,
                hop_count=redirect_hop_count,
                max_redirects=max_redirects,
                resolve_dns=resolve_dns,
            )
            if not redir_res.allowed:
                redirect_safe = False
                reasons.extend(redir_res.reasons)
            elif redir_res.resolved_ips:
                resolved_ips = sorted(set(resolved_ips) | set(redir_res.resolved_ips))

    return ScopeValidationResult(
        allowed=len(reasons) == 0,
        canonical_target=canonical,
        resolved_ips=resolved_ips,
        reasons=reasons,
        pre_flight_facts={
            "canonical_valid": True,
            "scope_matched": scope_matched,
            "port_allowed": port_allowed,
            "dns_safe": dns_safe,
            "redirect_safe": redirect_safe,
        },
    )
