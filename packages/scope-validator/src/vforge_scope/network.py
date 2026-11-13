"""DNS resolution, SSRF/metadata blocking, rebinding detection, and redirect guards."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Sequence
from typing import Protocol
from urllib.parse import urljoin

from vforge_scope.canonicalize import (
    IPAddress,
    IPNetwork,
    ScopeValidationError,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_url,
    match_domain,
    match_exact_url,
    match_url_path_prefix,
)
from vforge_scope.models import (
    CanonicalTarget,
    DnsResolutionResult,
    RedirectEvaluationResult,
    ScopeDefinition,
    ScopeReason,
    TargetType,
)

CLOUD_METADATA_HOSTNAMES: frozenset[str] = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
        "169.254.169.254",
    }
)

CLOUD_METADATA_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("169.254.170.2/32"),
    ipaddress.ip_network("169.254.169.253/32"),
    ipaddress.ip_network("169.254.169.123/32"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)

LOCALHOST_HOSTNAMES: frozenset[str] = frozenset({"localhost", "localhost.localdomain"})


class DnsResolver(Protocol):
    """Protocol for A and AAAA DNS resolution."""

    def resolve(self, hostname: str) -> list[str]:
        """Return resolved IPv4/IPv6 addresses for `hostname`, or raise OSError/ValueError."""
        ...


class SystemDnsResolver:
    """Default system DNS resolver querying A (IPv4) and AAAA (IPv6) records."""

    def resolve(self, hostname: str) -> list[str]:
        records = socket.getaddrinfo(
            hostname,
            None,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
        seen: set[str] = set()
        results: list[str] = []
        for _family, _type, _proto, _canonname, sockaddr in records:
            raw_ip = str(sockaddr[0])
            ip_obj = canonicalize_ip(raw_ip)
            if ip_obj.compressed not in seen:
                seen.add(ip_obj.compressed)
                results.append(ip_obj.compressed)
        return results


class StaticDnsResolver:
    """Deterministic mapping-backed DNS resolver for testing and pinned replay."""

    def __init__(self, records: dict[str, list[str]]) -> None:
        self._records = {k.rstrip(".").lower(): list(v) for k, v in records.items()}

    def resolve(self, hostname: str) -> list[str]:
        key = hostname.rstrip(".").lower()
        if key not in self._records:
            raise OSError(f"NXDOMAIN: {hostname}")
        return list(self._records[key])


def is_cloud_metadata_ip(ip_obj: IPAddress) -> bool:
    """Return True if `ip_obj` falls in any known cloud metadata endpoint range."""
    return any(ip_obj in net for net in CLOUD_METADATA_NETWORKS)


def is_ip_explicitly_authorized(ip_obj: IPAddress, scope: ScopeDefinition) -> bool:
    """Return True if `ip_obj` matches an explicitly authorized IP or CIDR in `scope`."""
    for raw_ip in scope.allowed_ips:
        try:
            if canonicalize_ip(raw_ip) == ip_obj:
                return True
        except ScopeValidationError:
            continue
    for raw_cidr in scope.allowed_cidrs:
        try:
            net = canonicalize_cidr(raw_cidr)
            if ip_obj.version == net.version and ip_obj in net:
                return True
        except ScopeValidationError:
            continue
    return False


def validate_ip_safety_and_scope(
    ip_obj: IPAddress,
    scope: ScopeDefinition,
    *,
    require_explicit_ip_match: bool = False,
) -> list[ScopeReason]:
    """Validate a single IP against cloud metadata, link-local, loopback, and scope rules."""
    reasons: list[ScopeReason] = []

    if is_cloud_metadata_ip(ip_obj):
        reasons.append(
            ScopeReason(
                code="cloud_metadata_blocked",
                message=(
                    f"Cloud metadata endpoint IP '{ip_obj.compressed}' is permanently forbidden"
                ),
                field="ip",
            )
        )
        return reasons

    if ip_obj.is_link_local:
        reasons.append(
            ScopeReason(
                code="link_local_blocked",
                message=f"Link-local IP '{ip_obj.compressed}' is forbidden",
                field="ip",
            )
        )
        return reasons

    if ip_obj.is_multicast or ip_obj.is_unspecified:
        reasons.append(
            ScopeReason(
                code="reserved_ip_blocked",
                message=f"Unspecified or multicast IP '{ip_obj.compressed}' is forbidden",
                field="ip",
            )
        )
        return reasons

    explicit_match = is_ip_explicitly_authorized(ip_obj, scope)

    if ip_obj.is_loopback:
        if not (scope.allow_loopback and explicit_match):
            reasons.append(
                ScopeReason(
                    code="localhost_blocked",
                    message=(
                        f"Loopback address '{ip_obj.compressed}' is denied unless explicitly "
                        "authorized for an isolated target"
                    ),
                    field="ip",
                )
            )
        return reasons

    if ip_obj.is_private:
        if not (scope.allow_private_networks and explicit_match):
            reasons.append(
                ScopeReason(
                    code="private_network_blocked",
                    message=(
                        f"Private network IP '{ip_obj.compressed}' requires explicit registration "
                        "and allow_private_networks authorization"
                    ),
                    field="ip",
                )
            )
        return reasons

    if require_explicit_ip_match and not explicit_match:
        reasons.append(
            ScopeReason(
                code="unauthorized_ip",
                message=f"IP address '{ip_obj.compressed}' is outside authorized IP/CIDR scope",
                field="ip",
            )
        )
    return reasons


def resolve_and_validate_host(
    hostname: str,
    scope: ScopeDefinition,
    dns_resolver: DnsResolver,
    *,
    pinned_ips: Sequence[str] | None = None,
    require_explicit_ip_match: bool = False,
) -> DnsResolutionResult:
    """Resolve A/AAAA records and reject any disallowed, mixed, or rebound answers."""
    clean_host = canonicalize_domain(hostname, allow_wildcard=False)
    reasons: list[ScopeReason] = []

    if clean_host in CLOUD_METADATA_HOSTNAMES:
        return DnsResolutionResult(
            hostname=clean_host,
            resolved_ips=[],
            allowed=False,
            reasons=[
                ScopeReason(
                    code="cloud_metadata_hostname_blocked",
                    message=f"Cloud metadata hostname '{clean_host}' is permanently forbidden",
                    field="host",
                )
            ],
        )

    if clean_host in LOCALHOST_HOSTNAMES or clean_host.endswith(".localhost"):
        if not scope.allow_loopback:
            return DnsResolutionResult(
                hostname=clean_host,
                resolved_ips=[],
                allowed=False,
                reasons=[
                    ScopeReason(
                        code="localhost_blocked",
                        message=f"Localhost hostname '{clean_host}' is forbidden",
                        field="host",
                    )
                ],
            )

    try:
        raw_ips = dns_resolver.resolve(clean_host)
    except Exception as exc:
        return DnsResolutionResult(
            hostname=clean_host,
            resolved_ips=[],
            allowed=False,
            reasons=[
                ScopeReason(
                    code="dns_resolution_failed",
                    message=f"DNS resolution failed for '{clean_host}': {type(exc).__name__}",
                    field="host",
                )
            ],
        )

    if not raw_ips:
        return DnsResolutionResult(
            hostname=clean_host,
            resolved_ips=[],
            allowed=False,
            reasons=[
                ScopeReason(
                    code="dns_no_records",
                    message=f"DNS returned no A or AAAA records for '{clean_host}'",
                    field="host",
                )
            ],
        )

    canonical_ips: list[str] = []
    seen_ips: set[str] = set()
    disallowed_count = 0

    for raw_ip in raw_ips:
        try:
            ip_obj = canonicalize_ip(raw_ip)
        except ScopeValidationError as exc:
            disallowed_count += 1
            reasons.append(ScopeReason(code=exc.code, message=exc.message, field="resolved_ips"))
            continue

        ip_str = ip_obj.compressed
        if ip_str not in seen_ips:
            seen_ips.add(ip_str)
            canonical_ips.append(ip_str)

        ip_reasons = validate_ip_safety_and_scope(
            ip_obj,
            scope,
            require_explicit_ip_match=require_explicit_ip_match,
        )
        if ip_reasons:
            disallowed_count += 1
            reasons.extend(ip_reasons)

    # Detect mixed allowed + disallowed DNS answers explicitly
    if disallowed_count > 0 and disallowed_count < len(raw_ips):
        reasons.append(
            ScopeReason(
                code="mixed_dns_response_blocked",
                message=(
                    f"DNS for '{clean_host}' returned a mix of allowed and disallowed IPs; "
                    "mixed responses are rejected fail-closed"
                ),
                field="resolved_ips",
            )
        )

    # Check DNS rebinding against pinned snapshot IPs (if provided)
    effective_pinned = (
        list(pinned_ips) if pinned_ips is not None else scope.pinned_dns_resolution.get(clean_host)
    )
    if effective_pinned:
        pinned_set = set()
        for p in effective_pinned:
            try:
                pinned_set.add(canonicalize_ip(p).compressed)
            except ScopeValidationError:
                continue
        if pinned_set and not set(canonical_ips).issubset(pinned_set):
            drifted = sorted(set(canonical_ips) - pinned_set)
            reasons.append(
                ScopeReason(
                    code="dns_rebinding_detected",
                    message=(
                        f"DNS resolution for '{clean_host}' drifted from approved snapshot "
                        f"IPs ({', '.join(drifted)})"
                    ),
                    field="resolved_ips",
                )
            )

    return DnsResolutionResult(
        hostname=clean_host,
        resolved_ips=canonical_ips,
        allowed=len(reasons) == 0,
        reasons=reasons,
    )


def target_matches_scope(target: CanonicalTarget, scope: ScopeDefinition) -> list[ScopeReason]:
    """Verify that a canonicalized target falls inside `scope` definitions."""
    reasons: list[ScopeReason] = []

    # Port check when target carries a network port and allowed_ports is configured
    if target.port is not None and scope.allowed_ports:
        if target.port not in scope.allowed_ports:
            reasons.append(
                ScopeReason(
                    code="unauthorized_port",
                    message=(f"Port {target.port} is not in allowed ports {scope.allowed_ports}"),
                    field="port",
                )
            )

    if target.target_type in {TargetType.IPV4, TargetType.IPV6} or (
        target.is_ip and target.ip_address is not None and target.scheme is None
    ):
        ip_obj = canonicalize_ip(target.ip_address or target.normalized)
        ip_reasons = validate_ip_safety_and_scope(
            ip_obj,
            scope,
            require_explicit_ip_match=True,
        )
        reasons.extend(ip_reasons)
        return reasons

    if target.target_type == TargetType.CIDR_RANGE:
        net = canonicalize_cidr(target.cidr or target.normalized)
        matched = False
        for raw_cidr in scope.allowed_cidrs:
            try:
                allowed_net = canonicalize_cidr(raw_cidr)
                if net.version == allowed_net.version and net.subnet_of(allowed_net):  # type: ignore[arg-type]
                    matched = True
                    break
            except ScopeValidationError:
                continue
        if not matched:
            reasons.append(
                ScopeReason(
                    code="unauthorized_cidr",
                    message=f"CIDR '{net.compressed}' is outside authorized CIDR ranges",
                    field="cidr",
                )
            )
            return reasons
        # Also block metadata/link-local overlap in CIDR
        for meta_net in CLOUD_METADATA_NETWORKS:
            if net.version == meta_net.version and net.overlaps(meta_net):
                reasons.append(
                    ScopeReason(
                        code="cloud_metadata_blocked",
                        message=f"CIDR '{net.compressed}' overlaps cloud metadata range",
                        field="cidr",
                    )
                )
        if net.is_link_local:
            reasons.append(
                ScopeReason(
                    code="link_local_blocked",
                    message=f"Link-local CIDR '{net.compressed}' is forbidden",
                    field="cidr",
                )
            )
        if net.is_loopback and not scope.allow_loopback:
            reasons.append(
                ScopeReason(
                    code="localhost_blocked",
                    message=(
                        f"Loopback CIDR '{net.compressed}' requires explicit loopback authorization"
                    ),
                    field="cidr",
                )
            )
        if net.is_private and not net.is_loopback and not net.is_link_local:
            if not scope.allow_private_networks:
                reasons.append(
                    ScopeReason(
                        code="private_network_blocked",
                        message=f"Private CIDR '{net.compressed}' requires allow_private_networks",
                        field="cidr",
                    )
                )
        return reasons

    if target.target_type in {TargetType.FQDN, TargetType.DOMAIN_AND_SUBDOMAINS}:
        host = target.host or ""
        if target.target_type == TargetType.DOMAIN_AND_SUBDOMAINS:
            # Wildcard target requires exact wildcard authorization or parent domain_and_subdomains
            matched = any(
                match_domain(host, allowed, include_subdomains=True)
                for allowed in scope.domain_and_subdomains
            )
        else:
            matched = any(
                match_domain(host, allowed, include_subdomains=False)
                for allowed in scope.exact_domains
            ) or any(
                match_domain(host, allowed, include_subdomains=True)
                for allowed in scope.domain_and_subdomains
            )
        if not matched:
            reasons.append(
                ScopeReason(
                    code="domain_out_of_scope",
                    message=f"Domain '{target.normalized}' is not authorized in target scope",
                    field="host",
                )
            )
        return reasons

    if target.target_type in {
        TargetType.EXACT_URL,
        TargetType.URL_PATH_PREFIX,
        TargetType.REST_API,
    }:
        # Check exact URLs, URL path prefixes, and domain rules
        matched_url = False
        for raw_exact in scope.exact_urls:
            try:
                allowed_url = canonicalize_url(raw_exact, target_type=TargetType.EXACT_URL)
                if match_exact_url(target, allowed_url):
                    matched_url = True
                    break
            except ScopeValidationError:
                continue
        if not matched_url:
            for raw_prefix in scope.url_path_prefixes:
                try:
                    prefix_url = canonicalize_url(
                        raw_prefix, target_type=TargetType.URL_PATH_PREFIX
                    )
                    if match_url_path_prefix(target, prefix_url):
                        matched_url = True
                        break
                except ScopeValidationError:
                    continue
        if not matched_url and target.is_domain and target.host:
            matched_url = any(
                match_domain(target.host, allowed, include_subdomains=False)
                for allowed in scope.exact_domains
            ) or any(
                match_domain(target.host, allowed, include_subdomains=True)
                for allowed in scope.domain_and_subdomains
            )
        if not matched_url and target.is_ip and target.ip_address:
            ip_obj = canonicalize_ip(target.ip_address)
            matched_url = is_ip_explicitly_authorized(ip_obj, scope)

        if not matched_url:
            reasons.append(
                ScopeReason(
                    code="url_out_of_scope",
                    message=f"URL '{target.normalized}' is outside authorized target scope",
                    field="target",
                )
            )
        elif target.is_ip and target.ip_address:
            ip_obj = canonicalize_ip(target.ip_address)
            reasons.extend(
                validate_ip_safety_and_scope(ip_obj, scope, require_explicit_ip_match=False)
            )
        return reasons

    if target.target_type == TargetType.NETWORK_SERVICE:
        if target.is_ip and target.ip_address:
            ip_obj = canonicalize_ip(target.ip_address)
            reasons.extend(
                validate_ip_safety_and_scope(ip_obj, scope, require_explicit_ip_match=True)
            )
        elif target.is_domain and target.host:
            matched = any(
                match_domain(target.host, allowed, include_subdomains=False)
                for allowed in scope.exact_domains
            ) or any(
                match_domain(target.host, allowed, include_subdomains=True)
                for allowed in scope.domain_and_subdomains
            )
            if not matched:
                reasons.append(
                    ScopeReason(
                        code="domain_out_of_scope",
                        message=f"Service host '{target.host}' is outside authorized domain scope",
                        field="host",
                    )
                )
        return reasons

    if target.target_type == TargetType.SOURCE_REPOSITORY:
        if target.normalized not in scope.allowed_repositories:
            reasons.append(
                ScopeReason(
                    code="repository_out_of_scope",
                    message=f"Repository '{target.normalized}' is not in authorized scope",
                    field="target",
                )
            )
        return reasons

    if target.target_type == TargetType.CONTAINER_IMAGE:
        if target.normalized not in scope.allowed_container_images:
            reasons.append(
                ScopeReason(
                    code="container_image_out_of_scope",
                    message=f"Container image '{target.normalized}' is not in authorized scope",
                    field="target",
                )
            )
        return reasons

    if target.target_type == TargetType.INFRASTRUCTURE_DEFINITION:
        if target.normalized not in scope.allowed_infrastructure_paths:
            reasons.append(
                ScopeReason(
                    code="infrastructure_path_out_of_scope",
                    message=f"Infrastructure path '{target.normalized}' is not in authorized scope",
                    field="target",
                )
            )
        return reasons

    return reasons


def evaluate_redirect_destination(
    *,
    source_url: str,
    location: str,
    scope: ScopeDefinition,
    dns_resolver: DnsResolver | None = None,
    hop_count: int = 1,
    max_redirects: int = 5,
    allow_scheme_downgrade: bool = False,
    resolve_dns: bool = True,
) -> RedirectEvaluationResult:
    """Validate an HTTP redirect destination before following it."""
    if hop_count > max_redirects:
        return RedirectEvaluationResult(
            allowed=False,
            source_url=source_url,
            location=location,
            reasons=[
                ScopeReason(
                    code="redirect_limit_exceeded",
                    message=f"Redirect hop {hop_count} exceeds max_redirects={max_redirects}",
                    field="redirect",
                )
            ],
        )

    try:
        src_canonical = canonicalize_url(source_url)
    except ScopeValidationError as exc:
        return RedirectEvaluationResult(
            allowed=False,
            source_url=source_url,
            location=location,
            reasons=[ScopeReason(code=exc.code, message=exc.message, field="source_url")],
        )

    raw_next = urljoin(src_canonical.normalized, location.strip())
    try:
        next_canonical = canonicalize_url(raw_next)
    except ScopeValidationError as exc:
        return RedirectEvaluationResult(
            allowed=False,
            source_url=source_url,
            location=location,
            reasons=[
                ScopeReason(
                    code=f"redirect_{exc.code}",
                    message=f"Unsafe redirect target: {exc.message}",
                    field="redirect_location",
                )
            ],
        )

    reasons: list[ScopeReason] = []
    if (
        not allow_scheme_downgrade
        and src_canonical.scheme == "https"
        and next_canonical.scheme == "http"
    ):
        reasons.append(
            ScopeReason(
                code="redirect_scheme_downgrade",
                message="HTTPS to HTTP redirect downgrade is forbidden",
                field="redirect_location",
            )
        )

    reasons.extend(target_matches_scope(next_canonical, scope))

    resolved_ips: list[str] = []
    if next_canonical.is_ip and next_canonical.ip_address:
        resolved_ips = [next_canonical.ip_address]
    elif resolve_dns and next_canonical.is_domain and next_canonical.host:
        resolver = dns_resolver or SystemDnsResolver()
        dns_res = resolve_and_validate_host(
            next_canonical.host,
            scope,
            resolver,
            require_explicit_ip_match=False,
        )
        resolved_ips = dns_res.resolved_ips
        reasons.extend(dns_res.reasons)

    # Prefix redirect rejection reasons cleanly for clarity
    prefixed_reasons = [
        ScopeReason(
            code=(
                r.code
                if r.code.startswith("redirect_") or r.code.endswith("_blocked")
                else f"redirect_{r.code}"
            ),
            message=r.message,
            field=r.field or "redirect_location",
        )
        for r in reasons
    ]

    return RedirectEvaluationResult(
        allowed=len(prefixed_reasons) == 0,
        source_url=src_canonical.normalized,
        location=location,
        resolved_url=next_canonical.normalized,
        resolved_ips=resolved_ips,
        reasons=prefixed_reasons,
    )
