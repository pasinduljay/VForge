"""Unit and property-based tests for the reusable `vforge_scope` package."""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from vforge_scope import (
    Capability,
    ScopeDefinition,
    ScopeValidationError,
    StaticDnsResolver,
    TargetType,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_port,
    canonicalize_target,
    canonicalize_url,
    evaluate_redirect_destination,
    evaluate_target_scope,
    match_domain,
    match_url_path_prefix,
    normalize_capabilities,
    normalize_url_path,
)


def test_domain_canonicalization_idna_and_trailing_dots() -> None:
    assert canonicalize_domain("Example.COM.") == "example.com"
    assert canonicalize_domain("sub.Example.COM...") == "sub.example.com"
    assert canonicalize_domain("münchen.example.com.") == "xn--mnchen-3ya.example.com"
    assert canonicalize_domain("*.Example.com.", allow_wildcard=True) == "*.example.com"

    with pytest.raises(ScopeValidationError):
        canonicalize_domain("*.example.com", allow_wildcard=False)
    with pytest.raises(ScopeValidationError):
        canonicalize_domain("*.com", allow_wildcard=True)
    with pytest.raises(ScopeValidationError):
        canonicalize_domain("2130706433")
    with pytest.raises(ScopeValidationError):
        canonicalize_domain("0x7f000001")
    with pytest.raises(ScopeValidationError):
        canonicalize_domain("0177.0.0.1")


def test_subdomain_and_lookalike_matching() -> None:
    assert match_domain("example.com", "example.com", include_subdomains=False) is True
    assert match_domain("sub.example.com", "example.com", include_subdomains=False) is False
    assert match_domain("notexample.com", "example.com", include_subdomains=False) is False
    assert match_domain("notexample.com", "example.com", include_subdomains=True) is False
    assert match_domain("api.example.com", "example.com", include_subdomains=True) is True


def test_url_canonicalization_and_path_traversal_bypass_guards() -> None:
    norm = canonicalize_url("HTTPS://App.Example.COM:443/api//v1/users")
    assert norm.normalized == "https://app.example.com/api/v1/users"
    assert norm.port == 443

    prefix = canonicalize_url("https://app.example.com/api", target_type=TargetType.URL_PATH_PREFIX)
    ok_child = canonicalize_url("https://app.example.com/api/v1")
    evil_sibling = canonicalize_url("https://app.example.com/api-admin")
    traversal_escape = canonicalize_url("https://app.example.com/api/../admin")

    assert match_url_path_prefix(ok_child, prefix) is True
    assert match_url_path_prefix(evil_sibling, prefix) is False
    assert match_url_path_prefix(traversal_escape, prefix) is False

    for bad_url in (
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/",
        "https://user:pass@example.com/",
        "https://example.com/#frag",
        "https://example.com\\@evil.com/",
        "https://example.com/api/%2e%2e/admin",
        "https://example.com/api/%2fadmin",
    ):
        with pytest.raises(ScopeValidationError):
            canonicalize_url(bad_url)


def test_ip_ipv4_mapped_ipv6_and_cidr_canonicalization() -> None:
    assert canonicalize_ip("2001:0db8:0000:0000:0000:0000:0000:0001").compressed == "2001:db8::1"
    assert canonicalize_ip("::ffff:127.0.0.1").compressed == "127.0.0.1"
    assert canonicalize_ip("::ffff:169.254.169.254").compressed == "169.254.169.254"
    assert canonicalize_cidr("10.20.30.40/24").compressed == "10.20.30.0/24"

    with pytest.raises(ScopeValidationError):
        canonicalize_ip("fe80::1%eth0")
    with pytest.raises(ScopeValidationError):
        canonicalize_cidr("0.0.0.0/0")


def test_capabilities_normalization_and_forbidden_checks() -> None:
    caps = normalize_capabilities(["sast", "passive_dast", "api_testing"])
    assert caps == [
        Capability.API_TESTING,
        Capability.PASSIVE_WEB_TESTING,
        Capability.SOURCE_CODE_ANALYSIS,
    ]
    for forbidden in ("dos_testing", "destructive_testing", "unrestricted_exploitation"):
        with pytest.raises(ValueError):
            normalize_capabilities([forbidden])


def test_dns_rebinding_mixed_response_metadata_and_redirect_guards() -> None:
    scope = ScopeDefinition(
        exact_domains=["app.example.com"],
        url_path_prefixes=["https://app.example.com/"],
        allowed_ports=[443],
        pinned_dns_resolution={"app.example.com": ["93.184.216.34"]},
    )

    # Valid pinned public IP
    ok_dns = StaticDnsResolver({"app.example.com": ["93.184.216.34"]})
    res_ok = evaluate_target_scope(
        target_type=TargetType.EXACT_URL,
        raw_target="https://app.example.com/health",
        scope=scope,
        dns_resolver=ok_dns,
    )
    assert res_ok.allowed is True

    # Mixed DNS response (one public + one metadata) -> denied
    mixed_dns = StaticDnsResolver({"app.example.com": ["93.184.216.34", "169.254.169.254"]})
    res_mixed = evaluate_target_scope(
        target_type=TargetType.EXACT_URL,
        raw_target="https://app.example.com/health",
        scope=scope,
        dns_resolver=mixed_dns,
    )
    assert res_mixed.allowed is False
    assert any(r.code == "mixed_dns_response_blocked" for r in res_mixed.reasons)

    # DNS rebinding drift -> denied
    rebind_dns = StaticDnsResolver({"app.example.com": ["93.184.216.99"]})
    res_rebind = evaluate_target_scope(
        target_type=TargetType.EXACT_URL,
        raw_target="https://app.example.com/health",
        scope=scope,
        dns_resolver=rebind_dns,
    )
    assert res_rebind.allowed is False
    assert any(r.code == "dns_rebinding_detected" for r in res_rebind.reasons)

    # Redirect to unauthorized domain or metadata IP -> denied
    redir_bad_domain = evaluate_redirect_destination(
        source_url="https://app.example.com/login",
        location="https://evil.example.org/steal",
        scope=scope,
        dns_resolver=StaticDnsResolver({"evil.example.org": ["93.184.216.34"]}),
    )
    assert redir_bad_domain.allowed is False

    redir_metadata = evaluate_redirect_destination(
        source_url="https://app.example.com/login",
        location="http://169.254.169.254/latest/meta-data/",
        scope=scope,
        dns_resolver=ok_dns,
    )
    assert redir_metadata.allowed is False


# --- Property-based tests (Hypothesis) ---


_DNS_LABEL_STRATEGY = st.from_regex(r"[a-z0-9](?:[a-z0-9-]{0,12}[a-z0-9])?", fullmatch=True)


@given(
    labels=st.lists(_DNS_LABEL_STRATEGY, min_size=1, max_size=4),
    tld=st.from_regex(r"[a-z]{2,8}", fullmatch=True),
    trailing_dots=st.sampled_from(["", ".", ".."]),
    uppercase=st.booleans(),
)
@settings(max_examples=100)
def test_property_domain_canonicalization_idempotent(
    labels: list[str],
    tld: str,
    trailing_dots: str,
    uppercase: bool,
) -> None:
    raw = ".".join([*labels, tld]) + trailing_dots
    if uppercase:
        raw = raw.upper()
    canon1 = canonicalize_domain(raw)
    canon2 = canonicalize_domain(canon1)
    assert canon1 == canon2
    assert not canon1.endswith(".")
    assert canon1 == canon1.lower()


@given(
    allowed_label=_DNS_LABEL_STRATEGY,
    prefix=st.from_regex(r"[a-z0-9]{1,8}", fullmatch=True),
    tld=st.from_regex(r"[a-z]{2,6}", fullmatch=True),
)
@settings(max_examples=100)
def test_property_lookalike_prefix_never_matches_domain(
    allowed_label: str,
    prefix: str,
    tld: str,
) -> None:
    allowed = f"{allowed_label}.{tld}"
    lookalike = f"{prefix}{allowed_label}.{tld}"
    assert match_domain(lookalike, allowed, include_subdomains=True) is False
    assert match_domain(lookalike, allowed, include_subdomains=False) is False


@given(ip_int=st.integers(min_value=0, max_value=(2**32) - 1))
@settings(max_examples=100)
def test_property_ipv4_and_mapped_ipv6_canonicalize_identically(ip_int: int) -> None:
    v4 = ipaddress.IPv4Address(ip_int)
    mapped_v6 = f"::ffff:{v4}"
    assert canonicalize_ip(str(v4)) == v4
    assert canonicalize_ip(mapped_v6) == v4


@given(
    port=st.integers(min_value=1, max_value=65535),
)
@settings(max_examples=100)
def test_property_valid_ports_roundtrip(port: int) -> None:
    assert canonicalize_port(port) == port
    assert canonicalize_port(str(port)) == port


@given(
    segments=st.lists(st.from_regex(r"[a-zA-Z0-9_-]{1,12}", fullmatch=True), min_size=1, max_size=4)
)
@settings(max_examples=100)
def test_property_url_path_normalization_starts_with_slash(segments: list[str]) -> None:
    raw_path = "//" + "/./".join(segments) + "/"
    norm = normalize_url_path(raw_path)
    assert norm.startswith("/")
    assert "//" not in norm
    assert "/./" not in norm
    assert "/../" not in norm


def test_canonicalize_target_all_asset_types() -> None:
    assert canonicalize_target(TargetType.FQDN, "API.Example.COM.").normalized == "api.example.com"
    assert (
        canonicalize_target(TargetType.DOMAIN_AND_SUBDOMAINS, "*.Example.COM.").normalized
        == "*.example.com"
    )
    assert canonicalize_target(TargetType.IPV4, "93.184.216.34").normalized == "93.184.216.34"
    assert canonicalize_target(TargetType.IPV6, "2001:0db8::1").normalized == "2001:db8::1"
    assert (
        canonicalize_target(TargetType.CIDR_RANGE, "198.51.100.42/24").normalized
        == "198.51.100.0/24"
    )
    assert (
        canonicalize_target(TargetType.NETWORK_SERVICE, "[2001:db8::1]:8443").normalized
        == "[2001:db8::1]:8443"
    )
    assert (
        canonicalize_target(TargetType.REST_API, "https://api.example.com/v1").normalized
        == "https://api.example.com/v1"
    )
    assert (
        canonicalize_target(TargetType.SOURCE_REPOSITORY, "https://github.com/org/repo/").normalized
        == "https://github.com/org/repo"
    )
    assert (
        canonicalize_target(TargetType.CONTAINER_IMAGE, "GHCR.IO/Org/App:v1.0.0").normalized
        == "ghcr.io/org/app:v1.0.0"
    )
    assert (
        canonicalize_target(TargetType.INFRASTRUCTURE_DEFINITION, "./tf/main.tf").normalized
        == "tf/main.tf"
    )
