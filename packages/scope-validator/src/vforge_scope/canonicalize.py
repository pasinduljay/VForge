"""Strict canonicalization and validation for domains, URLs, IPs, CIDRs, ports, and assets."""

from __future__ import annotations

import ipaddress
import posixpath
import re
from urllib.parse import urlsplit, urlunsplit

from vforge_scope.models import CanonicalTarget, TargetType

_DNS_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_HEX_TOKEN_RE = re.compile(r"^0x[0-9a-f]+$")
_CONTAINER_IMAGE_RE = re.compile(
    r"^(?:[a-z0-9.-]+(?::[0-9]+)?/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_.-]{1,128}|@sha256:[a-f0-9]{64})$"
)
_IAC_PATH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,512}$")
_ENCODED_BYPASS_RE = re.compile(r"%(?:2e|2f|5c|00)", re.IGNORECASE)

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class ScopeValidationError(ValueError):
    """Raised when a target or scope definition fails canonicalization or validation."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _assert_no_control_or_whitespace(value: str, *, allow_space: bool = False) -> None:
    for ch in value:
        code = ord(ch)
        if code < 32 or code == 127:
            raise ScopeValidationError(
                "control_chars", "Target contains forbidden control characters"
            )
        if not allow_space and ch.isspace():
            raise ScopeValidationError("whitespace", "Target must not contain whitespace")


def canonicalize_port(port: int | str) -> int:
    """Validate and return an integer TCP/UDP port in range 1..65535."""
    if isinstance(port, bool):
        raise ScopeValidationError("invalid_port", "Port must be an integer between 1 and 65535")
    try:
        parsed = int(port)
    except (TypeError, ValueError) as exc:
        raise ScopeValidationError("invalid_port", f"Invalid port: {port!r}") from exc
    if parsed < 1 or parsed > 65535:
        raise ScopeValidationError("invalid_port", "Port must be between 1 and 65535")
    return parsed


def canonicalize_ip(raw_ip: str) -> IPAddress:
    """Parse and canonicalize an IPv4 or IPv6 address, unwrapping IPv4-mapped IPv6."""
    cleaned = raw_ip.strip()
    if not cleaned:
        raise ScopeValidationError("invalid_ip", "IP address must not be empty")
    _assert_no_control_or_whitespace(cleaned)

    if cleaned.startswith("[") and cleaned.endswith("]"):
        cleaned = cleaned[1:-1]
    if "%" in cleaned:
        raise ScopeValidationError("ip_zone_id_forbidden", "IPv6 zone IDs are not permitted")

    try:
        parsed = ipaddress.ip_address(cleaned)
    except ValueError as exc:
        raise ScopeValidationError("invalid_ip", f"Invalid IP address: {raw_ip!r}") from exc

    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
        return parsed.ipv4_mapped
    return parsed


def canonicalize_cidr(raw_cidr: str) -> IPNetwork:
    """Parse and canonicalize an IPv4 or IPv6 CIDR range."""
    cleaned = raw_cidr.strip()
    if not cleaned:
        raise ScopeValidationError("invalid_cidr", "CIDR range must not be empty")
    _assert_no_control_or_whitespace(cleaned)
    if "%" in cleaned:
        raise ScopeValidationError("ip_zone_id_forbidden", "CIDR must not contain zone IDs")
    if "/" not in cleaned:
        raise ScopeValidationError("invalid_cidr", "CIDR range must include '/prefix'")

    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError as exc:
        raise ScopeValidationError("invalid_cidr", f"Invalid CIDR range: {raw_cidr!r}") from exc

    if network.prefixlen == 0:
        raise ScopeValidationError(
            "overbroad_cidr", "Prefix length /0 is forbidden in target scope"
        )
    if (
        isinstance(network, ipaddress.IPv6Network)
        and network.network_address.ipv4_mapped is not None
    ):
        mapped_prefix = max(0, network.prefixlen - 96)
        if mapped_prefix == 0:
            raise ScopeValidationError(
                "overbroad_cidr", "Prefix length /0 is forbidden in target scope"
            )
        return ipaddress.ip_network(
            f"{network.network_address.ipv4_mapped}/{mapped_prefix}", strict=False
        )
    return network


def canonicalize_domain(raw_domain: str, *, allow_wildcard: bool = False) -> str:
    """Canonicalize a domain name with IDNA/Punycode, trailing dot stripping, and bypass guards."""
    cleaned = raw_domain.strip()
    if not cleaned:
        raise ScopeValidationError("invalid_domain", "Domain must not be empty")
    _assert_no_control_or_whitespace(cleaned)
    if any(ch in cleaned for ch in ("/", "?", "#", "@", "\\", ":")):
        raise ScopeValidationError(
            "invalid_domain", f"Domain contains invalid authority characters: {raw_domain!r}"
        )

    # Strip trailing DNS root dots (e.g. 'example.com.' -> 'example.com')
    stripped = cleaned.rstrip(".")
    if not stripped or ".." in stripped or stripped.startswith("."):
        raise ScopeValidationError("invalid_domain", f"Malformed domain name: {raw_domain!r}")

    # Reject raw IP addresses passed as domains
    try:
        canonicalize_ip(stripped)
    except ScopeValidationError:
        pass
    else:
        raise ScopeValidationError("ip_not_domain", "IP literal cannot be used as a domain name")

    wildcard_prefix = ""
    domain_body = stripped
    if "*" in stripped:
        if not allow_wildcard:
            raise ScopeValidationError(
                "wildcard_not_allowed", "Wildcard '*' is not allowed for this target type"
            )
        if not stripped.startswith("*.") or stripped.count("*") > 1:
            raise ScopeValidationError(
                "invalid_wildcard_domain",
                "Wildcard domain must use a single leading '*.' label (e.g. '*.example.com')",
            )
        domain_body = stripped[2:]
        if "." not in domain_body:
            raise ScopeValidationError(
                "overbroad_wildcard",
                "Wildcard domain must include at least two labels after '*.'",
            )
        wildcard_prefix = "*."

    try:
        ascii_domain = domain_body.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ScopeValidationError(
            "invalid_idna_domain", f"Invalid IDNA domain: {raw_domain!r}"
        ) from exc

    if len(ascii_domain) > 253:
        raise ScopeValidationError("invalid_domain", "Domain exceeds 253-character DNS limit")

    labels = ascii_domain.split(".")
    for label in labels:
        if not _DNS_LABEL_RE.match(label):
            raise ScopeValidationError(
                "invalid_domain", f"Invalid DNS label {label!r} in domain {raw_domain!r}"
            )

    # Block obfuscated decimal/octal/hex IPv4 hostnames like 2130706433, 0x7f000001, 0177.0.0.1
    if len(labels) == 1 and (labels[0].isdigit() or _HEX_TOKEN_RE.match(labels[0])):
        raise ScopeValidationError(
            "obfuscated_ip_forbidden", "Numeric or hex IP obfuscation is forbidden"
        )
    if labels[-1].isdigit() or _HEX_TOKEN_RE.match(labels[-1]):
        raise ScopeValidationError(
            "obfuscated_ip_forbidden", "Numeric or hex TLD / obfuscated IP is forbidden"
        )

    return f"{wildcard_prefix}{ascii_domain}"


def normalize_url_path(raw_path: str) -> str:
    """Normalize a URL path while blocking traversal and encoded-separator bypasses."""
    if "\\" in raw_path:
        raise ScopeValidationError("invalid_url_path", "Backslashes are forbidden in URL paths")
    if _ENCODED_BYPASS_RE.search(raw_path):
        raise ScopeValidationError(
            "encoded_path_bypass",
            "Percent-encoded dots, slashes, backslashes, or null bytes are forbidden in URL paths",
        )

    path = raw_path or "/"
    if not path.startswith("/"):
        path = f"/{path}"

    # Collapse duplicate slashes and resolve '.' / '..' deterministically
    had_trailing_slash = len(path) > 1 and path.endswith("/")
    segments = [seg for seg in path.split("/") if seg not in ("", ".")]
    resolved: list[str] = []
    for seg in segments:
        if seg == "..":
            if not resolved:
                raise ScopeValidationError(
                    "path_traversal_outside_root",
                    "URL path attempts to traverse above root '/'",
                )
            resolved.pop()
        else:
            resolved.append(seg)

    if not resolved:
        return "/"
    normalized = "/" + "/".join(resolved)
    if had_trailing_slash and not normalized.endswith("/"):
        normalized = f"{normalized}/"
    return posixpath.normpath(normalized) + ("/" if had_trailing_slash and resolved else "")


def _validate_url_authority(parts_netloc: str) -> tuple[str, int | None, bool, bool]:
    if not parts_netloc:
        raise ScopeValidationError("missing_host", "URL missing host")
    if "@" in parts_netloc:
        raise ScopeValidationError("embedded_credentials", "URL must not contain '@' or userinfo")
    if "\\" in parts_netloc:
        raise ScopeValidationError(
            "invalid_authority", "URL authority must not contain backslashes"
        )

    host_part = parts_netloc
    port: int | None = None
    if parts_netloc.startswith("["):
        if "]" not in parts_netloc:
            raise ScopeValidationError("malformed_ipv6_url", "Malformed IPv6 bracket in URL")
        closing = parts_netloc.index("]")
        host_part = parts_netloc[1:closing]
        rest = parts_netloc[closing + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise ScopeValidationError("malformed_authority", "Malformed port after IPv6 host")
            port = canonicalize_port(rest[1:])
        ip_obj = canonicalize_ip(host_part)
        return ip_obj.compressed, port, True, False

    if ":" in parts_netloc:
        host_part, port_str = parts_netloc.rsplit(":", 1)
        if ":" in host_part:
            raise ScopeValidationError("malformed_ipv6_url", "Unbracketed IPv6 address in URL")
        port = canonicalize_port(port_str)

    try:
        ip_obj = canonicalize_ip(host_part)
        return ip_obj.compressed, port, True, False
    except ScopeValidationError as exc:
        if exc.code == "ip_zone_id_forbidden":
            raise
        domain = canonicalize_domain(host_part, allow_wildcard=False)
        return domain, port, False, True


def canonicalize_url(
    raw_url: str,
    *,
    allowed_schemes: frozenset[str] = frozenset({"http", "https"}),
    target_type: TargetType = TargetType.EXACT_URL,
) -> CanonicalTarget:
    """Strictly canonicalize an HTTP(S) URL with port, IDNA, IPv6, and path checks."""
    cleaned = raw_url.strip()
    if not cleaned or len(cleaned) > 2048:
        raise ScopeValidationError("invalid_url", "URL must be between 1 and 2048 characters")
    _assert_no_control_or_whitespace(cleaned)

    # Reject backslash anywhere before query string (authority confusion defense)
    before_query = cleaned.split("?", 1)[0]
    if "\\" in before_query:
        raise ScopeValidationError("invalid_url", "Backslashes are forbidden in URLs")

    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    if not scheme or scheme not in allowed_schemes:
        allowed_str = ", ".join(sorted(allowed_schemes))
        raise ScopeValidationError("disallowed_scheme", f"URL scheme must be one of: {allowed_str}")
    if parts.fragment:
        raise ScopeValidationError("fragment_forbidden", "URL fragments are not allowed")

    host, explicit_port, is_ip, is_domain = _validate_url_authority(parts.netloc)
    default_port = 80 if scheme == "http" else 443 if scheme == "https" else None
    effective_port = explicit_port if explicit_port is not None else default_port

    netloc = f"[{host}]" if ":" in host else host
    if explicit_port is not None and explicit_port != default_port:
        netloc = f"{netloc}:{explicit_port}"

    path = normalize_url_path(parts.path)
    normalized = urlunsplit((scheme, netloc, path, parts.query, ""))

    return CanonicalTarget(
        target_type=target_type,
        raw=raw_url,
        normalized=normalized,
        scheme=scheme,
        host=host,
        port=effective_port,
        path=path,
        query=parts.query or "",
        ip_address=host if is_ip else None,
        is_ip=is_ip,
        is_domain=is_domain,
    )


def canonicalize_host_or_ip(raw_host: str) -> tuple[str, bool, bool]:
    """Canonicalize a bare host string into `(canonical_host, is_ip, is_domain)`."""
    cleaned = raw_host.strip()
    _assert_no_control_or_whitespace(cleaned)
    try:
        ip_obj = canonicalize_ip(cleaned)
        return ip_obj.compressed, True, False
    except ScopeValidationError as exc:
        if exc.code == "ip_zone_id_forbidden":
            raise
        domain = canonicalize_domain(cleaned, allow_wildcard=False)
        return domain, False, True


def canonicalize_network_service(raw_service: str) -> CanonicalTarget:
    """Canonicalize `host:port` or `[ipv6]:port` network service target."""
    cleaned = raw_service.strip()
    if not cleaned:
        raise ScopeValidationError("invalid_network_service", "Network service must not be empty")
    _assert_no_control_or_whitespace(cleaned)

    if cleaned.startswith("[") and "]:" in cleaned:
        host_part, port_str = cleaned[1:].split("]:", 1)
    elif cleaned.count(":") == 1:
        host_part, port_str = cleaned.split(":", 1)
    else:
        raise ScopeValidationError(
            "invalid_network_service", "Network service must be host:port or [ipv6]:port"
        )

    host, is_ip, is_domain = canonicalize_host_or_ip(host_part)
    port = canonicalize_port(port_str)
    normalized = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return CanonicalTarget(
        target_type=TargetType.NETWORK_SERVICE,
        raw=raw_service,
        normalized=normalized,
        host=host,
        port=port,
        ip_address=host if is_ip else None,
        is_ip=is_ip,
        is_domain=is_domain,
    )


def canonicalize_source_repository(raw_repo: str) -> CanonicalTarget:
    """Canonicalize a Git/SCM source repository locator (`https`, `ssh`, or `git`)."""
    cleaned = raw_repo.strip()
    if not cleaned or len(cleaned) > 2048:
        raise ScopeValidationError("invalid_repository", "Repository locator length invalid")
    _assert_no_control_or_whitespace(cleaned)
    parts = urlsplit(cleaned)
    scheme = parts.scheme.lower()
    if scheme not in {"https", "ssh", "git"}:
        raise ScopeValidationError(
            "disallowed_scheme", "Source repository locator must use https, ssh, or git scheme"
        )
    if parts.password:
        raise ScopeValidationError(
            "embedded_credentials", "Repository locator must not embed passwords or tokens"
        )
    if parts.username and scheme == "https":
        raise ScopeValidationError(
            "embedded_credentials", "HTTPS repository locator must not embed user credentials"
        )
    if not parts.hostname:
        raise ScopeValidationError("missing_host", "Repository locator missing hostname")
    host, is_ip, is_domain = canonicalize_host_or_ip(parts.hostname)
    port = canonicalize_port(parts.port) if parts.port is not None else None
    netloc = f"{parts.username}@{host}" if parts.username else host
    if port is not None:
        netloc = f"{netloc}:{port}"
    path = parts.path.rstrip("/")
    if not path or path == "/":
        raise ScopeValidationError(
            "invalid_repository", "Repository locator must include repository path"
        )
    normalized = urlunsplit((scheme, netloc, path, "", ""))
    return CanonicalTarget(
        target_type=TargetType.SOURCE_REPOSITORY,
        raw=raw_repo,
        normalized=normalized,
        scheme=scheme,
        host=host,
        port=port,
        path=path,
        ip_address=host if is_ip else None,
        is_ip=is_ip,
        is_domain=is_domain,
    )


def canonicalize_container_image(raw_ref: str) -> CanonicalTarget:
    """Canonicalize a container image reference requiring explicit `:tag` or `@sha256:digest`."""
    cleaned = raw_ref.strip()
    if not cleaned or len(cleaned) > 2048:
        raise ScopeValidationError("invalid_container_image", "Container image length invalid")
    _assert_no_control_or_whitespace(cleaned)
    if "@" in cleaned:
        repo_part, digest_part = cleaned.split("@", 1)
        normalized = f"{repo_part.lower()}@{digest_part.lower()}"
    elif ":" in cleaned.rsplit("/", 1)[-1]:
        repo_part, tag_part = cleaned.rsplit(":", 1)
        normalized = f"{repo_part.lower()}:{tag_part}"
    else:
        raise ScopeValidationError(
            "invalid_container_image",
            "Container image must specify an explicit :tag or @sha256:digest",
        )
    if not _CONTAINER_IMAGE_RE.match(normalized):
        raise ScopeValidationError("invalid_container_image", "Invalid container image format")
    return CanonicalTarget(
        target_type=TargetType.CONTAINER_IMAGE,
        raw=raw_ref,
        normalized=normalized,
    )


def canonicalize_infrastructure_path(raw_path: str) -> CanonicalTarget:
    """Canonicalize a relative IaC/repository resource path without '..' traversal."""
    cleaned = raw_path.strip()
    if not cleaned or len(cleaned) > 512:
        raise ScopeValidationError("invalid_iac_path", "Infrastructure path length invalid")
    _assert_no_control_or_whitespace(cleaned, allow_space=True)
    normalized = cleaned.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized.removeprefix("./")
    if (
        not normalized
        or normalized.startswith("/")
        or ".." in normalized.split("/")
        or not _IAC_PATH_RE.match(normalized)
    ):
        raise ScopeValidationError("invalid_iac_path", "Invalid infrastructure definition path")
    return CanonicalTarget(
        target_type=TargetType.INFRASTRUCTURE_DEFINITION,
        raw=raw_path,
        normalized=normalized,
        path=normalized,
    )


def canonicalize_target(target_type: TargetType, raw_value: str) -> CanonicalTarget:
    """Canonicalize any supported Phase 2 target type into a `CanonicalTarget`."""
    cleaned = raw_value.strip()
    if not cleaned:
        raise ScopeValidationError("empty_target", "Target must not be empty")

    if target_type == TargetType.FQDN:
        domain = canonicalize_domain(cleaned, allow_wildcard=False)
        return CanonicalTarget(
            target_type=target_type,
            raw=raw_value,
            normalized=domain,
            host=domain,
            is_domain=True,
        )
    if target_type == TargetType.DOMAIN_AND_SUBDOMAINS:
        base = cleaned[2:] if cleaned.startswith("*.") else cleaned
        domain = canonicalize_domain(base, allow_wildcard=False)
        return CanonicalTarget(
            target_type=target_type,
            raw=raw_value,
            normalized=f"*.{domain}",
            host=domain,
            is_domain=True,
        )
    if target_type in {TargetType.EXACT_URL, TargetType.URL_PATH_PREFIX, TargetType.REST_API}:
        return canonicalize_url(cleaned, target_type=target_type)
    if target_type == TargetType.IPV4:
        ip_obj = canonicalize_ip(cleaned)
        if not isinstance(ip_obj, ipaddress.IPv4Address):
            raise ScopeValidationError("expected_ipv4", "Target is not an IPv4 address")
        return CanonicalTarget(
            target_type=target_type,
            raw=raw_value,
            normalized=ip_obj.compressed,
            host=ip_obj.compressed,
            ip_address=ip_obj.compressed,
            is_ip=True,
        )
    if target_type == TargetType.IPV6:
        ip_obj = canonicalize_ip(cleaned)
        if not isinstance(ip_obj, ipaddress.IPv6Address):
            raise ScopeValidationError("expected_ipv6", "Target is not an IPv6 address")
        return CanonicalTarget(
            target_type=target_type,
            raw=raw_value,
            normalized=ip_obj.compressed,
            host=ip_obj.compressed,
            ip_address=ip_obj.compressed,
            is_ip=True,
        )
    if target_type == TargetType.CIDR_RANGE:
        net = canonicalize_cidr(cleaned)
        return CanonicalTarget(
            target_type=target_type,
            raw=raw_value,
            normalized=net.compressed,
            cidr=net.compressed,
        )
    if target_type == TargetType.NETWORK_SERVICE:
        return canonicalize_network_service(cleaned)
    if target_type == TargetType.SOURCE_REPOSITORY:
        return canonicalize_source_repository(cleaned)
    if target_type == TargetType.CONTAINER_IMAGE:
        return canonicalize_container_image(cleaned)
    if target_type == TargetType.INFRASTRUCTURE_DEFINITION:
        return canonicalize_infrastructure_path(cleaned)
    raise ScopeValidationError("unsupported_target_type", f"Unsupported target type: {target_type}")


def match_domain(target_host: str, allowed_domain: str, *, include_subdomains: bool) -> bool:
    """Strictly match a canonical hostname without unsafe suffix substring bugs."""
    if target_host == allowed_domain:
        return True
    if include_subdomains:
        return target_host.endswith(f".{allowed_domain}")
    return False


def match_exact_url(target: CanonicalTarget, allowed: CanonicalTarget) -> bool:
    """Match exact normalized URL `(scheme, host, effective_port, path, query)`."""
    return (
        target.scheme == allowed.scheme
        and target.host == allowed.host
        and target.port == allowed.port
        and (target.path or "/") == (allowed.path or "/")
        and (target.query or "") == (allowed.query or "")
    )


def match_url_path_prefix(target: CanonicalTarget, prefix: CanonicalTarget) -> bool:
    """Match URL scheme/host/port and segment-safe path prefix."""
    if target.scheme != prefix.scheme or target.host != prefix.host or target.port != prefix.port:
        return False
    target_path = target.path or "/"
    prefix_path = prefix.path or "/"
    if prefix_path == "/":
        return True
    clean_prefix = prefix_path.rstrip("/")
    return target_path == clean_prefix or target_path.startswith(f"{clean_prefix}/")
