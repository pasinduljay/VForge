"""Multi-source free OSINT, infostealer compromise, and attack-surface correlation engine."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit

import anyio
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.errors import NotFoundError, ValidationError
from vforge.intel.connector import (
    FeedBatch,
    NormalizedIntelRecord,
    SourceHealth,
    SourceMetadata,
    ValidationResult,
)
from vforge.intel.enrichment import get_cve_threat_intel
from vforge.models.domain import Asset, Project
from vforge.models.enums import FindingEventType
from vforge.models.scanner import Finding, FindingEvent
from vforge.services.findings import DEFAULT_SLA_DAYS

_EMAIL_RE = re.compile(r"^[^@\s]+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}$")
_DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
_IPV4_IN_TEXT_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_HIGH_INTEREST_URL_RE = re.compile(
    r"(\.env|\.git|admin|login|signin|user|vpn|cpanel|webmail|2078|2083|2087|2096|"
    r"api|swagger|graphql|config|backup|\.sql|\.zip|\.bak|token|oauth|sso|portal|dev|staging)",
    re.IGNORECASE,
)
_STATIC_ASSET_URL_RE = re.compile(
    r"(?:\.(?:png|jpe?g|gif|svg|ico|webp|bmp|avif|woff2?|ttf|eot|otf|css|map|mp4|mp3|wav|webm)"
    r"(?:\?|$)|(?:jquery|bootstrap|fontawesome|popper)(?:\.min)?\.js)",
    re.IGNORECASE,
)
_STATIC_MIME_PREFIXES = ("image/", "font/", "audio/", "video/", "text/css")

_SEVERITY_RANK: dict[str, int] = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_ADMIN_PORTS = {
    21,
    22,
    23,
    445,
    1433,
    2082,
    2083,
    2086,
    2087,
    3306,
    3389,
    5432,
    6379,
    8080,
    8443,
    9200,
    27017,
}
_CRITICAL_PORTS = {23, 445, 3389, 6379, 9200, 27017}


class HudsonRockConnector:
    """Hudson Rock Cavalier OSINT v2 connector registered in IntelConnectorRegistry."""

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            slug="hudson_rock",
            name="Hudson Rock Cavalier Infostealer OSINT",
            source_type="exposure_intel",
            provider_url="https://cavalier.hudsonrock.com/api/json/v2/osint-tools",
            license_name="Hudson Rock Free OSINT API",
            license_url="https://docs.hudsonrock.com/",
            terms_reference=(
                "Real-time infostealer infection, credential exposure, and domain telemetry"
            ),
            is_gated=False,
            requires_scope_auth=False,
            allow_binary_upload=False,
        )

    async def health_check(self) -> SourceHealth:
        return SourceHealth(
            is_healthy=True,
            status_code=200,
            error_message=None,
            checked_at=datetime.now(UTC),
        )

    async def fetch_incremental(self, cursor: str | None = None) -> FeedBatch:
        now = datetime.now(UTC)
        payload = {
            "provider": "hudson_rock",
            "endpoint": "https://cavalier.hudsonrock.com/api/json/v2/osint-tools",
            "fetched_at": now.isoformat(),
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return FeedBatch(
            cursor_before=cursor,
            cursor_after=now.isoformat(),
            raw_payload=payload,
            raw_hash=hashlib.sha256(raw_bytes).hexdigest(),
            retrieved_at=now,
            record_count=0,
        )

    def validate(self, batch: FeedBatch) -> ValidationResult:
        return ValidationResult(is_valid=True, errors=[])

    def normalize(self, batch: FeedBatch) -> list[NormalizedIntelRecord]:
        return []

    def checkpoint(self, batch: FeedBatch) -> str | None:
        return batch.cursor_after


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _parse_iso_datetime(val: Any) -> datetime | None:
    if not isinstance(val, str) or not val.strip():
        return None
    cleaned = val.strip()
    try:
        if re.fullmatch(r"\d{14}", cleaned):
            dt = datetime.strptime(cleaned, "%Y%m%d%H%M%S").replace(tzinfo=UTC)
        else:
            if cleaned.endswith("Z"):
                cleaned = cleaned[:-1] + "+00:00"
            dt = datetime.fromisoformat(cleaned)
            dt = dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)
        # Filter out Unix epoch sentinel values (e.g., 1970-01-01T00:00:00.000Z)
        if dt.year <= 1970:
            return None
        return dt
    except ValueError:
        return None


def _extract_hostname_from_input(raw: str) -> str:
    candidate = raw.strip()
    if "://" in candidate:
        parsed = urlsplit(candidate)
        candidate = parsed.hostname or candidate
    else:
        candidate = candidate.split("/")[0].split("?")[0].split("#")[0]
        if ":" in candidate and not candidate.count(":") > 1:
            candidate = candidate.split(":")[0]
    return candidate.strip().lower().strip(".")


def detect_query_type(
    raw_query: str,
    requested_type: str = "auto",
) -> tuple[str, str]:
    """Classify and normalize an OSINT exposure query into `(detected_type, normalized_query)`."""
    cleaned = raw_query.strip()
    if not cleaned:
        raise ValidationError("Search query cannot be empty")
    if len(cleaned) > 255:
        raise ValidationError("Search query must be 255 characters or fewer")

    req = requested_type.strip().lower() or "auto"
    if req not in {"auto", "domain", "email", "ip", "company", "username"}:
        raise ValidationError("Invalid query_type")

    # Handle `@domain.com` shorthand as a domain-wide email/compromise search
    if cleaned.startswith("@") and _DOMAIN_RE.fullmatch(cleaned[1:].strip().lower()):
        domain_val = cleaned[1:].strip().lower()
        return ("domain", domain_val)

    # Explicit or auto IP check
    ip_candidate = cleaned.split("/")[0].strip() if req == "ip" else cleaned
    try:
        ip_obj = ipaddress.ip_address(ip_candidate)
        return ("ip", ip_obj.compressed)
    except ValueError:
        if req == "ip":
            raise ValidationError(f"'{cleaned}' is not a valid IPv4 or IPv6 address") from None

    # Explicit or auto Email check
    if _EMAIL_RE.fullmatch(cleaned):
        return ("email", cleaned.lower())
    if req == "email":
        if _DOMAIN_RE.fullmatch(cleaned.lstrip("@").lower()):
            return ("domain", cleaned.lstrip("@").lower())
        raise ValidationError(f"'{cleaned}' is not a valid email address")

    # Explicit or auto Domain/URL check
    host_candidate = _extract_hostname_from_input(cleaned)
    if req == "domain":
        host_candidate = host_candidate.lstrip("@")
        if not _DOMAIN_RE.fullmatch(host_candidate):
            raise ValidationError(f"'{cleaned}' is not a valid domain name")
        return ("domain", host_candidate)

    if req == "auto" and (" " not in cleaned) and _DOMAIN_RE.fullmatch(host_candidate):
        return ("domain", host_candidate)

    if req == "username":
        return ("username", cleaned.lstrip("@"))

    if req == "company":
        return ("company", cleaned)

    return ("company", cleaned)


def _generate_company_domain_candidates(company_query: str) -> list[str]:
    """Generate candidate primary domains from a company name like 'example corp'."""
    tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9]+", company_query) if t]
    if not tokens:
        return []

    joined = "".join(tokens)
    candidates: list[str] = [f"{joined}.com"]

    if len(tokens) >= 2:
        first, rest = tokens[0], "".join(tokens[1:])
        candidates.append(f"{first}-{rest}.com")
        candidates.append(f"{first}.com")
        if rest.startswith("technologies"):
            candidates.append(f"{first}tech.com")
    else:
        candidates.append(f"{joined}technologies.com")
        candidates.append(f"{joined}tech.com")

    deduped: list[str] = []
    for c in candidates:
        if _DOMAIN_RE.fullmatch(c) and c not in deduped:
            deduped.append(c)
    return deduped[:6]


def _resolve_host_ipv4_sync(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET, socket.SOCK_STREAM)
        ips: set[str] = set()
        for info in infos:
            ip_str = str(info[4][0])
            ip_obj = ipaddress.ip_address(ip_str)
            if not (ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_unspecified):
                ips.add(ip_str)
        return sorted(ips)
    except OSError:
        return []


async def _resolve_host_ipv4(hostname: str) -> list[str]:
    try:
        with anyio.move_on_after(2.5):
            return await anyio.to_thread.run_sync(_resolve_host_ipv4_sync, hostname)
    except Exception:
        return []
    return []


async def _resolve_company_domains(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    company_query: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[str], dict[str, Any]]:
    """Resolve a company name into active domain(s) via org assets, Clearbit, and DNS."""
    t0 = time.perf_counter()
    discovered_domains: list[str] = []
    raw_items: list[dict[str, Any]] = []

    tokens = [t.lower() for t in re.findall(r"[a-zA-Z0-9]+", company_query) if len(t) >= 3]
    if tokens:
        assets = (
            (await db.execute(select(Asset).where(Asset.organization_id == org_id))).scalars().all()
        )
        for asset in assets:
            host = _extract_hostname_from_input(asset.normalized_locator)
            if _DOMAIN_RE.fullmatch(host) and any(tok in host for tok in tokens):
                if host not in discovered_domains:
                    discovered_domains.append(host)

    clearbit_status = 200
    clearbit_err: str | None = None
    try:
        resp = await http_client.get(
            "https://autocomplete.clearbit.com/v1/companies/suggest",
            params={"query": company_query},
            timeout=4.5,
        )
        clearbit_status = resp.status_code
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for item in data[:5]:
                    if isinstance(item, dict):
                        dom = str(item.get("domain") or "").strip().lower()
                        if _DOMAIN_RE.fullmatch(dom) and dom not in discovered_domains:
                            discovered_domains.append(dom)
                            raw_items.append(item)
    except httpx.HTTPError as exc:
        clearbit_status = 503
        clearbit_err = str(exc)[:160]

    candidates = _generate_company_domain_candidates(company_query)
    if candidates:
        dns_results = await asyncio.gather(*(_resolve_host_ipv4(c) for c in candidates))
        for cand, ips in zip(candidates, dns_results, strict=False):
            if ips and cand not in discovered_domains:
                discovered_domains.append(cand)
                raw_items.append({"domain": cand, "resolved_ips": ips, "source": "dns_heuristic"})

    latency_ms = int((time.perf_counter() - t0) * 1000)
    raw_json = json.dumps(raw_items, sort_keys=True)
    source_status = {
        "source_slug": "clearbit_autocomplete",
        "source_name": "Clearbit & DNS Company-to-Domain Resolver",
        "status": (
            "succeeded" if discovered_domains else ("unavailable" if clearbit_err else "no_records")
        ),
        "http_status": clearbit_status,
        "records_found": len(discovered_domains),
        "latency_ms": latency_ms,
        "raw_sha256": _sha256_text(raw_json),
        "retrieved_at": datetime.now(UTC),
        "error_message": clearbit_err,
    }
    return discovered_domains[:3], source_status


async def _query_hudson_rock_domain(
    domain: str,
    http_client: httpx.AsyncClient,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, Any], list[str], list[str]]:
    """Query Hudson Rock Cavalier Free OSINT v2 `/search-by-domain`."""
    t0 = time.perf_counter()
    url = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain"
    records: list[dict[str, Any]] = []
    discovered_subdomains: list[str] = []
    discovered_ips: list[str] = []
    overview: dict[str, Any] = {
        "total_hits": 0,
        "employees_compromised": 0,
        "users_compromised": 0,
        "third_parties_compromised": 0,
        "last_employee_compromised": None,
        "last_user_compromised": None,
        "stealer_families": {},
        "weak_user_password_pct": None,
        "employee_urls_count": 0,
        "client_urls_count": 0,
        "third_party_domains": [],
    }

    try:
        resp = await http_client.get(url, params={"domain": domain}, timeout=7.0)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text)
        if resp.status_code == 429:
            return (
                overview,
                records,
                {
                    "source_slug": "hudson_rock",
                    "source_name": "Hudson Rock Cavalier Infostealer OSINT (Domain)",
                    "status": "rate_limited",
                    "http_status": 429,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": "Hudson Rock rate limit reached",
                },
                discovered_subdomains,
                discovered_ips,
            )
        if resp.status_code != 200:
            return (
                overview,
                records,
                {
                    "source_slug": "hudson_rock",
                    "source_name": "Hudson Rock Cavalier Infostealer OSINT (Domain)",
                    "status": "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
                discovered_subdomains,
                discovered_ips,
            )

        payload = resp.json()
        if not isinstance(payload, dict):
            payload = {}

        total_hits = int(payload.get("total") or 0)
        emp_count = int(payload.get("employees") or 0)
        usr_count = int(payload.get("users") or 0)
        tp_count = int(payload.get("third_parties") or 0)
        last_emp = _parse_iso_datetime(payload.get("last_employee_compromised"))
        last_usr = _parse_iso_datetime(payload.get("last_user_compromised"))

        raw_families = payload.get("stealerFamilies")
        families: dict[str, int] = {}
        if isinstance(raw_families, dict):
            for k, v in raw_families.items():
                if k != "total" and isinstance(v, (int, float)) and int(v) > 0:
                    families[str(k)] = int(v)

        user_pass = payload.get("userPasswords")
        weak_pct: float | None = None
        if isinstance(user_pass, dict):
            weak_obj = user_pass.get("weak")
            if isinstance(weak_obj, dict) and isinstance(weak_obj.get("perc"), (int, float)):
                weak_pct = float(weak_obj["perc"])

        raw_data_section = payload.get("data")
        data_section: dict[str, Any] = (
            raw_data_section if isinstance(raw_data_section, dict) else {}
        )
        raw_emp_urls = data_section.get("employees_urls")
        emp_urls: list[Any] = raw_emp_urls if isinstance(raw_emp_urls, list) else []
        raw_cli_urls = data_section.get("clients_urls")
        cli_urls: list[Any] = raw_cli_urls if isinstance(raw_cli_urls, list) else []
        raw_tp_domains = payload.get("thirdPartyDomains")
        tp_domains_raw: list[Any] = raw_tp_domains if isinstance(raw_tp_domains, list) else []
        tp_domains: list[dict[str, Any]] = []
        for item in tp_domains_raw[:15]:
            if isinstance(item, dict) and item.get("domain"):
                dom_str = str(item["domain"]).strip()
                occ = int(item.get("occurrence") or 1)
                tp_domains.append({"domain": dom_str, "occurrence": occ})
                if _IPV4_IN_TEXT_RE.fullmatch(dom_str) and dom_str not in discovered_ips:
                    discovered_ips.append(dom_str)

        overview = {
            "total_hits": total_hits,
            "employees_compromised": emp_count,
            "users_compromised": usr_count,
            "third_parties_compromised": tp_count,
            "last_employee_compromised": last_emp.isoformat() if last_emp else None,
            "last_user_compromised": last_usr.isoformat() if last_usr else None,
            "stealer_families": families,
            "weak_user_password_pct": weak_pct,
            "employee_urls_count": len(emp_urls),
            "client_urls_count": len(cli_urls),
            "third_party_domains": tp_domains,
        }

        latest_dt = last_emp or last_usr
        families_joined = ", ".join(f"{k} ({v})" for k, v in families.items())
        families_label = families_joined or "Infostealer malware"

        if total_hits > 0 or emp_count > 0 or usr_count > 0:
            sev = "critical" if emp_count > 0 else "high"
            records.append(
                {
                    "record_id": f"hr-domain-summary-{domain}",
                    "source_slug": "hudson_rock",
                    "source_name": "Hudson Rock Cavalier OSINT",
                    "category": "infostealer_infection",
                    "severity": sev,
                    "title": (
                        f"Infostealer Compromise Detected on {domain} "
                        f"({emp_count} employee, {usr_count} user, {tp_count} third-party hits)"
                    ),
                    "target": domain,
                    "summary": (
                        f"Hudson Rock recorded {total_hits} infostealer compromises "
                        f"linked to {domain} across stealer families: {families_label}."
                        + (
                            f" Weak user password ratio: {weak_pct:.1f}%."
                            if weak_pct is not None
                            else ""
                        )
                    ),
                    "occurred_at": latest_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Force immediate password reset and active session/token revocation "
                        f"for compromised @{domain} employee and user accounts; enforce "
                        "phishing-resistant FIDO2/WebAuthn MFA and audit login logs."
                    ),
                    "metadata": {
                        "domain": domain,
                        "employees_compromised": emp_count,
                        "users_compromised": usr_count,
                        "third_parties_compromised": tp_count,
                        "stealer_families": families,
                        "weak_user_password_pct": weak_pct,
                        "last_employee_compromised": overview["last_employee_compromised"],
                        "last_user_compromised": overview["last_user_compromised"],
                    },
                }
            )

        for idx, entry in enumerate(emp_urls[:15]):
            if not isinstance(entry, dict):
                continue
            comp_url = str(entry.get("url") or "").strip()
            if not comp_url or "•" in comp_url:
                continue
            occ = int(entry.get("occurrence") or 1)
            host = _extract_hostname_from_input(comp_url)
            is_sub = _DOMAIN_RE.fullmatch(host) and host.endswith(domain)
            if is_sub and host not in discovered_subdomains:
                discovered_subdomains.append(host)
            records.append(
                {
                    "record_id": f"hr-emp-url-{domain}-{idx}",
                    "source_slug": "hudson_rock",
                    "source_name": "Hudson Rock Cavalier OSINT",
                    "category": "compromised_endpoint",
                    "severity": "critical",
                    "title": f"Compromised Employee Login Endpoint: {comp_url}",
                    "target": comp_url,
                    "summary": (
                        f"Employee credentials for {comp_url} were exfiltrated by infostealer "
                        f"malware ({occ} recorded credential occurrence"
                        f"{'s' if occ != 1 else ''})."
                    ),
                    "occurred_at": last_emp or latest_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        f"Rotate all employee credentials and API keys accessing {comp_url}, "
                        "restrict administrative port/endpoint exposure behind VPN or "
                        "Zero-Trust access, and audit recent authentication logs."
                    ),
                    "metadata": {
                        "url": comp_url,
                        "exposure_type": "Employee",
                        "occurrences": occ,
                        "stealer_families": families,
                    },
                }
            )

        for idx, entry in enumerate(cli_urls[:20]):
            if not isinstance(entry, dict):
                continue
            comp_url = str(entry.get("url") or "").strip()
            if not comp_url or "•" in comp_url:
                continue
            occ = int(entry.get("occurrence") or 1)
            host = _extract_hostname_from_input(comp_url)
            is_sub = _DOMAIN_RE.fullmatch(host) and host.endswith(domain)
            if is_sub and host not in discovered_subdomains:
                discovered_subdomains.append(host)
            records.append(
                {
                    "record_id": f"hr-user-url-{domain}-{idx}",
                    "source_slug": "hudson_rock",
                    "source_name": "Hudson Rock Cavalier OSINT",
                    "category": "compromised_endpoint",
                    "severity": "high" if occ >= 3 else "medium",
                    "title": f"Compromised User/Client Application URL: {comp_url}",
                    "target": comp_url,
                    "summary": (
                        f"Captured in {occ} infostealer credential log"
                        f"{'s' if occ != 1 else ''} targeting {host or domain}."
                    ),
                    "occurred_at": last_usr or latest_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        f"Reset affected user credentials on {comp_url}, invalidate active "
                        "session cookies, and enable credential-stuffing rate limits and MFA."
                    ),
                    "metadata": {
                        "url": comp_url,
                        "exposure_type": str(entry.get("type") or "User"),
                        "occurrences": occ,
                    },
                }
            )

        if tp_domains:
            tp_preview = ", ".join(
                f"{item['domain']} ({item['occurrence']})" for item in tp_domains[:8]
            )
            records.append(
                {
                    "record_id": f"hr-thirdparty-{domain}",
                    "source_slug": "hudson_rock",
                    "source_name": "Hudson Rock Cavalier OSINT",
                    "category": "infostealer_infection",
                    "severity": "medium",
                    "title": f"Co-Compromised Third-Party & Infrastructure Domains for {domain}",
                    "target": domain,
                    "summary": (
                        f"Infected endpoints associated with {domain} also leaked credentials "
                        f"for adjacent domains/IPs: {tp_preview}."
                    ),
                    "occurred_at": latest_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Audit SSO/OAuth integrations, shared developer environments, and "
                        "direct-IP hosts referenced in co-compromised stealer logs."
                    ),
                    "metadata": {"third_party_domains": tp_domains},
                }
            )

        return (
            overview,
            records,
            {
                "source_slug": "hudson_rock",
                "source_name": "Hudson Rock Cavalier Infostealer OSINT (Domain)",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
            discovered_subdomains,
            discovered_ips,
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            overview,
            records,
            {
                "source_slug": "hudson_rock",
                "source_name": "Hudson Rock Cavalier Infostealer OSINT (Domain)",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
            discovered_subdomains,
            discovered_ips,
        )


async def _query_hudson_rock_stealers_endpoint(
    *,
    endpoint_suffix: str,
    param_name: str,
    param_value: str,
    label: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query Hudson Rock OSINT v2 search-by-email, search-by-ip, or search-by-username."""
    t0 = time.perf_counter()
    url = f"https://cavalier.hudsonrock.com/api/json/v2/osint-tools/{endpoint_suffix}"
    records: list[dict[str, Any]] = []
    slug = f"hudson_rock_{param_name}"
    try:
        resp = await http_client.get(url, params={param_name: param_value}, timeout=7.0)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text)
        if resp.status_code != 200:
            return (
                records,
                {
                    "source_slug": slug,
                    "source_name": f"Hudson Rock Cavalier OSINT ({label})",
                    "status": "rate_limited" if resp.status_code == 429 else "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        payload = resp.json()
        stealers = payload.get("stealers") if isinstance(payload, dict) else []
        if not isinstance(stealers, list):
            stealers = []

        for idx, st in enumerate(stealers[:20]):
            if not isinstance(st, dict):
                continue
            comp_dt = _parse_iso_datetime(st.get("date_compromised"))
            family = str(
                st.get("stealer_family") or st.get("malware_path") or "Infostealer Malware"
            ).strip()
            comp_name = str(st.get("computer_name") or "Redacted Host").strip()
            os_name = str(st.get("operating_system") or "Unknown OS").strip()
            ip_val = str(st.get("ip") or "Masked").strip()
            corp_svcs = int(st.get("total_corporate_services") or 0)
            user_svcs = int(st.get("total_user_services") or 0)
            top_logins = [str(x) for x in (st.get("top_logins") or []) if isinstance(x, str) and x][
                :5
            ]

            records.append(
                {
                    "record_id": f"hr-{param_name}-{param_value}-{idx}",
                    "source_slug": "hudson_rock",
                    "source_name": f"Hudson Rock Cavalier OSINT ({label})",
                    "category": "infostealer_infection",
                    "severity": "critical" if corp_svcs > 0 or param_name == "email" else "high",
                    "title": f"Infostealer Infection on {param_value} ({family} · {os_name})",
                    "target": param_value,
                    "summary": (
                        f"Host '{comp_name}' ({os_name}, IP {ip_val}) compromised by {family}; "
                        f"exfiltrated {corp_svcs} corporate services and {user_svcs} user services."
                    ),
                    "occurred_at": comp_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        f"Isolate and re-image infected host '{comp_name}', rotate all "
                        f"credentials and session tokens associated with {param_value}, "
                        "and revoke active OAuth grants."
                    ),
                    "metadata": {
                        "query_target": param_value,
                        "stealer_family": family,
                        "computer_name": comp_name,
                        "operating_system": os_name,
                        "ip": ip_val,
                        "total_corporate_services": corp_svcs,
                        "total_user_services": user_svcs,
                        "top_logins_redacted": top_logins,
                        "password_values_redacted": True,
                    },
                }
            )

        return (
            records,
            {
                "source_slug": slug,
                "source_name": f"Hudson Rock Cavalier OSINT ({label})",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            {
                "source_slug": slug,
                "source_name": f"Hudson Rock Cavalier OSINT ({label})",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


def _parse_breach_date(b_date_raw: str) -> datetime | None:
    if re.fullmatch(r"\d{4}-\d{2}", b_date_raw):
        return _parse_iso_datetime(f"{b_date_raw}-01T00:00:00Z")
    if re.fullmatch(r"\d{4}", b_date_raw):
        return _parse_iso_datetime(f"{b_date_raw}-01-01T00:00:00Z")
    return _parse_iso_datetime(b_date_raw)


async def _query_xposed_or_not(
    email: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query XposedOrNot free breach intelligence API for an email address."""
    t0 = time.perf_counter()
    url = f"https://api.xposedornot.com/v1/breach-analytics?email={quote(email)}"
    records: list[dict[str, Any]] = []
    try:
        resp = await http_client.get(url, timeout=6.5)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text)
        if resp.status_code == 404:
            return (
                records,
                {
                    "source_slug": "xposed_or_not",
                    "source_name": "XposedOrNot Open Breach Intelligence",
                    "status": "no_records",
                    "http_status": 404,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": None,
                },
            )
        if resp.status_code != 200:
            return (
                records,
                {
                    "source_slug": "xposed_or_not",
                    "source_name": "XposedOrNot Open Breach Intelligence",
                    "status": "rate_limited" if resp.status_code == 429 else "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        payload = resp.json()
        raw_exposed = payload.get("ExposedBreaches") if isinstance(payload, dict) else None
        exposed: dict[str, Any] = raw_exposed if isinstance(raw_exposed, dict) else {}
        raw_details = exposed.get("breaches_details")
        details: list[Any] = raw_details if isinstance(raw_details, list) else []
        for idx, b in enumerate(details[:20]):
            if not isinstance(b, dict):
                continue
            b_name = str(b.get("breach") or f"Breach-{idx}").strip()
            b_domain = str(b.get("domain") or "").strip()
            b_date_raw = str(b.get("xposed_date") or "").strip()
            b_dt = _parse_breach_date(b_date_raw)
            xposed_data = str(b.get("xposed_data") or "Credentials").strip()
            pw_risk = str(b.get("password_risk") or "unknown").strip()
            pw_lower = pw_risk.lower()
            is_crit_pw = "plaintext" in pw_lower or "easytocrack" in pw_lower
            sev = "critical" if is_crit_pw else "high"
            date_label = b_date_raw or "Recorded"
            records.append(
                {
                    "record_id": f"xon-{email}-{b_name}",
                    "source_slug": "xposed_or_not",
                    "source_name": "XposedOrNot Open Breach Intelligence",
                    "category": "credential_breach",
                    "severity": sev,
                    "title": f"Data Breach Exposure: {email} in '{b_name}' ({date_label})",
                    "target": email,
                    "summary": (
                        f"Account {email} exposed in {b_name}"
                        + (f" ({b_domain})" if b_domain else "")
                        + f". Exposed data classes: {xposed_data} (Password risk: {pw_risk})."
                    ),
                    "occurred_at": b_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        f"Rotate the password for {email}, check for credential reuse across "
                        "corporate SSO/VPN systems, and enforce multi-factor authentication."
                    ),
                    "metadata": {
                        "email": email,
                        "breach": b_name,
                        "breach_domain": b_domain,
                        "xposed_date": b_date_raw,
                        "xposed_data": xposed_data,
                        "password_risk": pw_risk,
                    },
                }
            )

        return (
            records,
            {
                "source_slug": "xposed_or_not",
                "source_name": "XposedOrNot Open Breach Intelligence",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            {
                "source_slug": "xposed_or_not",
                "source_name": "XposedOrNot Open Breach Intelligence",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def _query_proxynova_comb(
    query_target: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Query ProxyNova COMB breach directory and strictly redact any password strings."""
    t0 = time.perf_counter()
    url = "https://api.proxynova.com/comb"
    records: list[dict[str, Any]] = []
    discovered_emails: list[str] = []
    try:
        resp = await http_client.get(
            url,
            params={"query": query_target, "start": 0, "limit": 25},
            timeout=6.5,
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)
        if resp.status_code != 200:
            return (
                records,
                discovered_emails,
                {
                    "source_slug": "proxynova_comb",
                    "source_name": "ProxyNova COMB Breach Directory (Redacted)",
                    "status": "rate_limited" if resp.status_code == 429 else "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": _sha256_text(""),
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        payload = resp.json()
        total_count = int(payload.get("count") or 0) if isinstance(payload, dict) else 0
        raw_lines = payload.get("lines") if isinstance(payload, dict) else []
        if not isinstance(raw_lines, list):
            raw_lines = []

        redacted_entries: list[str] = []
        for line in raw_lines[:25]:
            if not isinstance(line, str) or not line.strip():
                continue
            identity_part = line.split(":", 1)[0].split(";", 1)[0].strip().lower()
            if not identity_part:
                continue
            redacted_entries.append(f"{identity_part}:********")
            if _EMAIL_RE.fullmatch(identity_part) and identity_part not in discovered_emails:
                discovered_emails.append(identity_part)

        raw_sha = _sha256_text(json.dumps({"count": total_count, "identities": redacted_entries}))
        if total_count > 0 or discovered_emails:
            preview = ", ".join(discovered_emails[:8]) or query_target
            plural = "s" if total_count != 1 else ""
            records.append(
                {
                    "record_id": f"comb-{query_target}",
                    "source_slug": "proxynova_comb",
                    "source_name": "ProxyNova COMB Breach Directory (Redacted)",
                    "category": "credential_breach",
                    "severity": "high",
                    "title": (
                        f"COMB Credential Dump Match for {query_target} "
                        f"({total_count} record{plural}, passwords redacted)"
                    ),
                    "target": query_target,
                    "summary": (
                        f"Found {total_count} credential dump entries matching '{query_target}'. "
                        f"Identities observed: {preview}. Plaintext secrets were automatically "
                        "redacted on ingestion."
                    ),
                    "occurred_at": None,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Force password rotation for all matched email accounts and audit "
                        "authentication logs for credential-stuffing attempts."
                    ),
                    "metadata": {
                        "total_matches": total_count,
                        "discovered_emails": discovered_emails[:15],
                        "secret_redacted": True,
                    },
                }
            )

        return (
            records,
            discovered_emails,
            {
                "source_slug": "proxynova_comb",
                "source_name": "ProxyNova COMB Breach Directory (Redacted)",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            discovered_emails,
            {
                "source_slug": "proxynova_comb",
                "source_name": "ProxyNova COMB Breach Directory (Redacted)",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def _query_hackertarget_hosts(
    domain: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], list[str], list[str], dict[str, Any]]:
    """Query HackerTarget Free Passive Host/DNS Search (`api.hackertarget.com/hostsearch/`)."""
    t0 = time.perf_counter()
    url = "https://api.hackertarget.com/hostsearch/"
    records: list[dict[str, Any]] = []
    subdomains: list[str] = []
    ips: list[str] = []
    try:
        resp = await http_client.get(url, params={"q": domain}, timeout=6.0)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text.strip()
        raw_sha = _sha256_text(raw_text)
        has_err = (
            resp.status_code != 200
            or "error" in raw_text.lower()
            or "API count exceeded" in raw_text
        )
        if has_err:
            err_msg = None if resp.status_code == 200 else f"HTTP {resp.status_code}"
            return (
                records,
                subdomains,
                ips,
                {
                    "source_slug": "hackertarget_dns",
                    "source_name": "HackerTarget Passive DNS & Origin Host Discovery",
                    "status": "rate_limited" if "exceeded" in raw_text else "no_records",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": err_msg,
                },
            )

        mappings: list[dict[str, str]] = []
        for line in raw_text.splitlines()[:30]:
            parts = [p.strip() for p in line.split(",")]
            if len(parts) == 2 and _DOMAIN_RE.fullmatch(parts[0].lower()):
                host_val, ip_val = parts[0].lower(), parts[1]
                mappings.append({"hostname": host_val, "ip": ip_val})
                if host_val not in subdomains:
                    subdomains.append(host_val)
                if _IPV4_IN_TEXT_RE.fullmatch(ip_val) and ip_val not in ips:
                    ips.append(ip_val)

        if mappings:
            summary_pairs = ", ".join(f"{m['hostname']} -> {m['ip']}" for m in mappings[:6])
            has_origin = any("vps." in m["hostname"] or "dev." in m["hostname"] for m in mappings)
            sev = "medium" if has_origin else "info"
            records.append(
                {
                    "record_id": f"ht-dns-{domain}",
                    "source_slug": "hackertarget_dns",
                    "source_name": "HackerTarget Passive DNS & Origin Host Discovery",
                    "category": "network_exposure",
                    "severity": sev,
                    "title": (
                        f"Passive DNS Host & Origin IP Mapping for {domain} ({len(mappings)} hosts)"
                    ),
                    "target": domain,
                    "summary": (
                        f"Passive DNS resolved {len(mappings)} host mappings: {summary_pairs}."
                    ),
                    "occurred_at": None,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Verify direct origin server IPs (e.g., vps/dev subdomains) restrict "
                        "inbound traffic strictly to CDN/WAF reverse-proxy IP ranges."
                    ),
                    "metadata": {"host_mappings": mappings},
                }
            )

        return (
            records,
            subdomains,
            ips,
            {
                "source_slug": "hackertarget_dns",
                "source_name": "HackerTarget Passive DNS & Origin Host Discovery",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            subdomains,
            ips,
            {
                "source_slug": "hackertarget_dns",
                "source_name": "HackerTarget Passive DNS & Origin Host Discovery",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def _query_crt_sh(
    domain: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], list[str], dict[str, Any]]:
    """Query crt.sh Certificate Transparency JSON API."""
    t0 = time.perf_counter()
    url = "https://crt.sh/"
    records: list[dict[str, Any]] = []
    subdomains: list[str] = []
    try:
        resp = await http_client.get(
            url,
            params={"q": f"%.{domain}", "output": "json"},
            timeout=6.0,
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text[:20000])
        if resp.status_code != 200:
            return (
                records,
                subdomains,
                {
                    "source_slug": "crt_sh",
                    "source_name": "crt.sh Certificate Transparency Logs",
                    "status": "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        payload = resp.json()
        if not isinstance(payload, list):
            payload = []

        latest_cert_dt: datetime | None = None
        for entry in payload[:150]:
            if not isinstance(entry, dict):
                continue
            nb = _parse_iso_datetime(str(entry.get("not_before") or ""))
            if nb and (latest_cert_dt is None or nb > latest_cert_dt):
                latest_cert_dt = nb
            raw_names = str(entry.get("name_value") or "")
            for candidate in raw_names.splitlines():
                clean_sub = candidate.strip().lower().lstrip("*.")
                if (
                    _DOMAIN_RE.fullmatch(clean_sub)
                    and (clean_sub == domain or clean_sub.endswith(f".{domain}"))
                    and clean_sub not in subdomains
                ):
                    subdomains.append(clean_sub)

        if subdomains:
            preview = ", ".join(subdomains[:10])
            records.append(
                {
                    "record_id": f"crtsh-{domain}",
                    "source_slug": "crt_sh",
                    "source_name": "crt.sh Certificate Transparency Logs",
                    "category": "attack_surface_url",
                    "severity": "info",
                    "title": (
                        f"Certificate Transparency Subdomain Footprint "
                        f"({len(subdomains)} subdomains)"
                    ),
                    "target": domain,
                    "summary": (
                        f"Discovered {len(subdomains)} unique subdomains in CT logs: {preview}."
                    ),
                    "occurred_at": latest_cert_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Decommission dangling DNS records to prevent subdomain takeover "
                        "and ensure non-production subdomains require authentication."
                    ),
                    "metadata": {"subdomains": subdomains[:30]},
                }
            )

        return (
            records,
            subdomains[:30],
            {
                "source_slug": "crt_sh",
                "source_name": "crt.sh Certificate Transparency Logs",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            subdomains,
            {
                "source_slug": "crt_sh",
                "source_name": "crt.sh Certificate Transparency Logs",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def _query_shodan_internetdb(
    db: AsyncSession,
    *,
    ips: list[str],
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query Shodan InternetDB (`internetdb.shodan.io/{ip}`) and enrich CVEs with KEV/EPSS."""
    t0 = time.perf_counter()
    records: list[dict[str, Any]] = []
    if not ips:
        return (
            records,
            {
                "source_slug": "shodan_internetdb",
                "source_name": "Shodan InternetDB (Open Ports, CPEs & CVEs)",
                "status": "skipped",
                "http_status": None,
                "records_found": 0,
                "latency_ms": 0,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )

    raw_blobs: list[str] = []
    last_http_status: int | None = None
    had_error: str | None = None

    for ip in ips[:4]:
        try:
            resp = await http_client.get(f"https://internetdb.shodan.io/{ip}", timeout=6.0)
            last_http_status = resp.status_code
            raw_blobs.append(resp.text)
            if resp.status_code != 200:
                continue
            payload = resp.json()
            if not isinstance(payload, dict):
                continue

            ports = [int(p) for p in (payload.get("ports") or []) if isinstance(p, int)]
            cpes = [str(c) for c in (payload.get("cpes") or []) if isinstance(c, str)]
            hostnames = [str(h) for h in (payload.get("hostnames") or []) if isinstance(h, str)]
            tags = [str(t) for t in (payload.get("tags") or []) if isinstance(t, str)]
            vulns = [str(v).upper() for v in (payload.get("vulns") or []) if isinstance(v, str)]

            if ports or cpes:
                admin_ports = [p for p in ports if p in _ADMIN_PORTS]
                has_crit_port = any(p in _CRITICAL_PORTS for p in ports)
                sev = "high" if has_crit_port else ("medium" if admin_ports else "low")
                admin_label = ", ".join(str(p) for p in admin_ports) or "open ports"
                records.append(
                    {
                        "record_id": f"shodan-ports-{ip}",
                        "source_slug": "shodan_internetdb",
                        "source_name": "Shodan InternetDB",
                        "category": "network_exposure",
                        "severity": sev,
                        "title": (
                            f"Exposed Network Ports & Services on {ip} ({len(ports)} open ports)"
                        ),
                        "target": ip,
                        "summary": (
                            f"Open ports on {ip}: {', '.join(str(p) for p in ports[:15])}. "
                            + (f"CPEs: {', '.join(cpes[:6])}. " if cpes else "")
                            + (f"Hostnames: {', '.join(hostnames[:4])}." if hostnames else "")
                        ),
                        "occurred_at": datetime.now(UTC),
                        "cve_id": None,
                        "is_known_exploited": False,
                        "epss_score": None,
                        "remediation": (
                            f"Restrict management and non-essential ports on {ip} ({admin_label}) "
                            "using host firewall / security group rules."
                        ),
                        "metadata": {
                            "ip": ip,
                            "ports": ports,
                            "cpes": cpes,
                            "hostnames": hostnames,
                            "tags": tags,
                        },
                    }
                )

            for cve_id in vulns[:10]:
                intel = await get_cve_threat_intel(db, cve_id)
                is_kev = bool(intel.get("is_known_exploited", False))
                epss = intel.get("epss_score")
                cvss = intel.get("cvss_score")
                is_high_cvss = isinstance(cvss, (int, float)) and cvss >= 9.0
                sev = "critical" if is_kev or is_high_cvss else "high"
                epss_note = (
                    f" EPSS: {float(epss) * 100:.1f}%." if isinstance(epss, (int, float)) else ""
                )
                kev_note = (
                    " Confirmed in CISA Known Exploited Vulnerabilities catalog." if is_kev else ""
                )
                records.append(
                    {
                        "record_id": f"shodan-cve-{ip}-{cve_id}",
                        "source_slug": "shodan_internetdb",
                        "source_name": "Shodan InternetDB + VForge KEV/EPSS",
                        "category": "network_exposure",
                        "severity": sev,
                        "title": (
                            f"Unpatched Vulnerability {cve_id} Exposed on {ip}"
                            + (" [CISA KEV Actively Exploited]" if is_kev else "")
                        ),
                        "target": f"{ip} ({cve_id})",
                        "summary": (
                            f"Shodan InternetDB detected {cve_id} on {ip}."
                            + (f" CVSS: {cvss}." if cvss is not None else "")
                            + epss_note
                            + kev_note
                        ),
                        "occurred_at": datetime.now(UTC),
                        "cve_id": cve_id,
                        "is_known_exploited": is_kev,
                        "epss_score": float(epss) if isinstance(epss, (int, float)) else None,
                        "remediation": (
                            f"Patch or upgrade the affected service on {ip} to remediate {cve_id}."
                        ),
                        "metadata": {
                            "ip": ip,
                            "cve_id": cve_id,
                            "cvss_score": cvss,
                            "epss_score": epss,
                            "is_known_exploited": is_kev,
                            "cpes": cpes,
                        },
                    }
                )
        except httpx.HTTPError as exc:
            had_error = str(exc)[:160]

    latency_ms = int((time.perf_counter() - t0) * 1000)
    return (
        records,
        {
            "source_slug": "shodan_internetdb",
            "source_name": "Shodan InternetDB (Open Ports, CPEs & CVEs)",
            "status": (
                "succeeded"
                if records
                else ("unavailable" if had_error and not raw_blobs else "no_records")
            ),
            "http_status": last_http_status or 200,
            "records_found": len(records),
            "latency_ms": latency_ms,
            "raw_sha256": _sha256_text("\n".join(raw_blobs)),
            "retrieved_at": datetime.now(UTC),
            "error_message": had_error if not records else None,
        },
    )


async def _query_alienvault_otx(
    *,
    indicator_type: str,
    indicator_value: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query AlienVault OTX Open Threat Exchange general indicator endpoint."""
    t0 = time.perf_counter()
    otx_type = "IPv4" if indicator_type == "ip" else "domain"
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    url = f"{base_url}/{otx_type}/{quote(indicator_value)}/general"
    records: list[dict[str, Any]] = []
    try:
        resp = await http_client.get(url, timeout=6.0)
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text[:20000])
        if resp.status_code != 200:
            return (
                records,
                {
                    "source_slug": "alienvault_otx",
                    "source_name": "AlienVault OTX Open Threat Exchange",
                    "status": "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        payload = resp.json()
        raw_pulse_info = payload.get("pulse_info") if isinstance(payload, dict) else None
        pulse_info: dict[str, Any] = raw_pulse_info if isinstance(raw_pulse_info, dict) else {}
        pulse_count = int(pulse_info.get("count") or 0)
        raw_pulses = pulse_info.get("pulses")
        pulses: list[Any] = raw_pulses if isinstance(raw_pulses, list) else []

        for idx, p in enumerate(pulses[:8]):
            if not isinstance(p, dict):
                continue
            p_name = str(p.get("name") or f"Threat Pulse {idx + 1}").strip()
            p_dt = _parse_iso_datetime(p.get("modified") or p.get("created"))
            tags = [str(t) for t in (p.get("tags") or []) if isinstance(t, str)][:8]
            records.append(
                {
                    "record_id": f"otx-{indicator_value}-{idx}",
                    "source_slug": "alienvault_otx",
                    "source_name": "AlienVault OTX",
                    "category": "attack_surface_url",
                    "severity": "high" if pulse_count >= 3 else "medium",
                    "title": f"OTX Threat Intelligence Pulse: {p_name}",
                    "target": indicator_value,
                    "summary": (
                        f"Indicator {indicator_value} referenced in AlienVault OTX pulse '{p_name}'"
                        + (f" (Tags: {', '.join(tags)})." if tags else ".")
                    ),
                    "occurred_at": p_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        f"Investigate threat indicator {indicator_value} for compromise or "
                        "malicious traffic correlation."
                    ),
                    "metadata": {"pulse_count": pulse_count, "pulse_name": p_name, "tags": tags},
                }
            )

        return (
            records,
            {
                "source_slug": "alienvault_otx",
                "source_name": "AlienVault OTX Open Threat Exchange",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            {
                "source_slug": "alienvault_otx",
                "source_name": "AlienVault OTX Open Threat Exchange",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def _query_urlscan_io(
    *,
    search_field: str,
    search_value: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], list[str], list[str], dict[str, Any]]:
    """Query URLScan.io public API for recent live web scans and malicious verdicts."""
    t0 = time.perf_counter()
    url = "https://urlscan.io/api/v1/search/"
    records: list[dict[str, Any]] = []
    subdomains: list[str] = []
    ips: list[str] = []
    try:
        resp = await http_client.get(
            url,
            params={"q": f"{search_field}:{search_value}", "size": 12},
            timeout=6.0,
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text[:20000])
        if resp.status_code != 200:
            return (
                records,
                subdomains,
                ips,
                {
                    "source_slug": "urlscan_io",
                    "source_name": "URLScan.io Live Web & Phishing Intelligence",
                    "status": "rate_limited" if resp.status_code == 429 else "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        payload = resp.json()
        results = payload.get("results") if isinstance(payload, dict) else []
        if not isinstance(results, list):
            results = []

        seen_urls: set[str] = set()
        for idx, item in enumerate(results[:10]):
            if not isinstance(item, dict):
                continue
            raw_page = item.get("page")
            page: dict[str, Any] = raw_page if isinstance(raw_page, dict) else {}
            raw_task = item.get("task")
            task: dict[str, Any] = raw_task if isinstance(raw_task, dict) else {}
            raw_verdicts = item.get("verdicts")
            verdicts: dict[str, Any] = raw_verdicts if isinstance(raw_verdicts, dict) else {}
            raw_overall = verdicts.get("overall")
            overall: dict[str, Any] = raw_overall if isinstance(raw_overall, dict) else {}
            is_malicious = bool(overall.get("malicious", False))

            page_url = str(page.get("url") or task.get("url") or "").strip()
            if not page_url or page_url in seen_urls:
                continue
            seen_urls.add(page_url)

            page_domain = str(page.get("domain") or "").strip().lower()
            page_ip = str(page.get("ip") or "").strip()
            server_hdr = str(page.get("server") or "").strip()
            scan_dt = _parse_iso_datetime(task.get("time"))

            if _DOMAIN_RE.fullmatch(page_domain) and page_domain not in subdomains:
                subdomains.append(page_domain)
            if _IPV4_IN_TEXT_RE.fullmatch(page_ip) and page_ip not in ips:
                ips.append(page_ip)

            is_high_interest = bool(_HIGH_INTEREST_URL_RE.search(page_url))
            sev = "critical" if is_malicious else ("low" if is_high_interest else "info")
            mal_prefix = "Malicious " if is_malicious else ""
            records.append(
                {
                    "record_id": f"urlscan-{search_value}-{idx}",
                    "source_slug": "urlscan_io",
                    "source_name": "URLScan.io Public Intelligence",
                    "category": "attack_surface_url",
                    "severity": sev,
                    "title": f"{mal_prefix}Observed Web Endpoint: {page_url[:90]}",
                    "target": page_url,
                    "summary": (
                        f"Indexed by URLScan.io on {page_domain or search_value}"
                        + (f" (IP: {page_ip})" if page_ip else "")
                        + (f", Server: {server_hdr}" if server_hdr else "")
                        + (" — FLAGGED MALICIOUS." if is_malicious else ".")
                    ),
                    "occurred_at": scan_dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Verify exposed endpoint authentication, TLS configuration, "
                        "and security headers."
                    ),
                    "metadata": {
                        "url": page_url,
                        "domain": page_domain,
                        "ip": page_ip,
                        "server": server_hdr,
                        "malicious": is_malicious,
                    },
                }
            )

        return (
            records,
            subdomains,
            ips,
            {
                "source_slug": "urlscan_io",
                "source_name": "URLScan.io Live Web & Phishing Intelligence",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except httpx.HTTPError as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            subdomains,
            ips,
            {
                "source_slug": "urlscan_io",
                "source_name": "URLScan.io Live Web & Phishing Intelligence",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def _query_wayback_cdx(
    domain: str,
    http_client: httpx.AsyncClient,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Query Internet Archive Wayback Machine CDX API for historically exposed endpoints."""
    t0 = time.perf_counter()
    url = "https://web.archive.org/cdx/search/cdx"
    records: list[dict[str, Any]] = []
    try:
        resp = await http_client.get(
            url,
            params={
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "timestamp,original,mimetype,statuscode",
                "collapse": "urlkey",
                "limit": 45,
            },
            timeout=6.5,
        )
        latency_ms = int((time.perf_counter() - t0) * 1000)
        raw_text = resp.text
        raw_sha = _sha256_text(raw_text[:20000])
        if resp.status_code != 200:
            return (
                records,
                {
                    "source_slug": "wayback_cdx",
                    "source_name": "Wayback Machine Historical Endpoint Scanner",
                    "status": "unavailable",
                    "http_status": resp.status_code,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": f"HTTP {resp.status_code}",
                },
            )

        rows = resp.json()
        if not isinstance(rows, list) or len(rows) <= 1:
            return (
                records,
                {
                    "source_slug": "wayback_cdx",
                    "source_name": "Wayback Machine Historical Endpoint Scanner",
                    "status": "no_records",
                    "http_status": 200,
                    "records_found": 0,
                    "latency_ms": latency_ms,
                    "raw_sha256": raw_sha,
                    "retrieved_at": datetime.now(UTC),
                    "error_message": None,
                },
            )

        data_rows = [r for r in rows[1:] if isinstance(r, list) and len(r) >= 4]
        data_rows.sort(key=lambda r: str(r[0]), reverse=True)

        filtered_rows: list[list[Any]] = []
        for r in data_rows:
            orig = str(r[1])
            mime_val = str(r[2]).lower().strip()
            if _STATIC_ASSET_URL_RE.search(orig) or mime_val.startswith(_STATIC_MIME_PREFIXES):
                continue
            filtered_rows.append(r)

        selected: list[list[Any]] = []
        for r in filtered_rows:
            orig = str(r[1])
            if _HIGH_INTEREST_URL_RE.search(orig):
                selected.append(r)
            if len(selected) >= 8:
                break
        if len(selected) < 5:
            seen_sel = {str(x[1]) for x in selected}
            for r in filtered_rows:
                orig = str(r[1])
                if orig not in seen_sel:
                    selected.append(r)
                    seen_sel.add(orig)
                if len(selected) >= 5:
                    break

        for idx, r in enumerate(selected):
            ts_raw, orig_url, mime, status_code = str(r[0]), str(r[1]), str(r[2]), str(r[3])
            dt = _parse_iso_datetime(ts_raw)
            is_sensitive = bool(_HIGH_INTEREST_URL_RE.search(orig_url))
            records.append(
                {
                    "record_id": f"wayback-{domain}-{idx}",
                    "source_slug": "wayback_cdx",
                    "source_name": "Wayback Machine CDX Archive",
                    "category": "attack_surface_url",
                    "severity": "medium" if is_sensitive and status_code == "200" else "info",
                    "title": f"Archived Web Endpoint: {orig_url[:90]}",
                    "target": orig_url,
                    "summary": (
                        f"Archived snapshot captured ({mime}, HTTP {status_code}). "
                        + (
                            "Matches sensitive path/config pattern."
                            if is_sensitive
                            else "Historical attack-surface URL."
                        )
                    ),
                    "occurred_at": dt,
                    "cve_id": None,
                    "is_known_exploited": False,
                    "epss_score": None,
                    "remediation": (
                        "Confirm historical endpoints no longer expose sensitive configuration, "
                        "debug descriptors, or unauthenticated portals."
                    ),
                    "metadata": {
                        "url": orig_url,
                        "mimetype": mime,
                        "http_status": status_code,
                        "timestamp": ts_raw,
                    },
                }
            )

        return (
            records,
            {
                "source_slug": "wayback_cdx",
                "source_name": "Wayback Machine Historical Endpoint Scanner",
                "status": "succeeded" if records else "no_records",
                "http_status": 200,
                "records_found": len(records),
                "latency_ms": latency_ms,
                "raw_sha256": raw_sha,
                "retrieved_at": datetime.now(UTC),
                "error_message": None,
            },
        )
    except Exception as exc:
        latency_ms = int((time.perf_counter() - t0) * 1000)
        return (
            records,
            {
                "source_slug": "wayback_cdx",
                "source_name": "Wayback Machine Historical Endpoint Scanner",
                "status": "unavailable",
                "http_status": None,
                "records_found": 0,
                "latency_ms": latency_ms,
                "raw_sha256": _sha256_text(""),
                "retrieved_at": datetime.now(UTC),
                "error_message": str(exc)[:160],
            },
        )


async def search_multi_source_exposure(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    query: str,
    query_type: str = "auto",
    http_client: httpx.AsyncClient | None = None,
) -> dict[str, Any]:
    """Execute a correlated multi-source OSINT & infostealer compromise search."""
    detected_type, normalized_query = detect_query_type(query, query_type)

    close_client = http_client is None
    client = http_client or httpx.AsyncClient(
        timeout=8.0,
        headers={
            "User-Agent": "VForge-ThreatIntel/1.2 (+https://vforge.local)",
            "Accept": "application/json",
        },
        follow_redirects=True,
    )

    try:
        resolved_domains: list[str] = []
        resolved_ips: list[str] = []
        discovered_subdomains: list[str] = []
        discovered_emails: list[str] = []
        sources_queried: list[dict[str, Any]] = []
        all_records: list[dict[str, Any]] = []
        hr_overview: dict[str, Any] = {
            "total_hits": 0,
            "employees_compromised": 0,
            "users_compromised": 0,
            "third_parties_compromised": 0,
            "last_employee_compromised": None,
            "last_user_compromised": None,
            "stealer_families": {},
            "weak_user_password_pct": None,
            "employee_urls_count": 0,
            "client_urls_count": 0,
            "third_party_domains": [],
        }

        target_email: str | None = None
        target_username: str | None = None

        if detected_type == "company":
            comp_domains, clearbit_status = await _resolve_company_domains(
                db,
                org_id=org_id,
                company_query=normalized_query,
                http_client=client,
            )
            sources_queried.append(clearbit_status)
            resolved_domains.extend(comp_domains)
            slug_user = "".join(re.findall(r"[a-zA-Z0-9]+", normalized_query)).lower()
            if slug_user:
                target_username = slug_user
        elif detected_type == "domain":
            resolved_domains.append(normalized_query)
        elif detected_type == "email":
            target_email = normalized_query
            discovered_emails.append(normalized_query)
            email_domain = normalized_query.split("@", 1)[1].lower()
            if _DOMAIN_RE.fullmatch(email_domain):
                resolved_domains.append(email_domain)
        elif detected_type == "ip":
            resolved_ips.append(normalized_query)
        elif detected_type == "username":
            target_username = normalized_query

        primary_domain = resolved_domains[0] if resolved_domains else None

        tasks: list[Any] = []
        task_tags: list[str] = []

        if primary_domain:
            tasks.append(_query_hudson_rock_domain(primary_domain, client))
            task_tags.append("hr_domain")

            tasks.append(_query_hackertarget_hosts(primary_domain, client))
            task_tags.append("hackertarget")

            tasks.append(_query_crt_sh(primary_domain, client))
            task_tags.append("crt_sh")

            tasks.append(_query_proxynova_comb(primary_domain, client))
            task_tags.append("comb_domain")

            tasks.append(
                _query_alienvault_otx(
                    indicator_type="domain",
                    indicator_value=primary_domain,
                    http_client=client,
                )
            )
            task_tags.append("otx_domain")

            tasks.append(
                _query_urlscan_io(
                    search_field="domain",
                    search_value=primary_domain,
                    http_client=client,
                )
            )
            task_tags.append("urlscan_domain")

            tasks.append(_query_wayback_cdx(primary_domain, client))
            task_tags.append("wayback")

            tasks.append(_resolve_host_ipv4(primary_domain))
            task_tags.append("dns_primary")

        if target_email:
            tasks.append(
                _query_hudson_rock_stealers_endpoint(
                    endpoint_suffix="search-by-email",
                    param_name="email",
                    param_value=target_email,
                    label="Email",
                    http_client=client,
                )
            )
            task_tags.append("hr_email")

            tasks.append(_query_xposed_or_not(target_email, client))
            task_tags.append("xon_email")

            if not primary_domain:
                tasks.append(_query_proxynova_comb(target_email, client))
                task_tags.append("comb_email")

        if target_username:
            tasks.append(
                _query_hudson_rock_stealers_endpoint(
                    endpoint_suffix="search-by-username",
                    param_name="username",
                    param_value=target_username,
                    label="Username",
                    http_client=client,
                )
            )
            task_tags.append("hr_username")

        if detected_type == "ip" and resolved_ips:
            ip0 = resolved_ips[0]
            tasks.append(
                _query_hudson_rock_stealers_endpoint(
                    endpoint_suffix="search-by-ip",
                    param_name="ip",
                    param_value=ip0,
                    label="IP",
                    http_client=client,
                )
            )
            task_tags.append("hr_ip")

            tasks.append(
                _query_alienvault_otx(
                    indicator_type="ip",
                    indicator_value=ip0,
                    http_client=client,
                )
            )
            task_tags.append("otx_ip")

            tasks.append(
                _query_urlscan_io(
                    search_field="ip",
                    search_value=ip0,
                    http_client=client,
                )
            )
            task_tags.append("urlscan_ip")

        results = await asyncio.gather(*tasks, return_exceptions=True)
        simple_tags = {
            "hr_email",
            "xon_email",
            "hr_username",
            "hr_ip",
            "otx_domain",
            "otx_ip",
            "wayback",
        }

        for tag, res in zip(task_tags, results, strict=False):
            if isinstance(res, BaseException):
                continue
            if tag == "hr_domain":
                ov, recs, st, subs, ips = res
                hr_overview = ov
                all_records.extend(recs)
                sources_queried.append(st)
                for s in subs:
                    if s not in discovered_subdomains:
                        discovered_subdomains.append(s)
                for ip_item in ips:
                    if ip_item not in resolved_ips:
                        resolved_ips.append(ip_item)
            elif tag == "hackertarget":
                recs, subs, ips, st = res
                all_records.extend(recs)
                sources_queried.append(st)
                for s in subs:
                    if s not in discovered_subdomains:
                        discovered_subdomains.append(s)
                for ip_item in ips:
                    if ip_item not in resolved_ips:
                        resolved_ips.append(ip_item)
            elif tag == "crt_sh":
                recs, subs, st = res
                all_records.extend(recs)
                sources_queried.append(st)
                for s in subs:
                    if s not in discovered_subdomains:
                        discovered_subdomains.append(s)
            elif tag in {"comb_domain", "comb_email"}:
                recs, emails, st = res
                all_records.extend(recs)
                sources_queried.append(st)
                for em in emails:
                    if em not in discovered_emails:
                        discovered_emails.append(em)
            elif tag in {"urlscan_domain", "urlscan_ip"}:
                recs, subs, ips, st = res
                all_records.extend(recs)
                sources_queried.append(st)
                for s in subs:
                    if s not in discovered_subdomains:
                        discovered_subdomains.append(s)
                for ip_item in ips:
                    if ip_item not in resolved_ips:
                        resolved_ips.append(ip_item)
            elif tag == "dns_primary":
                for ip_item in res:
                    if ip_item not in resolved_ips:
                        resolved_ips.append(ip_item)
            elif tag in simple_tags:
                recs, st = res
                all_records.extend(recs)
                sources_queried.append(st)

        if not target_email and discovered_emails:
            top_email = discovered_emails[0]
            sub_results: list[Any] = list(
                await asyncio.gather(
                    _query_hudson_rock_stealers_endpoint(
                        endpoint_suffix="search-by-email",
                        param_name="email",
                        param_value=top_email,
                        label=f"Discovered Email {top_email}",
                        http_client=client,
                    ),
                    _query_xposed_or_not(top_email, client),
                    return_exceptions=True,
                )
            )
            for sub_res in sub_results:
                if not isinstance(sub_res, BaseException):
                    recs, st = sub_res
                    all_records.extend(recs)
                    sources_queried.append(st)

        shodan_recs, shodan_status = await _query_shodan_internetdb(
            db,
            ips=resolved_ips,
            http_client=client,
        )
        all_records.extend(shodan_recs)
        sources_queried.append(shodan_status)

        epoch_min = datetime(1970, 1, 1, tzinfo=UTC)
        compromise_cats = {"infostealer_infection", "credential_breach", "compromised_endpoint"}
        all_records.sort(
            key=lambda r: (
                _SEVERITY_RANK.get(str(r.get("severity") or "info"), 1),
                1 if r.get("category") in compromise_cats else 0,
                r.get("occurred_at") is not None,
                r.get("occurred_at") or epoch_min,
            ),
            reverse=True,
        )

        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        latest_compromise: datetime | None = None
        for r in all_records:
            sev_key = str(r.get("severity") or "info").lower()
            if sev_key in sev_counts:
                sev_counts[sev_key] += 1
            occ_dt = r.get("occurred_at")
            if isinstance(occ_dt, datetime) and r.get("category") in {
                "infostealer_infection",
                "compromised_endpoint",
                "credential_breach",
            }:
                if latest_compromise is None or occ_dt > latest_compromise:
                    latest_compromise = occ_dt

        return {
            "query": query.strip(),
            "normalized_query": normalized_query,
            "detected_type": detected_type,
            "resolved_domains": resolved_domains,
            "resolved_ips": resolved_ips,
            "discovered_subdomains": discovered_subdomains[:35],
            "discovered_emails": discovered_emails[:25],
            "total_records": len(all_records),
            "critical_count": sev_counts["critical"],
            "high_count": sev_counts["high"],
            "medium_count": sev_counts["medium"],
            "low_count": sev_counts["low"],
            "info_count": sev_counts["info"],
            "latest_compromise_at": latest_compromise,
            "hudson_rock_overview": hr_overview,
            "sources_queried": sources_queried,
            "records": all_records,
            "searched_at": datetime.now(UTC),
        }
    finally:
        if close_client:
            await client.aclose()


async def import_exposure_as_finding(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    source_slug: str,
    category: str,
    severity: str,
    title: str,
    target: str,
    summary: str,
    remediation: str | None = None,
    cve_id: str | None = None,
) -> tuple[Finding, bool]:
    """Promote an OSINT / Hudson Rock compromise record into a tracked project Finding."""
    project = (
        await db.execute(
            select(Project).where(
                Project.organization_id == org_id,
                Project.id == project_id,
            )
        )
    ).scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project not found in organization")

    # Map exposure category to Finding category ('sast','secret','sca','iac','dast','network')
    cat_map = {
        "infostealer_infection": "secret",
        "credential_breach": "secret",
        "compromised_endpoint": "dast",
        "network_exposure": "network",
        "attack_surface_url": "dast",
    }
    finding_category = cat_map.get(category, "secret")
    sev_clean = severity.lower() if severity.lower() in DEFAULT_SLA_DAYS else "high"
    valid_priorities = {"critical", "high", "medium", "low", "info"}
    priority_clean = sev_clean if sev_clean in valid_priorities else "medium"

    target_norm = target.strip().lower()
    title_norm = title.strip().lower()
    fp_material = (
        f"osint_exposure|{org_id}|{project_id}|{source_slug}|{category}|{target_norm}|{title_norm}"
    )
    fingerprint = hashlib.sha256(fp_material.encode("utf-8")).hexdigest()[:64]

    existing = (
        await db.execute(
            select(Finding).where(
                Finding.organization_id == org_id,
                Finding.project_id == project_id,
                Finding.fingerprint == fingerprint,
            )
        )
    ).scalar_one_or_none()

    now = datetime.now(UTC)
    if existing is not None:
        existing.last_seen_at = now
        existing.updated_at = now
        await db.flush()
        return existing, False

    clean_cve = cve_id.strip().upper() if cve_id and cve_id.strip() else None
    is_kev = False
    epss_val: float | None = None
    cvss_val: float | None = None
    cvss_vec: str | None = None
    cwe_list: list[str] = ["CWE-522"] if finding_category == "secret" else ["CWE-200"]

    if clean_cve:
        intel = await get_cve_threat_intel(db, clean_cve)
        is_kev = bool(intel.get("is_known_exploited", False))
        if isinstance(intel.get("epss_score"), (int, float)):
            epss_val = float(intel["epss_score"])
        if isinstance(intel.get("cvss_score"), (int, float)):
            cvss_val = float(intel["cvss_score"])
        if isinstance(intel.get("cvss_vector"), str):
            cvss_vec = intel["cvss_vector"]
        if isinstance(intel.get("cwes"), list) and intel["cwes"]:
            cwe_list = [str(x) for x in intel["cwes"][:5]]

    sla_days = DEFAULT_SLA_DAYS.get(sev_clean, 14)
    default_remediation = (
        "Rotate compromised credentials, revoke active sessions, and restrict external exposure."
    )
    finding = Finding(
        organization_id=org_id,
        project_id=project_id,
        fingerprint=fingerprint,
        category=finding_category,
        scanner_tool_id=f"osint_{source_slug[:60]}",
        scanner_version="2026.11-osint",
        rule_id=f"osint.{source_slug}.{category}",
        title=title.strip()[:500],
        description=f"{summary.strip()}\n\nTarget / Indicator: {target.strip()}",
        severity=sev_clean,
        confidence="high",
        validation_status="unverified",
        status="open",
        cwe_ids=cwe_list,
        file_path=target.strip()[:500],
        secret_redacted=True,
        remediation=(
            remediation.strip() if remediation and remediation.strip() else default_remediation
        ),
        cve_id=clean_cve,
        sla_due_at=now + timedelta(days=sla_days),
        sla_breached=False,
        business_priority=priority_clean,
        cvss_score=cvss_val,
        cvss_vector=cvss_vec,
        is_known_exploited=is_kev,
        epss_score=epss_val,
        occurrence_count=1,
        first_seen_at=now,
        last_seen_at=now,
    )
    db.add(finding)
    await db.flush()

    event = FindingEvent(
        organization_id=org_id,
        finding_id=finding.id,
        actor_id=actor_id,
        event_type=FindingEventType.COMMENT_ADDED.value,
        previous_status=None,
        new_status="open",
        comment=f"Imported from Threat Intelligence OSINT source '{source_slug}' ({target})",
        metadata_payload={
            "project_id": str(project_id),
            "source_slug": source_slug,
            "category": category,
            "target": target,
        },
    )
    db.add(event)
    await db.flush()
    return finding, True
