"""Safety boundary verification and OPA gating for Phase 13 Isolated Learning Lab."""

from __future__ import annotations

import ipaddress
import re
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse

import httpx
import yaml

from vforge.config import Settings
from vforge.errors import ForbiddenError, ValidationError
from vforge.models.enums import LabValidationAction

ALLOWED_SAFE_VALIDATION_ACTIONS: frozenset[str] = frozenset(m.value for m in LabValidationAction)

FORBIDDEN_EXPLOITATION_MODES: frozenset[str] = frozenset(
    {
        "persistence",
        "stealth",
        "credential_theft",
        "malware",
        "destructive_action",
        "lateral_movement",
        "exfiltration",
        "arbitrary_internet_exploit",
        "dos_flood",
    }
)

_ALLOWED_LAB_LOCAL_PORTS: frozenset[int] = frozenset({3100, 3101, 3102, 8090})
_ALLOWED_INTERNAL_LAB_HOSTS: frozenset[str] = frozenset(
    {
        "juice-shop",
        "webgoat",
        "crapi-web",
        "crapi-identity",
        "vforge-sample",
    }
)
_BLOCKED_CONTROL_HOSTS: frozenset[str] = frozenset(
    {
        "postgres",
        "rabbitmq",
        "valkey",
        "opa",
        "api",
        "orchestrator",
        "update-controller",
        "frontend",
        "keycloak",
        "metadata.google.internal",
        "metadata.azure.internal",
    }
)
_DIGEST_SUFFIX_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_LAB_ENV_DEFAULT_PATHS = (
    Path("/opt/infrastructure/lab/compose.lab.yaml"),
    Path("/app/infrastructure/lab/compose.lab.yaml"),
)


def resolve_lab_compose_path() -> Path | None:
    """Locate infrastructure/lab/compose.lab.yaml if available inside container or repo."""
    for candidate in _LAB_ENV_DEFAULT_PATHS:
        if candidate.is_file():
            return candidate
    for parent in Path(__file__).resolve().parents:
        repo_candidate = parent / "infrastructure" / "lab" / "compose.lab.yaml"
        if repo_candidate.is_file():
            return repo_candidate
    return None


def validate_lab_target_url(target_url: str, *, permitted_target: str | None = None) -> str:
    """Restrict lab target URLs strictly to isolated loopback or lab.vforge.local targets."""
    cleaned = target_url.strip()
    if "\\" in cleaned or any(ord(ch) < 32 for ch in cleaned):
        raise ValidationError("Lab target_url must not contain backslashes or control characters")
    parsed = urlparse(cleaned)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValidationError("Lab target_url must be a valid HTTP/HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValidationError("Lab target_url must not contain credentials or URL fragments")
    sensitive_qs_keys = {
        "token",
        "api_key",
        "apikey",
        "secret",
        "password",
        "passwd",
        "auth",
        "key",
        "access_token",
    }
    for param_k, _ in parse_qsl(parsed.query, keep_blank_values=True):
        if param_k.strip().lower() in sensitive_qs_keys:
            raise ValidationError(
                "Lab target_url query string must not carry credential or token parameters"
            )

    host = parsed.hostname.rstrip(".").lower()
    if host in _BLOCKED_CONTROL_HOSTS or host in {"169.254.169.254", "169.254.170.2"}:
        raise ForbiddenError("Control-plane and cloud metadata hosts are strictly forbidden")

    # Reject raw private/external IPs other than isolated loopback lab ports
    try:
        ip_obj = ipaddress.ip_address(host)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        if ip_obj.is_loopback:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if port not in _ALLOWED_LAB_LOCAL_PORTS:
                raise ForbiddenError(
                    f"Loopback port {port} is outside isolated lab ports "
                    f"{sorted(_ALLOWED_LAB_LOCAL_PORTS)}"
                )
        else:
            raise ForbiddenError(
                "Direct public or non-loopback IP targets are forbidden in the learning lab"
            )
    except ValueError:
        if host != "localhost":
            is_lab_fqdn = (
                host.endswith(".lab.vforge.local")
                and host.removesuffix(".lab.vforge.local") in _ALLOWED_INTERNAL_LAB_HOSTS
            )
            if host not in _ALLOWED_INTERNAL_LAB_HOSTS and not is_lab_fqdn:
                raise ForbiddenError(
                    "External internet targets are strictly forbidden; "
                    "only isolated lab hosts are permitted"
                ) from None
        else:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            if port not in _ALLOWED_LAB_LOCAL_PORTS:
                raise ForbiddenError(
                    f"Localhost port {port} is outside isolated lab ports "
                    f"{sorted(_ALLOWED_LAB_LOCAL_PORTS)}"
                ) from None

    if permitted_target:
        perm_parsed = urlparse(permitted_target.strip())
        perm_host = (perm_parsed.hostname or "").rstrip(".").lower()
        perm_port = perm_parsed.port or (443 if perm_parsed.scheme == "https" else 80)
        req_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme != perm_parsed.scheme or host != perm_host or req_port != perm_port:
            raise ForbiddenError(
                f"Target URL ({parsed.scheme}://{host}:{req_port}) does not match permitted "
                f"target ({perm_parsed.scheme}://{perm_host}:{perm_port})"
            )

    return cleaned


def validate_safe_action_and_tool(
    *,
    action_type: str,
    tool_slug: str,
    permitted_tools: list[str],
) -> tuple[str, str]:
    """Ensure lab validation action is bounded, non-destructive, and tool-allowlisted."""
    normalized_action = action_type.strip().lower()
    if normalized_action in FORBIDDEN_EXPLOITATION_MODES:
        raise ForbiddenError(
            f"Exploitation boundary forbids '{normalized_action}' in VForge Learning Lab"
        )
    if normalized_action not in ALLOWED_SAFE_VALIDATION_ACTIONS:
        raise ValidationError(
            f"Unsupported lab action '{action_type}'. Allowed safe actions: "
            f"{sorted(ALLOWED_SAFE_VALIDATION_ACTIONS)}"
        )

    normalized_tool = tool_slug.strip().lower()
    allowed_set = {t.strip().lower() for t in permitted_tools if t.strip()}
    if normalized_tool not in allowed_set:
        raise ForbiddenError(
            f"Tool '{tool_slug}' is not allowed for challenge (allowed: {sorted(allowed_set)})"
        )
    return normalized_action, normalized_tool


def verify_lab_compose_isolation(compose_path: Path | None = None) -> dict[str, Any]:
    """Verify isolated lab Compose invariants: egress denied, pinned, non-public."""
    target_path = compose_path or resolve_lab_compose_path()
    if target_path is None or not target_path.is_file():
        return {
            "verified": False,
            "path": None,
            "violations": ["infrastructure/lab/compose.lab.yaml not found"],
            "services_checked": 0,
        }

    raw_text = target_path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw_text) or {}
    violations: list[str] = []

    if "/var/run/docker.sock" in raw_text:
        violations.append("Forbidden /var/run/docker.sock reference detected")

    networks = data.get("networks") or {}
    lab_net = networks.get("lab_internal")
    if not isinstance(lab_net, dict) or lab_net.get("internal") is not True:
        violations.append("Network 'lab_internal' must declare internal: true to deny egress")

    for forbidden_net in ("control", "edge", "default"):
        if forbidden_net in networks:
            violations.append(f"Lab must not declare control-plane network '{forbidden_net}'")

    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        violations.append("Lab compose defines zero services")
    else:
        for svc_name, svc_cfg in services.items():
            if not isinstance(svc_cfg, dict):
                violations.append(f"Invalid service configuration for '{svc_name}'")
                continue
            if svc_cfg.get("privileged") is True:
                violations.append(f"Service '{svc_name}' must not run privileged")
            image_ref = str(svc_cfg.get("image", "")).strip()
            has_digest = bool(_DIGEST_SUFFIX_RE.search(image_ref))
            if not image_ref or ":latest" in image_ref.lower() or not has_digest:
                violations.append(
                    f"Service '{svc_name}' image must pin @sha256 digest and forbid :latest"
                )
            svc_nets = svc_cfg.get("networks") or []
            if svc_nets != ["lab_internal"]:
                violations.append(f"Service '{svc_name}' must attach strictly to ['lab_internal']")
            for port_mapping in svc_cfg.get("ports") or []:
                port_str = str(port_mapping).strip()
                if not port_str.startswith("127.0.0.1:"):
                    violations.append(
                        f"Service '{svc_name}' port '{port_str}' must bind strictly to 127.0.0.1"
                    )
            caps_drop = [str(c).upper() for c in (svc_cfg.get("cap_drop") or [])]
            if "ALL" not in caps_drop:
                violations.append(f"Service '{svc_name}' must set cap_drop: [ALL]")
            sec_opt = [str(o).lower() for o in (svc_cfg.get("security_opt") or [])]
            if "no-new-privileges:true" not in sec_opt:
                violations.append(
                    f"Service '{svc_name}' must set security_opt: [no-new-privileges:true]"
                )
            caps_add = {str(c).upper() for c in (svc_cfg.get("cap_add") or [])}
            dangerous_caps = caps_add & {
                "ALL",
                "SYS_ADMIN",
                "NET_ADMIN",
                "SYS_PTRACE",
                "NET_RAW",
                "SYS_MODULE",
            }
            if dangerous_caps:
                violations.append(
                    f"Service '{svc_name}' must not grant dangerous capabilities: "
                    f"{sorted(dangerous_caps)}"
                )
            for ns_key in ("network_mode", "pid", "ipc"):
                if str(svc_cfg.get(ns_key, "")).strip().lower() == "host":
                    violations.append(f"Service '{svc_name}' must not share host {ns_key}")
            for vol_entry in svc_cfg.get("volumes") or []:
                vol_str = str(vol_entry).strip()
                src_part = vol_str.split(":", 1)[0] if ":" in vol_str else ""
                if "/var/run/docker.sock" in vol_str or src_part.startswith(("/", ".")):
                    violations.append(
                        f"Service '{svc_name}' volume '{vol_str}' must not bind host paths"
                    )

    return {
        "verified": len(violations) == 0,
        "path": str(target_path),
        "violations": violations,
        "services_checked": len(services) if isinstance(services, dict) else 0,
    }


async def evaluate_lab_action_with_opa(
    *,
    settings: Settings,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str,
    action: str,
    lab_action_type: str,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool, str]:
    """Fail-closed OPA check for Phase 13 lab practice and management boundary enforcement."""
    opa_url = (settings.opa_url or "").strip().rstrip("/")
    if not opa_url:
        return False, "OPA_URL not configured — failing closed"

    payload = {
        "input": {
            "action": action,
            "subject": {
                "id": str(user_id),
                "role": role,
                "organization_id": str(organization_id),
                "authenticated": True,
            },
            "resource": {
                "organization_id": str(organization_id),
                "lab_action_type": lab_action_type.strip().lower(),
            },
        }
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(3.0), transport=opa_transport) as client:
            resp = await client.post(f"{opa_url}/v1/data/vforge/authz/allow", json=payload)
            if resp.status_code != 200:
                return False, f"OPA HTTP {resp.status_code} — failing closed"
            data = resp.json()
            if isinstance(data, dict) and data.get("result") is True:
                return True, "OPA permitted bounded lab action"
            return False, "OPA denied lab action or exploitation boundary"
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        return False, f"OPA unavailable ({exc.__class__.__name__}) — failing closed"
