"""Phase 15 AI red-team policy: tool/target/budget allowlists, sandbox compose verification.

All checks here are pure and fail closed. The agent can never widen its own tools, targets or
budgets: those are frozen at request time, approved by a different human, and enforced again on
every tool call by the control plane (and independently by OPA).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

from vforge.errors import ForbiddenError, ValidationError
from vforge.lab.safety import validate_lab_target_url

ALLOWED_TOOL_CATALOG: Mapping[str, str] = {
    "http_probe": "Bounded GET/HEAD/OPTIONS requests to approved lab targets",
    "browser_navigate": "Headless navigation to approved lab targets (no file/download access)",
    "dom_inspect": "Read-only DOM/response inspection of an already fetched lab page",
    "template_lookup": "Read-only lookup of approved rule/template metadata",
    "note_hypothesis": "Record an unverified hypothesis (never a confirmed finding)",
}

# Tools that require a network target and are therefore checked against the session target list.
TARGETED_TOOLS: frozenset[str] = frozenset({"http_probe", "browser_navigate", "dom_inspect"})

FORBIDDEN_TOOLS: frozenset[str] = frozenset(
    {
        "shell_exec",
        "shell:exec",
        "file_write",
        "file_read_host",
        "docker",
        "raw_docker_socket",
        "scope_modify",
        "scope:modify",
        "opa_modify",
        "opa:modify",
        "rule_sign",
        "rule:sign",
        "rule_promote",
        "rule:promote",
        "finding_auto_confirm",
        "finding:auto_confirm",
        "network_scan_unrestricted",
        "network:expand_scope",
        "credential_exfiltrate",
        "package_install",
        "git_push",
        "exploit_payload_external",
    }
)

MAX_TARGETS = 5
_DIGEST_SUFFIX_RE = re.compile(r"@sha256:[0-9a-f]{64}$")
_REQUIRED_IMAGE_VAR_RE = re.compile(r"^\$\{[A-Z][A-Z0-9_]*:\?[^}]+\}$")
_SECRET_ENV_KEY_RE = re.compile(r"(PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)", re.I)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,79}$")
_REDTEAM_PATHS = (
    Path("/opt/infrastructure/redteam/compose.redteam.yaml"),
    Path("/app/infrastructure/redteam/compose.redteam.yaml"),
)


def validate_tool_allowlist(tools: Iterable[str]) -> list[str]:
    """Normalize and validate a requested tool allowlist against the fixed safe catalog."""
    cleaned: list[str] = []
    for raw in tools:
        name = str(raw).strip().lower()
        if not name:
            continue
        if name in FORBIDDEN_TOOLS:
            raise ForbiddenError(f"Tool '{name}' is permanently forbidden for AI red-team agents")
        if name not in ALLOWED_TOOL_CATALOG:
            raise ValidationError(
                f"Unknown tool '{name}'. Allowed tools: {sorted(ALLOWED_TOOL_CATALOG)}"
            )
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        raise ValidationError("At least one allowed tool is required")
    return sorted(cleaned)


def validate_session_targets(urls: Iterable[str]) -> list[str]:
    """Validate that every session target is an isolated learning-lab URL (Phase 13 rules)."""
    cleaned: list[str] = []
    for raw in urls:
        normalized = validate_lab_target_url(str(raw))
        if normalized not in cleaned:
            cleaned.append(normalized)
    if not cleaned:
        raise ValidationError("At least one lab target URL is required")
    if len(cleaned) > MAX_TARGETS:
        raise ValidationError(f"At most {MAX_TARGETS} lab targets are allowed per session")
    return cleaned


def target_host_label(url: str) -> str:
    parsed = urlparse(url)
    host = (parsed.hostname or "").rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
        host = str(ip)
    except ValueError:
        pass
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    return f"{host}:{port}"


def assert_url_within_session_targets(url: str, permitted_targets: Iterable[str]) -> str:
    """Return the validated URL if it matches an approved target host:port, else raise."""
    last_error: Exception | None = None
    for permitted in permitted_targets:
        try:
            return validate_lab_target_url(url, permitted_target=permitted)
        except (ForbiddenError, ValidationError) as exc:
            last_error = exc
    raise ForbiddenError(
        "Target is outside the approved session target list"
        + (f" ({last_error.message})" if isinstance(last_error, ForbiddenError) else "")
    )


def normalize_slug_list(values: Iterable[str], *, label: str) -> list[str]:
    out: list[str] = []
    for raw in values:
        slug = str(raw).strip().lower()
        if not _SLUG_RE.match(slug):
            raise ValidationError(f"{label} contains an invalid challenge slug")
        if slug not in out:
            out.append(slug)
    if len(out) > 200:
        raise ValidationError(f"{label} exceeds 200 entries")
    return sorted(out)


def compute_benchmark_metrics(
    *,
    ground_truth: list[str],
    ai_detected: list[str],
    zap_detected: list[str],
    nuclei_detected: list[str],
) -> dict[str, Any]:
    """Compare engines against known lab challenges. Claims outside ground truth never count."""
    truth = set(ground_truth)
    if not truth:
        raise ValidationError("ground_truth_slugs must not be empty")

    def _cov(detected: list[str]) -> tuple[set[str], int]:
        det = set(detected)
        return det & truth, len(det - truth)

    ai_hit, ai_unknown = _cov(ai_detected)
    zap_hit, zap_unknown = _cov(zap_detected)
    nuc_hit, nuc_unknown = _cov(nuclei_detected)
    scanners_union = zap_hit | nuc_hit

    def _recall(hit: set[str]) -> float:
        return round(len(hit) / len(truth), 4)

    return {
        "ground_truth_count": len(truth),
        "recall": {
            "ai_redteam": _recall(ai_hit),
            "zap": _recall(zap_hit),
            "nuclei": _recall(nuc_hit),
            "zap_plus_nuclei": _recall(scanners_union),
            "all_engines": _recall(ai_hit | scanners_union),
        },
        "ai_unique_true_positives": sorted(ai_hit - scanners_union),
        "scanner_unique_true_positives": sorted(scanners_union - ai_hit),
        "missed_by_all": sorted(truth - (ai_hit | scanners_union)),
        "claims_outside_ground_truth": {
            "ai_redteam": ai_unknown,
            "zap": zap_unknown,
            "nuclei": nuc_unknown,
        },
        "notes": (
            "Slug lists are operator-supplied and not auto-verified; AI detections count only "
            "after human confirmation in the observation review workflow."
        ),
    }


def resolve_redteam_compose_path() -> Path | None:
    for candidate in _REDTEAM_PATHS:
        if candidate.is_file():
            return candidate
    for parent in Path(__file__).resolve().parents:
        repo_candidate = parent / "infrastructure" / "redteam" / "compose.redteam.yaml"
        if repo_candidate.is_file():
            return repo_candidate
    return None


def verify_redteam_compose_isolation(compose_path: Path | None = None) -> dict[str, Any]:
    """Verify the opt-in sandbox definition cannot reach the control plane or the internet."""
    target = compose_path or resolve_redteam_compose_path()
    if target is None or not target.is_file():
        return {
            "verified": False,
            "path": None,
            "violations": ["infrastructure/redteam/compose.redteam.yaml not found"],
            "services_checked": 0,
        }
    raw_text = target.read_text(encoding="utf-8")
    try:
        loaded = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        return {
            "verified": False,
            "path": str(target),
            "violations": [f"Malformed sandbox compose YAML: {type(exc).__name__}"],
            "services_checked": 0,
        }
    if not isinstance(loaded, dict):
        return {
            "verified": False,
            "path": str(target),
            "violations": ["Sandbox compose YAML root must be a mapping"],
            "services_checked": 0,
        }
    data = loaded
    violations: list[str] = []

    if "docker.sock" in raw_text:
        violations.append("Forbidden docker.sock reference detected")

    networks = data.get("networks") or {}
    if set(networks) != {"lab_internal"}:
        violations.append("Sandbox must declare only the 'lab_internal' network")
    lab_net = networks.get("lab_internal")
    if not isinstance(lab_net, dict) or lab_net.get("external") is not True:
        violations.append("'lab_internal' must be the external isolated lab network")
    elif lab_net.get("name") != "vforge-lab_lab_internal":
        violations.append("'lab_internal' must reference vforge-lab_lab_internal")

    services = data.get("services") or {}
    if not isinstance(services, dict) or not services:
        violations.append("Sandbox compose defines zero services")
        services = {}
    for name, cfg in services.items():
        if not isinstance(cfg, dict):
            violations.append(f"Invalid service configuration for '{name}'")
            continue
        image = str(cfg.get("image", "")).strip()
        if not image or ":latest" in image.lower():
            violations.append(f"Service '{name}' must not use :latest or an empty image")
        elif not (_DIGEST_SUFFIX_RE.search(image) or _REQUIRED_IMAGE_VAR_RE.match(image)):
            violations.append(
                f"Service '{name}' image must be an @sha256 digest "
                "or a required ${VAR:?} reference"
            )
        if cfg.get("privileged") is True:
            violations.append(f"Service '{name}' must not be privileged")
        if cfg.get("profiles") != ["redteam"]:
            violations.append(f"Service '{name}' must set profiles: ['redteam'] (opt-in only)")
        if cfg.get("networks") != ["lab_internal"]:
            violations.append(f"Service '{name}' must attach strictly to ['lab_internal']")
        if cfg.get("ports"):
            violations.append(f"Service '{name}' must not publish any ports")
        if cfg.get("devices"):
            violations.append(f"Service '{name}' must not mount host devices")
        if cfg.get("extra_hosts"):
            violations.append(f"Service '{name}' must not define extra_hosts")
        if cfg.get("env_file"):
            violations.append(f"Service '{name}' must not load env_file")
        if cfg.get("read_only") is not True:
            violations.append(f"Service '{name}' must set read_only: true")
        if str(cfg.get("restart", "")).strip().lower() not in {"no", "false", ""}:
            violations.append(f"Service '{name}' must not auto-restart (restart: \"no\")")
        user = str(cfg.get("user", "")).strip()
        if not user or user.split(":", 1)[0] in {"0", "root"}:
            violations.append(f"Service '{name}' must run as a non-root user")
        if "ALL" not in [str(c).upper() for c in (cfg.get("cap_drop") or [])]:
            violations.append(f"Service '{name}' must set cap_drop: [ALL]")
        if cfg.get("cap_add"):
            violations.append(f"Service '{name}' must not add capabilities")
        sec_opts = [str(o).lower() for o in (cfg.get("security_opt") or [])]
        if "no-new-privileges:true" not in sec_opts:
            violations.append(f"Service '{name}' must set no-new-privileges:true")
        for ns_key in ("network_mode", "pid", "ipc"):
            if str(cfg.get(ns_key, "")).strip().lower() == "host":
                violations.append(f"Service '{name}' must not share host {ns_key}")
        if cfg.get("volumes"):
            violations.append(f"Service '{name}' must not mount volumes (tmpfs only)")
        limits = ((cfg.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        if not limits.get("memory") or not limits.get("pids"):
            violations.append(f"Service '{name}' must set memory and pids limits")
        env = cfg.get("environment") or {}
        env_items = env.items() if isinstance(env, dict) else [e.split("=", 1) for e in env]
        for item in env_items:
            key = str(item[0])
            if _SECRET_ENV_KEY_RE.search(key):
                violations.append(f"Service '{name}' must not receive secret-like env '{key}'")

    return {
        "verified": not violations,
        "path": str(target),
        "violations": violations,
        "services_checked": len(services),
    }
