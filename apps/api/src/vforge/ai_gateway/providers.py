"""Provider-agnostic runtime AI adapters with SSRF, DNS, and secret-namespace enforcement."""

from __future__ import annotations

import ipaddress
import re
import socket
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

from vforge.config import get_settings
from vforge.errors import ForbiddenError, ValidationError
from vforge.models.enums import AiProviderClass
from vforge.secrets.provider import SecretProvider, SecretResolutionError

_ALLOWED_SECRET_REF_RE = re.compile(r"^[A-Z0-9_]{2,120}$|^[a-z0-9_./:-]{3,160}$")
_RAW_KEY_PREFIXES = (
    "sk-",
    "aiza",
    "ghp_",
    "gho_",
    "github_pat_",
    "glpat-",
    "xox",
    "akia",
    "hf_",
    "npm_",
    "whsec_",
    "eyj",
)
_HOSTED_VENDOR_HOSTS: dict[str, frozenset[str]] = {
    AiProviderClass.MANAGED_ZDR.value: frozenset({"api.managed-zdr.example.com"}),
    AiProviderClass.MANAGED_RETAINED.value: frozenset({"api.managed-retained.example.com"}),
    AiProviderClass.OPENAI.value: frozenset({"api.openai.com"}),
}
_BLOCKED_CONTROL_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata.azure.internal",
        "postgres",
        "rabbitmq",
        "valkey",
        "redis",
        "opa",
        "api",
        "orchestrator",
        "frontend",
        "migrator",
        "update-controller",
        "openbao",
    }
)
_BLOCKED_CIDRS = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fd00:ec2::/32"),
)


class ProviderInvocationError(RuntimeError):
    """Raised when a configured provider fails, times out, or returns invalid output."""


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    provider_class: str
    model_slug: str
    is_local: bool
    supports_structured_json: bool = True


@dataclass(frozen=True, slots=True)
class ProviderHealth:
    healthy: bool
    detail: str


@dataclass(frozen=True, slots=True)
class TokenEstimate:
    input_tokens: int
    output_tokens: int


@dataclass(frozen=True, slots=True)
class ModelRequest:
    task_type: str
    role_name: str
    prompt_template_version: str
    system_directive: str
    wrapped_user_prompt: str
    rag_context: list[str]
    model_slug: str
    max_tokens: int
    correlation_id: str | None = None
    proposed_tools: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ModelResponse:
    structured_output: dict[str, Any]
    rationale_summary: str
    uncertainty_notes: str
    token_input_count: int
    token_output_count: int
    latency_ms: int
    proposed_tools: list[dict[str, Any]] = field(default_factory=list)


class ModelProvider(Protocol):
    """Constrained contract implemented by all Phase 12 runtime model adapters (Arch §25.2)."""

    def metadata(self) -> ProviderMetadata: ...

    async def health_check(self) -> ProviderHealth: ...

    async def generate_structured(self, request: ModelRequest) -> ModelResponse: ...

    def count_tokens(self, request: ModelRequest) -> TokenEstimate | None: ...


def validate_secret_reference(
    secret_ref: str | None,
    *,
    provider_class: str,
    organization_id: uuid.UUID,
) -> None:
    """Enforce strictly tenant-namespaced secret references and reject raw keys/platform refs."""
    if not secret_ref:
        if provider_class == AiProviderClass.LOCAL_INFERENCE.value:
            return
        raise ValidationError("Hosted AI providers require a SecretProvider reference name")
    stripped = secret_ref.strip()
    if stripped.lower().startswith(_RAW_KEY_PREFIXES):
        raise ValidationError("Raw API keys are forbidden; store a SecretProvider reference name")
    if not _ALLOWED_SECRET_REF_RE.match(stripped):
        raise ValidationError("Invalid SecretProvider reference format")

    env_prefix = f"VF_AI_{organization_id.hex.upper()}_"
    path_prefix = f"ai/orgs/{organization_id}/"
    if not (stripped.startswith(env_prefix) or stripped.startswith(path_prefix)):
        raise ForbiddenError(
            "secret_ref must use tenant-scoped namespace prefix "
            f"'{env_prefix}*' or '{path_prefix}*'"
        )


def _unwrap_ip(
    ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        return ip_obj.ipv4_mapped
    return ip_obj


def _validate_resolved_ip(
    raw_ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    provider_class: str,
) -> None:
    ip_obj = _unwrap_ip(raw_ip)
    if ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified or ip_obj.is_reserved:
        raise ForbiddenError("Link-local, multicast, unspecified, and reserved IPs are forbidden")
    if any(ip_obj in net for net in _BLOCKED_CIDRS) or str(ip_obj) == "100.100.100.200":
        raise ForbiddenError("Cloud metadata or CGNAT IP ranges are forbidden for AI endpoints")
    if provider_class != AiProviderClass.LOCAL_INFERENCE.value and (
        ip_obj.is_private or ip_obj.is_loopback or not ip_obj.is_global
    ):
        raise ForbiddenError(
            "Private, loopback, or non-global IPs are only allowed for local_inference providers"
        )


def validate_provider_endpoint_url(
    endpoint_url: str | None,
    *,
    provider_class: str,
    resolve_dns: bool = False,
) -> None:
    """Validate AI provider endpoint URL against SSRF, vendor-host pinning, and metadata leaks."""
    if not endpoint_url:
        return
    parsed = urlparse(endpoint_url.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname:
        raise ValidationError("Provider endpoint_url must be a valid HTTP/HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValidationError("Provider endpoint_url must not contain credentials or URL fragments")

    host = parsed.hostname.rstrip(".").lower()
    if host in _BLOCKED_CONTROL_HOSTS or host == "169.254.169.254" or host == "169.254.170.2":
        raise ForbiddenError("Cloud metadata or internal control-plane hosts are forbidden")

    pinned_hosts = _HOSTED_VENDOR_HOSTS.get(provider_class)
    if pinned_hosts is not None:
        if parsed.scheme != "https" or host not in pinned_hosts:
            raise ForbiddenError(
                f"Provider '{provider_class}' endpoints must use HTTPS on pinned host: "
                f"{sorted(pinned_hosts)}"
            )
    elif provider_class != AiProviderClass.LOCAL_INFERENCE.value and parsed.scheme != "https":
        raise ValidationError("External AI provider endpoints must use HTTPS")

    try:
        ip_literal = ipaddress.ip_address(host)
    except ValueError:
        ip_literal = None

    if ip_literal is not None:
        _validate_resolved_ip(ip_literal, provider_class=provider_class)
        return

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addrinfos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        if resolve_dns:
            raise ProviderInvocationError(
                f"DNS resolution failed for provider host: {type(exc).__name__}"
            ) from exc
        return

    for _family, _socktype, _proto, _canonname, sockaddr in addrinfos:
        resolved_str = str(sockaddr[0]).split("%", 1)[0]
        try:
            resolved_ip = ipaddress.ip_address(resolved_str)
        except ValueError:
            continue
        _validate_resolved_ip(resolved_ip, provider_class=provider_class)


class _BaseHttpAdapter:
    """Shared token estimation, secret lookup, and transport execution."""

    def __init__(
        self,
        *,
        provider_class: str,
        model_slug: str,
        endpoint_url: str | None,
        secret_ref: str | None,
        is_local: bool,
        secret_provider: SecretProvider | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        simulate_offline: bool = True,
    ) -> None:
        self._provider_class = provider_class
        self._model_slug = model_slug
        self._endpoint_url = endpoint_url
        self._secret_ref = secret_ref
        self._is_local = is_local
        self._secret_provider = secret_provider or get_settings().get_secret_provider()
        self._transport = transport
        self._simulate_offline = simulate_offline

    def metadata(self) -> ProviderMetadata:
        return ProviderMetadata(
            provider_class=self._provider_class,
            model_slug=self._model_slug,
            is_local=self._is_local,
        )

    def _resolve_api_key(self) -> str | None:
        if not self._secret_ref:
            return None
        try:
            return self._secret_provider.get_secret(self._secret_ref, required=False)
        except SecretResolutionError as exc:
            raise ProviderInvocationError(
                "Configured AI provider secret reference could not be resolved"
            ) from exc

    def count_tokens(self, request: ModelRequest) -> TokenEstimate | None:
        chars = len(request.wrapped_user_prompt) + sum(len(c) for c in request.rag_context)
        in_tok = max(32, chars // 4)
        out_tok = min(request.max_tokens, max(64, in_tok // 2))
        return TokenEstimate(input_tokens=in_tok, output_tokens=out_tok)

    async def health_check(self) -> ProviderHealth:
        if self._transport is None and (self._simulate_offline or not self._endpoint_url):
            return ProviderHealth(healthy=True, detail=f"{self._provider_class}:ready")
        url = self._endpoint_url or ""
        validate_provider_endpoint_url(
            url,
            provider_class=self._provider_class,
            resolve_dns=self._transport is None,
        )
        try:
            async with httpx.AsyncClient(
                timeout=5.0,
                transport=self._transport,
                follow_redirects=False,
            ) as client:
                resp = await client.get(url)
            return ProviderHealth(
                healthy=resp.status_code < 500,
                detail=f"http_{resp.status_code}",
            )
        except (httpx.HTTPError, ProviderInvocationError, ForbiddenError, ValidationError) as exc:
            return ProviderHealth(healthy=False, detail=f"unreachable:{type(exc).__name__}")

    async def generate_structured(self, request: ModelRequest) -> ModelResponse:
        est = self.count_tokens(request) or TokenEstimate(input_tokens=64, output_tokens=64)
        if self._endpoint_url and (self._transport is not None or not self._simulate_offline):
            validate_provider_endpoint_url(
                self._endpoint_url,
                provider_class=self._provider_class,
                resolve_dns=self._transport is None,
            )
            headers: dict[str, str] = {"X-VForge-Correlation-Id": request.correlation_id or ""}
            api_key = self._resolve_api_key()
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
            try:
                async with httpx.AsyncClient(
                    timeout=15.0,
                    transport=self._transport,
                    follow_redirects=False,
                ) as client:
                    resp = await client.post(
                        self._endpoint_url,
                        headers=headers,
                        json={
                            "model": request.model_slug,
                            "task_type": request.task_type,
                            "role": request.role_name,
                            "prompt_version": request.prompt_template_version,
                            "system": request.system_directive,
                            "rag_context": request.rag_context,
                            "input": request.wrapped_user_prompt,
                            "max_tokens": request.max_tokens,
                        },
                    )
            except httpx.HTTPError as exc:
                raise ProviderInvocationError(
                    f"Provider {self._provider_class} transport error: {type(exc).__name__}"
                ) from exc
            if resp.status_code >= 400:
                raise ProviderInvocationError(
                    f"Provider {self._provider_class} returned HTTP {resp.status_code}"
                )
            try:
                data = resp.json()
            except ValueError as exc:
                raise ProviderInvocationError(
                    f"Provider {self._provider_class} returned non-JSON payload"
                ) from exc
            if not isinstance(data, dict):
                raise ProviderInvocationError(
                    f"Provider {self._provider_class} returned non-object JSON payload"
                )

            raw_struct = data.get("structured_output")
            structured = dict(raw_struct) if isinstance(raw_struct, dict) else {}
            raw_in = data.get("token_input_count", est.input_tokens)
            raw_out = data.get("token_output_count", est.output_tokens)
            raw_lat = data.get("latency_ms", 42)
            try:
                in_tokens = max(0, int(raw_in))
                out_tokens = min(request.max_tokens, max(0, int(raw_out)))
                latency_ms = max(0, int(raw_lat))
            except (TypeError, ValueError) as exc:
                raise ProviderInvocationError("Provider returned invalid token metrics") from exc

            raw_tools = data.get("proposed_tools")
            if raw_tools is None:
                tools = list(request.proposed_tools)
            elif isinstance(raw_tools, list) and all(isinstance(t, dict) for t in raw_tools):
                tools = list(raw_tools)[:10]
            else:
                raise ProviderInvocationError("Provider returned invalid proposed_tools list")

            return ModelResponse(
                structured_output=structured,
                rationale_summary=str(data.get("rationale_summary") or "Provider response OK"),
                uncertainty_notes=str(
                    data.get("uncertainty_notes") or "Requires deterministic verification."
                ),
                token_input_count=in_tokens,
                token_output_count=out_tokens,
                latency_ms=latency_ms,
                proposed_tools=tools,
            )

        # Deterministic offline adapter output when live external endpoints are not wired
        return ModelResponse(
            structured_output={
                "provider_class": self._provider_class,
                "model_slug": request.model_slug,
                "role": request.role_name,
                "task_type": request.task_type,
                "rag_chunks_used": len(request.rag_context),
                "hypothesis_only": True,
                "recommendation": (
                    f"[{request.role_name}] Structured defensive analysis completed under "
                    f"tenant policy controls using {request.model_slug}."
                ),
            },
            rationale_summary=(
                f"Evaluated sanitized input ({len(request.wrapped_user_prompt)} chars) "
                f"with {len(request.rag_context)} approved RAG citations."
            ),
            uncertainty_notes=(
                "AI output is advisory only; deterministic fixture tests or human review required."
            ),
            token_input_count=est.input_tokens,
            token_output_count=est.output_tokens,
            latency_ms=15,
            proposed_tools=list(request.proposed_tools),
        )


def build_provider_adapter(
    *,
    provider_class: str,
    model_slug: str,
    endpoint_url: str | None = None,
    secret_ref: str | None = None,
    is_local: bool = False,
    secret_provider: SecretProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> ModelProvider:
    """Instantiate a provider-agnostic ModelProvider implementation."""
    return _BaseHttpAdapter(
        provider_class=provider_class,
        model_slug=model_slug,
        endpoint_url=endpoint_url,
        secret_ref=secret_ref,
        is_local=is_local or provider_class == AiProviderClass.LOCAL_INFERENCE.value,
        secret_provider=secret_provider,
        transport=transport,
    )
