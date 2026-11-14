"""Host/container scoped HTTP + CONNECT egress gateway with DNS pinning and SSRF blocking."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from vforge_scope import (
    CanonicalTarget,
    DnsResolver,
    ScopeDefinition,
    ScopeReason,
    ScopeValidationError,
    SystemDnsResolver,
    TargetType,
    canonicalize_cidr,
    canonicalize_domain,
    canonicalize_ip,
    canonicalize_url,
    evaluate_redirect_destination,
    resolve_and_validate_host,
    target_matches_scope,
    validate_ip_safety_and_scope,
)

from vforge_runner.manifest import VerifiedJobManifest

EgressEventCallback = Callable[[str, str, dict[str, Any]], Awaitable[None] | None]

_MAX_HEADER_BYTES = 65536
_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


class EgressBlockedError(PermissionError):
    """Raised when an outbound connection or HTTP request violates scope or SSRF policy."""

    def __init__(
        self, code: str, message: str, *, reasons: list[ScopeReason] | None = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.reasons = reasons or [ScopeReason(code=code, message=message, field="egress")]


@dataclass(frozen=True, slots=True)
class ValidatedDestination:
    """Validated destination host, port, and pinned IPv4/IPv6 addresses."""

    host: str
    port: int
    pinned_ip: str
    scheme: str
    url: str


def build_scope_definition_from_manifest(manifest: VerifiedJobManifest) -> ScopeDefinition:
    """Construct a strict `ScopeDefinition` from a signed `VerifiedJobManifest`."""
    exact_domains: list[str] = []
    exact_urls: list[str] = []
    url_path_prefixes: list[str] = []
    allowed_ips: list[str] = []
    allowed_cidrs: list[str] = []
    pinned_dns: dict[str, list[str]] = {}

    raw_targets: list[str] = list(manifest.allowed_targets)
    if manifest.probe_url and manifest.probe_url not in raw_targets:
        raw_targets.append(manifest.probe_url)

    for raw in raw_targets:
        candidate = raw.strip()
        if not candidate:
            continue
        if "://" in candidate:
            try:
                url_target = canonicalize_url(candidate, target_type=TargetType.URL_PATH_PREFIX)
                url_path_prefixes.append(url_target.normalized)
                if (
                    url_target.is_domain
                    and url_target.host
                    and url_target.host not in exact_domains
                ):
                    exact_domains.append(url_target.host)
                elif (
                    url_target.is_ip
                    and url_target.ip_address
                    and url_target.ip_address not in allowed_ips
                ):
                    allowed_ips.append(url_target.ip_address)
                continue
            except ScopeValidationError:
                pass
        if "/" in candidate:
            try:
                cidr = canonicalize_cidr(candidate)
                allowed_cidrs.append(cidr.compressed)
                continue
            except ScopeValidationError:
                pass
        try:
            ip_obj = canonicalize_ip(candidate)
            if ip_obj.compressed not in allowed_ips:
                allowed_ips.append(ip_obj.compressed)
            continue
        except ScopeValidationError:
            pass
        try:
            domain = canonicalize_domain(candidate, allow_wildcard=False)
            if domain not in exact_domains:
                exact_domains.append(domain)
        except ScopeValidationError:
            continue

    manifest_pins = [str(ip).strip() for ip in manifest.pinned_ips if str(ip).strip()]
    if manifest_pins:
        for domain in exact_domains:
            pinned_dns[domain] = list(manifest_pins)
        if manifest.allow_private_networks:
            for raw_pin in manifest_pins:
                try:
                    pin_ip = canonicalize_ip(raw_pin)
                except ScopeValidationError:
                    continue
                if (
                    pin_ip.is_private
                    and not pin_ip.is_loopback
                    and not pin_ip.is_link_local
                    and pin_ip.compressed not in allowed_ips
                ):
                    allowed_ips.append(pin_ip.compressed)

    return ScopeDefinition(
        exact_domains=exact_domains,
        exact_urls=exact_urls,
        url_path_prefixes=url_path_prefixes,
        allowed_ips=allowed_ips,
        allowed_cidrs=allowed_cidrs,
        allowed_ports=list(manifest.allowed_ports),
        allow_private_networks=manifest.allow_private_networks,
        allow_loopback=False,
        pinned_dns_resolution=pinned_dns,
    )


def _open_pinned_tcp_socket(pinned_ip: str, port: int, timeout: float = 10.0) -> socket.socket:
    """Create a connected non-blocking-ready TCP socket directly to `pinned_ip` without DNS."""
    ip_obj = ipaddress.ip_address(pinned_ip)
    family = socket.AF_INET6 if ip_obj.version == 6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((ip_obj.compressed, port))
        sock.setblocking(False)
    except OSError:
        sock.close()
        raise
    return sock


class ScopedEgressGateway:
    """Ephemeral forward HTTP/CONNECT proxy enforcing signed manifest scope and pinned sockets."""

    def __init__(
        self,
        manifest: VerifiedJobManifest,
        *,
        dns_resolver: DnsResolver | None = None,
        on_block: EgressEventCallback | None = None,
        bind_host: str = "127.0.0.1",
        bind_port: int = 0,
        max_redirects: int = 5,
    ) -> None:
        self.manifest = manifest
        self.scope = build_scope_definition_from_manifest(manifest)
        self.dns_resolver: DnsResolver = dns_resolver or SystemDnsResolver()
        self.on_block = on_block
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.max_redirects = max_redirects
        self._server: asyncio.AbstractServer | None = None
        self.listening_port: int | None = None
        self.blocked_events: list[dict[str, Any]] = []

    @property
    def proxy_url(self) -> str:
        if self.listening_port is None:
            raise RuntimeError("ScopedEgressGateway is not running")
        return f"http://{self.bind_host}:{self.listening_port}"

    async def start(self) -> int:
        if self._server is not None and self.listening_port is not None:
            return self.listening_port
        self._server = await asyncio.start_server(
            self._handle_client,
            host=self.bind_host,
            port=self.bind_port,
        )
        sock = self._server.sockets[0]
        self.listening_port = int(sock.getsockname()[1])
        return self.listening_port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self.listening_port = None

    async def __aenter__(self) -> ScopedEgressGateway:
        await self.start()
        return self

    async def __aexit__(self, *_args: object) -> None:
        await self.stop()

    async def _record_block(self, target: str, exc: EgressBlockedError) -> None:
        details: dict[str, Any] = {
            "target": target,
            "code": exc.code,
            "message": exc.message,
            "reasons": [{"code": r.code, "message": r.message} for r in exc.reasons],
        }
        self.blocked_events.append(details)
        if self.on_block is not None:
            result = self.on_block("egress_blocked", "security", details)
            if asyncio.iscoroutine(result):
                await result

    async def validate_destination(
        self,
        *,
        url: str | None = None,
        host: str | None = None,
        port: int | None = None,
        scheme: str = "https",
    ) -> ValidatedDestination:
        """Validate scope, allowed ports, SSRF IPs, DNS rebinding, and return pinned IP."""
        if url is not None:
            try:
                canonical = canonicalize_url(url, target_type=TargetType.EXACT_URL)
            except ScopeValidationError as exc:
                raise EgressBlockedError(exc.code, exc.message) from exc
            resolved_host = canonical.host or canonical.ip_address or ""
            resolved_port = canonical.port or (443 if canonical.scheme == "https" else 80)
            resolved_scheme = canonical.scheme or scheme
            normalized_url = canonical.normalized
            target_obj = canonical
        else:
            if not host:
                raise EgressBlockedError(
                    "invalid_destination", "Missing destination hostname or IP"
                )
            resolved_scheme = scheme.lower()
            resolved_port = int(port or (443 if resolved_scheme == "https" else 80))
            clean_ip: str | None = None
            clean_domain: str | None = None
            try:
                parsed_ip = canonicalize_ip(host)
                clean_ip = parsed_ip.compressed
                resolved_host = clean_ip
                target_type = TargetType.IPV6 if parsed_ip.version == 6 else TargetType.IPV4
            except ScopeValidationError:
                try:
                    clean_domain = canonicalize_domain(host, allow_wildcard=False)
                except ScopeValidationError as exc:
                    raise EgressBlockedError(exc.code, exc.message) from exc
                resolved_host = clean_domain
                target_type = TargetType.FQDN
            normalized_url = f"{resolved_scheme}://{resolved_host}:{resolved_port}/"
            target_obj = CanonicalTarget(
                target_type=target_type,
                raw=host,
                normalized=resolved_host,
                scheme=resolved_scheme,
                host=clean_domain or clean_ip,
                port=resolved_port,
                ip_address=clean_ip,
            )

        if self.scope.allowed_ports and resolved_port not in self.scope.allowed_ports:
            raise EgressBlockedError(
                "port_out_of_scope",
                f"Destination port {resolved_port} is not authorized in job manifest",
            )

        scope_reasons = target_matches_scope(target_obj, self.scope)
        if scope_reasons:
            raise EgressBlockedError(
                scope_reasons[0].code,
                scope_reasons[0].message,
                reasons=scope_reasons,
            )

        if target_obj.is_ip and target_obj.ip_address:
            ip_obj = canonicalize_ip(target_obj.ip_address)
            ip_reasons = validate_ip_safety_and_scope(
                ip_obj,
                self.scope,
                require_explicit_ip_match=True,
            )
            if ip_reasons:
                raise EgressBlockedError(
                    ip_reasons[0].code, ip_reasons[0].message, reasons=ip_reasons
                )
            pinned_ip = ip_obj.compressed
        else:
            pinned_for_host = self.scope.pinned_dns_resolution.get(
                resolved_host.lower(),
                list(self.manifest.pinned_ips),
            )
            dns_res = await asyncio.to_thread(
                resolve_and_validate_host,
                resolved_host,
                self.scope,
                self.dns_resolver,
                pinned_ips=pinned_for_host or None,
                require_explicit_ip_match=False,
            )
            if not dns_res.allowed or not dns_res.resolved_ips:
                code = dns_res.reasons[0].code if dns_res.reasons else "dns_blocked"
                msg = dns_res.reasons[0].message if dns_res.reasons else "DNS resolution blocked"
                raise EgressBlockedError(code, msg, reasons=dns_res.reasons)
            pinned_ip = dns_res.resolved_ips[0]

        return ValidatedDestination(
            host=resolved_host,
            port=resolved_port,
            pinned_ip=pinned_ip,
            scheme=resolved_scheme,
            url=normalized_url,
        )

    async def validate_redirect(
        self,
        *,
        source_url: str,
        location: str,
        hop_count: int,
    ) -> ValidatedDestination:
        """Validate a 3xx redirect destination against HTTPS downgrade, SSRF, DNS, and scope."""
        redir = await asyncio.to_thread(
            evaluate_redirect_destination,
            source_url=source_url,
            location=location,
            scope=self.scope,
            dns_resolver=self.dns_resolver,
            hop_count=hop_count,
            max_redirects=self.max_redirects,
            allow_scheme_downgrade=False,
            resolve_dns=True,
        )
        if not redir.allowed or not redir.resolved_url:
            code = redir.reasons[0].code if redir.reasons else "redirect_blocked"
            msg = redir.reasons[0].message if redir.reasons else "Redirect target denied"
            raise EgressBlockedError(code, msg, reasons=redir.reasons)
        return await self.validate_destination(url=redir.resolved_url)

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw_head = await asyncio.wait_for(
                client_reader.readuntil(b"\r\n\r\n"),
                timeout=10.0,
            )
        except (
            asyncio.IncompleteReadError,
            asyncio.LimitOverrunError,
            TimeoutError,
            ConnectionError,
        ):
            client_writer.close()
            return

        if len(raw_head) > _MAX_HEADER_BYTES:
            await self._send_error(
                client_writer, 431, "headers_too_large", "Request headers too large"
            )
            return

        lines = raw_head.decode("latin-1").split("\r\n")
        if not lines or len(lines[0].split(" ")) < 3:
            await self._send_error(
                client_writer, 400, "malformed_request", "Malformed proxy request"
            )
            return

        method, target, http_version = lines[0].split(" ", 2)
        headers: list[tuple[str, str]] = []
        for header_line in lines[1:]:
            if not header_line:
                continue
            if ":" not in header_line:
                continue
            name, value = header_line.split(":", 1)
            headers.append((name.strip(), value.strip()))

        try:
            if method.upper() == "CONNECT":
                await self._handle_connect(target, client_reader, client_writer)
            else:
                await self._handle_http_forward(
                    method=method.upper(),
                    target_url=target,
                    http_version=http_version,
                    headers=headers,
                    client_reader=client_reader,
                    client_writer=client_writer,
                )
        except Exception as exc:  # pragma: no cover - fail-closed defensive guard
            if not client_writer.is_closing():
                await self._send_error(
                    client_writer,
                    502,
                    "egress_gateway_error",
                    f"Gateway error: {type(exc).__name__}",
                )
        finally:
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()

    async def _handle_connect(
        self,
        authority: str,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        host, port = _parse_connect_authority(authority)
        try:
            dest = await self.validate_destination(host=host, port=port, scheme="https")
        except EgressBlockedError as exc:
            await self._record_block(authority, exc)
            await self._send_error(client_writer, 403, exc.code, exc.message)
            return

        try:
            sock = await asyncio.to_thread(_open_pinned_tcp_socket, dest.pinned_ip, dest.port, 10.0)
            up_reader, up_writer = await asyncio.open_connection(sock=sock)
        except OSError as exc:
            await self._send_error(
                client_writer,
                502,
                "upstream_connect_failed",
                f"Failed to connect to upstream target: {type(exc).__name__}",
            )
            return

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await client_writer.drain()

        async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    chunk = await reader.read(16384)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
            except (ConnectionError, asyncio.CancelledError):
                pass
            finally:
                if not writer.is_closing():
                    writer.close()

        await asyncio.gather(_pipe(client_reader, up_writer), _pipe(up_reader, client_writer))

    async def _handle_http_forward(
        self,
        *,
        method: str,
        target_url: str,
        http_version: str,
        headers: list[tuple[str, str]],
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        del http_version
        content_length = 0
        for name, value in headers:
            if name.lower() == "content-length":
                try:
                    content_length = max(0, int(value))
                except ValueError:
                    await self._send_error(
                        client_writer,
                        400,
                        "invalid_content_length",
                        "Invalid Content-Length",
                    )
                    return

        body = b""
        if content_length > 0:
            body = await asyncio.wait_for(client_reader.readexactly(content_length), timeout=15.0)

        try:
            dest = await self.validate_destination(url=target_url)
        except EgressBlockedError as exc:
            await self._record_block(target_url, exc)
            await self._send_error(client_writer, 403, exc.code, exc.message)
            return

        current_url = dest.url
        current_dest = dest
        hop = 0

        while True:
            status_code, resp_headers, raw_response = await self._forward_single_http_request(
                method=method if hop == 0 else "GET",
                dest=current_dest,
                url=current_url,
                request_headers=headers,
                body=body if hop == 0 else b"",
            )
            if status_code not in _REDIRECT_STATUSES:
                client_writer.write(raw_response)
                await client_writer.drain()
                return

            location = _find_header(resp_headers, "location")
            if not location:
                client_writer.write(raw_response)
                await client_writer.drain()
                return

            hop += 1
            try:
                current_dest = await self.validate_redirect(
                    source_url=current_url,
                    location=location,
                    hop_count=hop,
                )
            except EgressBlockedError as exc:
                await self._record_block(location, exc)
                await self._send_error(client_writer, 403, exc.code, exc.message)
                return
            current_url = current_dest.url

    async def _forward_single_http_request(
        self,
        *,
        method: str,
        dest: ValidatedDestination,
        url: str,
        request_headers: Iterable[tuple[str, str]],
        body: bytes,
    ) -> tuple[int, list[tuple[str, str]], bytes]:
        sock = await asyncio.to_thread(_open_pinned_tcp_socket, dest.pinned_ip, dest.port, 10.0)
        ssl_ctx = ssl.create_default_context() if dest.scheme == "https" else None
        up_reader, up_writer = await asyncio.open_connection(
            sock=sock,
            ssl=ssl_ctx,
            server_hostname=dest.host if ssl_ctx is not None else None,
        )
        try:
            split = urlsplit(url)
            path_query = split.path or "/"
            if split.query:
                path_query = f"{path_query}?{split.query}"

            filtered_headers: list[tuple[str, str]] = []
            for name, val in request_headers:
                lower = name.lower()
                if lower in {"proxy-connection", "proxy-authorization", "connection", "host"}:
                    continue
                filtered_headers.append((name, val))
            default_port = 443 if dest.scheme == "https" else 80
            host_header = dest.host if dest.port == default_port else f"{dest.host}:{dest.port}"
            header_lines = [
                f"{method} {path_query} HTTP/1.1",
                f"Host: {host_header}",
                "Connection: close",
            ]
            for name, val in filtered_headers:
                header_lines.append(f"{name}: {val}")
            raw_req = ("\r\n".join(header_lines) + "\r\n\r\n").encode("latin-1") + body
            up_writer.write(raw_req)
            await up_writer.drain()

            max_resp_bytes = 10 * 1024 * 1024
            raw_resp = await asyncio.wait_for(
                up_reader.read(max_resp_bytes + 1),
                timeout=30.0,
            )
            if len(raw_resp) > max_resp_bytes:
                raise EgressBlockedError(
                    "response_too_large",
                    "Upstream HTTP response exceeded 10 MiB safety limit",
                )
            head_end = raw_resp.find(b"\r\n\r\n")
            if head_end == -1:
                raise EgressBlockedError(
                    "invalid_upstream_response", "Malformed upstream HTTP response"
                )
            head_text = raw_resp[:head_end].decode("latin-1")
            head_lines = head_text.split("\r\n")
            status_parts = head_lines[0].split(" ")
            status_code = int(status_parts[1]) if len(status_parts) >= 2 else 502
            parsed_headers: list[tuple[str, str]] = []
            for hline in head_lines[1:]:
                if ":" in hline:
                    k, v = hline.split(":", 1)
                    parsed_headers.append((k.strip(), v.strip()))
            return status_code, parsed_headers, raw_resp
        finally:
            if not up_writer.is_closing():
                up_writer.close()
                await up_writer.wait_closed()

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter,
        status: int,
        code: str,
        message: str,
    ) -> None:
        payload = json.dumps({"error": code, "message": message}).encode("utf-8")
        response = (
            f"HTTP/1.1 {status} Forbidden\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(payload)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1") + payload
        writer.write(response)
        await writer.drain()


def _parse_connect_authority(authority: str) -> tuple[str, int]:
    clean = authority.strip()
    if clean.startswith("[") and "]" in clean:
        host_part, _, port_part = clean[1:].partition("]")
        port = int(port_part.lstrip(":")) if port_part else 443
        return host_part, port
    if ":" in clean:
        host_part, port_part = clean.rsplit(":", 1)
        return host_part, int(port_part)
    return clean, 443


def _find_header(headers: Iterable[tuple[str, str]], name: str) -> str | None:
    target = name.lower()
    for key, value in headers:
        if key.lower() == target:
            return value
    return None
