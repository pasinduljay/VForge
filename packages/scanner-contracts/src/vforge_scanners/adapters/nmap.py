"""Pinned Instrumentisto Nmap network assessment adapter (TCP connect non-root)."""

from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from vforge_scanners.redaction import redact_text_secrets, scrub_finding_dict
from vforge_scanners.sdk import (
    ExecutionResult,
    ExecutionSpec,
    NormalizedFinding,
    SeverityLevel,
    ToolContext,
    ToolMetadata,
    compute_finding_fingerprint,
    find_artifact_by_name,
)

DEFAULT_NMAP_IMAGE = (
    "instrumentisto/nmap@sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827"
)

_RISKY_PORT_SEVERITIES: dict[int, tuple[SeverityLevel, str]] = {
    21: ("medium", "Insecure FTP service exposed"),
    23: ("high", "Cleartext Telnet service exposed"),
    69: ("high", "Insecure TFTP service exposed"),
    3389: ("low", "Remote Desktop (RDP) service exposed"),
    5432: ("low", "PostgreSQL database port exposed"),
    6379: ("medium", "Valkey/Redis in-memory store exposed"),
    27017: ("medium", "MongoDB database port exposed"),
    9200: ("medium", "Elasticsearch cluster port exposed"),
    11211: ("medium", "Memcached port exposed"),
}

_FORBIDDEN_XML_DECL_RE = re.compile(r"<!(?:DOCTYPE|ENTITY)", re.IGNORECASE)


def _safe_parse_nmap_xml_text(raw: str) -> ET.Element:
    if _FORBIDDEN_XML_DECL_RE.search(raw):
        raise ValueError("Nmap XML contains forbidden DOCTYPE or ENTITY declarations")
    return ET.fromstring(raw)  # noqa: S314


def _safe_parse_nmap_xml(xml_path: Path) -> ET.Element:
    return _safe_parse_nmap_xml_text(xml_path.read_text(encoding="utf-8"))


class NmapAdapter:
    """ScannerAdapter contract for unprivileged Nmap TCP connect scanning."""

    def __init__(self, *, pinned_image: str = DEFAULT_NMAP_IMAGE) -> None:
        self._pinned_image = pinned_image

    def metadata(self) -> ToolMetadata:
        return ToolMetadata(
            tool_id="nmap",
            tool_version="7.98",
            adapter_version="0.1.0",
            capabilities=("network_scan", "port_scan", "service_detection"),
            risk_class="network",
            supported_input_types=("host", "ip", "cidr"),
            output_formats=("xml",),
            pinned_image=self._pinned_image,
        )

    def validate(self, context: ToolContext) -> None:
        if not context.job_id.strip() or not context.scan_run_id.strip():
            raise ValueError("ToolContext requires non-empty job_id and scan_run_id")
        target = str(
            context.config.get("target_host")
            or context.config.get("target_ip")
            or context.config.get("target_locator")
            or ""
        ).strip()
        if not target:
            raise ValueError("NmapAdapter requires config['target_host'] or config['target_ip']")

    def build_execution_spec(self, context: ToolContext) -> ExecutionSpec:
        self.validate(context)
        target = str(
            context.config.get("target_host")
            or context.config.get("target_ip")
            or context.config.get("target_locator")
            or ""
        ).strip()
        if "://" in target:
            target = urlsplit(target).hostname or target

        ports = context.config.get("ports")
        if not ports and context.approved_scope.get("allowed_ports"):
            ports = ",".join(str(p) for p in context.approved_scope["allowed_ports"])
        if not ports:
            ports = "80,443,8000,8080,8443,3000,5000,9000"

        cmd: tuple[str, ...] = (
            "nmap",
            "-sT",
            "-Pn",
            "-p",
            str(ports),
            "-oX",
            "/work/out/nmap.xml",
            target,
        )

        return ExecutionSpec(
            tool_id="nmap",
            image=self._pinned_image,
            command=cmd,
            env={"HOME": "/tmp"},  # noqa: S108
            network_mode="scoped-http-egress",
            expected_outputs=("nmap.xml",),
            allowed_exit_codes=(0,),
            read_only_root=True,
        )

    def execute(self, context: ToolContext) -> ExecutionResult:
        spec = self.build_execution_spec(context)
        completed = subprocess.run(  # noqa: S603
            list(spec.command),
            capture_output=True,
            text=True,
            check=False,
        )
        return ExecutionResult(
            status="completed" if completed.returncode in spec.allowed_exit_codes else "failed",
            exit_code=completed.returncode,
            metrics={"stderr_bytes": len(completed.stderr or "")},
        )

    def validate_outputs(self, result: ExecutionResult) -> None:
        xml_path = find_artifact_by_name(result.artifacts, "nmap.xml")
        if xml_path is None or not xml_path.exists():
            raise ValueError("Missing required Nmap report artifact: nmap.xml")
        try:
            root = _safe_parse_nmap_xml(xml_path)
            if root.tag != "nmaprun":
                raise ValueError(f"Unexpected Nmap XML root tag: {root.tag!r}")
        except (ET.ParseError, OSError, ValueError) as err:
            raise ValueError(f"Corrupted or invalid Nmap XML report: {err}") from err

    def normalize(
        self,
        result: ExecutionResult,
        context: ToolContext | None = None,
    ) -> list[NormalizedFinding]:
        xml_path = find_artifact_by_name(result.artifacts, "nmap.xml")
        if xml_path is None:
            return []
        return self.parse_xml_text(xml_path.read_text(encoding="utf-8"))

    def parse_xml_text(self, text: str) -> list[NormalizedFinding]:
        """Parse an Nmap XML report string into NormalizedFinding objects."""
        root = _safe_parse_nmap_xml_text(text)
        findings: list[NormalizedFinding] = []
        for host in root.findall("host"):
            address_elem = host.find("address")
            host_addr = (
                str(address_elem.get("addr") or "unknown")
                if address_elem is not None
                else "unknown"
            )
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue

            for port in ports_elem.findall("port"):
                state_elem = port.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue

                port_id_raw = str(port.get("portid") or "0")
                protocol = str(port.get("protocol") or "tcp")
                port_num = int(port_id_raw) if port_id_raw.isdigit() else 0

                service_elem = port.find("service")
                service_name = (
                    str(service_elem.get("name") or "unknown")
                    if service_elem is not None
                    else "unknown"
                )
                product = str(service_elem.get("product") or "") if service_elem is not None else ""
                version = str(service_elem.get("version") or "") if service_elem is not None else ""

                severity: SeverityLevel = "info"
                if port_num in _RISKY_PORT_SEVERITIES:
                    severity, title = _RISKY_PORT_SEVERITIES[port_num]
                else:
                    title = f"Open Port {port_num}/{protocol} ({service_name})"

                desc_parts = [
                    f"Port {port_num}/{protocol} observed 'open' on host {host_addr}.",
                ]
                if product:
                    desc_parts.append(f"Product: {product} {version}".strip())
                description = " ".join(desc_parts)

                rule_id = f"nmap-port-{port_num}-{protocol}"
                locator_path = f"port/{port_num}/{protocol}"
                fingerprint = compute_finding_fingerprint(
                    category="network",
                    tool_id="nmap",
                    rule_id=rule_id,
                    file_path=locator_path,
                    start_line=None,
                    discriminator=host_addr,
                )

                findings.append(
                    NormalizedFinding(
                        scanner_tool_id="nmap",
                        scanner_version="7.98",
                        category="network",
                        rule_id=rule_id,
                        title=str(redact_text_secrets(title) or title),
                        description=str(redact_text_secrets(description) or description),
                        severity=severity,
                        confidence="high",
                        file_path=locator_path,
                        start_line=None,
                        end_line=None,
                        start_column=None,
                        end_column=None,
                        cwe_ids=("CWE-200",),
                        fingerprint=fingerprint,
                        network_port=port_num,
                        network_protocol=protocol,
                        remediation=(
                            "Verify whether this network service is required; "
                            "restrict exposure via network firewall or security groups."
                        ),
                        raw_metadata=scrub_finding_dict(
                            {
                                "host": host_addr,
                                "port": port_num,
                                "protocol": protocol,
                                "service": service_name,
                                "product": product,
                                "version": version,
                            }
                        ),
                    )
                )

        return findings

    def cleanup(self, context: ToolContext) -> None:
        return None
