"""Unit & fixture tests for VForge Phase 5 ScannerAdapter SDK, redaction, and coverage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vforge_scanners import (
    GITLEAKS_FINDINGS_EXIT_CODE,
    CheckovAdapter,
    ExecutionResult,
    GitleaksAdapter,
    GrypeAdapter,
    OpenGrepAdapter,
    SyftAdapter,
    ToolContext,
    UnsafeArchiveError,
    canonicalize_source_archive,
    detect_repository_languages,
    evaluate_coverage,
    extract_grype_db_provenance,
    redact_secret_value,
    redact_text_secrets,
    safe_extract_archive_bytes,
)


def _dummy_context(tmp_path: Path) -> ToolContext:
    src = tmp_path / "source"
    out = tmp_path / "out"
    src.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    return ToolContext(
        job_id="11111111-1111-1111-1111-111111111111",
        scan_run_id="22222222-2222-2222-2222-222222222222",
        workspace=tmp_path,
        input_paths=(src,),
        output_dir=out,
    )


def test_secret_redaction_strips_known_credentials_and_tokens() -> None:
    fake_aws = "AKIA" + "IOSFODNN7EXAMPLE"
    fake_gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1L2M3N4O5"
    raw = (
        f"AWS_ACCESS_KEY_ID={fake_aws}\n"
        f"TOKEN={fake_gh}\n"
        "postgres://app:SuperSecretPass123@db:5432/vf"
    )

    scrubbed = redact_text_secrets(raw, known_secrets=(fake_aws, fake_gh))
    assert scrubbed is not None
    assert fake_aws not in scrubbed
    assert fake_gh not in scrubbed
    assert "SuperSecretPass123" not in scrubbed
    assert "[REDACTED:" in scrubbed
    # Deterministic tag without revealing cleartext bytes.
    assert redact_secret_value(fake_aws) == redact_secret_value(fake_aws)


def test_opengrep_adapter_contract_and_json_normalization(tmp_path: Path) -> None:
    adapter = OpenGrepAdapter()
    meta = adapter.metadata()
    assert meta.tool_id == "opengrep"
    assert meta.risk_class == "static"
    assert "@sha256:" in meta.pinned_image

    ctx = _dummy_context(tmp_path)
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "none"
    assert spec.read_only_root is True
    assert "/work/in/source" in spec.command
    assert "--no-git-ignore" in spec.command

    report_path = ctx.output_dir / "opengrep.json"
    report_path.write_text(
        json.dumps(
            {
                "version": "1.33.1",
                "results": [
                    {
                        "check_id": (
                            "opt.opengrep.rules.vforge.python.command-injection.subprocess-shell"
                        ),
                        "path": "/work/in/source/app.py",
                        "start": {"line": 12, "col": 5},
                        "end": {"line": 12, "col": 42},
                        "extra": {
                            "severity": "ERROR",
                            "message": "Potential command injection",
                            "lines": "subprocess.run(cmd, shell=True)",
                            "metadata": {
                                "cwe": ["CWE-78: OS Command Injection"],
                                "confidence": "HIGH",
                                "remediation": "Use shell=False",
                            },
                        },
                    }
                ],
                "errors": [],
            }
        ),
        encoding="utf-8",
    )

    findings = adapter.normalize(
        ExecutionResult(status="completed", exit_code=0, artifacts=[report_path])
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner_tool_id == "opengrep"
    assert finding.category == "sast"
    assert finding.rule_id == "vforge.python.command-injection.subprocess-shell"
    assert finding.file_path == "app.py"
    assert finding.start_line == 12
    assert finding.severity == "high"
    assert finding.confidence == "high"
    assert finding.cwe_ids == ("CWE-78",)
    assert len(finding.fingerprint) == 64

    # Identical output must produce identical fingerprint for reproducible rescans.
    findings_again = adapter.normalize(
        ExecutionResult(status="completed", exit_code=0, artifacts=[report_path])
    )
    assert findings_again[0].fingerprint == finding.fingerprint


def test_opengrep_adapter_clean_fixture_and_sarif_fallback(tmp_path: Path) -> None:
    adapter = OpenGrepAdapter()
    ctx = _dummy_context(tmp_path)
    sarif_path = ctx.output_dir / "opengrep.sarif"
    sarif_path.write_text(
        json.dumps(
            {
                "version": "2.1.0",
                "runs": [{"tool": {"driver": {"semanticVersion": "1.33.1"}}, "results": []}],
            }
        ),
        encoding="utf-8",
    )
    findings = adapter.normalize(
        ExecutionResult(status="completed", exit_code=0, artifacts=[sarif_path])
    )
    assert findings == []


def test_gitleaks_adapter_redacts_secrets_and_handles_exit_code_10(tmp_path: Path) -> None:
    adapter = GitleaksAdapter()
    ctx = _dummy_context(tmp_path)
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "none"
    assert "--redact=100" in spec.command
    assert GITLEAKS_FINDINGS_EXIT_CODE in spec.allowed_exit_codes

    leaked_secret = "ghp_" + "ZXCVBNMASDFGHJKLQWERTYUIOP123456"
    report_path = ctx.output_dir / "gitleaks.json"
    report_path.write_text(
        json.dumps(
            [
                {
                    "RuleID": "github-pat",
                    "Description": "Detected GitHub Personal Access Token",
                    "File": "/work/in/source/config.py",
                    "StartLine": 3,
                    "EndLine": 3,
                    "StartColumn": 10,
                    "EndColumn": 49,
                    "Secret": leaked_secret,
                    "Match": f'GITHUB_TOKEN = "{leaked_secret}"',
                    "Entropy": 4.9,
                }
            ]
        ),
        encoding="utf-8",
    )

    findings = adapter.normalize(
        ExecutionResult(
            status="completed",
            exit_code=GITLEAKS_FINDINGS_EXIT_CODE,
            artifacts=[report_path],
        )
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "secret"
    assert f.secret_redacted is True
    assert f.file_path == "config.py"
    assert leaked_secret not in (f.code_snippet_redacted or "")
    assert leaked_secret not in json.dumps(f.raw_metadata)
    assert f.severity == "high"
    assert f.cwe_ids == ("CWE-798",)

    with pytest.raises(ValueError, match="Unexpected Gitleaks exit code"):
        adapter.normalize(ExecutionResult(status="completed", exit_code=2, artifacts=[report_path]))


def test_polyglot_coverage_marks_unsupported_languages_as_partial(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / "main.ts").write_text("export const x = 1;\n", encoding="utf-8")
    (tmp_path / "Contract.sol").write_text("pragma solidity ^0.8.0;\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("eval(x)\n", encoding="utf-8")

    discovery = detect_repository_languages(tmp_path)
    assert discovery.languages == {"python": 1, "solidity": 1, "typescript": 1}
    assert "vendored_dependencies" in discovery.excluded_directories

    cov = evaluate_coverage(discovery, selected_tools=("opengrep", "gitleaks"))
    assert cov["assessment_coverage_status"] == "partial"
    assert "solidity" in cov["unsupported_languages"]
    assert "python" in cov["supported_languages"]
    assert "typescript" in cov["supported_languages"]


def test_polyglot_coverage_supported_only_is_complete(tmp_path: Path) -> None:
    (tmp_path / "service.py").write_text("print('clean')\n", encoding="utf-8")
    (tmp_path / "handler.go").write_text("package main\n", encoding="utf-8")
    discovery = detect_repository_languages(tmp_path)
    cov = evaluate_coverage(discovery, selected_tools=("opengrep", "gitleaks"))
    assert cov["assessment_coverage_status"] == "complete"
    assert cov["unsupported_languages"] == []


def test_archive_canonicalization_rejects_traversal_symlinks_and_bombs(tmp_path: Path) -> None:
    import io
    import tarfile
    import zipfile

    # Traversal inside tar.gz
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = b"pwned"
        ti = tarfile.TarInfo(name="../../etc/passwd")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    with pytest.raises(UnsafeArchiveError, match="traversal"):
        canonicalize_source_archive(buf.getvalue(), source_type="archive_tar_gz")

    # Symlink inside tar.gz
    buf_sym = io.BytesIO()
    with tarfile.open(fileobj=buf_sym, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="link")
        ti.type = tarfile.SYMTYPE
        ti.linkname = "/etc/shadow"
        tf.addfile(ti)
    with pytest.raises(UnsafeArchiveError, match="non-regular"):
        canonicalize_source_archive(buf_sym.getvalue(), source_type="archive_tar_gz")

    # Quota exceeded in zip
    buf_zip = io.BytesIO()
    with zipfile.ZipFile(buf_zip, mode="w") as zf:
        zf.writestr("big.txt", b"A" * 1024)
    with pytest.raises(UnsafeArchiveError, match="quota"):
        canonicalize_source_archive(
            buf_zip.getvalue(),
            source_type="archive_zip",
            max_extracted_bytes=256,
        )

    # NUL byte rejected as UnsafeArchiveError when present in crafted archive headers
    from vforge_scanners.archive import _normalize_archive_member_path

    with pytest.raises(UnsafeArchiveError, match="NUL"):
        _normalize_archive_member_path("bad\x00file.py")

    # Clean extraction succeeds read-only
    clean_zip = io.BytesIO()
    with zipfile.ZipFile(clean_zip, mode="w") as zf:
        zf.writestr("src/app.py", b"print('hello')\n")
    canon = canonicalize_source_archive(clean_zip.getvalue(), source_type="archive_zip")
    assert canon.file_count == 1
    out_dir = tmp_path / "extracted"
    count = safe_extract_archive_bytes(canon.canonical_tar_gz, out_dir, read_only=False)
    assert count == 1
    assert (out_dir / "src" / "app.py").read_text(encoding="utf-8") == "print('hello')\n"


def test_syft_adapter_contract_and_cyclonedx_parsing(tmp_path: Path) -> None:
    ctx = _dummy_context(tmp_path)
    ctx_with_cfg = ToolContext(
        job_id=ctx.job_id,
        scan_run_id=ctx.scan_run_id,
        workspace=ctx.workspace,
        input_paths=ctx.input_paths,
        output_dir=ctx.output_dir,
        config={"source_name": "org/web app!"},
    )
    adapter = SyftAdapter()
    spec = adapter.build_execution_spec(ctx_with_cfg)
    assert spec.network_mode == "none"
    assert spec.env["SYFT_CHECK_FOR_APP_UPDATE"] == "false"
    assert "cyclonedx-json=" in " ".join(spec.command)
    assert "org-web-app" in spec.command[-1]

    sample_cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:11111111-1111-4111-8111-111111111111",
        "components": [
            {
                "type": "library",
                "name": "urllib3",
                "version": "1.26.5",
                "purl": "pkg:pypi/urllib3@1.26.5",
                "properties": [
                    {"name": "syft:package:type", "value": "python"},
                    {"name": "syft:package:foundBy", "value": "python-package-cataloger"},
                    {"name": "syft:location:0:path", "value": "/requirements.txt"},
                ],
            }
        ],
    }
    cdx_path = ctx.output_dir / "sbom.cdx.json"
    cdx_path.write_text(json.dumps(sample_cdx), encoding="utf-8")
    result = ExecutionResult(status="completed", exit_code=0, artifacts=[cdx_path])
    assert adapter.normalize(result) == []
    parsed = adapter.parse_cyclonedx(sample_cdx)
    assert parsed.component_count == 1
    assert parsed.components[0].purl == "pkg:pypi/urllib3@1.26.5"
    assert parsed.components[0].locations == ("requirements.txt",)


def test_grype_adapter_requires_valid_db_and_preserves_purl_traceability(tmp_path: Path) -> None:
    sbom_file = tmp_path / "sbom.cdx.json"
    sbom_file.write_text("{}", encoding="utf-8")
    ctx = ToolContext(
        job_id="job-grype",
        scan_run_id="run-grype",
        workspace=tmp_path,
        input_paths=(sbom_file,),
        output_dir=tmp_path / "out",
    )
    adapter = GrypeAdapter()
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "none"
    assert spec.env["GRYPE_DB_AUTO_UPDATE"] == "false"
    assert spec.env["GRYPE_CHECK_FOR_APP_UPDATE"] == "false"
    assert spec.command[0].startswith("sbom:")

    # Missing/invalid DB provenance must fail closed
    with pytest.raises(ValueError, match="descriptor.db.status"):
        extract_grype_db_provenance({"matches": []})
    with pytest.raises(ValueError, match="invalid"):
        extract_grype_db_provenance({"descriptor": {"db": {"status": {"valid": False}}}})
    with pytest.raises(ValueError, match="SHA-256"):
        extract_grype_db_provenance(
            {
                "descriptor": {
                    "db": {
                        "status": {
                            "schemaVersion": "v6.1.10",
                            "built": "2026-11-12T06:20:58Z",
                            "from": "https://grype.anchore.io/databases/v6/db.tar.zst",
                            "valid": True,
                        }
                    }
                }
            }
        )

    expected_db_sha = "c98bd6bd207590fa04c8e2fea3db1859f7f952b57400fc62e19f517f1b562f5e"
    sample_report = {
        "descriptor": {
            "db": {
                "status": {
                    "schemaVersion": "v6.1.10",
                    "from": (
                        "https://grype.anchore.io/databases/v6/db.tar.zst"
                        f"?checksum=sha256%3A{expected_db_sha}"
                    ),
                    "built": "2026-11-12T06:20:58Z",
                    "valid": True,
                },
                "providers": {"nvd": {"captured": "2026-11-12T00:23:17Z"}},
            }
        },
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-38jv-5279-wg99",
                    "severity": "High",
                    "description": "Improper handling in urllib3.",
                    "fix": {"versions": ["2.6.3"], "state": "fixed"},
                    "cwes": [{"cwe": "CWE-20"}],
                },
                "relatedVulnerabilities": [{"id": "CVE-2023-45803"}],
                "artifact": {
                    "name": "urllib3",
                    "version": "1.26.5",
                    "purl": "pkg:pypi/urllib3@1.26.5",
                    "locations": [{"path": "/requirements.txt"}],
                },
            }
        ],
    }
    report_path = tmp_path / "out" / "grype.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(sample_report), encoding="utf-8")

    prov = extract_grype_db_provenance(sample_report)
    assert prov.db_archive_sha256 == expected_db_sha
    assert prov.source_url == "https://grype.anchore.io/databases/v6/db.tar.zst"

    exec_res = ExecutionResult(status="completed", exit_code=0, artifacts=[report_path])
    findings = adapter.normalize(exec_res)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "sca"
    assert f.purl == "pkg:pypi/urllib3@1.26.5"
    assert f.package_name == "urllib3"
    assert f.package_version == "1.26.5"
    assert f.fixed_version == "2.6.3"
    assert f.cve_id == "CVE-2023-45803"
    assert f.file_path == "requirements.txt"
    assert f.cwe_ids == ("CWE-20",)


def test_checkov_adapter_contract_line_evidence_and_coverage(tmp_path: Path) -> None:
    ctx = _dummy_context(tmp_path)
    ctx_custom = ToolContext(
        job_id=ctx.job_id,
        scan_run_id=ctx.scan_run_id,
        workspace=ctx.workspace,
        input_paths=ctx.input_paths,
        output_dir=ctx.output_dir,
        config={"enable_custom_policies": True},
    )
    adapter = CheckovAdapter()
    spec = adapter.build_execution_spec(ctx_custom)
    assert spec.network_mode == "none"
    assert "--skip-download" in spec.command
    assert "--external-checks-dir" in spec.command

    sample_checkov = [
        {
            "check_type": "terraform",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 Bucket has public READ ACL access",
                        "file_path": "/main.tf",
                        "file_abs_path": "/work/in/source/main.tf",
                        "file_line_range": [1, 4],
                        "resource": "aws_s3_bucket.public_bucket",
                        "code_block": [
                            [1, 'resource "aws_s3_bucket" "public_bucket" {\n'],
                            [3, '  acl = "public-read"\n'],
                        ],
                    }
                ]
            },
        }
    ]
    out_json = ctx.output_dir / "results_json.json"
    out_json.write_text(json.dumps(sample_checkov), encoding="utf-8")
    exec_res = ExecutionResult(status="completed", exit_code=0, artifacts=[out_json])
    findings = adapter.normalize(exec_res)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "iac"
    assert f.rule_id == "CKV_AWS_20"
    assert f.severity == "critical"
    assert f.file_path == "main.tf"
    assert f.start_line == 1
    assert f.end_line == 4
    assert f.iac_resource == "aws_s3_bucket.public_bucket"
    assert "public-read" in (f.code_snippet_redacted or "")

    # Terraform + Dockerfile covered when Checkov is enabled alongside OpenGrep/Gitleaks
    iac_dir = tmp_path / "iac_repo"
    iac_dir.mkdir()
    (iac_dir / "main.tf").write_text('resource "null_resource" "x" {}\n', encoding="utf-8")
    (iac_dir / "Dockerfile").write_text("FROM python:3.13-slim\n", encoding="utf-8")
    discovery = detect_repository_languages(iac_dir)
    cov_with_checkov = evaluate_coverage(
        discovery,
        selected_tools=("opengrep", "gitleaks", "checkov"),
    )
    assert cov_with_checkov["assessment_coverage_status"] == "complete"
    assert "terraform" in cov_with_checkov["supported_languages"]
    assert "dockerfile" in cov_with_checkov["supported_languages"]


def test_zap_adapter_plan_execution_and_normalization(tmp_path: Path) -> None:
    from vforge_scanners.adapters.zap import (
        ZAPAdapter,
        build_zap_automation_plan,
    )

    plan_yaml = build_zap_automation_plan(
        target_url="https://app.staging.internal:8443",
        active_scan=True,
        has_openapi_spec=True,
        max_rps=4,
    )
    assert 'targetUrl: "https://app.staging.internal:8443"' in plan_yaml
    assert 'type: "openapi"' in plan_yaml
    assert 'type: "activeScan"' in plan_yaml
    assert 'type: "report"' in plan_yaml

    ctx = ToolContext(
        job_id="job-zap-1",
        scan_run_id="run-zap-1",
        workspace=tmp_path,
        input_paths=(),
        output_dir=tmp_path / "out",
        config={"target_url": "https://app.staging.internal:8443"},
        limits={"max_requests_per_second": 4},
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    adapter = ZAPAdapter()
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "scoped-http-egress"
    assert "zap.sh" in spec.command
    assert "-autorun" in spec.command

    sample_zap_report = {
        "site": [
            {
                "@name": "https://app.staging.internal:8443",
                "alerts": [
                    {
                        "pluginid": "40012",
                        "alert": "Cross Site Scripting (Reflected)",
                        "name": "Cross Site Scripting (Reflected)",
                        "riskcode": "3",
                        "confidence": "3",
                        "desc": "XSS in parameter q",
                        "solution": "HTML encode output",
                        "cweid": "79",
                        "instances": [
                            {
                                "uri": "https://app.staging.internal:8443/search?q=test",
                                "method": "GET",
                                "param": "q",
                                "attack": "<script>alert(1)</script>",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    rep_file = ctx.output_dir / "zap-report.json"
    rep_file.write_text(json.dumps(sample_zap_report), encoding="utf-8")
    exec_res = ExecutionResult(status="completed", exit_code=0, artifacts=[rep_file])
    adapter.validate_outputs(exec_res)
    findings = adapter.normalize(exec_res, ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "dast"
    assert f.scanner_tool_id == "zap"
    assert f.rule_id == "zap-40012"
    assert f.severity == "high"
    assert f.confidence == "high"
    assert f.cwe_ids == ("CWE-79",)
    assert f.http_method == "GET"
    assert f.http_param == "q"


def test_nuclei_adapter_spec_and_normalization(tmp_path: Path) -> None:
    from vforge_scanners.adapters.nuclei import NucleiAdapter

    ctx = ToolContext(
        job_id="job-nuc-1",
        scan_run_id="run-nuc-1",
        workspace=tmp_path,
        input_paths=(),
        output_dir=tmp_path / "out",
        config={
            "target_url": "https://app.staging.internal:8443",
            "max_rps": 2,
            "concurrency": 1,
        },
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    adapter = NucleiAdapter()
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "scoped-http-egress"
    assert "-disable-update-check" in spec.command
    assert "-rate-limit" in spec.command

    sample_jsonl = json.dumps(
        {
            "template-id": "cors-misconfig",
            "info": {
                "name": "CORS Misconfiguration Wildcard",
                "severity": "medium",
                "description": "Permissive CORS origin",
                "classification": {
                    "cwe-id": ["CWE-942"],
                    "cve-id": ["CVE-2023-1234"],
                },
            },
            "type": "http",
            "matched-at": "https://app.staging.internal:8443/api/profile",
            "extracted-results": ["Access-Control-Allow-Origin: *"],
        }
    )
    jsonl_file = ctx.output_dir / "nuclei.jsonl"
    jsonl_file.write_text(sample_jsonl + "\n", encoding="utf-8")
    exec_res = ExecutionResult(status="completed", exit_code=0, artifacts=[jsonl_file])
    adapter.validate_outputs(exec_res)
    findings = adapter.normalize(exec_res, ctx)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "dast"
    assert f.rule_id == "nuclei-cors-misconfig"
    assert f.severity == "medium"
    assert f.cve_id == "CVE-2023-1234"
    assert f.cwe_ids == ("CWE-942",)


def test_nmap_adapter_spec_and_normalization(tmp_path: Path) -> None:
    from vforge_scanners.adapters.nmap import NmapAdapter

    ctx = ToolContext(
        job_id="job-nmap-1",
        scan_run_id="run-nmap-1",
        workspace=tmp_path,
        input_paths=(),
        output_dir=tmp_path / "out",
        config={"target_host": "192.168.10.5", "ports": "80,443,6379"},
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    adapter = NmapAdapter()
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "scoped-http-egress"
    assert "-sT" in spec.command

    sample_nmap_xml = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sT" version="7.98">
  <host>
    <address addr="192.168.10.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.21.3"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Valkey" version="8.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    xml_file = ctx.output_dir / "nmap.xml"
    xml_file.write_text(sample_nmap_xml, encoding="utf-8")
    exec_res = ExecutionResult(status="completed", exit_code=0, artifacts=[xml_file])
    adapter.validate_outputs(exec_res)
    findings = adapter.normalize(exec_res, ctx)
    assert len(findings) == 2
    f_ports = {f.network_port: f for f in findings}
    assert 443 in f_ports
    assert f_ports[443].severity == "info"
    assert 6379 in f_ports
    assert f_ports[6379].severity == "medium"
    assert f_ports[6379].category == "network"


def test_testssl_adapter_spec_and_normalization(tmp_path: Path) -> None:
    from vforge_scanners.adapters.testssl import TestsslAdapter

    ctx = ToolContext(
        job_id="job-ssl-1",
        scan_run_id="run-ssl-1",
        workspace=tmp_path,
        input_paths=(),
        output_dir=tmp_path / "out",
        config={"target_host": "app.staging.internal:8443"},
    )
    ctx.output_dir.mkdir(parents=True, exist_ok=True)
    adapter = TestsslAdapter()
    spec = adapter.build_execution_spec(ctx)
    assert spec.network_mode == "scoped-http-egress"
    assert "testssl.sh" in spec.command

    sample_testssl = [
        {
            "id": "TLS1",
            "severity": "MEDIUM",
            "finding": "offered (deprecated)",
            "cwe": "326",
        },
        {
            "id": "heartbleed",
            "severity": "OK",
            "finding": "not vulnerable",
        },
    ]
    json_file = ctx.output_dir / "testssl.json"
    json_file.write_text(json.dumps(sample_testssl), encoding="utf-8")
    exec_res = ExecutionResult(status="completed", exit_code=0, artifacts=[json_file])
    adapter.validate_outputs(exec_res)
    findings = adapter.normalize(exec_res, ctx)
    assert len(findings) == 1
    assert findings[0].rule_id == "testssl-tls1"
    assert findings[0].severity == "medium"
    assert findings[0].category == "network"


def test_phase7_standalone_parsers() -> None:
    from vforge_scanners.adapters.nmap import NmapAdapter, _safe_parse_nmap_xml_text
    from vforge_scanners.adapters.nuclei import NucleiAdapter
    from vforge_scanners.adapters.testssl import TestsslAdapter
    from vforge_scanners.adapters.zap import ZAPAdapter

    # ZAP standalone parse
    zap_payload = {
        "site": [
            {
                "@name": "https://example.com",
                "alerts": [
                    {
                        "pluginid": "10020",
                        "alert": "X-Frame-Options Header Not Set",
                        "riskcode": "2",
                        "confidence": "2",
                        "desc": "Missing frame protection",
                        "instances": [{"uri": "https://example.com/app", "method": "GET"}],
                    }
                ],
            }
        ]
    }
    zap_res = ZAPAdapter().parse_json_report(zap_payload)
    assert len(zap_res) == 1
    assert zap_res[0].rule_id == "zap-10020"
    assert zap_res[0].severity == "medium"
    assert zap_res[0].category == "dast"

    # Nuclei standalone parse
    nuclei_jsonl = (
        '{"template-id": "missing-security-headers", '
        '"info": {"name": "Missing Security Headers", "severity": "low"}, '
        '"matched-at": "https://example.com/api"}\n'
    )
    nuclei_res = NucleiAdapter().parse_jsonl_text(nuclei_jsonl)
    assert len(nuclei_res) == 1
    assert nuclei_res[0].rule_id == "nuclei-missing-security-headers"
    assert nuclei_res[0].severity == "low"
    assert nuclei_res[0].category == "dast"

    # Nmap standalone parse & XXE rejection
    nmap_xml = (
        '<nmaprun><host><address addr="10.0.0.5"/>'
        '<ports><port protocol="tcp" portid="80">'
        '<state state="open"/><service name="http"/></port></ports></host></nmaprun>'
    )
    nmap_res = NmapAdapter().parse_xml_text(nmap_xml)
    assert len(nmap_res) == 1
    assert nmap_res[0].network_port == 80
    assert nmap_res[0].category == "network"

    with pytest.raises(ValueError, match="DOCTYPE|ENTITY"):
        _safe_parse_nmap_xml_text(
            '<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><nmaprun></nmaprun>'
        )

    # Testssl standalone parse
    sample_ssl = [{"id": "TLS1_1", "severity": "LOW", "finding": "offered", "cwe": "326"}]
    testssl_res = TestsslAdapter().parse_json_report(sample_ssl)
    assert len(testssl_res) == 1
    assert testssl_res[0].rule_id == "testssl-tls1_1"
    assert testssl_res[0].category == "network"
