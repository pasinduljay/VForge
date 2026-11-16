"""Phase 11 AI candidate rule-authoring gateway interface and safe Phase 12 stub."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

from vforge.errors import ValidationError

_INJECTION_LINE_RE = re.compile(
    r"(?i)(ignore\s+previous|system\s+prompt|sign_pack|promote_stable|approve_review|modify_opa)"
)


@dataclass(slots=True)
class AiGeneratedCandidate:
    rules: list[dict[str, Any]]
    provenance: dict[str, Any]


class RuleAuthorGateway(Protocol):
    """Contract satisfied by Phase 12's governed AI Gateway adapter."""

    def generate_rule_candidate(
        self,
        *,
        engine: str,
        rule_key: str,
        title: str,
        cwe_id: str,
        target_context: str,
        untrusted_source_snippet: str,
    ) -> AiGeneratedCandidate: ...


def _sanitize_untrusted_context(raw_snippet: str) -> tuple[str, str]:
    """Strip directive-like lines from untrusted code/comments and hash the original input."""
    digest = hashlib.sha256(raw_snippet.encode("utf-8")).hexdigest()
    safe_lines = [line for line in raw_snippet.splitlines() if not _INJECTION_LINE_RE.search(line)]
    return "\n".join(safe_lines[:40]), digest


class Phase12StubRuleAuthorGateway:
    """Offline deterministic stub used prior to live Phase 12 multi-provider AI Gateway."""

    MODEL_ID = "phase12-stub-rule-author-v1"
    PROVIDER_ID = "local_stub"
    PROMPT_VERSION = "vf-rule-author-prompt-v1"

    def generate_rule_candidate(
        self,
        *,
        engine: str,
        rule_key: str,
        title: str,
        cwe_id: str,
        target_context: str,
        untrusted_source_snippet: str,
    ) -> AiGeneratedCandidate:
        sanitized_snippet, snippet_sha = _sanitize_untrusted_context(untrusted_source_snippet)
        clean_key = re.sub(r"[^A-Za-z0-9._-]", "-", rule_key.strip())[:100] or "vf-ai-cand-001"
        safe_title = json.dumps(" ".join(title.splitlines()).strip()[:200])
        provenance = {
            "gateway_mode": "phase12_stub",
            "provider": self.PROVIDER_ID,
            "model": self.MODEL_ID,
            "prompt_template_version": self.PROMPT_VERSION,
            "input_snapshot_sha256": snippet_sha,
            "untrusted_snippet_sanitized": True,
            "sanitized_preview": sanitized_snippet[:240],
        }

        if engine == "nuclei":
            rule_def: dict[str, Any] = {
                "rule_key": clean_key,
                "title": title,
                "engine": "nuclei",
                "native_format": "yaml",
                "risk_class": "passive",
                "severity": "medium",
                "confidence": "medium",
                "cwe_id": cwe_id,
                "rationale": f"AI-assisted detection candidate ({cwe_id} in {target_context})",
                "target_context": target_context,
                "network_requirements": "http_readonly_single_probe",
                "known_limitations": (
                    "Requires HTTP response visibility; must pass lab fixture verification."
                ),
                "timeout_seconds": 30,
                "memory_budget_mb": 256,
                "expected_evidence_fields": ["url", "status_code", "matched_word"],
                "native_content": (
                    f"id: {clean_key}\n"
                    "info:\n"
                    f"  name: {safe_title}\n"
                    "  severity: medium\n"
                    "http:\n"
                    "  - method: GET\n"
                    "    path:\n"
                    "      - '{{BaseURL}}/api/debug'\n"
                    "    matchers:\n"
                    "      - type: word\n"
                    "        words:\n"
                    "          - 'stack_trace_dump'\n"
                ),
                "positive_fixtures": [
                    {
                        "name": "exposed-stack-trace",
                        "status_code": 200,
                        "response": "stack_trace_dump: File main.py",
                    }
                ],
                "negative_fixtures": [
                    {"name": "healthy-ok", "status_code": 200, "response": '{"status": "ok"}'}
                ],
                "near_miss_fixtures": [
                    {
                        "name": "docs-mention-trace",
                        "status_code": 200,
                        "response": "trace logging disabled",
                    }
                ],
            }
        elif engine == "gitleaks":
            rule_def = {
                "rule_key": clean_key,
                "title": title,
                "engine": "gitleaks",
                "native_format": "toml",
                "risk_class": "static",
                "severity": "high",
                "confidence": "high",
                "cwe_id": cwe_id,
                "rationale": f"AI-assisted secret candidate ({cwe_id} in {target_context})",
                "target_context": target_context,
                "network_requirements": "none",
                "known_limitations": (
                    "Excludes documented example placeholder tokens via allowlist."
                ),
                "timeout_seconds": 20,
                "memory_budget_mb": 128,
                "expected_evidence_fields": ["file", "line", "redacted_secret"],
                "native_content": (
                    "[[rules]]\n"
                    f"id = {json.dumps(clean_key)}\n"
                    f"description = {safe_title}\n"
                    'regex = "vf_api_[A-Za-z0-9]{20}"\n'
                    "[rules.allowlist]\n"
                    'regexes = ["vf_api_EXAMPLE0000000000000"]\n'
                ),
                "positive_fixtures": [
                    {
                        "name": "live-key",
                        "path": "src/config.py",
                        "content": 'KEY = "vf_api_9876543210abcdefghij"',
                    }
                ],
                "negative_fixtures": [
                    {
                        "name": "no-secret",
                        "path": "src/config.py",
                        "content": 'KEY = os.environ["API_KEY"]',
                    }
                ],
                "near_miss_fixtures": [
                    {
                        "name": "example-placeholder",
                        "path": "README.md",
                        "content": 'KEY = "vf_api_EXAMPLE0000000000000"',
                    }
                ],
            }
        elif engine == "opengrep":
            rule_def = {
                "rule_key": clean_key,
                "title": title,
                "engine": "opengrep",
                "native_format": "yaml",
                "risk_class": "static",
                "severity": "high",
                "confidence": "medium",
                "cwe_id": cwe_id,
                "rationale": f"AI-assisted AST candidate ({cwe_id} in {target_context})",
                "target_context": target_context,
                "network_requirements": "none",
                "known_limitations": (
                    "Single-file pattern; assumes standard subprocess call "
                    "without literal safe invocation."
                ),
                "timeout_seconds": 30,
                "memory_budget_mb": 256,
                "expected_evidence_fields": ["file", "line", "snippet"],
                "native_content": (
                    "rules:\n"
                    f"  - id: {clean_key}\n"
                    f"    message: {safe_title}\n"
                    "    severity: HIGH\n"
                    "    languages: [python]\n"
                    "    patterns:\n"
                    "      - pattern: 'subprocess.run(..., shell=True)'\n"
                    "      - pattern-not: 'subprocess.run([...], shell=False)'\n"
                ),
                "positive_fixtures": [
                    {"name": "shell-true", "content": "subprocess.run(user_cmd, shell=True)"}
                ],
                "negative_fixtures": [
                    {
                        "name": "safe-list-exec",
                        "content": "subprocess.run(['ls', '-la'], shell=False)",
                    }
                ],
                "near_miss_fixtures": [
                    {
                        "name": "comment-mention",
                        "content": "# never set subprocess.run with shell=False bypassed",
                    }
                ],
            }
        else:
            raise ValidationError(
                f"AI author stub supports 'opengrep', 'nuclei', or 'gitleaks' (got '{engine}')"
            )

        return AiGeneratedCandidate(rules=[rule_def], provenance=provenance)
