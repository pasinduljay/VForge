"""Native format validators, safety AST guards, and skill constraint checks."""

from __future__ import annotations

import ast
import hashlib
import json
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any

import yaml

from vforge.errors import ValidationError

_CWE_RE = re.compile(r"^CWE-[1-9]\d{0,5}$")
_SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$")
_RULE_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,118}$")
_MAX_RULE_BYTES = 131_072

ENGINE_FORMAT_RULES: dict[str, dict[str, Any]] = {
    "opengrep": {"formats": {"yaml"}, "risk_classes": {"static"}},
    "nuclei": {"formats": {"yaml"}, "risk_classes": {"passive", "active"}},
    "checkov": {"formats": {"yaml", "python"}, "risk_classes": {"static"}},
    "gitleaks": {"formats": {"toml", "json"}, "risk_classes": {"static"}},
    "zap": {"formats": {"yaml"}, "risk_classes": {"passive", "active"}},
    "nmap": {"formats": {"lua"}, "risk_classes": {"privileged_network"}},
}

FORBIDDEN_SKILL_CAPABILITIES = frozenset(
    {
        "modify_opa",
        "edit_opa",
        "sign_pack",
        "sign_skill",
        "approve_review",
        "promote_stable",
        "bypass_scope",
        "execute_shell",
        "raw_docker_socket",
    }
)

REQUIRED_SKILL_FORBIDDEN_ACTIONS = (
    "modify_opa",
    "sign_pack",
    "promote_stable",
    "approve_review",
    "bypass_scope",
)

_FORBIDDEN_PYTHON_CALLS = frozenset(
    {
        "eval",
        "exec",
        "compile",
        "__import__",
        "open",
        "system",
        "getattr",
        "setattr",
        "delattr",
        "globals",
        "locals",
        "vars",
        "dir",
        "input",
        "breakpoint",
    }
)
_ALLOWED_PYTHON_ROOT_IMPORTS = frozenset({"checkov", "typing"})
_FORBIDDEN_LUA_IDENTIFIERS = (
    "os.",
    "os[",
    "io.",
    "io[",
    "debug.",
    "debug[",
    "package.",
    "package[",
    "ffi",
    "require(",
    "require ",
    "loadstring",
    "loadfile",
    "dofile",
    "setfenv",
    "getfenv",
    "rawget",
    "stdnse.exec",
    "nmap.new_socket",
    "_g",
)
_FORBIDDEN_NMAP_CATEGORIES = frozenset({"dos", "exploit", "brute", "intrusive"})
_FORBIDDEN_YAML_EXECUTION_KEYS = frozenset(
    {
        "shell",
        "command",
        "script_exec",
        "code",
        "script",
        "inline",
        "exec",
        "eval",
        "cmd",
        "sh",
        "bash",
        "python",
        "powershell",
        "pwsh",
    }
)
_FORBIDDEN_NUCLEI_BLOCKS = frozenset(
    {"headless", "javascript", "file", "websocket", "workflows", "self-contained", "code"}
)
_ALLOWED_ZAP_JOB_TYPES = frozenset(
    {
        "passivescan-config",
        "passivescan-wait",
        "alertfilter",
        "openapi",
        "graphql",
        "spider",
        "activescan-config",
    }
)
_MAX_YAML_DEPTH = 32
_MAX_REGEX_LEN = 512
_NESTED_QUANTIFIER_RE = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*?{]")


class _NoAliasSafeLoader(yaml.SafeLoader):
    """SafeLoader blocking YAML aliases/anchors to prevent expansion DoS."""

    def compose_node(self, parent: yaml.nodes.Node | None, index: Any) -> yaml.nodes.Node | None:
        if self.check_event(yaml.AliasEvent):
            raise yaml.YAMLError("YAML aliases (*) are forbidden in rule definitions")
        return super().compose_node(parent, index)


def _compile_safe_regex(pattern: str, context: str, errors: list[str]) -> None:
    if len(pattern) > _MAX_REGEX_LEN:
        errors.append(f"Regex too long in {context} (max {_MAX_REGEX_LEN} chars)")
        return
    if _NESTED_QUANTIFIER_RE.search(pattern):
        errors.append(f"Potentially catastrophic nested quantifier regex in {context}")
        return
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append(f"Invalid regex in {context}: {exc}")


@dataclass(slots=True)
class NativeValidationOutcome:
    passed: bool
    errors: list[str] = field(default_factory=list)
    parsed_payload: dict[str, Any] = field(default_factory=dict)
    content_sha256: str = ""


def compute_content_sha256(text_content: str) -> str:
    return hashlib.sha256(text_content.encode("utf-8")).hexdigest()


def validate_semver(version: str) -> None:
    if not _SEMVER_RE.match(version.strip()):
        raise ValidationError(f"Version '{version}' must follow semantic versioning (e.g. 1.0.0)")


def validate_rule_metadata(
    *,
    rule_key: str,
    engine: str,
    native_format: str,
    risk_class: str,
    cwe_id: str,
    rationale: str,
    known_limitations: str,
    positive_fixtures: list[dict[str, Any]],
    negative_fixtures: list[dict[str, Any]],
    near_miss_fixtures: list[dict[str, Any]],
    expected_evidence_fields: list[str],
) -> None:
    """Enforce Phase 11 required acceptance metadata and fixture completeness."""
    if not _RULE_KEY_RE.match(rule_key.strip()):
        raise ValidationError(f"Invalid rule_key '{rule_key}'")
    engine_spec = ENGINE_FORMAT_RULES.get(engine)
    if engine_spec is None:
        raise ValidationError(f"Unsupported rule engine '{engine}'")
    if native_format not in engine_spec["formats"]:
        raise ValidationError(
            f"Engine '{engine}' only supports formats {sorted(engine_spec['formats'])}"
        )
    if risk_class not in engine_spec["risk_classes"]:
        raise ValidationError(
            f"Engine '{engine}' requires risk_class in {sorted(engine_spec['risk_classes'])}"
        )
    if not _CWE_RE.match(cwe_id.strip()):
        raise ValidationError(f"cwe_id '{cwe_id}' must be a valid CWE identifier (e.g. CWE-89)")
    if len(rationale.strip()) < 10:
        raise ValidationError("Rule rationale must explain the target weakness clearly")
    if len(known_limitations.strip()) < 5:
        raise ValidationError("Rule known_limitations must document blind spots or scope limits")
    if not expected_evidence_fields:
        raise ValidationError("expected_evidence_fields must declare captured evidence attributes")
    if not positive_fixtures:
        raise ValidationError("Every rule requires at least one positive fixture")
    if not negative_fixtures:
        raise ValidationError("Every rule requires at least one negative fixture")
    if not near_miss_fixtures:
        raise ValidationError("Every rule requires at least one near-miss fixture")


def _safe_load_yaml(raw_text: str) -> dict[str, Any]:
    parsed = yaml.load(raw_text, Loader=_NoAliasSafeLoader)  # noqa: S506
    if not isinstance(parsed, dict):
        raise ValueError("YAML root must be a mapping")
    return parsed


def _check_forbidden_keys_recursive(
    obj: Any, errors: list[str], path: str = "", depth: int = 0
) -> None:
    if depth > _MAX_YAML_DEPTH:
        errors.append(f"YAML nesting depth exceeds {_MAX_YAML_DEPTH} at '{path or 'root'}'")
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            key_str = str(key).lower()
            next_path = f"{path}.{key_str}" if path else key_str
            if key_str in _FORBIDDEN_YAML_EXECUTION_KEYS:
                errors.append(f"Forbidden unsafe execution directive at '{next_path}'")
            _check_forbidden_keys_recursive(val, errors, next_path, depth + 1)
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            _check_forbidden_keys_recursive(item, errors, f"{path}[{idx}]", depth + 1)


def _validate_opengrep(raw_text: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    doc = _safe_load_yaml(raw_text)
    _check_forbidden_keys_recursive(doc, errors)
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("OpenGrep YAML must define a non-empty 'rules' list")
        return doc, errors
    for idx, entry in enumerate(rules):
        if not isinstance(entry, dict):
            errors.append(f"OpenGrep rules[{idx}] must be a mapping")
            continue
        for req_key in ("id", "message", "severity", "languages"):
            if not entry.get(req_key):
                errors.append(f"OpenGrep rules[{idx}] missing required field '{req_key}'")
        if not any(k in entry for k in ("pattern", "patterns", "pattern-either", "pattern-regex")):
            errors.append(
                f"OpenGrep rules[{idx}] must specify 'pattern', 'patterns', "
                "'pattern-either', or 'pattern-regex'"
            )
        if "pattern-regex" in entry:
            _compile_safe_regex(str(entry["pattern-regex"]), f"rules[{idx}].pattern-regex", errors)
    return doc, errors


def _validate_nuclei(raw_text: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    doc = _safe_load_yaml(raw_text)
    _check_forbidden_keys_recursive(doc, errors)
    for bad_key in _FORBIDDEN_NUCLEI_BLOCKS:
        if bad_key in doc:
            errors.append(f"Forbidden Nuclei execution block '{bad_key}'")
    if not doc.get("id"):
        errors.append("Nuclei template missing 'id'")
    info = doc.get("info")
    if not isinstance(info, dict) or not info.get("name") or not info.get("severity"):
        errors.append("Nuclei template requires 'info.name' and 'info.severity'")
    protocols = ("http", "requests", "dns", "tcp", "network", "ssl")
    present_protos = [p for p in protocols if p in doc]
    if not present_protos:
        errors.append(
            "Nuclei template must define at least one supported protocol block (http/dns/tcp/ssl)"
        )
        return doc, errors
    for proto in present_protos:
        steps = doc.get(proto)
        if not isinstance(steps, list) or not steps:
            errors.append(f"Nuclei protocol '{proto}' must be a non-empty list")
            continue
        for idx, step in enumerate(steps):
            if not isinstance(step, dict) or not step.get("matchers"):
                errors.append(f"Nuclei {proto}[{idx}] requires non-empty 'matchers'")
                continue
            for m_idx, matcher in enumerate(step.get("matchers") or []):
                if isinstance(matcher, dict) and str(matcher.get("type", "")).lower() == "regex":
                    for pat in matcher.get("regex") or []:
                        _compile_safe_regex(
                            str(pat), f"{proto}[{idx}].matchers[{m_idx}].regex", errors
                        )
    return doc, errors


def _validate_checkov_yaml(raw_text: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    doc = _safe_load_yaml(raw_text)
    _check_forbidden_keys_recursive(doc, errors)
    meta = doc.get("metadata")
    if not isinstance(meta, dict) or not meta.get("id") or not meta.get("name"):
        errors.append("Checkov YAML policy requires 'metadata.id' and 'metadata.name'")
    if not isinstance(doc.get("definition"), dict):
        errors.append("Checkov YAML policy requires 'definition' mapping")
    return doc, errors


def _validate_checkov_python(raw_text: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    try:
        tree = ast.parse(raw_text)
    except SyntaxError as exc:
        return {}, [f"Invalid Python syntax: {exc.msg}"]
    has_check_class = False
    for stmt in tree.body:
        if not isinstance(
            stmt, (ast.Import, ast.ImportFrom, ast.ClassDef, ast.Assign, ast.AnnAssign)
        ):
            errors.append(
                f"Forbidden top-level statement '{type(stmt).__name__}' in Checkov Python check"
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root_pkg = alias.name.split(".")[0]
                if root_pkg not in _ALLOWED_PYTHON_ROOT_IMPORTS:
                    errors.append(
                        f"Disallowed import '{alias.name}' in Checkov Python check (allowlist only)"
                    )
        elif isinstance(node, ast.ImportFrom):
            root_pkg = (node.module or "").split(".")[0]
            if root_pkg not in _ALLOWED_PYTHON_ROOT_IMPORTS:
                errors.append(f"Disallowed import from '{node.module}' in Checkov Python check")
        elif isinstance(node, ast.Attribute) and node.attr.startswith("__"):
            errors.append(f"Forbidden dunder attribute '{node.attr}' in Checkov Python check")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_PYTHON_CALLS:
            errors.append(f"Forbidden identifier '{node.id}' in Checkov Python check")
        elif isinstance(node, ast.ClassDef):
            base_names = [getattr(b, "id", getattr(b, "attr", "")) for b in node.bases]
            if node.name.endswith("Check") or any("Check" in bn for bn in base_names):
                has_check_class = True
    if not has_check_class:
        errors.append(
            "Checkov Python check must define a *Check class inheriting BaseResourceCheck"
        )
    return {"ast_validated": len(errors) == 0}, errors


def _validate_gitleaks(raw_text: str, native_format: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    doc = tomllib.loads(raw_text) if native_format == "toml" else json.loads(raw_text)
    if not isinstance(doc, dict):
        return {}, ["Gitleaks configuration root must be a table/object"]
    rules = doc.get("rules")
    if not isinstance(rules, list) or not rules:
        errors.append("Gitleaks config requires non-empty 'rules' list")
        return doc, errors
    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"Gitleaks rules[{idx}] must be a mapping")
            continue
        if not rule.get("id") or not rule.get("description") or not rule.get("regex"):
            errors.append(f"Gitleaks rules[{idx}] requires 'id', 'description', and 'regex'")
        else:
            _compile_safe_regex(str(rule["regex"]), f"rules[{idx}].regex", errors)
        allowlist = rule.get("allowlist") or {}
        if isinstance(allowlist, dict):
            for p_idx, p_pat in enumerate(allowlist.get("paths") or []):
                _compile_safe_regex(str(p_pat), f"rules[{idx}].allowlist.paths[{p_idx}]", errors)
            for r_idx, r_pat in enumerate(allowlist.get("regexes") or []):
                _compile_safe_regex(str(r_pat), f"rules[{idx}].allowlist.regexes[{r_idx}]", errors)
    return doc, errors


def _validate_zap(raw_text: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    doc = _safe_load_yaml(raw_text)
    _check_forbidden_keys_recursive(doc, errors)
    env = doc.get("env")
    jobs = doc.get("jobs")
    if not isinstance(env, dict) or not isinstance(jobs, list) or not jobs:
        errors.append(
            "ZAP Automation Framework plan requires 'env' mapping and non-empty 'jobs' list"
        )
        return doc, errors
    for idx, job in enumerate(jobs):
        if not isinstance(job, dict) or not job.get("type"):
            errors.append(f"ZAP jobs[{idx}] must specify a 'type'")
            continue
        jtype = str(job["type"]).strip().lower()
        if jtype not in _ALLOWED_ZAP_JOB_TYPES:
            errors.append(f"ZAP job type '{job['type']}' is not allowlisted")
    for idx, flt in enumerate(doc.get("alertFilters") or []):
        if isinstance(flt, dict) and flt.get("headerRegex"):
            _compile_safe_regex(str(flt["headerRegex"]), f"alertFilters[{idx}].headerRegex", errors)
    return doc, errors


def _strip_lua_comments(raw_text: str) -> str:
    without_block = re.sub(r"--\[\[.*?\]\]", " ", raw_text, flags=re.DOTALL)
    return re.sub(r"--[^\n]*", " ", without_block)


def _validate_nmap_lua(raw_text: str) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    code_only = _strip_lua_comments(raw_text)
    lowered_code = re.sub(r"\s+", " ", code_only.lower())
    compact_code = re.sub(r"\s+", "", code_only.lower())
    for token in _FORBIDDEN_LUA_IDENTIFIERS:
        normalized_tok = token.replace(" ", "")
        if token in lowered_code or normalized_tok in compact_code:
            errors.append(f"Forbidden privileged Lua primitive '{token}' in NSE script")
    if "description" not in code_only or "categories" not in code_only:
        errors.append("Nmap NSE script must declare 'description' and 'categories'")
    if "portrule" not in code_only and "hostrule" not in code_only:
        errors.append("Nmap NSE script must define 'portrule' or 'hostrule'")
    if (
        "action =" not in lowered_code
        and "action=" not in compact_code
        and "function action" not in lowered_code
    ):
        errors.append("Nmap NSE script must define an 'action' function")
    categories: list[str] = []
    cat_matches = list(re.finditer(r"categories\s*=\s*\{([^}]*)\}", code_only))
    if not cat_matches:
        errors.append("Nmap NSE script must define literal categories table")
    for match in cat_matches:
        items = [c.strip().strip("\"'").lower() for c in match.group(1).split(",") if c.strip()]
        categories.extend(items)
        bad_cats = [c for c in items if c in _FORBIDDEN_NMAP_CATEGORIES]
        if bad_cats:
            errors.append(
                f"Nmap NSE forbidden categories {bad_cats}; "
                "intrusive/dos/exploit/brute scripts are blocked"
            )
    banner_match = re.search(r"banner_regex:\s*['\"]([^'\"]+)['\"]", raw_text)
    if banner_match:
        _compile_safe_regex(banner_match.group(1), "nmap.banner_regex", errors)
    return {"categories": categories}, errors


def validate_native_rule_content(
    *,
    engine: str,
    native_format: str,
    native_content: str,
) -> NativeValidationOutcome:
    """Parse and statically validate native scanner rule definitions fail-closed."""
    if not native_content or not native_content.strip():
        return NativeValidationOutcome(passed=False, errors=["native_content cannot be empty"])
    if len(native_content.encode("utf-8")) > _MAX_RULE_BYTES:
        return NativeValidationOutcome(
            passed=False, errors=[f"native_content exceeds {_MAX_RULE_BYTES} bytes budget"]
        )

    sha = compute_content_sha256(native_content)
    try:
        if engine == "opengrep":
            parsed, errors = _validate_opengrep(native_content)
        elif engine == "nuclei":
            parsed, errors = _validate_nuclei(native_content)
        elif engine == "checkov":
            if native_format == "python":
                parsed, errors = _validate_checkov_python(native_content)
            else:
                parsed, errors = _validate_checkov_yaml(native_content)
        elif engine == "gitleaks":
            parsed, errors = _validate_gitleaks(native_content, native_format)
        elif engine == "zap":
            parsed, errors = _validate_zap(native_content)
        elif engine == "nmap":
            parsed, errors = _validate_nmap_lua(native_content)
        else:
            return NativeValidationOutcome(
                passed=False, errors=[f"Unsupported engine '{engine}'"], content_sha256=sha
            )
    except (
        yaml.YAMLError,
        tomllib.TOMLDecodeError,
        json.JSONDecodeError,
        ValueError,
        RecursionError,
    ) as exc:
        return NativeValidationOutcome(
            passed=False,
            errors=[f"Failed to parse {engine}/{native_format} content: {exc}"],
            content_sha256=sha,
        )

    return NativeValidationOutcome(
        passed=len(errors) == 0,
        errors=errors,
        parsed_payload=parsed,
        content_sha256=sha,
    )


def validate_skill_definition(
    *,
    intent_description: str,
    allowed_capabilities: list[str],
    forbidden_actions: list[str],
    supported_agent_versions: list[str],
    playbook_steps: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Enforce least-privilege boundaries on constrained AssessmentSkill definitions."""
    if len(intent_description.strip()) < 10:
        raise ValidationError("Skill intent_description must clearly explain bounded purpose")
    if not allowed_capabilities:
        raise ValidationError("Skill must declare at least one allowed capability")
    if not supported_agent_versions:
        raise ValidationError("Skill must declare supported_agent_versions")
    if not playbook_steps:
        raise ValidationError("Skill must define non-empty playbook_steps")

    normalized_caps = [c.strip() for c in allowed_capabilities if c.strip()]
    bad_caps = [
        c
        for c in normalized_caps
        if c.lower().replace("-", "_") in FORBIDDEN_SKILL_CAPABILITIES or "*" in c
    ]
    if bad_caps:
        raise ValidationError(
            f"Skill cannot grant forbidden privileged capabilities: {sorted(set(bad_caps))}"
        )
    allowed_step_keys = {"step", "action", "capability", "description", "notes", "target"}
    for idx, step in enumerate(playbook_steps):
        if not isinstance(step, dict):
            raise ValidationError(f"Skill playbook_steps[{idx}] must be an object")
        unknown_keys = set(step.keys()) - allowed_step_keys
        if unknown_keys:
            raise ValidationError(
                f"Skill playbook_steps[{idx}] has disallowed fields: {sorted(unknown_keys)}"
            )
        for field_name in ("action", "capability"):
            raw_val = str(step.get(field_name, "")).strip().lower().replace("-", "_")
            if raw_val and (raw_val in FORBIDDEN_SKILL_CAPABILITIES or "*" in raw_val):
                raise ValidationError(
                    f"Skill playbook_steps[{idx}] cannot reference forbidden '{raw_val}'"
                )

    normalized_forbidden = sorted(
        {f.strip() for f in forbidden_actions if f.strip()} | set(REQUIRED_SKILL_FORBIDDEN_ACTIONS)
    )
    return normalized_caps, normalized_forbidden


def generate_native_rule_skeleton(engine: str, rule_key: str) -> dict[str, str]:
    """Provide clean starter native rule boilerplate for Rule Studio authoring."""
    safe_key = rule_key.strip() or "vf-custom-rule-001"
    if engine == "opengrep":
        return {
            "native_format": "yaml",
            "risk_class": "static",
            "native_content": (
                "rules:\n"
                f"  - id: {safe_key}\n"
                "    message: Detect unsafe dynamic eval usage\n"
                "    severity: HIGH\n"
                "    languages: [python]\n"
                "    patterns:\n"
                "      - pattern: 'eval(...)'\n"
                "      - pattern-not: 'ast.literal_eval(...)'\n"
            ),
        }
    if engine == "nuclei":
        return {
            "native_format": "yaml",
            "risk_class": "passive",
            "native_content": (
                f"id: {safe_key}\n"
                "info:\n"
                "  name: Exposed Internal Debug Header\n"
                "  severity: medium\n"
                "http:\n"
                "  - method: GET\n"
                "    path:\n"
                "      - '{{BaseURL}}/api/health'\n"
                "    matchers:\n"
                "      - type: word\n"
                "        words:\n"
                "          - 'X-Debug-Stacktrace:'\n"
            ),
        }
    if engine == "checkov":
        return {
            "native_format": "yaml",
            "risk_class": "static",
            "native_content": (
                "metadata:\n"
                f"  id: {safe_key}\n"
                "  name: Ensure S3 bucket public ACL is disabled\n"
                "definition:\n"
                "  resource_type: aws_s3_bucket\n"
                "  attribute: acl\n"
                "  operator: not_equals\n"
                "  value: public-read\n"
            ),
        }
    if engine == "gitleaks":
        return {
            "native_format": "toml",
            "risk_class": "static",
            "native_content": (
                "[[rules]]\n"
                f'id = "{safe_key}"\n'
                'description = "Internal Service Token"\n'
                'regex = "vf_live_[A-Za-z0-9]{24}"\n'
                "[rules.allowlist]\n"
                'regexes = ["vf_live_EXAMPLE_TEST_DO_NOT_USE"]\n'
            ),
        }
    if engine == "zap":
        return {
            "native_format": "yaml",
            "risk_class": "passive",
            "native_content": (
                "env:\n"
                "  contexts:\n"
                "    - name: default\n"
                "      urls: ['http://target.local']\n"
                "jobs:\n"
                "  - type: passiveScan-config\n"
                "  - type: passiveScan-wait\n"
                "alertFilters:\n"
                f"  - ruleKey: {safe_key}\n"
                "    headerRegex: 'Server:\\s*Werkzeug/'\n"
            ),
        }
    if engine == "nmap":
        return {
            "native_format": "lua",
            "risk_class": "privileged_network",
            "native_content": (
                f"description = [[Detects unauthenticated Redis banner for {safe_key}]]\n"
                'author = "vforge-studio"\n'
                'categories = {"safe", "discovery"}\n'
                "portrule = function(host, port) return port.number == 6379 end\n"
                "action = function(host, port)\n"
                "  -- banner_regex: '\\+PONG'\n"
                "  return nil\n"
                "end\n"
            ),
        }
    raise ValidationError(f"Unsupported engine '{engine}'")
