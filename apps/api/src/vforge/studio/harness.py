"""Deterministic offline positive/negative/near-miss fixture execution harness."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from vforge.models.studio import StudioRule
from vforge.studio.validators import validate_native_rule_content


@dataclass(slots=True)
class RuleFixtureDetail:
    rule_key: str
    engine: str
    static_validation_passed: bool
    positive_passed: int
    positive_total: int
    negative_passed: int
    negative_total: int
    near_miss_passed: int
    near_miss_total: int
    false_positives: int
    false_negatives: int
    duration_ms: int
    failures: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_key": self.rule_key,
            "engine": self.engine,
            "static_validation_passed": self.static_validation_passed,
            "positive_passed": self.positive_passed,
            "positive_total": self.positive_total,
            "negative_passed": self.negative_passed,
            "negative_total": self.negative_total,
            "near_miss_passed": self.near_miss_passed,
            "near_miss_total": self.near_miss_total,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "duration_ms": self.duration_ms,
            "failures": self.failures,
        }


@dataclass(slots=True)
class FixtureEvaluationSummary:
    corpus_sha256: str
    total_positive: int
    passed_positive: int
    total_negative: int
    passed_negative: int
    total_near_miss: int
    passed_near_miss: int
    false_positives: int
    false_negatives: int
    total_duration_ms: int
    regression_passed: bool
    rule_results: list[dict[str, Any]]


def _compile_opengrep_pattern(pat: str) -> re.Pattern[str]:
    """Convert minimal Semgrep/OpenGrep '...' metawildcard into bounded regex."""
    escaped = re.escape(pat.strip())
    regex_text = escaped.replace(re.escape("..."), r"[^;\n]{0,160}")
    return re.compile(regex_text)


def _match_opengrep(parsed: dict[str, Any], fixture: dict[str, Any]) -> bool:
    content = str(fixture.get("content", ""))
    rule = (parsed.get("rules") or [{}])[0]
    if "pattern-regex" in rule:
        return bool(re.search(str(rule["pattern-regex"]), content, re.MULTILINE))
    if "pattern" in rule:
        return bool(_compile_opengrep_pattern(str(rule["pattern"])).search(content))
    if "pattern-either" in rule:
        for item in rule["pattern-either"]:
            if isinstance(item, dict) and "pattern" in item:
                if _compile_opengrep_pattern(str(item["pattern"])).search(content):
                    return True
        return False
    patterns = rule.get("patterns") or []
    positive_parts = [p["pattern"] for p in patterns if isinstance(p, dict) and "pattern" in p]
    not_parts = [p["pattern-not"] for p in patterns if isinstance(p, dict) and "pattern-not" in p]
    if not positive_parts:
        return False
    for line in content.splitlines() or [content]:
        if all(_compile_opengrep_pattern(str(p)).search(line) for p in positive_parts) and not any(
            _compile_opengrep_pattern(str(n)).search(line) for n in not_parts
        ):
            return True
    return False


def _match_gitleaks(parsed: dict[str, Any], fixture: dict[str, Any]) -> bool:
    content = str(fixture.get("content", ""))
    path_val = str(fixture.get("path", ""))
    rule = (parsed.get("rules") or [{}])[0]
    regex = re.compile(str(rule.get("regex", "(?!)")))
    allowlist = rule.get("allowlist") or {}
    for allow_path in allowlist.get("paths") or []:
        if re.search(str(allow_path), path_val):
            return False
    allow_regexes = [re.compile(str(r)) for r in (allowlist.get("regexes") or [])]
    for match in regex.finditer(content):
        token = match.group(0)
        if not any(ar.search(token) for ar in allow_regexes):
            return True
    return False


def _match_checkov(parsed: dict[str, Any], native_format: str, fixture: dict[str, Any]) -> bool:
    if native_format == "python":
        raise ValueError(
            "Checkov Python rules require isolated runner container verification; "
            "offline inline fixture harness supports declarative Checkov YAML only"
        )
    defn = parsed.get("definition") or {}
    res_type = str(defn.get("resource_type", ""))
    attr = str(defn.get("attribute", ""))
    op = str(defn.get("operator", "equals"))
    expected = defn.get("value")
    resource = fixture.get("resource") or {}
    if res_type and str(resource.get("type", res_type)) != res_type:
        return False
    actual = resource.get(attr)
    if op == "not_equals":
        return actual != expected
    if op == "equals":
        return actual == expected
    if op == "exists":
        return attr in resource and actual is not None
    if op == "not_exists":
        return attr not in resource or actual is None
    if op == "within" and isinstance(expected, list):
        return actual in expected
    return False


def _match_nuclei(parsed: dict[str, Any], fixture: dict[str, Any]) -> bool:
    protocols = ("http", "requests", "dns", "tcp", "network", "ssl")
    proto_key = next((p for p in protocols if isinstance(parsed.get(p), list)), "")
    if not proto_key:
        return False
    step = parsed[proto_key][0]
    matchers = step.get("matchers") or []
    overall_cond = str(step.get("matchers-condition", "and")).lower()
    body = str(fixture.get("response", fixture.get("content", "")))
    status_code = fixture.get("status_code")
    results: list[bool] = []
    for m in matchers:
        if not isinstance(m, dict):
            continue
        mtype = str(m.get("type", "word")).lower()
        cond = str(m.get("condition", "or")).lower()
        negative = bool(m.get("negative", False))
        matched = False
        if mtype == "word":
            words = [str(w) for w in (m.get("words") or [])]
            matched = (
                all(w in body for w in words) if cond == "and" else any(w in body for w in words)
            )
        elif mtype == "regex":
            pats = [str(p) for p in (m.get("regex") or [])]
            matched = (
                all(re.search(p, body) for p in pats)
                if cond == "and"
                else any(re.search(p, body) for p in pats)
            )
        elif mtype == "status":
            codes = [int(c) for c in (m.get("status") or [])]
            matched = status_code is not None and int(status_code) in codes
        results.append((not matched) if negative else matched)
    if not results:
        return False
    return all(results) if overall_cond == "and" else any(results)


def _match_zap(parsed: dict[str, Any], fixture: dict[str, Any]) -> bool:
    response = str(fixture.get("response", fixture.get("content", "")))
    filters = parsed.get("alertFilters") or []
    for flt in filters:
        if isinstance(flt, dict) and flt.get("headerRegex"):
            if re.search(str(flt["headerRegex"]), response, re.IGNORECASE | re.MULTILINE):
                return True
    return False


def _match_nmap(native_content: str, fixture: dict[str, Any]) -> bool:
    banner = str(fixture.get("banner", fixture.get("content", "")))
    port = fixture.get("port")
    port_req = re.search(r"port\.number\s*==\s*(\d+)", native_content)
    if port_req and port is not None and int(port) != int(port_req.group(1)):
        return False
    banner_req = re.search(r"banner_regex:\s*['\"]([^'\"]+)['\"]", native_content)
    if banner_req:
        return bool(re.search(banner_req.group(1), banner))
    return False


def _evaluate_fixture_match(
    *,
    engine: str,
    native_format: str,
    native_content: str,
    parsed: dict[str, Any],
    fixture: dict[str, Any],
) -> bool:
    if engine == "opengrep":
        return _match_opengrep(parsed, fixture)
    if engine == "gitleaks":
        return _match_gitleaks(parsed, fixture)
    if engine == "checkov":
        return _match_checkov(parsed, native_format, fixture)
    if engine == "nuclei":
        return _match_nuclei(parsed, fixture)
    if engine == "zap":
        return _match_zap(parsed, fixture)
    if engine == "nmap":
        return _match_nmap(native_content, fixture)
    return False


def evaluate_pack_version_fixtures(rules: list[StudioRule]) -> FixtureEvaluationSummary:
    """Execute deterministic positive, negative, and near-miss fixture checks per rule."""
    total_pos = passed_pos = 0
    total_neg = passed_neg = 0
    total_nm = passed_nm = 0
    false_pos = false_neg = 0
    total_ms = 0
    all_static_ok = bool(rules)
    budget_ok = True
    details: list[dict[str, Any]] = []
    corpus_records: list[dict[str, Any]] = []

    for rule in rules:
        t0 = time.perf_counter()
        val = validate_native_rule_content(
            engine=rule.engine,
            native_format=rule.native_format,
            native_content=rule.native_content,
        )
        failures = list(val.errors)
        if not val.passed:
            all_static_ok = False

        pos_list = list(rule.positive_fixtures_json or [])
        neg_list = list(rule.negative_fixtures_json or [])
        nm_list = list(rule.near_miss_fixtures_json or [])

        r_pos_pass = r_neg_pass = r_nm_pass = 0
        r_fp = r_fn = 0

        for idx, fx in enumerate(pos_list):
            try:
                matched = val.passed and _evaluate_fixture_match(
                    engine=rule.engine,
                    native_format=rule.native_format,
                    native_content=rule.native_content,
                    parsed=val.parsed_payload,
                    fixture=fx,
                )
            except (re.error, ValueError, TypeError) as exc:
                matched = False
                failures.append(f"positive[{idx}] evaluation error: {exc}")
            if matched:
                r_pos_pass += 1
            else:
                r_fn += 1
                failures.append(f"positive[{idx}] ({fx.get('name', 'unnamed')}) did not match")

        for idx, fx in enumerate(neg_list):
            try:
                matched = val.passed and _evaluate_fixture_match(
                    engine=rule.engine,
                    native_format=rule.native_format,
                    native_content=rule.native_content,
                    parsed=val.parsed_payload,
                    fixture=fx,
                )
            except (re.error, ValueError, TypeError) as exc:
                matched = True
                failures.append(f"negative[{idx}] evaluation error: {exc}")
            if not matched:
                r_neg_pass += 1
            else:
                r_fp += 1
                failures.append(f"negative[{idx}] ({fx.get('name', 'unnamed')}) false-positive")

        for idx, fx in enumerate(nm_list):
            try:
                matched = val.passed and _evaluate_fixture_match(
                    engine=rule.engine,
                    native_format=rule.native_format,
                    native_content=rule.native_content,
                    parsed=val.parsed_payload,
                    fixture=fx,
                )
            except (re.error, ValueError, TypeError) as exc:
                matched = True
                failures.append(f"near_miss[{idx}] evaluation error: {exc}")
            if not matched:
                r_nm_pass += 1
            else:
                r_fp += 1
                failures.append(f"near_miss[{idx}] ({fx.get('name', 'unnamed')}) false-positive")

        elapsed_ms = max(1, int((time.perf_counter() - t0) * 1000))
        if elapsed_ms > rule.timeout_seconds * 1000:
            budget_ok = False
            failures.append(
                f"Execution duration {elapsed_ms}ms exceeded timeout {rule.timeout_seconds}s"
            )

        total_pos += len(pos_list)
        passed_pos += r_pos_pass
        total_neg += len(neg_list)
        passed_neg += r_neg_pass
        total_nm += len(nm_list)
        passed_nm += r_nm_pass
        false_pos += r_fp
        false_neg += r_fn
        total_ms += elapsed_ms

        corpus_records.append(
            {
                "rule_key": rule.rule_key,
                "content_sha256": rule.content_sha256,
                "pos": pos_list,
                "neg": neg_list,
                "near_miss": nm_list,
            }
        )
        details.append(
            RuleFixtureDetail(
                rule_key=rule.rule_key,
                engine=rule.engine,
                static_validation_passed=val.passed,
                positive_passed=r_pos_pass,
                positive_total=len(pos_list),
                negative_passed=r_neg_pass,
                negative_total=len(neg_list),
                near_miss_passed=r_nm_pass,
                near_miss_total=len(nm_list),
                false_positives=r_fp,
                false_negatives=r_fn,
                duration_ms=elapsed_ms,
                failures=failures,
            ).to_dict()
        )

    corpus_bytes = json.dumps(corpus_records, sort_keys=True, separators=(",", ":")).encode("utf-8")
    corpus_sha256 = hashlib.sha256(corpus_bytes).hexdigest()
    regression_passed = (
        all_static_ok
        and budget_ok
        and total_pos > 0
        and total_neg > 0
        and total_nm > 0
        and false_pos == 0
        and false_neg == 0
        and passed_pos == total_pos
        and passed_neg == total_neg
        and passed_nm == total_nm
    )
    return FixtureEvaluationSummary(
        corpus_sha256=corpus_sha256,
        total_positive=total_pos,
        passed_positive=passed_pos,
        total_negative=total_neg,
        passed_negative=passed_neg,
        total_near_miss=total_nm,
        passed_near_miss=passed_nm,
        false_positives=false_pos,
        false_negatives=false_neg,
        total_duration_ms=total_ms,
        regression_passed=regression_passed,
        rule_results=details,
    )
