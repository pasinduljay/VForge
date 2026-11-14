"""Polyglot language & scanner capability registry enforcing honest partial coverage reporting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from vforge_scanners.languages import SourceDiscoveryReport, is_config_only_language

SupportStatus = Literal["supported", "partial", "unsupported"]


@dataclass(frozen=True, slots=True)
class LanguageCapabilityRecord:
    """Explicit analyzer coverage declaration per language and tool (Architecture §23.2)."""

    language: str
    tool_id: str
    support_status: SupportStatus
    parser_mode: str
    supported_versions: str
    known_blind_spots: str
    last_validated: str = "2026-11-12"


CAPABILITY_REGISTRY: tuple[LanguageCapabilityRecord, ...] = (
    LanguageCapabilityRecord(
        language="python",
        tool_id="opengrep",
        support_status="supported",
        parser_mode="ast-pattern+taint",
        supported_versions="3.8-3.13",
        known_blind_spots=(
            "Dynamic getattr reflection and runtime metaclasses require DAST verification."
        ),
    ),
    LanguageCapabilityRecord(
        language="javascript",
        tool_id="opengrep",
        support_status="supported",
        parser_mode="ast-pattern+taint",
        supported_versions="ES2018-ES2024",
        known_blind_spots=(
            "Bundled/minified output and dynamic require() paths are out of baseline scope."
        ),
    ),
    LanguageCapabilityRecord(
        language="typescript",
        tool_id="opengrep",
        support_status="supported",
        parser_mode="ast-pattern+taint",
        supported_versions="4.x-5.x",
        known_blind_spots=("Cross-module type resolution without tsc relies on local AST rules."),
    ),
    LanguageCapabilityRecord(
        language="go",
        tool_id="opengrep",
        support_status="supported",
        parser_mode="ast-pattern",
        supported_versions="1.20-1.24",
        known_blind_spots="CGo native bindings and build-tag gated files are partially covered.",
    ),
    LanguageCapabilityRecord(
        language="java",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="11-21",
        known_blind_spots=(
            "Complex Spring/CDI annotation wiring needs dedicated bytecode/CodeQL rules."
        ),
    ),
    LanguageCapabilityRecord(
        language="kotlin",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="1.9-2.x",
        known_blind_spots="DSL reflection requires Kotlin compiler frontend plugins.",
    ),
    LanguageCapabilityRecord(
        language="php",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="8.1-8.4",
        known_blind_spots="Dynamic include/autoload magic requires PHP specialist rules.",
    ),
    LanguageCapabilityRecord(
        language="ruby",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="3.1-3.4",
        known_blind_spots="Rails metaprogramming needs Brakeman benchmark comparison.",
    ),
    LanguageCapabilityRecord(
        language="csharp",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions=".NET 8-9",
        known_blind_spots="Roslyn semantic analysis not included in Phase 5 baseline.",
    ),
    LanguageCapabilityRecord(
        language="rust",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="2021-2024 edition",
        known_blind_spots=(
            "Macro-expanded unsafe blocks require macro expansion checks and Cargo SCA."
        ),
    ),
    LanguageCapabilityRecord(
        language="c_cpp",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="C11/C++20",
        known_blind_spots=(
            "Preprocessor macro paths and pointer alias analysis require compiler SAST."
        ),
    ),
    LanguageCapabilityRecord(
        language="shell",
        tool_id="opengrep",
        support_status="partial",
        parser_mode="ast-pattern",
        supported_versions="POSIX/Bash",
        known_blind_spots="Dedicated ShellCheck integration is planned beyond Phase 5.",
    ),
    LanguageCapabilityRecord(
        language="solidity",
        tool_id="opengrep",
        support_status="unsupported",
        parser_mode="none",
        supported_versions="none",
        known_blind_spots=(
            "Smart-contract EVM semantics require dedicated Solidity analyzers (unsupported)."
        ),
    ),
    LanguageCapabilityRecord(
        language="apex",
        tool_id="opengrep",
        support_status="unsupported",
        parser_mode="none",
        supported_versions="none",
        known_blind_spots="Salesforce Apex parser is not supported in Phase 5.",
    ),
    LanguageCapabilityRecord(
        language="cobol",
        tool_id="opengrep",
        support_status="unsupported",
        parser_mode="none",
        supported_versions="none",
        known_blind_spots="Mainframe COBOL is unsupported.",
    ),
    LanguageCapabilityRecord(
        language="zig",
        tool_id="opengrep",
        support_status="unsupported",
        parser_mode="none",
        supported_versions="none",
        known_blind_spots="Zig parser is unsupported.",
    ),
    LanguageCapabilityRecord(
        language="terraform",
        tool_id="checkov",
        support_status="supported",
        parser_mode="hcl2-graph",
        supported_versions="0.12-1.10",
        known_blind_spots=("Remote registry modules are not fetched during offline execution."),
    ),
    LanguageCapabilityRecord(
        language="dockerfile",
        tool_id="checkov",
        support_status="supported",
        parser_mode="dockerfile-ast",
        supported_versions="all",
        known_blind_spots="Base-image OS package CVEs require Syft + Grype SCA stage.",
    ),
    LanguageCapabilityRecord(
        language="yaml",
        tool_id="checkov",
        support_status="partial",
        parser_mode="yaml-iac",
        supported_versions="1.1-1.2",
        known_blind_spots=(
            "K8s, CloudFormation, and GHA YAML evaluated; plain YAML config skipped."
        ),
    ),
    LanguageCapabilityRecord(
        language="json",
        tool_id="checkov",
        support_status="partial",
        parser_mode="json-iac",
        supported_versions="all",
        known_blind_spots=("CloudFormation, ARM, and TFPlan JSON evaluated; plain JSON skipped."),
    ),
    LanguageCapabilityRecord(
        language="python",
        tool_id="syft",
        support_status="supported",
        parser_mode="lockfile-manifest",
        supported_versions="pip/poetry",
        known_blind_spots="Transitive dependencies need locked requirements/poetry.lock.",
    ),
    LanguageCapabilityRecord(
        language="javascript",
        tool_id="syft",
        support_status="supported",
        parser_mode="lockfile-manifest",
        supported_versions="npm/pnpm/yarn",
        known_blind_spots=(
            "Unpinned semver ranges in package.json without lockfiles may miss transitives."
        ),
    ),
    LanguageCapabilityRecord(
        language="go",
        tool_id="syft",
        support_status="supported",
        parser_mode="gomod-parser",
        supported_versions="1.18-1.24",
        known_blind_spots="Private vendored forks outside go.mod/go.sum require source review.",
    ),
)

_BY_LANG: dict[str, list[LanguageCapabilityRecord]] = {}
for _rec in CAPABILITY_REGISTRY:
    _BY_LANG.setdefault(_rec.language, []).append(_rec)


def evaluate_coverage(
    discovery: SourceDiscoveryReport,
    *,
    selected_tools: tuple[str, ...] | list[str] = ("opengrep", "gitleaks"),
) -> dict[str, Any]:
    """Compute honest coverage status & blind spots per Architecture §23.4.

    A repository containing any language without full compatible analyzer support
    never reports 'complete' — it reports 'partial' with explicit unsupported items.
    """
    tools = {t.strip().lower() for t in selected_tools if t.strip()}
    supported_langs: list[str] = []
    partial_langs: list[str] = []
    unsupported_langs: list[str] = []
    blind_spots: list[dict[str, str]] = []

    has_opengrep = "opengrep" in tools
    has_gitleaks = "gitleaks" in tools
    has_checkov = "checkov" in tools
    has_supply_chain = bool({"syft", "grype"} & tools)

    for lang, count in discovery.languages.items():
        if count <= 0:
            continue
        if is_config_only_language(lang):
            if has_checkov:
                iac_records = [r for r in _BY_LANG.get(lang, []) if r.tool_id == "checkov"]
                if any(r.support_status == "supported" for r in iac_records):
                    supported_langs.append(lang)
                    for r in iac_records:
                        if r.support_status == "supported":
                            blind_spots.append(
                                {
                                    "language": lang,
                                    "status": "supported",
                                    "reason": r.known_blind_spots,
                                }
                            )
                elif iac_records:
                    partial_langs.append(lang)
                    for r in iac_records:
                        blind_spots.append(
                            {
                                "language": lang,
                                "status": "partial",
                                "reason": r.known_blind_spots,
                            }
                        )
                else:
                    partial_langs.append(lang)
            elif has_gitleaks:
                partial_langs.append(lang)
                blind_spots.append(
                    {
                        "language": lang,
                        "status": "partial",
                        "reason": (
                            "Secrets scanning active; run Checkov IaC stage for policy evaluation."
                        ),
                    }
                )
            else:
                unsupported_langs.append(lang)
            continue

        records = [r for r in _BY_LANG.get(lang, []) if r.tool_id in tools]
        if any(r.support_status == "supported" for r in records) and has_opengrep:
            supported_langs.append(lang)
            for r in records:
                if r.support_status == "supported":
                    blind_spots.append(
                        {"language": lang, "status": "supported", "reason": r.known_blind_spots}
                    )
        elif any(r.support_status == "partial" for r in records):
            partial_langs.append(lang)
            for r in records:
                if r.support_status == "partial":
                    blind_spots.append(
                        {"language": lang, "status": "partial", "reason": r.known_blind_spots}
                    )
        else:
            unsupported_langs.append(lang)
            reason = (
                next((r.known_blind_spots for r in _BY_LANG.get(lang, [])), None)
                or f"No compatible SAST/language analyzer selected for '{lang}'."
            )
            blind_spots.append({"language": lang, "status": "unsupported", "reason": reason})

    if discovery.files_total_eligible == 0:
        overall = "not_applicable"
    elif unsupported_langs or partial_langs or discovery.files_truncated:
        overall = "partial"
    elif supported_langs:
        overall = "complete"
    elif has_gitleaks or has_supply_chain or has_checkov:
        overall = "partial"
    else:
        overall = "failed"

    return {
        "assessment_coverage_status": overall,
        "selected_tools": sorted(tools),
        "files_total_eligible": discovery.files_total_eligible,
        "files_skipped_symlinks": discovery.files_skipped_symlinks,
        "files_truncated": discovery.files_truncated,
        "detected_languages": discovery.languages,
        "supported_languages": sorted(supported_langs),
        "partial_languages": sorted(partial_langs),
        "unsupported_languages": sorted(unsupported_langs),
        "manifests_detected": list(discovery.manifests_detected),
        "ecosystems_detected": list(discovery.ecosystems_detected),
        "excluded_directories": discovery.excluded_directories,
        "blind_spots": blind_spots,
        "notes": (
            "Partially assessed: unsupported or partial language coverage detected."
            if overall == "partial"
            else "All detected source languages are covered by selected baseline analyzers."
        ),
    }
