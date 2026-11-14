"""Static polyglot source language and manifest discovery without executing build hooks."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

_EXCLUDED_DIR_REASONS: dict[str, str] = {
    ".git": "vcs_metadata",
    "node_modules": "vendored_dependencies",
    "vendor": "vendored_dependencies",
    "venv": "local_virtualenv",
    ".venv": "local_virtualenv",
    "__pycache__": "python_bytecode_cache",
    "dist": "build_artifact",
    "build": "build_artifact",
    "target": "build_artifact",
    ".next": "framework_build_cache",
}

_EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
    ".c": "c_cpp",
    ".cc": "c_cpp",
    ".cpp": "c_cpp",
    ".h": "c_cpp",
    ".hpp": "c_cpp",
    ".cs": "csharp",
    ".swift": "swift",
    ".dart": "dart",
    ".sh": "shell",
    ".bash": "shell",
    ".ps1": "powershell",
    ".tf": "terraform",
    ".tfvars": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".sol": "solidity",
    ".cls": "apex",
    ".trigger": "apex",
    ".cbl": "cobol",
    ".cob": "cobol",
    ".zig": "zig",
}

_FILENAME_TO_LANGUAGE: dict[str, tuple[str, str | None]] = {
    "Dockerfile": ("dockerfile", "container"),
    "pyproject.toml": ("python", "pip/poetry"),
    "requirements.txt": ("python", "pip"),
    "poetry.lock": ("python", "poetry"),
    "package.json": ("javascript", "npm/pnpm/yarn"),
    "package-lock.json": ("javascript", "npm"),
    "pnpm-lock.yaml": ("javascript", "pnpm"),
    "tsconfig.json": ("typescript", "typescript"),
    "go.mod": ("go", "gomod"),
    "go.sum": ("go", "gomod"),
    "pom.xml": ("java", "maven"),
    "build.gradle": ("java", "gradle"),
    "composer.json": ("php", "composer"),
    "Gemfile": ("ruby", "bundler"),
    "Cargo.toml": ("rust", "cargo"),
    "pubspec.yaml": ("dart", "pub"),
}

_CONF_CONFIG_FILES = frozenset({"yaml", "json", "dockerfile", "terraform"})


@dataclass(frozen=True, slots=True)
class SourceDiscoveryReport:
    """Honest inventory of languages, manifests, analyzed files, and exclusions."""

    files_total_eligible: int
    files_skipped_symlinks: int
    files_truncated: bool
    languages: dict[str, int] = field(default_factory=dict)
    manifests_detected: tuple[str, ...] = ()
    ecosystems_detected: tuple[str, ...] = ()
    excluded_directories: dict[str, dict[str, int | str]] = field(default_factory=dict)


def detect_repository_languages(
    source_root: Path,
    *,
    max_files: int = 20_000,
) -> SourceDiscoveryReport:
    """Discover languages and package manifests read-only without running any user scripts."""
    if not source_root.exists() or not source_root.is_dir():
        return SourceDiscoveryReport(
            files_total_eligible=0,
            files_skipped_symlinks=0,
            files_truncated=False,
        )

    lang_counts: dict[str, int] = {}
    manifests: set[str] = set()
    ecosystems: set[str] = set()
    excluded_dirs: dict[str, dict[str, int | str]] = {}
    files_seen = 0
    symlinks_skipped = 0
    truncated = False

    resolved_root = source_root.resolve()
    for current_dir, dirnames, filenames in os.walk(resolved_root, followlinks=False):
        kept_dirs: list[str] = []
        for dirname in sorted(dirnames):
            dir_path = Path(current_dir) / dirname
            if dir_path.is_symlink():
                symlinks_skipped += 1
                continue
            reason = _EXCLUDED_DIR_REASONS.get(dirname)
            if reason is not None:
                entry = excluded_dirs.setdefault(reason, {"count": 0, "example": dirname})
                entry["count"] = int(entry["count"]) + 1
                continue
            kept_dirs.append(dirname)
        dirnames[:] = kept_dirs

        for filename in sorted(filenames):
            file_path = Path(current_dir) / filename
            if file_path.is_symlink():
                symlinks_skipped += 1
                continue
            if files_seen >= max_files:
                truncated = True
                break
            files_seen += 1

            if filename in _FILENAME_TO_LANGUAGE:
                manifest_lang, ecosystem = _FILENAME_TO_LANGUAGE[filename]
                rel = file_path.relative_to(resolved_root).as_posix()
                manifests.add(rel)
                if ecosystem:
                    ecosystems.add(ecosystem)
                if file_path.suffix == "":
                    lang_counts[manifest_lang] = lang_counts.get(manifest_lang, 0) + 1
                    continue

            suffix = file_path.suffix.lower()
            detected_lang = _EXTENSION_TO_LANGUAGE.get(suffix)
            if detected_lang is not None:
                lang_counts[detected_lang] = lang_counts.get(detected_lang, 0) + 1

        if truncated:
            break

    return SourceDiscoveryReport(
        files_total_eligible=files_seen,
        files_skipped_symlinks=symlinks_skipped,
        files_truncated=truncated,
        languages=dict(sorted(lang_counts.items())),
        manifests_detected=tuple(sorted(manifests)),
        ecosystems_detected=tuple(sorted(ecosystems)),
        excluded_directories=excluded_dirs,
    )


def is_config_only_language(language: str) -> bool:
    """Return True for config/IaC languages covered cleanly by IaC/secrets rather than SAST."""
    return language in _CONF_CONFIG_FILES
