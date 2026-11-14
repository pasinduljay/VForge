"""Safe source archive canonicalization and extraction preventing traversal, symlinks, and bombs."""

from __future__ import annotations

import io
import os
import posixpath
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

ArchiveFormat = Literal["archive_tar_gz", "archive_zip"]

_DEFAULT_MAX_COMPRESSED_BYTES = 20_971_520  # 20 MiB
_DEFAULT_MAX_EXTRACTED_BYTES = 52_428_800  # 50 MiB
_DEFAULT_MAX_FILES = 5_000
_DEFAULT_MAX_DEPTH = 24


class UnsafeArchiveError(ValueError):
    """Raised when a source archive violates path traversal, symlink, or quota limits."""


@dataclass(frozen=True, slots=True)
class CanonicalArchiveResult:
    """Validated canonical `.tar.gz` bytes and deterministic metrics."""

    canonical_tar_gz: bytes
    file_count: int
    total_bytes: int


def _normalize_archive_member_path(raw_name: str) -> str | None:
    """Validate and normalize relative archive member path, failing closed on traversal."""
    if "\x00" in raw_name:
        raise UnsafeArchiveError("Archive member path contains forbidden NUL byte")
    cleaned = raw_name.replace("\\", "/").strip()
    if not cleaned or cleaned in {".", "./"}:
        return None
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned:
        return None
    if cleaned.startswith("/") or ":" in cleaned.split("/", 1)[0]:
        raise UnsafeArchiveError(f"Absolute or drive-prefixed archive path rejected: {raw_name}")
    normalized = posixpath.normpath(cleaned)
    parts = [p for p in normalized.split("/") if p]
    if not parts or parts[0] == ".." or ".." in parts:
        raise UnsafeArchiveError(f"Path traversal member rejected: {raw_name}")
    if len(parts) > _DEFAULT_MAX_DEPTH:
        raise UnsafeArchiveError(
            f"Archive path depth exceeds limit ({_DEFAULT_MAX_DEPTH}): {raw_name}"
        )
    return "/".join(parts)


def _iter_validated_archive_files(
    archive_bytes: bytes,
    *,
    source_type: ArchiveFormat,
    max_compressed_bytes: int,
    max_extracted_bytes: int,
    max_files: int,
) -> list[tuple[str, bytes]]:
    if len(archive_bytes) > max_compressed_bytes:
        raise UnsafeArchiveError(
            f"Compressed archive exceeds max limit ({len(archive_bytes)} > {max_compressed_bytes})"
        )

    entries: dict[str, bytes] = {}
    total_bytes = 0

    if source_type == "archive_tar_gz":
        try:
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
                for member in tf.getmembers():
                    if (
                        member.issym()
                        or member.islnk()
                        or member.ischr()
                        or member.isblk()
                        or member.isfifo()
                    ):
                        raise UnsafeArchiveError(
                            f"Unsafe non-regular tar member rejected: {member.name}"
                        )
                    if member.isdir():
                        _normalize_archive_member_path(member.name)
                        continue
                    if not member.isreg():
                        raise UnsafeArchiveError(
                            f"Unsupported tar member type rejected: {member.name}"
                        )
                    rel = _normalize_archive_member_path(member.name)
                    if rel is None:
                        continue
                    if len(entries) >= max_files:
                        raise UnsafeArchiveError(
                            f"Archive exceeds maximum file limit ({max_files})"
                        )
                    if member.size < 0 or total_bytes + member.size > max_extracted_bytes:
                        raise UnsafeArchiveError(
                            f"Extracted size exceeds quota ({max_extracted_bytes} bytes)"
                        )
                    extracted = tf.extractfile(member)
                    if extracted is None:
                        raise UnsafeArchiveError(f"Could not read tar member: {member.name}")
                    data = extracted.read(max_extracted_bytes - total_bytes + 1)
                    if total_bytes + len(data) > max_extracted_bytes:
                        raise UnsafeArchiveError(
                            f"Extracted size exceeds quota ({max_extracted_bytes} bytes)"
                        )
                    total_bytes += len(data)
                    entries[rel] = data
        except tarfile.TarError as exc:
            raise UnsafeArchiveError(f"Invalid tar.gz archive: {exc}") from exc
    elif source_type == "archive_zip":
        try:
            with zipfile.ZipFile(io.BytesIO(archive_bytes), mode="r") as zf:
                for info in zf.infolist():
                    mode = info.external_attr >> 16
                    if stat.S_ISLNK(mode):
                        raise UnsafeArchiveError(f"Symlink zip member rejected: {info.filename}")
                    if info.is_dir():
                        _normalize_archive_member_path(info.filename)
                        continue
                    rel = _normalize_archive_member_path(info.filename)
                    if rel is None:
                        continue
                    if len(entries) >= max_files:
                        raise UnsafeArchiveError(
                            f"Archive exceeds maximum file limit ({max_files})"
                        )
                    if info.file_size < 0 or total_bytes + info.file_size > max_extracted_bytes:
                        raise UnsafeArchiveError(
                            f"Extracted size exceeds quota ({max_extracted_bytes} bytes)"
                        )
                    with zf.open(info, "r") as member_fp:
                        data = member_fp.read(max_extracted_bytes - total_bytes + 1)
                    if total_bytes + len(data) > max_extracted_bytes:
                        raise UnsafeArchiveError(
                            f"Extracted size exceeds quota ({max_extracted_bytes} bytes)"
                        )
                    total_bytes += len(data)
                    entries[rel] = data
        except zipfile.BadZipFile as exc:
            raise UnsafeArchiveError(f"Invalid zip archive: {exc}") from exc
    else:
        raise UnsafeArchiveError(f"Unsupported archive format: {source_type}")

    if not entries:
        raise UnsafeArchiveError("Source archive contains zero regular files")

    return sorted(entries.items(), key=lambda pair: pair[0])


def canonicalize_source_archive(
    archive_bytes: bytes,
    *,
    source_type: ArchiveFormat,
    max_compressed_bytes: int = _DEFAULT_MAX_COMPRESSED_BYTES,
    max_extracted_bytes: int = _DEFAULT_MAX_EXTRACTED_BYTES,
    max_files: int = _DEFAULT_MAX_FILES,
) -> CanonicalArchiveResult:
    """Validate and repackage a source archive into a deterministic canonical `.tar.gz`."""
    files = _iter_validated_archive_files(
        archive_bytes,
        source_type=source_type,
        max_compressed_bytes=max_compressed_bytes,
        max_extracted_bytes=max_extracted_bytes,
        max_files=max_files,
    )

    out_buf = io.BytesIO()
    total_bytes = 0
    with tarfile.open(fileobj=out_buf, mode="w:gz", compresslevel=6) as out_tar:
        for rel_path, data in files:
            total_bytes += len(data)
            info = tarfile.TarInfo(name=rel_path)
            info.size = len(data)
            info.mode = 0o444
            info.uid = 10001
            info.gid = 10001
            info.uname = "vforge"
            info.gname = "vforge"
            info.mtime = 0
            out_tar.addfile(info, io.BytesIO(data))

    return CanonicalArchiveResult(
        canonical_tar_gz=out_buf.getvalue(),
        file_count=len(files),
        total_bytes=total_bytes,
    )


def safe_extract_archive_bytes(
    archive_bytes: bytes,
    target_dir: Path,
    *,
    source_type: ArchiveFormat = "archive_tar_gz",
    max_compressed_bytes: int = _DEFAULT_MAX_COMPRESSED_BYTES,
    max_extracted_bytes: int = _DEFAULT_MAX_EXTRACTED_BYTES,
    max_files: int = _DEFAULT_MAX_FILES,
    read_only: bool = True,
) -> int:
    """Safely extract validated regular files into `target_dir` and return file count."""
    files = _iter_validated_archive_files(
        archive_bytes,
        source_type=source_type,
        max_compressed_bytes=max_compressed_bytes,
        max_extracted_bytes=max_extracted_bytes,
        max_files=max_files,
    )
    resolved_root = target_dir.resolve()
    resolved_root.mkdir(parents=True, exist_ok=True)
    created_dirs: set[Path] = set()

    for rel_path, data in files:
        dest = (resolved_root / rel_path).resolve()
        if not dest.is_relative_to(resolved_root):
            raise UnsafeArchiveError(f"Resolved path escapes target workspace: {rel_path}")
        dest.parent.mkdir(parents=True, exist_ok=True)
        created_dirs.add(dest.parent)
        dest.write_bytes(data)
        if read_only:
            try:
                os.chmod(dest, 0o444)
            except OSError:
                pass

    if read_only:
        for d in sorted(created_dirs, key=lambda p: len(p.parts), reverse=True):
            try:
                os.chmod(d, 0o555)  # noqa: S103
            except OSError:
                pass
    return len(files)
