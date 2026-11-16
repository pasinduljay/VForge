"""Release monitor for digest-pinned lockfiles across VForge update streams."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.errors import ValidationError
from vforge.models import ToolCatalog, ToolVersion
from vforge.models.enums import UpdateAuditAction, UpdateChangeType, UpdateRunStatus

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def parse_digest_reference(image_ref: str) -> tuple[str, str]:
    """Validate and split a digest-pinned image reference into (repository, sha256:digest)."""
    cleaned = image_ref.strip()
    if "@" not in cleaned:
        raise ValidationError("Image reference must include an immutable @sha256: digest")
    repo_part, digest_part = cleaned.rsplit("@", 1)
    if not repo_part:
        raise ValidationError("Image repository cannot be empty")
    if not _DIGEST_RE.fullmatch(digest_part):
        raise ValidationError("Image digest must match ^sha256:[0-9a-f]{64}$")
    # Reject mutable :latest tag if a tag portion is present after the last slash
    tail = repo_part.rsplit("/", 1)[-1]
    if ":" in tail:
        tag = tail.rsplit(":", 1)[-1].strip().lower()
        if tag == "latest":
            raise ValidationError("Mutable ':latest' image tag is forbidden")
    return repo_part, digest_part


def validate_image_repository(image_repository: str) -> str:
    """Ensure image repository is non-empty and never uses a mutable :latest tag."""
    cleaned = image_repository.strip()
    if not cleaned or any(ch.isspace() for ch in cleaned):
        raise ValidationError("image_repository cannot be empty or contain whitespace")
    tail = cleaned.rsplit("/", 1)[-1]
    if ":" in tail and tail.rsplit(":", 1)[-1].strip().lower() == "latest":
        raise ValidationError("Mutable ':latest' image repository tag is strictly forbidden")
    if cleaned.lower().endswith(":latest"):
        raise ValidationError("Mutable ':latest' image repository tag is strictly forbidden")
    return cleaned


def validate_version_tag_and_digest(version_tag: str, image_digest: str) -> tuple[str, str]:
    """Enforce non-:latest semantic/date tag and strict sha256 digest."""
    tag = version_tag.strip()
    if not tag:
        raise ValidationError("version_tag cannot be empty")
    if tag.lower() == "latest" or tag.lower().endswith(":latest"):
        raise ValidationError("Mutable ':latest' version tag is strictly forbidden")
    digest = image_digest.strip().lower()
    if not _DIGEST_RE.fullmatch(digest):
        raise ValidationError("image_digest must match sha256:<64 lowercase hex chars>")
    return tag, digest


def validate_archive_sha256(archive_sha256: str) -> str:
    """Validate a raw 64-char lowercase hex SHA-256 checksum for feeds/bundles."""
    cleaned = archive_sha256.strip().lower()
    if cleaned.startswith("sha256:"):
        cleaned = cleaned.split(":", 1)[1]
    if not _SHA256_HEX_RE.fullmatch(cleaned):
        raise ValidationError("archive_sha256 must be a 64-character lowercase SHA-256 hex digest")
    return cleaned


def resolve_default_image_lock_dir() -> Path | None:
    """Locate repository lifecycle/image-lock directory if mounted/available."""
    candidates: list[Path] = [
        Path("/opt/lifecycle/image-lock"),
        Path("/app/lifecycle/image-lock"),
    ]
    for parent in Path(__file__).resolve().parents:
        candidates.append(parent / "lifecycle" / "image-lock")
    for path in candidates:
        if path.is_dir():
            return path
    return None


def inspect_image_lock_files(lock_dir: Path | None = None) -> list[dict[str, Any]]:
    """Inspect digest-pinned manifests in lifecycle/image-lock/*.json."""
    target_dir = lock_dir or resolve_default_image_lock_dir()
    if target_dir is None or not target_dir.is_dir():
        return []

    discovered: list[dict[str, Any]] = []
    for manifest_path in sorted(target_dir.glob("*-images.json")):
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        phase = payload.get("phase")
        for image in payload.get("images", []):
            name = str(image.get("name") or image.get("tool_id") or "").strip()
            repo = str(image.get("repository", "")).strip()
            tag = str(image.get("tag") or image.get("tool_version") or "").strip()
            digest = str(image.get("digest", "")).strip().lower()
            full_image_ref = str(image.get("image", "")).strip()
            if (not repo or not digest) and full_image_ref:
                parsed_repo, parsed_digest = parse_digest_reference(full_image_ref)
                repo = repo or parsed_repo
                digest = digest or parsed_digest
            channel = str(image.get("updateChannel", "scanner_engine_versions")).strip()
            if not name or not repo:
                continue
            repo = validate_image_repository(repo)
            valid_tag, valid_digest = validate_version_tag_and_digest(tag, digest)
            discovered.append(
                {
                    "tool_slug": name,
                    "phase": phase,
                    "image_repository": repo,
                    "version_tag": valid_tag,
                    "image_digest": valid_digest,
                    "update_channel": channel,
                    "approval_state": str(image.get("approvalState", "candidate")).strip(),
                    "source_file": manifest_path.name,
                }
            )
    return discovered


async def detect_candidates_from_image_locks(
    db: AsyncSession,
    *,
    lock_dir: Path | None = None,
    detected_from: str = "update-controller:image-lock",
) -> list[dict[str, Any]]:
    """Compare lifecycle image-lock manifests against catalog and register unseen digests."""
    from vforge.lifecycle.pipeline import record_audit_event

    entries = inspect_image_lock_files(lock_dir=lock_dir)
    created_candidates: list[dict[str, Any]] = []
    for entry in entries:
        tool = (
            await db.execute(select(ToolCatalog).where(ToolCatalog.tool_slug == entry["tool_slug"]))
        ).scalar_one_or_none()
        if tool is None:
            continue

        existing_ver = (
            await db.execute(
                select(ToolVersion).where(
                    ToolVersion.tool_id == tool.id,
                    ToolVersion.image_digest == entry["image_digest"],
                )
            )
        ).scalar_one_or_none()
        if existing_ver is not None:
            continue

        active_stable = (
            await db.execute(
                select(ToolVersion).where(
                    ToolVersion.tool_id == tool.id,
                    ToolVersion.is_active_stable.is_(True),
                )
            )
        ).scalar_one_or_none()

        from vforge.models import ToolUpdate

        candidate_ver = ToolVersion(
            tool_id=tool.id,
            version_tag=entry["version_tag"],
            image_repository=entry["image_repository"],
            image_digest=entry["image_digest"],
            approval_channel="candidate",
            signature_verified=False,
            metadata_json={"source_file": entry["source_file"], "phase": entry.get("phase")},
        )
        db.add(candidate_ver)
        await db.flush()

        update_row = ToolUpdate(
            tool_id=tool.id,
            candidate_version_id=candidate_ver.id,
            previous_version_id=active_stable.id if active_stable else None,
            stream=tool.stream,
            update_channel=tool.update_channel,
            change_type=UpdateChangeType.MINOR.value,
            status=UpdateRunStatus.DETECTED.value,
            detected_from=detected_from,
        )
        db.add(update_row)
        await db.flush()

        await record_audit_event(
            db,
            tool_id=tool.id,
            update_id=update_row.id,
            tool_version_id=candidate_ver.id,
            action=UpdateAuditAction.CANDIDATE_DETECTED,
            actor_user_id=None,
            actor_email="update-controller@vforge.local",
            reason=f"Detected new digest {entry['image_digest']} in {entry['source_file']}",
            details={
                "version_tag": entry["version_tag"],
                "image_digest": entry["image_digest"],
                "source_file": entry["source_file"],
            },
        )
        created_candidates.append(
            {
                "tool_slug": tool.tool_slug,
                "update_id": str(update_row.id),
                "version_id": str(candidate_ver.id),
                "version_tag": candidate_ver.version_tag,
                "image_digest": candidate_ver.image_digest,
            }
        )
    return created_candidates
