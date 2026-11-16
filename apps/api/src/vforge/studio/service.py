"""Phase 11 Rule & Skill Studio service with SoD, Ed25519 signing, and rollback."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from vforge.ai_gateway.rule_author import GovernedRuleAuthorGateway
from vforge.config import Settings, get_settings
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.models.enums import (
    SemverChangeType,
    StudioActorType,
    StudioAuditAction,
    StudioChannel,
    StudioCreationMethod,
    StudioReviewStatus,
)
from vforge.models.studio import (
    AssessmentSkill,
    RuleFixtureRun,
    RulePack,
    RulePackVersion,
    SkillVersion,
    StudioAuditEvent,
    StudioRule,
)
from vforge.security.signing import SnapshotSigner, compute_payload_sha256
from vforge.studio.ai_author import RuleAuthorGateway
from vforge.studio.harness import evaluate_pack_version_fixtures
from vforge.studio.validators import (
    validate_native_rule_content,
    validate_rule_metadata,
    validate_semver,
    validate_skill_definition,
)


def _assert_human_operator(actor_type: str, action: str) -> None:
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError(
            f"AI or non-human actors ('{actor_type}') are forbidden from '{action}'"
        )


def _record_audit(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    entity_type: str,
    entity_id: uuid.UUID,
    action: StudioAuditAction,
    actor_id: uuid.UUID | None,
    actor_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    previous_state: str | None = None,
    new_state: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        StudioAuditEvent(
            id=uuid.uuid4(),
            organization_id=organization_id,
            entity_type=entity_type,
            entity_id=entity_id,
            action=action.value,
            actor_id=actor_id,
            actor_email=actor_email,
            actor_type=actor_type,
            previous_state=previous_state,
            new_state=new_state,
            details_json=details or {},
        )
    )


async def create_rule_pack(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    slug: str,
    title: str,
    description: str,
    owner_team: str,
    actor_id: uuid.UUID,
    actor_email: str,
) -> RulePack:
    clean_slug = slug.strip().lower()
    existing = (
        await db.execute(
            select(RulePack).where(
                RulePack.organization_id == organization_id,
                RulePack.slug == clean_slug,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(f"RulePack slug '{clean_slug}' already exists in this organization")

    pack = RulePack(
        id=uuid.uuid4(),
        organization_id=organization_id,
        slug=clean_slug,
        title=title.strip(),
        description=description.strip(),
        owner_team=owner_team.strip() or "security-engineering",
        created_by=actor_id,
        is_active=True,
    )
    db.add(pack)
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack",
        entity_id=pack.id,
        action=StudioAuditAction.PACK_CREATED,
        actor_id=actor_id,
        actor_email=actor_email,
        new_state="active",
        details={"slug": clean_slug, "title": pack.title},
    )
    return pack


async def _load_pack_version_locked(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
) -> RulePackVersion:
    ver = (
        await db.execute(
            select(RulePackVersion)
            .where(
                RulePackVersion.organization_id == organization_id,
                RulePackVersion.id == version_id,
            )
            .options(
                selectinload(RulePackVersion.rules),
                selectinload(RulePackVersion.fixture_runs),
                selectinload(RulePackVersion.rule_pack),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if ver is None:
        raise NotFoundError(f"RulePackVersion {version_id} not found")
    return ver


def _build_rule_entities(
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    rule_items: list[dict[str, Any]],
) -> tuple[list[StudioRule], list[str]]:
    if not rule_items:
        raise ValidationError("A RulePackVersion must contain at least one rule")
    seen_keys: set[str] = set()
    rules: list[StudioRule] = []
    all_errors: list[str] = []

    for item in rule_items:
        rule_key = str(item["rule_key"]).strip()
        if rule_key in seen_keys:
            raise ValidationError(f"Duplicate rule_key '{rule_key}' in rule pack version")
        seen_keys.add(rule_key)

        pos_fx = list(item.get("positive_fixtures") or [])
        neg_fx = list(item.get("negative_fixtures") or [])
        nm_fx = list(item.get("near_miss_fixtures") or [])
        ev_fields = [str(f) for f in (item.get("expected_evidence_fields") or [])]

        validate_rule_metadata(
            rule_key=rule_key,
            engine=str(item["engine"]),
            native_format=str(item["native_format"]),
            risk_class=str(item["risk_class"]),
            cwe_id=str(item["cwe_id"]),
            rationale=str(item["rationale"]),
            known_limitations=str(item["known_limitations"]),
            positive_fixtures=pos_fx,
            negative_fixtures=neg_fx,
            near_miss_fixtures=nm_fx,
            expected_evidence_fields=ev_fields,
        )
        outcome = validate_native_rule_content(
            engine=str(item["engine"]),
            native_format=str(item["native_format"]),
            native_content=str(item["native_content"]),
        )
        if not outcome.passed:
            all_errors.extend([f"{rule_key}: {e}" for e in outcome.errors])

        rules.append(
            StudioRule(
                id=uuid.uuid4(),
                organization_id=organization_id,
                rule_pack_version_id=version_id,
                rule_key=rule_key,
                title=str(item["title"]).strip(),
                engine=str(item["engine"]),
                native_format=str(item["native_format"]),
                risk_class=str(item["risk_class"]),
                severity=str(item["severity"]),
                confidence=str(item["confidence"]),
                cwe_id=str(item["cwe_id"]).strip(),
                rationale=str(item["rationale"]).strip(),
                target_context=str(item.get("target_context") or "source_code").strip(),
                network_requirements=str(item.get("network_requirements") or "none").strip(),
                known_limitations=str(item["known_limitations"]).strip(),
                timeout_seconds=int(item.get("timeout_seconds") or 30),
                memory_budget_mb=int(item.get("memory_budget_mb") or 256),
                native_content=str(item["native_content"]),
                content_sha256=outcome.content_sha256,
                positive_fixtures_json=pos_fx,
                negative_fixtures_json=neg_fx,
                near_miss_fixtures_json=nm_fx,
                expected_evidence_fields=ev_fields,
                static_validation_passed=outcome.passed,
                static_validation_errors=outcome.errors,
            )
        )
    return rules, all_errors


async def create_rule_pack_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    rule_pack_id: uuid.UUID,
    version: str,
    semver_change_type: str,
    compatibility: dict[str, str],
    rules_payload: list[dict[str, Any]],
    actor_id: uuid.UUID,
    actor_email: str,
    creation_method: str = StudioCreationMethod.HUMAN.value,
    actor_type: str = StudioActorType.HUMAN.value,
    ai_provenance: dict[str, Any] | None = None,
) -> RulePackVersion:
    validate_semver(version)
    if semver_change_type not in {m.value for m in SemverChangeType}:
        raise ValidationError(f"Unsupported semver_change_type '{semver_change_type}'")

    pack = (
        await db.execute(
            select(RulePack)
            .where(
                RulePack.organization_id == organization_id,
                RulePack.id == rule_pack_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if pack is None:
        raise NotFoundError(f"RulePack {rule_pack_id} not found")

    dup = (
        await db.execute(
            select(RulePackVersion).where(
                RulePackVersion.organization_id == organization_id,
                RulePackVersion.rule_pack_id == rule_pack_id,
                RulePackVersion.version == version.strip(),
            )
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise ConflictError(
            f"Version '{version}' already exists for RulePack '{pack.slug}'; "
            "signed/released versions are immutable"
        )

    ver_id = uuid.uuid4()
    rule_objs, static_errors = _build_rule_entities(
        organization_id=organization_id,
        version_id=ver_id,
        rule_items=rules_payload,
    )
    if static_errors:
        raise ValidationError("Native rule static validation failed: " + "; ".join(static_errors))

    pack_ver = RulePackVersion(
        id=ver_id,
        organization_id=organization_id,
        rule_pack_id=rule_pack_id,
        version=version.strip(),
        semver_change_type=semver_change_type,
        channel=StudioChannel.DRAFT.value,
        review_status=StudioReviewStatus.DRAFT.value,
        creation_method=creation_method,
        author_id=actor_id,
        author_actor_type=actor_type,
        compatibility_json=dict(compatibility or {}),
        validation_summary_json={"static_validation_passed": True, "rule_count": len(rule_objs)},
        ai_provenance_json=dict(ai_provenance or {}),
    )
    db.add(pack_ver)
    for r in rule_objs:
        db.add(r)
    await db.flush()

    action = (
        StudioAuditAction.AI_DRAFT_GENERATED
        if creation_method == StudioCreationMethod.AI_ASSISTED.value
        else StudioAuditAction.VERSION_CREATED
    )
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=ver_id,
        action=action,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_type=actor_type,
        new_state=StudioReviewStatus.DRAFT.value,
        details={"pack_slug": pack.slug, "version": pack_ver.version, "rule_count": len(rule_objs)},
    )
    return await _load_pack_version_locked(db, organization_id=organization_id, version_id=ver_id)


async def generate_ai_candidate_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    rule_pack_id: uuid.UUID,
    version: str,
    engine: str,
    rule_key: str,
    title: str,
    cwe_id: str,
    target_context: str,
    untrusted_source_snippet: str,
    actor_id: uuid.UUID,
    actor_email: str,
    gateway: RuleAuthorGateway | None = None,
) -> RulePackVersion:
    """Create an AI-assisted candidate RulePackVersion via the Phase 12 Governed Gateway."""
    author_gw = gateway or GovernedRuleAuthorGateway()
    generated = author_gw.generate_rule_candidate(
        engine=engine,
        rule_key=rule_key,
        title=title,
        cwe_id=cwe_id,
        target_context=target_context,
        untrusted_source_snippet=untrusted_source_snippet,
    )
    return await create_rule_pack_version(
        db,
        organization_id=organization_id,
        rule_pack_id=rule_pack_id,
        version=version,
        semver_change_type=SemverChangeType.MINOR.value,
        compatibility={engine: ">=pinned"},
        rules_payload=generated.rules,
        actor_id=actor_id,
        actor_email=actor_email,
        creation_method=StudioCreationMethod.AI_ASSISTED.value,
        actor_type=StudioActorType.AI_AGENT.value,
        ai_provenance=generated.provenance,
    )


async def run_version_fixtures(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    corpus_ref: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
) -> RuleFixtureRun:
    ver = await _load_pack_version_locked(
        db, organization_id=organization_id, version_id=version_id
    )
    if ver.signed_at is not None:
        raise ConflictError("Signed RulePackVersion is immutable; create a new version to re-test")

    summary = evaluate_pack_version_fixtures(list(ver.rules))
    run_row = RuleFixtureRun(
        id=uuid.uuid4(),
        organization_id=organization_id,
        rule_pack_version_id=ver.id,
        corpus_ref=corpus_ref.strip() or "inline-pack-corpus",
        corpus_sha256=summary.corpus_sha256,
        executed_by=actor_id,
        actor_type=actor_type,
        total_positive=summary.total_positive,
        passed_positive=summary.passed_positive,
        total_negative=summary.total_negative,
        passed_negative=summary.passed_negative,
        total_near_miss=summary.total_near_miss,
        passed_near_miss=summary.passed_near_miss,
        false_positives=summary.false_positives,
        false_negatives=summary.false_negatives,
        total_duration_ms=summary.total_duration_ms,
        regression_passed=summary.regression_passed,
        rule_results_json=summary.rule_results,
    )
    db.add(run_row)

    ver.fixture_regression_passed = summary.regression_passed
    ver.true_positive_count = summary.passed_positive
    ver.false_positive_count = summary.false_positives
    ver.false_negative_count = summary.false_negatives
    ver.validation_summary_json = {
        **(ver.validation_summary_json or {}),
        "latest_corpus_sha256": summary.corpus_sha256,
        "regression_passed": summary.regression_passed,
        "false_positives": summary.false_positives,
        "false_negatives": summary.false_negatives,
        "duration_ms": summary.total_duration_ms,
    }
    await db.flush()

    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=ver.id,
        action=StudioAuditAction.FIXTURES_EXECUTED,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_type=actor_type,
        new_state="passed" if summary.regression_passed else "failed",
        details={
            "corpus_sha256": summary.corpus_sha256,
            "false_positives": summary.false_positives,
            "false_negatives": summary.false_negatives,
        },
    )
    return run_row


async def submit_rule_pack_version_for_review(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_email: str,
) -> RulePackVersion:
    ver = await _load_pack_version_locked(
        db, organization_id=organization_id, version_id=version_id
    )
    if ver.signed_at is not None:
        raise ConflictError("Signed version cannot be resubmitted for review")
    if ver.review_status == StudioReviewStatus.APPROVED.value:
        raise ConflictError("Approved RulePackVersion cannot be resubmitted for review")
    if not ver.fixture_regression_passed:
        raise ConflictError(
            "Positive/negative/near-miss fixture regression must pass before requesting review"
        )
    if ver.false_positive_count > 0 or ver.false_negative_count > 0:
        raise ConflictError("Fixture false positives/negatives block review submission")

    prev = ver.review_status
    ver.review_status = StudioReviewStatus.PENDING_REVIEW.value
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=ver.id,
        action=StudioAuditAction.REVIEW_REQUESTED,
        actor_id=actor_id,
        actor_email=actor_email,
        previous_state=prev,
        new_state=ver.review_status,
    )
    return ver


async def review_rule_pack_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    decision: str,
    comment: str | None,
    reviewer_id: uuid.UUID,
    reviewer_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
) -> RulePackVersion:
    _assert_human_operator(actor_type, "review_rule_pack_version")
    ver = await _load_pack_version_locked(
        db, organization_id=organization_id, version_id=version_id
    )
    if ver.signed_at is not None:
        raise ConflictError("Signed version review status is immutable")
    if ver.review_status != StudioReviewStatus.PENDING_REVIEW.value:
        raise ConflictError(
            "RulePackVersion must be in 'pending_review' state before review decision"
        )
    if reviewer_id == ver.author_id:
        raise ForbiddenError(
            "Segregation of duties: rule author cannot review or approve their own version"
        )

    prev = ver.review_status
    now = datetime.now(UTC)
    if decision == "approved":
        if not ver.fixture_regression_passed:
            raise ConflictError("Fixture regression must pass before approval")
        if ver.false_positive_count > 0 or ver.false_negative_count > 0:
            raise ConflictError("Regression false positives/negatives block approval")
        ver.review_status = StudioReviewStatus.APPROVED.value
        ver.reviewer_id = reviewer_id
        ver.approved_at = now
        ver.rejection_reason = None
        audit_action = StudioAuditAction.REVIEW_APPROVED
    elif decision == "rejected":
        ver.review_status = StudioReviewStatus.REJECTED.value
        ver.reviewer_id = reviewer_id
        ver.approved_at = None
        ver.rejection_reason = (comment or "Rejected by reviewer").strip()
        audit_action = StudioAuditAction.REVIEW_REJECTED
    elif decision == "changes_requested":
        ver.review_status = StudioReviewStatus.CHANGES_REQUESTED.value
        ver.reviewer_id = reviewer_id
        ver.approved_at = None
        ver.rejection_reason = (comment or "Changes requested").strip()
        audit_action = StudioAuditAction.REVIEW_CHANGES_REQUESTED
    else:
        raise ValidationError("decision must be 'approved', 'rejected', or 'changes_requested'")

    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=ver.id,
        action=audit_action,
        actor_id=reviewer_id,
        actor_email=reviewer_email,
        previous_state=prev,
        new_state=ver.review_status,
        details={"comment": comment or ""},
    )
    return ver


def _build_pack_manifest_payload(ver: RulePackVersion) -> dict[str, Any]:
    return {
        "schema_version": "vforge.rulepack.v1",
        "organization_id": str(ver.organization_id),
        "rule_pack_id": str(ver.rule_pack_id),
        "rule_pack_version_id": str(ver.id),
        "pack_slug": ver.rule_pack.slug,
        "version": ver.version,
        "semver_change_type": ver.semver_change_type,
        "creation_method": ver.creation_method,
        "author_id": str(ver.author_id),
        "reviewer_id": str(ver.reviewer_id) if ver.reviewer_id else None,
        "fixture_regression_passed": ver.fixture_regression_passed,
        "compatibility": ver.compatibility_json,
        "rules": [
            {
                "rule_key": r.rule_key,
                "engine": r.engine,
                "native_format": r.native_format,
                "risk_class": r.risk_class,
                "severity": r.severity,
                "cwe_id": r.cwe_id,
                "content_sha256": r.content_sha256,
            }
            for r in sorted(ver.rules, key=lambda x: x.rule_key)
        ],
    }


async def sign_rule_pack_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    signer_id: uuid.UUID,
    signer_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    settings: Settings | None = None,
) -> RulePackVersion:
    _assert_human_operator(actor_type, "sign_rule_pack_version")
    cfg = settings or get_settings()
    ver = await _load_pack_version_locked(
        db, organization_id=organization_id, version_id=version_id
    )
    if ver.signed_at is not None:
        raise ConflictError("RulePackVersion is already signed and immutable")
    if ver.review_status != StudioReviewStatus.APPROVED.value:
        raise ForbiddenError("Unreviewed or unapproved RulePackVersion cannot be signed")
    if (
        not ver.fixture_regression_passed
        or ver.false_positive_count > 0
        or ver.false_negative_count > 0
    ):
        raise ConflictError("Fixture regression failures block signing")
    if signer_id == ver.author_id:
        raise ForbiddenError("Rule author cannot self-sign their own pack version")

    payload = _build_pack_manifest_payload(ver)
    bundle = SnapshotSigner.from_settings(cfg).sign_payload(payload)
    ver.manifest_payload_json = payload
    ver.manifest_sha256 = bundle.payload_sha256
    ver.manifest_signature = bundle.signature
    ver.signing_key_id = bundle.signing_key_id
    ver.signed_by = signer_id
    ver.signed_at = datetime.now(UTC)
    prev_ch = ver.channel
    if ver.channel == StudioChannel.DRAFT.value:
        ver.channel = StudioChannel.CANDIDATE.value
    await db.flush()

    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=ver.id,
        action=StudioAuditAction.VERSION_SIGNED,
        actor_id=signer_id,
        actor_email=signer_email,
        previous_state=prev_ch,
        new_state=ver.channel,
        details={"manifest_sha256": ver.manifest_sha256, "signing_key_id": ver.signing_key_id},
    )
    return ver


def _verify_pack_signature(ver: RulePackVersion, cfg: Settings) -> None:
    if (
        not ver.manifest_payload_json
        or not ver.manifest_sha256
        or not ver.manifest_signature
        or not ver.signing_key_id
    ):
        raise ForbiddenError(f"RulePackVersion {ver.version} lacks a cryptographic signature")
    for rule in ver.rules:
        actual_rule_sha = hashlib.sha256(rule.native_content.encode("utf-8")).hexdigest()
        if actual_rule_sha != rule.content_sha256:
            raise ForbiddenError(
                f"Rule '{rule.rule_key}' content digest mismatch in RulePackVersion {ver.version}"
            )
    expected_manifest = _build_pack_manifest_payload(ver)
    if ver.manifest_payload_json != expected_manifest:
        raise ForbiddenError(
            f"RulePackVersion {ver.version} live metadata/rules diverge from signed manifest"
        )
    signer = SnapshotSigner.from_settings(cfg)
    res = signer.verify_payload(
        payload=ver.manifest_payload_json,
        expected_sha256=ver.manifest_sha256,
        signing_key_id=ver.signing_key_id,
        signature_algorithm="Ed25519",
        signature=ver.manifest_signature,
    )
    if not res.valid:
        raise ForbiddenError(
            f"RulePackVersion {ver.version} signature verification failed: {res.reason}"
        )


async def promote_rule_pack_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    target_channel: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    settings: Settings | None = None,
) -> RulePackVersion:
    _assert_human_operator(actor_type, "promote_rule_pack_version")
    cfg = settings or get_settings()
    if target_channel not in {
        StudioChannel.CANDIDATE.value,
        StudioChannel.CANARY.value,
        StudioChannel.STABLE.value,
    }:
        raise ValidationError("target_channel must be 'candidate', 'canary', or 'stable'")

    ver = await _load_pack_version_locked(
        db, organization_id=organization_id, version_id=version_id
    )
    if not ver.rule_pack.is_active:
        raise ForbiddenError("Inactive RulePack cannot be promoted")
    if ver.channel == StudioChannel.QUARANTINED.value:
        raise ForbiddenError("Quarantined RulePackVersion cannot be re-promoted")
    if ver.review_status != StudioReviewStatus.APPROVED.value:
        raise ForbiddenError("Unapproved RulePackVersion cannot be promoted")
    if (
        not ver.fixture_regression_passed
        or ver.false_positive_count > 0
        or ver.false_negative_count > 0
    ):
        raise ConflictError("Fixture regression failures block promotion")
    if actor_id == ver.author_id:
        raise ForbiddenError("Rule author cannot self-promote their own pack version")

    _verify_pack_signature(ver, cfg)

    all_pack_versions = (
        (
            await db.execute(
                select(RulePackVersion)
                .where(
                    RulePackVersion.organization_id == organization_id,
                    RulePackVersion.rule_pack_id == ver.rule_pack_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )

    prev = ver.channel
    if target_channel == StudioChannel.CANARY.value:
        for other in all_pack_versions:
            if other.id != ver.id and other.is_active_canary:
                other.is_active_canary = False
                other.channel = StudioChannel.ROLLED_BACK.value
        await db.flush()
        ver.is_active_canary = True
        ver.channel = StudioChannel.CANARY.value
        audit_action = StudioAuditAction.PROMOTED_CANARY
    elif target_channel == StudioChannel.STABLE.value:
        for other in all_pack_versions:
            if other.id != ver.id and other.is_active_stable:
                other.is_active_stable = False
                other.channel = StudioChannel.ROLLED_BACK.value
            if other.id == ver.id:
                other.is_active_canary = False
        await db.flush()
        ver.is_active_stable = True
        ver.is_active_canary = False
        ver.channel = StudioChannel.STABLE.value
        audit_action = StudioAuditAction.PROMOTED_STABLE
    else:
        ver.is_active_canary = False
        ver.is_active_stable = False
        ver.channel = StudioChannel.CANDIDATE.value
        audit_action = StudioAuditAction.PROMOTED_CANDIDATE

    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=ver.id,
        action=audit_action,
        actor_id=actor_id,
        actor_email=actor_email,
        previous_state=prev,
        new_state=ver.channel,
        details={"version": ver.version},
    )
    return ver


async def rollback_rule_pack(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    rule_pack_id: uuid.UUID,
    target_channel: str,
    reason: str,
    quarantine: bool,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    settings: Settings | None = None,
) -> RulePackVersion:
    _assert_human_operator(actor_type, "rollback_rule_pack")
    cfg = settings or get_settings()
    if target_channel not in {StudioChannel.CANARY.value, StudioChannel.STABLE.value}:
        raise ValidationError("target_channel for rollback must be 'canary' or 'stable'")

    versions = (
        (
            await db.execute(
                select(RulePackVersion)
                .where(
                    RulePackVersion.organization_id == organization_id,
                    RulePackVersion.rule_pack_id == rule_pack_id,
                )
                .options(
                    selectinload(RulePackVersion.rule_pack),
                    selectinload(RulePackVersion.rules),
                    selectinload(RulePackVersion.fixture_runs),
                )
                .order_by(RulePackVersion.created_at.desc())
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if not versions:
        raise NotFoundError(f"No versions found for RulePack {rule_pack_id}")

    active_attr = (
        "is_active_canary" if target_channel == StudioChannel.CANARY.value else "is_active_stable"
    )
    current = next((v for v in versions if getattr(v, active_attr)), None)
    if current is None:
        raise ConflictError(f"No active {target_channel} RulePackVersion to roll back")

    setattr(current, active_attr, False)
    current.channel = (
        StudioChannel.QUARANTINED.value if quarantine else StudioChannel.ROLLED_BACK.value
    )
    await db.flush()

    opposing_attr = (
        "is_active_stable" if target_channel == StudioChannel.CANARY.value else "is_active_canary"
    )
    prior = next(
        (
            v
            for v in versions
            if v.id != current.id
            and v.review_status == StudioReviewStatus.APPROVED.value
            and v.fixture_regression_passed
            and v.manifest_signature
            and v.channel != StudioChannel.QUARANTINED.value
            and not getattr(v, opposing_attr)
        ),
        None,
    )
    restored = current
    if prior is not None:
        _verify_pack_signature(prior, cfg)
        setattr(prior, active_attr, True)
        prior.channel = target_channel
        restored = prior
    await db.flush()

    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="rule_pack_version",
        entity_id=current.id,
        action=StudioAuditAction.QUARANTINED if quarantine else StudioAuditAction.ROLLED_BACK,
        actor_id=actor_id,
        actor_email=actor_email,
        previous_state=target_channel,
        new_state=current.channel,
        details={
            "reason": reason.strip(),
            "restored_version": prior.version if prior else None,
        },
    )
    return restored


async def resolve_and_verify_rule_packs_for_scan(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    rule_pack_version_ids: list[uuid.UUID],
    settings: Settings | None = None,
) -> list[dict[str, Any]]:
    """Verify attached RulePackVersions are reviewed, signed, and active before scan execution."""
    if not rule_pack_version_ids:
        return []
    cfg = settings or get_settings()
    rows = (
        (
            await db.execute(
                select(RulePackVersion)
                .where(
                    RulePackVersion.organization_id == organization_id,
                    RulePackVersion.id.in_(rule_pack_version_ids),
                )
                .options(
                    selectinload(RulePackVersion.rule_pack), selectinload(RulePackVersion.rules)
                )
            )
        )
        .scalars()
        .all()
    )
    by_id = {row.id: row for row in rows}
    pins: list[dict[str, Any]] = []

    for vid in rule_pack_version_ids:
        ver = by_id.get(vid)
        if ver is None:
            raise ForbiddenError(f"RulePackVersion {vid} not accessible for this organization")
        if not ver.rule_pack.is_active:
            raise ForbiddenError(f"Inactive RulePack '{ver.rule_pack.slug}' cannot run in scans")
        if (
            ver.review_status != StudioReviewStatus.APPROVED.value
            or not ver.fixture_regression_passed
            or ver.false_positive_count > 0
            or ver.false_negative_count > 0
        ):
            raise ForbiddenError(
                f"Unreviewed or unvalidated RulePackVersion {ver.version} cannot run in scans"
            )
        if ver.channel not in {StudioChannel.CANARY.value, StudioChannel.STABLE.value} or not (
            ver.is_active_canary or ver.is_active_stable
        ):
            raise ForbiddenError(
                f"RulePackVersion {ver.version} in channel '{ver.channel}' "
                "is not promoted for scan execution"
            )
        _verify_pack_signature(ver, cfg)
        pins.append(
            {
                "rule_pack_id": str(ver.rule_pack_id),
                "rule_pack_slug": ver.rule_pack.slug,
                "rule_pack_version_id": str(ver.id),
                "version": ver.version,
                "channel": ver.channel,
                "manifest_sha256": ver.manifest_sha256,
                "signing_key_id": ver.signing_key_id,
                "rules": [r.rule_key for r in ver.rules],
            }
        )
    return pins


# ---------------------------------------------------------------------------
# Constrained Assessment Skills
# ---------------------------------------------------------------------------


async def create_skill(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    slug: str,
    title: str,
    description: str,
    owner_team: str,
    actor_id: uuid.UUID,
    actor_email: str,
) -> AssessmentSkill:
    clean_slug = slug.strip().lower()
    dup = (
        await db.execute(
            select(AssessmentSkill).where(
                AssessmentSkill.organization_id == organization_id,
                AssessmentSkill.slug == clean_slug,
            )
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise ConflictError(f"Skill slug '{clean_slug}' already exists in this organization")

    skill = AssessmentSkill(
        id=uuid.uuid4(),
        organization_id=organization_id,
        slug=clean_slug,
        title=title.strip(),
        description=description.strip(),
        owner_team=owner_team.strip() or "appsec-ai",
        created_by=actor_id,
        is_active=True,
    )
    db.add(skill)
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill",
        entity_id=skill.id,
        action=StudioAuditAction.SKILL_CREATED,
        actor_id=actor_id,
        actor_email=actor_email,
        new_state="active",
        details={"slug": clean_slug},
    )
    return skill


async def create_skill_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    skill_id: uuid.UUID,
    version: str,
    intent_description: str,
    allowed_capabilities: list[str],
    forbidden_actions: list[str],
    supported_agent_versions: list[str],
    playbook_steps: list[dict[str, Any]],
    actor_id: uuid.UUID,
    actor_email: str,
    creation_method: str = StudioCreationMethod.HUMAN.value,
    actor_type: str = StudioActorType.HUMAN.value,
) -> SkillVersion:
    validate_semver(version)
    skill = (
        await db.execute(
            select(AssessmentSkill)
            .where(
                AssessmentSkill.organization_id == organization_id,
                AssessmentSkill.id == skill_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if skill is None:
        raise NotFoundError(f"Skill {skill_id} not found")

    dup = (
        await db.execute(
            select(SkillVersion).where(
                SkillVersion.organization_id == organization_id,
                SkillVersion.skill_id == skill_id,
                SkillVersion.version == version.strip(),
            )
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise ConflictError(f"SkillVersion '{version}' already exists for '{skill.slug}'")

    caps, forbidden = validate_skill_definition(
        intent_description=intent_description,
        allowed_capabilities=allowed_capabilities,
        forbidden_actions=forbidden_actions,
        supported_agent_versions=supported_agent_versions,
        playbook_steps=playbook_steps,
    )
    manifest = {
        "schema_version": "vforge.skill.v1",
        "organization_id": str(organization_id),
        "skill_id": str(skill_id),
        "skill_slug": skill.slug,
        "version": version.strip(),
        "intent_description": intent_description.strip(),
        "allowed_capabilities": caps,
        "forbidden_actions": forbidden,
        "supported_agent_versions": [v.strip() for v in supported_agent_versions if v.strip()],
        "playbook_steps": playbook_steps,
    }
    sv = SkillVersion(
        id=uuid.uuid4(),
        organization_id=organization_id,
        skill_id=skill_id,
        version=version.strip(),
        intent_description=intent_description.strip(),
        allowed_capabilities=caps,
        forbidden_actions=forbidden,
        supported_agent_versions=manifest["supported_agent_versions"],
        playbook_steps_json=playbook_steps,
        creation_method=creation_method,
        author_id=actor_id,
        author_actor_type=actor_type,
        review_status=StudioReviewStatus.DRAFT.value,
        channel=StudioChannel.DRAFT.value,
        manifest_payload_json=manifest,
        content_sha256=compute_payload_sha256(manifest),
    )
    db.add(sv)
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill_version",
        entity_id=sv.id,
        action=StudioAuditAction.SKILL_VERSION_CREATED,
        actor_id=actor_id,
        actor_email=actor_email,
        actor_type=actor_type,
        new_state=StudioReviewStatus.DRAFT.value,
        details={"skill_slug": skill.slug, "version": sv.version},
    )
    return sv


async def submit_skill_version_for_review(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_email: str,
) -> SkillVersion:
    sv = (
        await db.execute(
            select(SkillVersion)
            .where(
                SkillVersion.organization_id == organization_id,
                SkillVersion.id == version_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if sv is None:
        raise NotFoundError(f"SkillVersion {version_id} not found")
    if sv.signed_at is not None:
        raise ConflictError("Signed SkillVersion cannot be resubmitted")
    if sv.review_status == StudioReviewStatus.APPROVED.value:
        raise ConflictError("Approved SkillVersion cannot be resubmitted")
    prev = sv.review_status
    sv.review_status = StudioReviewStatus.PENDING_REVIEW.value
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill_version",
        entity_id=sv.id,
        action=StudioAuditAction.REVIEW_REQUESTED,
        actor_id=actor_id,
        actor_email=actor_email,
        previous_state=prev,
        new_state=sv.review_status,
    )
    return sv


async def review_skill_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    decision: str,
    comment: str | None,
    reviewer_id: uuid.UUID,
    reviewer_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
) -> SkillVersion:
    _assert_human_operator(actor_type, "review_skill_version")
    sv = (
        await db.execute(
            select(SkillVersion)
            .where(
                SkillVersion.organization_id == organization_id,
                SkillVersion.id == version_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if sv is None:
        raise NotFoundError(f"SkillVersion {version_id} not found")
    if sv.signed_at is not None:
        raise ConflictError("Signed SkillVersion is immutable")
    if sv.review_status != StudioReviewStatus.PENDING_REVIEW.value:
        raise ConflictError("SkillVersion must be in 'pending_review' state before review decision")
    if reviewer_id == sv.author_id:
        raise ForbiddenError("Segregation of duties: skill author cannot self-approve")

    prev = sv.review_status
    if decision == "approved":
        sv.review_status = StudioReviewStatus.APPROVED.value
        sv.reviewer_id = reviewer_id
        sv.approved_at = datetime.now(UTC)
        sv.rejection_reason = None
        action = StudioAuditAction.SKILL_REVIEW_APPROVED
    elif decision == "rejected":
        sv.review_status = StudioReviewStatus.REJECTED.value
        sv.reviewer_id = reviewer_id
        sv.approved_at = None
        sv.rejection_reason = (comment or "Rejected").strip()
        action = StudioAuditAction.SKILL_REVIEW_REJECTED
    elif decision == "changes_requested":
        sv.review_status = StudioReviewStatus.CHANGES_REQUESTED.value
        sv.reviewer_id = reviewer_id
        sv.approved_at = None
        sv.rejection_reason = (comment or "Changes requested").strip()
        action = StudioAuditAction.REVIEW_CHANGES_REQUESTED
    else:
        raise ValidationError("decision must be 'approved', 'rejected', or 'changes_requested'")
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill_version",
        entity_id=sv.id,
        action=action,
        actor_id=reviewer_id,
        actor_email=reviewer_email,
        previous_state=prev,
        new_state=sv.review_status,
    )
    return sv


async def sign_skill_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    signer_id: uuid.UUID,
    signer_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    settings: Settings | None = None,
) -> SkillVersion:
    _assert_human_operator(actor_type, "sign_skill_version")
    cfg = settings or get_settings()
    sv = (
        await db.execute(
            select(SkillVersion)
            .where(
                SkillVersion.organization_id == organization_id,
                SkillVersion.id == version_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if sv is None:
        raise NotFoundError(f"SkillVersion {version_id} not found")
    if sv.signed_at is not None:
        raise ConflictError("SkillVersion is already signed")
    if sv.review_status != StudioReviewStatus.APPROVED.value:
        raise ForbiddenError("Unapproved SkillVersion cannot be signed")
    if signer_id == sv.author_id:
        raise ForbiddenError("Skill author cannot self-sign their own version")

    bundle = SnapshotSigner.from_settings(cfg).sign_payload(sv.manifest_payload_json)
    sv.content_sha256 = bundle.payload_sha256
    sv.signature = bundle.signature
    sv.signing_key_id = bundle.signing_key_id
    sv.signed_by = signer_id
    sv.signed_at = datetime.now(UTC)
    prev = sv.channel
    if sv.channel == StudioChannel.DRAFT.value:
        sv.channel = StudioChannel.CANDIDATE.value
    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill_version",
        entity_id=sv.id,
        action=StudioAuditAction.SKILL_SIGNED,
        actor_id=signer_id,
        actor_email=signer_email,
        previous_state=prev,
        new_state=sv.channel,
        details={"content_sha256": sv.content_sha256, "signing_key_id": sv.signing_key_id},
    )
    return sv


def _build_skill_manifest_payload(sv: SkillVersion) -> dict[str, Any]:
    return {
        "schema_version": "vforge.skill.v1",
        "organization_id": str(sv.organization_id),
        "skill_id": str(sv.skill_id),
        "skill_slug": sv.skill.slug,
        "version": sv.version,
        "intent_description": sv.intent_description,
        "allowed_capabilities": list(sv.allowed_capabilities or []),
        "forbidden_actions": list(sv.forbidden_actions or []),
        "supported_agent_versions": list(sv.supported_agent_versions or []),
        "playbook_steps": list(sv.playbook_steps_json or []),
    }


def _verify_skill_signature(sv: SkillVersion, cfg: Settings) -> None:
    if not sv.manifest_payload_json or not sv.signature or not sv.signing_key_id:
        raise ForbiddenError(f"SkillVersion {sv.version} lacks a cryptographic signature")
    expected_manifest = _build_skill_manifest_payload(sv)
    if sv.manifest_payload_json != expected_manifest:
        raise ForbiddenError(
            f"SkillVersion {sv.version} live metadata diverges from signed manifest"
        )
    signer = SnapshotSigner.from_settings(cfg)
    res = signer.verify_payload(
        payload=sv.manifest_payload_json,
        expected_sha256=sv.content_sha256,
        signing_key_id=sv.signing_key_id,
        signature_algorithm="Ed25519",
        signature=sv.signature,
    )
    if not res.valid:
        raise ForbiddenError(f"SkillVersion signature verification failed: {res.reason}")


async def promote_skill_version(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    version_id: uuid.UUID,
    target_channel: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    settings: Settings | None = None,
) -> SkillVersion:
    _assert_human_operator(actor_type, "promote_skill_version")
    cfg = settings or get_settings()
    if target_channel not in {
        StudioChannel.CANDIDATE.value,
        StudioChannel.CANARY.value,
        StudioChannel.STABLE.value,
    }:
        raise ValidationError("target_channel must be 'candidate', 'canary', or 'stable'")
    sv = (
        await db.execute(
            select(SkillVersion)
            .where(
                SkillVersion.organization_id == organization_id,
                SkillVersion.id == version_id,
            )
            .options(selectinload(SkillVersion.skill))
            .with_for_update()
        )
    ).scalar_one_or_none()
    if sv is None:
        raise NotFoundError(f"SkillVersion {version_id} not found")
    if not sv.skill.is_active:
        raise ForbiddenError("Inactive AssessmentSkill cannot be promoted")
    if sv.channel == StudioChannel.QUARANTINED.value:
        raise ForbiddenError("Quarantined SkillVersion cannot be re-promoted")
    if (
        sv.review_status != StudioReviewStatus.APPROVED.value
        or not sv.signature
        or not sv.signing_key_id
    ):
        raise ForbiddenError("SkillVersion must be approved and signed before promotion")
    if actor_id == sv.author_id:
        raise ForbiddenError("Skill author cannot self-promote their own version")

    _verify_skill_signature(sv, cfg)

    peers = (
        (
            await db.execute(
                select(SkillVersion)
                .where(
                    SkillVersion.organization_id == organization_id,
                    SkillVersion.skill_id == sv.skill_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    prev = sv.channel
    if target_channel == StudioChannel.CANARY.value:
        for other in peers:
            if other.id != sv.id and other.is_active_canary:
                other.is_active_canary = False
                other.channel = StudioChannel.ROLLED_BACK.value
        await db.flush()
        sv.is_active_canary = True
        sv.channel = StudioChannel.CANARY.value
    elif target_channel == StudioChannel.STABLE.value:
        for other in peers:
            if other.id != sv.id and other.is_active_stable:
                other.is_active_stable = False
                other.channel = StudioChannel.ROLLED_BACK.value
        await db.flush()
        sv.is_active_stable = True
        sv.is_active_canary = False
        sv.channel = StudioChannel.STABLE.value
    else:
        sv.is_active_canary = False
        sv.is_active_stable = False
        sv.channel = StudioChannel.CANDIDATE.value

    await db.flush()
    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill_version",
        entity_id=sv.id,
        action=StudioAuditAction.SKILL_PROMOTED,
        actor_id=actor_id,
        actor_email=actor_email,
        previous_state=prev,
        new_state=sv.channel,
    )
    return sv


async def rollback_skill(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    skill_id: uuid.UUID,
    target_channel: str,
    reason: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_type: str = StudioActorType.HUMAN.value,
    settings: Settings | None = None,
) -> SkillVersion:
    _assert_human_operator(actor_type, "rollback_skill")
    cfg = settings or get_settings()
    if target_channel not in {StudioChannel.CANARY.value, StudioChannel.STABLE.value}:
        raise ValidationError("target_channel must be 'canary' or 'stable'")
    peers = (
        (
            await db.execute(
                select(SkillVersion)
                .where(
                    SkillVersion.organization_id == organization_id,
                    SkillVersion.skill_id == skill_id,
                )
                .options(selectinload(SkillVersion.skill))
                .order_by(SkillVersion.created_at.desc())
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    active_attr = (
        "is_active_canary" if target_channel == StudioChannel.CANARY.value else "is_active_stable"
    )
    opposing_attr = (
        "is_active_stable" if target_channel == StudioChannel.CANARY.value else "is_active_canary"
    )
    current = next((v for v in peers if getattr(v, active_attr)), None)
    if current is None:
        raise ConflictError(f"No active {target_channel} SkillVersion to roll back")
    setattr(current, active_attr, False)
    current.channel = StudioChannel.ROLLED_BACK.value
    await db.flush()

    prior = next(
        (
            v
            for v in peers
            if v.id != current.id
            and v.review_status == StudioReviewStatus.APPROVED.value
            and v.signature
            and v.channel != StudioChannel.QUARANTINED.value
            and not getattr(v, opposing_attr)
        ),
        None,
    )
    if prior is not None:
        _verify_skill_signature(prior, cfg)
        setattr(prior, active_attr, True)
        prior.channel = target_channel
        await db.flush()

    _record_audit(
        db,
        organization_id=organization_id,
        entity_type="skill_version",
        entity_id=current.id,
        action=StudioAuditAction.SKILL_ROLLED_BACK,
        actor_id=actor_id,
        actor_email=actor_email,
        previous_state=target_channel,
        new_state=current.channel,
        details={"reason": reason.strip(), "restored_version": prior.version if prior else None},
    )
    return prior or current


async def get_studio_overview(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
) -> dict[str, Any]:
    packs = (
        (
            await db.execute(
                select(RulePack)
                .where(RulePack.organization_id == organization_id)
                .options(
                    selectinload(RulePack.versions).selectinload(RulePackVersion.rules),
                    selectinload(RulePack.versions).selectinload(RulePackVersion.fixture_runs),
                )
                .order_by(RulePack.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    skills = (
        (
            await db.execute(
                select(AssessmentSkill)
                .where(AssessmentSkill.organization_id == organization_id)
                .options(selectinload(AssessmentSkill.versions))
                .order_by(AssessmentSkill.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    events = (
        (
            await db.execute(
                select(StudioAuditEvent)
                .where(StudioAuditEvent.organization_id == organization_id)
                .order_by(StudioAuditEvent.occurred_at.desc())
                .limit(40)
            )
        )
        .scalars()
        .all()
    )
    return {"rule_packs": list(packs), "skills": list(skills), "audit_events": list(events)}
