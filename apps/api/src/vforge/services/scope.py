"""Phase 2 scope evaluation, DNS binding, OPA integration, and signed snapshot services."""

from __future__ import annotations

import hmac
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from vforge_scope import (
    FORBIDDEN_CAPABILITIES,
    LEGACY_ACTIVITY_TO_CAPABILITY,
    DnsResolver,
    IntensityLevel,
    ScopeDefinition,
    ScopeReason,
    ScopeValidationError,
    SystemDnsResolver,
    build_scope_definition_from_asset,
    canonicalize_cidr,
    canonicalize_domain,
    evaluate_target_scope,
    normalize_capabilities,
    resolve_and_validate_host,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import NotFoundError, ValidationError
from vforge.models import (
    Asset,
    AuditOutcome,
    Authorization,
    AuthorizationStatus,
    Environment,
    Organization,
    Project,
    Role,
    ScanProfile,
    ScopeSnapshot,
)
from vforge.schemas import (
    ScopeEvaluateRequest,
    ScopeEvaluationResponse,
    ScopePolicyReasonOut,
    SnapshotVerifyResponse,
)
from vforge.security.opa_client import OpaDecision, OpaScopeClient
from vforge.security.signing import (
    SnapshotSigner,
    SnapshotVerificationResult,
    compute_payload_sha256,
)
from vforge.services.audit import record_audit_event

_NETWORK_ASSET_TYPES = frozenset({"web_application", "rest_api", "network_service"})


def _normalize_capability_tokens(raw_items: list[str], *, strict: bool) -> list[str]:
    """Normalize known capabilities while optionally preserving invalid/forbidden tokens for OPA."""
    if strict:
        return [cap.value for cap in normalize_capabilities(raw_items)]

    tokens: list[str] = []
    seen: set[str] = set()
    for raw in raw_items:
        cleaned = raw.strip().lower()
        if not cleaned:
            continue
        if cleaned in FORBIDDEN_CAPABILITIES:
            val = cleaned
        elif cleaned in LEGACY_ACTIVITY_TO_CAPABILITY:
            val = LEGACY_ACTIVITY_TO_CAPABILITY[cleaned].value
        else:
            val = cleaned
        if val not in seen:
            seen.add(val)
            tokens.append(val)
    return tokens


def _extract_hostnames_for_dns(scope_def: ScopeDefinition) -> list[str]:
    hosts: list[str] = []
    for dom in scope_def.exact_domains + scope_def.domain_and_subdomains:
        if dom not in hosts:
            hosts.append(dom)
    from urllib.parse import urlsplit

    for url in scope_def.exact_urls + scope_def.url_path_prefixes:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            continue
        try:
            ipaddress.ip_address(host.strip("[]"))
            continue
        except ValueError:
            pass
        canonical_host = canonicalize_domain(host)
        if canonical_host not in hosts:
            hosts.append(canonical_host)
    return hosts


def _resolve_scope_dns_bindings(
    *,
    asset: Asset,
    scope_def: ScopeDefinition,
    dns_resolver: DnsResolver,
    require_live_dns: bool,
) -> tuple[dict[str, list[str]], list[str]]:
    """Resolve and validate hostnames in `scope_def`; always fail on disallowed/mixed IPs."""
    if asset.asset_type not in _NETWORK_ASSET_TYPES:
        ips: set[str] = set(scope_def.allowed_ips)
        for cidr in scope_def.allowed_cidrs:
            net = canonicalize_cidr(cidr)
            ips.add(str(net.network_address))
        return {}, sorted(ips)

    dns_bindings: dict[str, list[str]] = {}
    all_ips: set[str] = set(scope_def.allowed_ips)

    for host in _extract_hostnames_for_dns(scope_def):
        res = resolve_and_validate_host(host, scope_def, dns_resolver)
        if not res.allowed:
            failure_codes = {reason.code for reason in res.reasons}
            if failure_codes == {"dns_resolution_failed"} and not require_live_dns:
                continue
            messages = "; ".join(reason.message for reason in res.reasons)
            raise ValidationError(f"Scope DNS safety check failed for '{host}': {messages}")
        dns_bindings[host] = res.resolved_ips
        all_ips.update(res.resolved_ips)

    return dns_bindings, sorted(all_ips)


def validate_authorization_scope(
    *,
    asset: Asset,
    approved_testing_scope: dict[str, Any],
    approved_activities: list[str],
    allowed_ports: list[int] | None,
    allow_private_networks: bool,
) -> tuple[ScopeDefinition, list[str]]:
    """Validate and canonicalize authorization capabilities and scope rules."""
    try:
        caps = [cap.value for cap in normalize_capabilities(approved_activities)]
        scope_def = build_scope_definition_from_asset(
            asset_type=asset.asset_type,
            normalized_locator=asset.normalized_locator,
            approved_testing_scope=approved_testing_scope,
            allowed_ports=allowed_ports,
            allow_private_networks=allow_private_networks,
        )
    except (ValueError, ScopeValidationError) as exc:
        msg = exc.message if isinstance(exc, ScopeValidationError) else str(exc)
        raise ValidationError(msg) from exc
    return scope_def, caps


async def create_signed_snapshot_for_authorization(
    db: AsyncSession,
    *,
    auth: Authorization,
    asset: Asset,
    actor_id: uuid.UUID,
    correlation_id: str | None,
    settings: Settings | None = None,
    dns_resolver: DnsResolver | None = None,
    signer: SnapshotSigner | None = None,
) -> ScopeSnapshot:
    """Resolve DNS safely, build canonical snapshot payload, sign with Ed25519, and persist."""
    cfg = settings or get_settings()
    resolver = dns_resolver or SystemDnsResolver()
    active_signer = signer or SnapshotSigner.from_settings(cfg)

    scope_def, permitted_caps = validate_authorization_scope(
        asset=asset,
        approved_testing_scope=auth.approved_testing_scope,
        approved_activities=auth.approved_activities,
        allowed_ports=auth.allowed_ports,
        allow_private_networks=auth.allow_private_networks,
    )
    dns_bindings, resolved_ips = _resolve_scope_dns_bindings(
        asset=asset,
        scope_def=scope_def,
        dns_resolver=resolver,
        require_live_dns=cfg.require_live_dns_on_approval,
    )
    scope_with_dns = scope_def.model_copy(update={"pinned_dns_resolution": dns_bindings})

    max_ver_res = await db.execute(
        select(func.max(ScopeSnapshot.snapshot_version)).where(
            ScopeSnapshot.authorization_id == auth.id
        )
    )
    current_max = max_ver_res.scalar_one_or_none()
    next_version = int(current_max) + 1 if current_max is not None else 1

    now = datetime.now(UTC)
    allowed_ports = sorted(set(scope_with_dns.allowed_ports))
    scope_dict = scope_with_dns.model_dump(mode="json")

    payload: dict[str, Any] = {
        "schema_version": 2,
        "snapshot_version": next_version,
        "organization_id": str(auth.organization_id),
        "project_id": str(auth.project_id),
        "environment_id": str(auth.environment_id),
        "asset_id": str(auth.asset_id),
        "asset_version": asset.version,
        "authorization_id": str(auth.id),
        "authorization_reference": auth.authorization_reference,
        "requested_by": str(auth.requested_by),
        "approved_by": str(auth.approved_by) if auth.approved_by else "",
        "target_type": asset.asset_type,
        "canonical_locator": asset.normalized_locator,
        "resolved_ips": resolved_ips,
        "dns_bindings": dns_bindings,
        "allowed_ports": allowed_ports,
        "permitted_capabilities": permitted_caps,
        "permitted_intensity": auth.permitted_intensity,
        "allow_private_networks": auth.allow_private_networks,
        "authorization_valid_from": auth.valid_from.isoformat(),
        "authorization_expires_at": auth.expires_at.isoformat(),
        "policy_version": auth.policy_version,
        "scope_definition": scope_dict,
        "created_at": now.isoformat(),
    }
    signed = active_signer.sign_payload(payload)

    snapshot = ScopeSnapshot(
        organization_id=auth.organization_id,
        project_id=auth.project_id,
        environment_id=auth.environment_id,
        asset_id=auth.asset_id,
        authorization_id=auth.id,
        snapshot_version=next_version,
        asset_version=asset.version,
        policy_version=auth.policy_version,
        target_type=asset.asset_type,
        canonical_locator=asset.normalized_locator,
        resolved_ips=resolved_ips,
        allowed_ports=allowed_ports,
        permitted_capabilities=permitted_caps,
        permitted_intensity=auth.permitted_intensity,
        scope_definition=scope_dict,
        payload=payload,
        payload_sha256=signed.payload_sha256,
        signing_key_id=signed.signing_key_id,
        signature_algorithm=signed.signature_algorithm,
        signature=signed.signature,
        authorization_expires_at=auth.expires_at,
        created_by=actor_id,
    )
    db.add(snapshot)
    await db.flush()
    await db.refresh(snapshot)

    await record_audit_event(
        db,
        organization_id=auth.organization_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scope_snapshot.created",
        resource_type="scope_snapshot",
        resource_id=snapshot.id,
        metadata={
            "authorization_id": str(auth.id),
            "asset_id": str(auth.asset_id),
            "snapshot_version": snapshot.snapshot_version,
            "asset_version": snapshot.asset_version,
            "policy_version": snapshot.policy_version,
            "payload_sha256": snapshot.payload_sha256,
            "signing_key_id": snapshot.signing_key_id,
        },
    )
    return snapshot


async def list_snapshots(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    authorization_id: uuid.UUID | None = None,
    asset_id: uuid.UUID | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[ScopeSnapshot], int]:
    """List immutable scope snapshots for an organization."""
    assert_permission(actor_role, Permission.SNAPSHOT_READ)
    stmt = select(ScopeSnapshot).where(ScopeSnapshot.organization_id == org_id)
    count_stmt = (
        select(func.count())
        .select_from(ScopeSnapshot)
        .where(ScopeSnapshot.organization_id == org_id)
    )
    if authorization_id is not None:
        stmt = stmt.where(ScopeSnapshot.authorization_id == authorization_id)
        count_stmt = count_stmt.where(ScopeSnapshot.authorization_id == authorization_id)
    if asset_id is not None:
        stmt = stmt.where(ScopeSnapshot.asset_id == asset_id)
        count_stmt = count_stmt.where(ScopeSnapshot.asset_id == asset_id)

    total = int((await db.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await db.execute(
                stmt.order_by(ScopeSnapshot.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return rows, total


async def get_snapshot(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    actor_role: Role,
) -> ScopeSnapshot:
    """Fetch a single scope snapshot scoped to the organization."""
    assert_permission(actor_role, Permission.SNAPSHOT_READ)
    res = await db.execute(
        select(ScopeSnapshot).where(
            ScopeSnapshot.id == snapshot_id,
            ScopeSnapshot.organization_id == org_id,
        )
    )
    snapshot = res.scalar_one_or_none()
    if snapshot is None:
        raise NotFoundError("Scope snapshot not found")
    return snapshot


def _verify_snapshot_crypto_and_consistency(
    *,
    snapshot: ScopeSnapshot,
    signer: SnapshotSigner,
) -> tuple[SnapshotVerificationResult, bool]:
    """Check canonical payload hash, key status, Ed25519 signature, and payload consistency."""
    verification = signer.verify_payload(
        payload=snapshot.payload,
        expected_sha256=snapshot.payload_sha256,
        signing_key_id=snapshot.signing_key_id,
        signature_algorithm=snapshot.signature_algorithm,
        signature=snapshot.signature,
    )
    computed = compute_payload_sha256(snapshot.payload)
    hash_matches = hmac.compare_digest(computed, snapshot.payload_sha256.lower())
    payload_consistent = (
        snapshot.payload.get("authorization_id") == str(snapshot.authorization_id)
        and snapshot.payload.get("asset_id") == str(snapshot.asset_id)
        and snapshot.payload.get("policy_version") == snapshot.policy_version
        and snapshot.payload.get("asset_version") == snapshot.asset_version
    )
    if not payload_consistent:
        hash_matches = False
        verification = SnapshotVerificationResult(
            valid=False,
            reason="snapshot_payload_column_mismatch",
            computed_sha256=computed,
            signing_key_id=snapshot.signing_key_id,
            key_status=verification.key_status,
        )
    return verification, hash_matches


def _build_opa_input(
    *,
    actor_id: uuid.UUID,
    actor_role: Role,
    org: Organization,
    project: Project,
    env: Environment,
    asset: Asset,
    auth: Authorization,
    auth_capabilities: list[str],
    requested_capabilities: list[str],
    requested_intensity: IntensityLevel,
    tool_category: str | None,
    target_port: int | None,
    pre_flight_facts: dict[str, Any],
    now: datetime,
    expected_policy_version: str,
    scan_profile: ScanProfile | None = None,
    snapshot: ScopeSnapshot | None = None,
    snapshot_hash_matches: bool = False,
    snapshot_signature_valid: bool = False,
) -> dict[str, Any]:
    scan_profile_block: dict[str, Any] = {"present": False}
    if scan_profile is not None:
        cfg = scan_profile.configuration or {}
        scan_profile_block = {
            "present": True,
            "id": str(scan_profile.id),
            "organization_id": str(scan_profile.organization_id),
            "status": scan_profile.status,
            "passive_only": bool(cfg.get("passive_only", True)),
        }

    snapshot_block: dict[str, Any] = {"present": False}
    if snapshot is not None:
        snapshot_block = {
            "present": True,
            "id": str(snapshot.id),
            "hash_matches": snapshot_hash_matches,
            "signature_valid": snapshot_signature_valid,
            "expired": now >= snapshot.authorization_expires_at,
            "policy_version": snapshot.policy_version,
            "asset_version": snapshot.asset_version,
        }

    return {
        "policy_version": expected_policy_version,
        "expected_policy_version": expected_policy_version,
        "action": "scope:evaluate",
        "subject": {
            "authenticated": True,
            "user_id": str(actor_id),
            "organization_id": str(org.id),
            "role": actor_role.value,
        },
        "organization": {
            "id": str(org.id),
            "status": org.status,
        },
        "project": {
            "id": str(project.id),
            "organization_id": str(project.organization_id),
            "status": project.status,
            "criticality": project.criticality,
        },
        "environment": {
            "id": str(env.id),
            "organization_id": str(env.organization_id),
            "project_id": str(env.project_id),
            "environment_type": env.environment_type,
            "status": env.status,
        },
        "asset": {
            "id": str(asset.id),
            "organization_id": str(asset.organization_id),
            "environment_id": str(asset.environment_id),
            "asset_type": asset.asset_type,
            "normalized_locator": asset.normalized_locator,
            "registration_state": asset.registration_state,
            "version": asset.version,
        },
        "authorization": {
            "id": str(auth.id),
            "organization_id": str(auth.organization_id),
            "project_id": str(auth.project_id),
            "environment_id": str(auth.environment_id),
            "asset_id": str(auth.asset_id),
            "status": auth.status,
            "requested_by": str(auth.requested_by),
            "approved_by": str(auth.approved_by) if auth.approved_by else "",
            "valid_from_epoch": int(auth.valid_from.timestamp()),
            "expires_at_epoch": int(auth.expires_at.timestamp()),
            "capabilities": auth_capabilities,
            "allowed_ports": sorted(set(auth.allowed_ports or [])),
            "permitted_intensity": auth.permitted_intensity,
            "policy_version": auth.policy_version,
            "production_active_approved": bool(
                (auth.approved_testing_scope or {}).get("production_active_approved", False)
            ),
        },
        "scan_profile": scan_profile_block,
        "snapshot": snapshot_block,
        "request": {
            "requested_capabilities": requested_capabilities,
            "requested_intensity": requested_intensity.value,
            "tool_category": (tool_category or "").strip().lower(),
            "target_port": target_port,
            "current_epoch": int(now.timestamp()),
            "pre_flight": pre_flight_facts,
        },
    }


def _merge_reasons(
    opa_decision: OpaDecision,
    scope_reasons: list[ScopeReason],
    snapshot_verification: SnapshotVerificationResult | None = None,
) -> list[ScopePolicyReasonOut]:
    merged: list[ScopePolicyReasonOut] = []
    seen_codes: set[str] = set()
    for sr in scope_reasons:
        if sr.code not in seen_codes:
            seen_codes.add(sr.code)
            merged.append(ScopePolicyReasonOut(code=sr.code, message=sr.message))
    if snapshot_verification is not None and not snapshot_verification.valid:
        if snapshot_verification.reason not in seen_codes:
            seen_codes.add(snapshot_verification.reason)
            merged.append(
                ScopePolicyReasonOut(
                    code=snapshot_verification.reason,
                    message=f"Snapshot verification failed: {snapshot_verification.reason}",
                )
            )
    for r in opa_decision.reasons:
        if r.code == "authorized" and merged:
            continue
        if r.code not in seen_codes:
            seen_codes.add(r.code)
            merged.append(ScopePolicyReasonOut(code=r.code, message=r.message))
    return merged


async def _load_authorization_hierarchy(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    authorization_id: uuid.UUID,
) -> tuple[Organization, Project, Environment, Asset, Authorization]:
    auth_res = await db.execute(
        select(Authorization).where(
            Authorization.id == authorization_id,
            Authorization.organization_id == org_id,
        )
    )
    auth = auth_res.scalar_one_or_none()
    if auth is None:
        raise NotFoundError("Authorization not found")

    org = (
        await db.execute(select(Organization).where(Organization.id == org_id))
    ).scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization not found")

    asset = (
        await db.execute(
            select(Asset).where(Asset.id == auth.asset_id, Asset.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found")

    env = (
        await db.execute(
            select(Environment).where(
                Environment.id == asset.environment_id,
                Environment.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if env is None:
        raise NotFoundError("Environment not found")

    project = (
        await db.execute(
            select(Project).where(
                Project.id == env.project_id,
                Project.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project not found")

    return org, project, env, asset, auth


async def evaluate_scope(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    request: ScopeEvaluateRequest,
    correlation_id: str | None,
    settings: Settings | None = None,
    dns_resolver: DnsResolver | None = None,
    opa_client: OpaScopeClient | None = None,
    signer: SnapshotSigner | None = None,
) -> ScopeEvaluationResponse:
    """Evaluate a proposed target + capability against DB authorization, DNS safety, and OPA."""
    assert_permission(actor_role, Permission.SCOPE_EVALUATE)
    cfg = settings or get_settings()
    resolver = dns_resolver or SystemDnsResolver()
    client = opa_client or OpaScopeClient(
        base_url=cfg.opa_url,
        timeout_seconds=cfg.opa_timeout_seconds,
    )
    active_signer = signer or SnapshotSigner.from_settings(cfg)
    now = datetime.now(UTC)

    org, project, env, asset, auth = await _load_authorization_hierarchy(
        db,
        org_id=org_id,
        authorization_id=request.authorization_id,
    )

    if auth.status == AuthorizationStatus.APPROVED.value and auth.expires_at <= now:
        auth.status = AuthorizationStatus.EXPIRED.value

    scan_profile: ScanProfile | None = None
    if request.scan_profile_id is not None:
        scan_profile = (
            await db.execute(
                select(ScanProfile).where(
                    ScanProfile.id == request.scan_profile_id,
                    ScanProfile.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()
        if scan_profile is None:
            raise NotFoundError("Scan profile not found")

    snapshot: ScopeSnapshot | None = None
    if request.snapshot_id is not None:
        snapshot = (
            await db.execute(
                select(ScopeSnapshot).where(
                    ScopeSnapshot.id == request.snapshot_id,
                    ScopeSnapshot.organization_id == org_id,
                )
            )
        ).scalar_one_or_none()
        if snapshot is None:
            raise NotFoundError("Scope snapshot not found")
        if snapshot.authorization_id != auth.id:
            raise ValidationError("Snapshot does not belong to specified authorization")
    elif auth.status == AuthorizationStatus.APPROVED.value:
        snapshot = (
            await db.execute(
                select(ScopeSnapshot)
                .where(
                    ScopeSnapshot.authorization_id == auth.id,
                    ScopeSnapshot.organization_id == org_id,
                )
                .order_by(ScopeSnapshot.snapshot_version.desc())
                .limit(1)
            )
        ).scalar_one_or_none()

    snapshot_verification: SnapshotVerificationResult | None = None
    hash_matches = False
    pinned_dns: dict[str, list[str]] | None = None
    if snapshot is not None:
        snapshot_verification, hash_matches = _verify_snapshot_crypto_and_consistency(
            snapshot=snapshot,
            signer=active_signer,
        )
        bindings = (snapshot.payload or {}).get("dns_bindings")
        if isinstance(bindings, dict):
            pinned_dns = {
                str(host): [str(ip) for ip in ips]
                for host, ips in bindings.items()
                if isinstance(ips, list)
            }

    scope_def = build_scope_definition_from_asset(
        asset_type=asset.asset_type,
        normalized_locator=asset.normalized_locator,
        approved_testing_scope=auth.approved_testing_scope,
        allowed_ports=auth.allowed_ports,
        allow_private_networks=auth.allow_private_networks,
        pinned_dns_resolution=pinned_dns,
    )
    scope_result = evaluate_target_scope(
        target_type=request.target_type,
        raw_target=request.raw_target,
        scope=scope_def,
        dns_resolver=resolver,
        resolve_dns=request.resolve_dns,
        redirect_location=request.redirect_location,
        redirect_hop_count=request.redirect_hop_count,
    )

    auth_caps = _normalize_capability_tokens(auth.approved_activities, strict=False)
    req_caps = _normalize_capability_tokens(request.requested_capabilities, strict=False)

    # Check explicit caller project/env/asset assertions if supplied by request
    extra_reasons: list[ScopeReason] = list(scope_result.reasons)
    if request.asset_id is not None and request.asset_id != asset.id:
        extra_reasons.append(
            ScopeReason(
                code="wrong_authorization_asset",
                message="Requested asset_id does not match authorization asset",
            )
        )
    if request.environment_id is not None and request.environment_id != env.id:
        extra_reasons.append(
            ScopeReason(
                code="wrong_authorization_environment",
                message="Requested environment_id does not match asset environment",
            )
        )
    if request.project_id is not None and request.project_id != project.id:
        extra_reasons.append(
            ScopeReason(
                code="wrong_authorization_project",
                message="Requested project_id does not match environment project",
            )
        )

    target_port = (
        scope_result.canonical_target.port if scope_result.canonical_target is not None else None
    )

    opa_input = _build_opa_input(
        actor_id=actor_id,
        actor_role=actor_role,
        org=org,
        project=project,
        env=env,
        asset=asset,
        auth=auth,
        auth_capabilities=auth_caps,
        requested_capabilities=req_caps,
        requested_intensity=request.requested_intensity,
        tool_category=request.tool_category,
        target_port=target_port,
        pre_flight_facts=scope_result.pre_flight_facts,
        now=now,
        expected_policy_version=cfg.policy_bundle_version,
        scan_profile=scan_profile,
        snapshot=snapshot,
        snapshot_hash_matches=hash_matches,
        snapshot_signature_valid=(
            snapshot_verification.valid if snapshot_verification is not None else False
        ),
    )
    # Apply explicit mismatch IDs into OPA input so OPA itself enforces wrong project/env/asset
    if request.asset_id is not None and request.asset_id != asset.id:
        opa_input["asset"]["id"] = str(request.asset_id)
    if request.environment_id is not None and request.environment_id != env.id:
        opa_input["environment"]["id"] = str(request.environment_id)
    if request.project_id is not None and request.project_id != project.id:
        opa_input["project"]["id"] = str(request.project_id)

    opa_decision = await client.evaluate_scope_decision(
        opa_input,
        expected_policy_version=cfg.policy_bundle_version,
    )
    combined_reasons = _merge_reasons(opa_decision, extra_reasons, snapshot_verification)

    canonical_str = (
        scope_result.canonical_target.normalized
        if scope_result.canonical_target is not None
        else None
    )
    redirect_safe = bool(scope_result.pre_flight_facts.get("redirect_safe", True))

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scope.evaluated",
        resource_type="authorization",
        resource_id=auth.id,
        outcome=AuditOutcome.SUCCESS if opa_decision.allowed else AuditOutcome.DENIED,
        metadata={
            "opa_outcome": opa_decision.outcome,
            "target_type": request.target_type.value,
            "canonical_target": canonical_str,
            "resolved_ips": scope_result.resolved_ips,
            "snapshot_id": str(snapshot.id) if snapshot else None,
            "reasons": [r.code for r in combined_reasons],
        },
    )

    return ScopeEvaluationResponse(
        outcome=opa_decision.outcome,
        allowed=opa_decision.allowed,
        requires_approval=opa_decision.requires_approval,
        reasons=combined_reasons,
        canonical_target=canonical_str,
        target_type=request.target_type.value,
        target_port=target_port,
        resolved_ips=scope_result.resolved_ips,
        redirect_safe=redirect_safe,
        policy_version=opa_decision.policy_version,
        snapshot_id=snapshot.id if snapshot else None,
        snapshot_verified=(
            snapshot_verification.valid if snapshot_verification is not None else None
        ),
    )


async def verify_snapshot(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    revalidate_dns: bool,
    correlation_id: str | None,
    settings: Settings | None = None,
    dns_resolver: DnsResolver | None = None,
    opa_client: OpaScopeClient | None = None,
    signer: SnapshotSigner | None = None,
    skip_rbac: bool = False,
) -> SnapshotVerifyResponse:
    """Verify cryptographic signature, key status, policy/asset freshness, DNS, and OPA."""
    if not skip_rbac:
        assert_permission(actor_role, Permission.SNAPSHOT_VERIFY)
    cfg = settings or get_settings()
    resolver = dns_resolver or SystemDnsResolver()
    client = opa_client or OpaScopeClient(
        base_url=cfg.opa_url,
        timeout_seconds=cfg.opa_timeout_seconds,
    )
    active_signer = signer or SnapshotSigner.from_settings(cfg)
    now = datetime.now(UTC)

    snapshot = (
        await db.execute(
            select(ScopeSnapshot).where(
                ScopeSnapshot.id == snapshot_id,
                ScopeSnapshot.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if snapshot is None:
        raise NotFoundError("Scope snapshot not found")
    org, project, env, asset, auth = await _load_authorization_hierarchy(
        db,
        org_id=org_id,
        authorization_id=snapshot.authorization_id,
    )
    if auth.status == AuthorizationStatus.APPROVED.value and auth.expires_at <= now:
        auth.status = AuthorizationStatus.EXPIRED.value

    verification, hash_matches = _verify_snapshot_crypto_and_consistency(
        snapshot=snapshot,
        signer=active_signer,
    )

    dns_passed: bool | None = None
    dns_reasons: list[ScopeReason] = []
    revalidated_ips: list[str] = list(snapshot.resolved_ips)
    dns_safe = True

    if revalidate_dns:
        bindings = (snapshot.payload or {}).get("dns_bindings")
        pinned_dns: dict[str, list[str]] | None = None
        if isinstance(bindings, dict):
            pinned_dns = {
                str(host): [str(ip) for ip in ips]
                for host, ips in bindings.items()
                if isinstance(ips, list)
            }
        scope_def = ScopeDefinition.model_validate(snapshot.scope_definition).model_copy(
            update={"pinned_dns_resolution": pinned_dns or {}}
        )
        hostnames = _extract_hostnames_for_dns(scope_def)
        if asset.asset_type in _NETWORK_ASSET_TYPES and hostnames:
            collected_ips: set[str] = set()
            all_hosts_ok = True
            for host in hostnames:
                res = resolve_and_validate_host(host, scope_def, resolver)
                if not res.allowed:
                    all_hosts_ok = False
                    dns_safe = False
                    dns_reasons.extend(res.reasons)
                else:
                    collected_ips.update(res.resolved_ips)
            dns_passed = all_hosts_ok
            revalidated_ips = sorted(collected_ips)
        else:
            dns_passed = True

    auth_caps = _normalize_capability_tokens(auth.approved_activities, strict=False)
    pre_flight = {
        "canonical_valid": True,
        "scope_matched": True,
        "port_allowed": True,
        "dns_safe": dns_safe,
        "redirect_safe": True,
    }
    opa_input = _build_opa_input(
        actor_id=actor_id,
        actor_role=actor_role,
        org=org,
        project=project,
        env=env,
        asset=asset,
        auth=auth,
        auth_capabilities=auth_caps,
        requested_capabilities=snapshot.permitted_capabilities or auth_caps,
        requested_intensity=IntensityLevel(snapshot.permitted_intensity),
        tool_category=None,
        target_port=None,
        pre_flight_facts=pre_flight,
        now=now,
        expected_policy_version=cfg.policy_bundle_version,
        snapshot=snapshot,
        snapshot_hash_matches=hash_matches,
        snapshot_signature_valid=verification.valid,
    )
    opa_decision = await client.evaluate_scope_decision(
        opa_input,
        expected_policy_version=cfg.policy_bundle_version,
    )
    combined_reasons = _merge_reasons(opa_decision, dns_reasons, verification)

    policy_current = (
        snapshot.policy_version == cfg.policy_bundle_version
        and auth.policy_version == cfg.policy_bundle_version
    )
    asset_current = snapshot.asset_version == asset.version
    auth_active = (
        auth.status == AuthorizationStatus.APPROVED.value
        and auth.valid_from <= now < auth.expires_at
        and now < snapshot.authorization_expires_at
    )
    overall_valid = (
        verification.valid
        and hash_matches
        and policy_current
        and asset_current
        and auth_active
        and (dns_passed is not False)
        and opa_decision.allowed
    )

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scope_snapshot.verified",
        resource_type="scope_snapshot",
        resource_id=snapshot.id,
        outcome=AuditOutcome.SUCCESS if overall_valid else AuditOutcome.DENIED,
        metadata={
            "valid": overall_valid,
            "signature_valid": verification.valid,
            "signature_reason": verification.reason,
            "policy_version_current": policy_current,
            "asset_version_current": asset_current,
            "dns_revalidation_passed": dns_passed,
            "opa_outcome": opa_decision.outcome,
        },
    )

    return SnapshotVerifyResponse(
        snapshot_id=snapshot.id,
        valid=overall_valid,
        signature_valid=verification.valid,
        signature_reason=verification.reason,
        policy_version_current=policy_current,
        asset_version_current=asset_current,
        authorization_active=auth_active,
        dns_revalidation_passed=dns_passed,
        resolved_ips=revalidated_ips,
        opa_outcome=opa_decision.outcome,
        reasons=combined_reasons,
    )
