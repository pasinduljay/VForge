"""Pydantic v2 request and response schemas for Phase 1 API."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any, Literal

from vforge_scope import (
    IntensityLevel,
    ScopeValidationError,
    TargetType,
    normalize_capabilities,
)
from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator

from vforge.models.enums import (
    ArtifactType,
    AssetType,
    AuthorizationStatus,
    AuthProfileStatus,
    AuthProfileType,
    BusinessPriority,
    CoverageStatus,
    EnvironmentStatus,
    EnvironmentType,
    FindingCategory,
    FindingConfidence,
    FindingEventType,
    FindingSeverity,
    FindingStatus,
    FindingValidationStatus,
    LeaseRiskClass,
    MembershipStatus,
    OrgStatus,
    ProjectCriticality,
    ProjectStatus,
    RegistrationState,
    ReportFormat,
    ReportType,
    RetestStatus,
    RiskExceptionStatus,
    Role,
    RunnerEventSeverity,
    RunnerJobStatus,
    RunnerPoolType,
    RunnerStatus,
    ScanProfileStatus,
    ScanRunStatus,
    ScanStageStatus,
    SourceSnapshotStatus,
    TargetLeaseStatus,
    ToolExecutionStatus,
)


class StrictBaseModel(BaseModel):
    """Base schema rejecting unexpected extra fields."""

    model_config = ConfigDict(extra="forbid", from_attributes=True, populate_by_name=True)


# --- Auth & Identity ---


class UserOut(StrictBaseModel):
    id: uuid.UUID
    oidc_issuer: str
    oidc_subject: str
    email: str
    display_name: str
    status: str
    last_login_at: datetime | None
    created_at: datetime


class OrganizationMembershipSummary(StrictBaseModel):
    organization_id: uuid.UUID
    organization_name: str
    organization_slug: str
    organization_status: str
    role: Role
    membership_status: MembershipStatus
    permissions: list[str]


class AuthMeResponse(StrictBaseModel):
    user: UserOut
    active_organization_id: uuid.UUID | None
    csrf_token: str | None = None
    memberships: list[OrganizationMembershipSummary]


class SwitchOrganizationRequest(StrictBaseModel):
    organization_id: uuid.UUID


# --- Organizations & Memberships ---


class OrganizationCreate(StrictBaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=100)


class OrganizationUpdate(StrictBaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    status: OrgStatus | None = None


class OrganizationOut(StrictBaseModel):
    id: uuid.UUID
    name: str
    slug: str
    status: str
    created_at: datetime
    updated_at: datetime


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class MembershipCreate(StrictBaseModel):
    oidc_issuer: str = Field(min_length=3, max_length=512)
    oidc_subject: str = Field(min_length=1, max_length=256)
    email: str = Field(min_length=3, max_length=320)
    display_name: str = Field(min_length=1, max_length=200)
    role: Role
    status: MembershipStatus = MembershipStatus.ACTIVE

    @field_validator("email")
    @classmethod
    def validate_email(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not _EMAIL_RE.match(cleaned):
            raise ValueError("Invalid email address format")
        return cleaned


class MembershipUpdate(StrictBaseModel):
    role: Role | None = None
    status: MembershipStatus | None = None


class MembershipOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    user_id: uuid.UUID
    role: Role
    status: MembershipStatus
    user_email: str
    user_display_name: str
    oidc_issuer: str
    oidc_subject: str
    created_at: datetime
    updated_at: datetime


# --- Projects & Environments ---


class ProjectCreate(StrictBaseModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    criticality: ProjectCriticality = ProjectCriticality.MEDIUM


class ProjectUpdate(StrictBaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    criticality: ProjectCriticality | None = None
    status: ProjectStatus | None = None


class ProjectOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    description: str | None
    criticality: ProjectCriticality
    status: ProjectStatus
    created_at: datetime
    updated_at: datetime


class EnvironmentCreate(StrictBaseModel):
    name: str = Field(min_length=1, max_length=100)
    environment_type: EnvironmentType


class EnvironmentUpdate(StrictBaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    environment_type: EnvironmentType | None = None
    status: EnvironmentStatus | None = None


class EnvironmentOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    name: str
    environment_type: EnvironmentType
    status: EnvironmentStatus
    created_at: datetime
    updated_at: datetime


# --- Assets & Auth Profiles ---


class AssetCreate(StrictBaseModel):
    asset_type: AssetType
    locator: str = Field(min_length=1, max_length=2048)
    scope_metadata: dict[str, Any] = Field(default_factory=dict)
    registration_state: RegistrationState = RegistrationState.REGISTERED


class AssetUpdate(StrictBaseModel):
    scope_metadata: dict[str, Any] | None = None
    registration_state: RegistrationState | None = None


class AssetOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    environment_id: uuid.UUID
    asset_type: AssetType
    normalized_locator: str
    scope_metadata: dict[str, Any]
    registration_state: RegistrationState
    version: int = 1
    created_at: datetime
    updated_at: datetime


class AuthProfileCreate(StrictBaseModel):
    name: str = Field(min_length=2, max_length=150)
    auth_type: AuthProfileType
    secret_manager_ref: str = Field(min_length=6, max_length=512)


class AuthProfileUpdate(StrictBaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=150)
    auth_type: AuthProfileType | None = None
    secret_manager_ref: str | None = Field(default=None, min_length=6, max_length=512)
    status: AuthProfileStatus | None = None


class AuthProfileOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    environment_id: uuid.UUID
    name: str
    auth_type: AuthProfileType
    secret_manager_ref: str
    status: AuthProfileStatus
    created_at: datetime
    updated_at: datetime


# --- Authorizations ---


ALLOWED_TESTING_ACTIVITIES = frozenset(
    {
        "sast",
        "secrets",
        "sbom",
        "sca",
        "iac",
        "passive_dast",
        "active_dast",
        "network_discovery",
        "tls_assessment",
        "passive_web_testing",
        "active_web_testing",
        "api_testing",
        "authenticated_testing",
        "container_assessment",
        "source_code_analysis",
        "infrastructure_analysis",
        "approved_exploit_validation",
    }
)


def _validate_activities_list(items: list[str]) -> list[str]:
    cleaned = [item.strip().lower() for item in items if item.strip()]
    if not cleaned:
        raise ValueError("approved_activities must contain at least one activity")
    try:
        normalize_capabilities(cleaned)
    except (ValueError, ScopeValidationError) as exc:
        message = exc.message if isinstance(exc, ScopeValidationError) else str(exc)
        raise ValueError(message) from exc
    invalid = set(cleaned) - ALLOWED_TESTING_ACTIVITIES
    if invalid:
        raise ValueError(f"Unsupported activities: {sorted(invalid)}")
    return sorted(set(cleaned))


def _validate_ports_list(ports: list[int] | None) -> list[int] | None:
    if ports is None:
        return None
    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError("Ports must be between 1 and 65535")
    return sorted(set(ports))


class AuthorizationCreate(StrictBaseModel):
    asset_id: uuid.UUID
    approved_testing_scope: dict[str, Any] = Field(default_factory=dict)
    approved_activities: list[str] = Field(min_length=1, max_length=20)
    allowed_ports: list[int] | None = Field(default=None, max_length=100)
    permitted_intensity: IntensityLevel = IntensityLevel.PASSIVE
    allow_private_networks: bool = False
    authorization_reference: str = Field(min_length=2, max_length=200)
    valid_from: datetime
    expires_at: datetime

    @field_validator("approved_activities")
    @classmethod
    def validate_activities(cls, items: list[str]) -> list[str]:
        return _validate_activities_list(items)

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, ports: list[int] | None) -> list[int] | None:
        return _validate_ports_list(ports)


class AuthorizationUpdate(StrictBaseModel):
    approved_testing_scope: dict[str, Any] | None = None
    approved_activities: list[str] | None = Field(default=None, min_length=1, max_length=20)
    allowed_ports: list[int] | None = Field(default=None, max_length=100)
    permitted_intensity: IntensityLevel | None = None
    allow_private_networks: bool | None = None
    authorization_reference: str | None = Field(default=None, min_length=2, max_length=200)
    valid_from: datetime | None = None
    expires_at: datetime | None = None

    @field_validator("approved_activities")
    @classmethod
    def validate_activities(cls, items: list[str] | None) -> list[str] | None:
        if items is None:
            return None
        return _validate_activities_list(items)

    @field_validator("allowed_ports")
    @classmethod
    def validate_ports(cls, ports: list[int] | None) -> list[int] | None:
        return _validate_ports_list(ports)


class AuthorizationDecisionRequest(StrictBaseModel):
    reason: str | None = Field(default=None, max_length=1000)


class AuthorizationRevokeRequest(StrictBaseModel):
    reason: str = Field(min_length=3, max_length=1000)


class AuthorizationOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    asset_id: uuid.UUID
    requested_by: uuid.UUID
    approved_by: uuid.UUID | None
    revoked_by: uuid.UUID | None
    approved_testing_scope: dict[str, Any]
    approved_activities: list[str]
    allowed_ports: list[int] | None
    permitted_intensity: IntensityLevel
    policy_version: str
    allow_private_networks: bool
    authorization_reference: str
    valid_from: datetime
    expires_at: datetime
    status: AuthorizationStatus
    decision_reason: str | None
    revocation_reason: str | None
    approved_at: datetime | None
    revoked_at: datetime | None
    audit_history: list[dict[str, Any]]
    created_at: datetime
    updated_at: datetime


# --- Scope Evaluation & Immutable Snapshots (Phase 2) ---


class ScopePolicyReasonOut(StrictBaseModel):
    code: str
    message: str


class ScopeEvaluateRequest(StrictBaseModel):
    authorization_id: uuid.UUID
    asset_id: uuid.UUID | None = None
    project_id: uuid.UUID | None = None
    environment_id: uuid.UUID | None = None
    scan_profile_id: uuid.UUID | None = None
    snapshot_id: uuid.UUID | None = None
    target_type: TargetType
    raw_target: str = Field(min_length=1, max_length=2048)
    requested_capabilities: list[str] = Field(min_length=1, max_length=20)
    requested_intensity: IntensityLevel = IntensityLevel.PASSIVE
    tool_category: str | None = Field(default=None, max_length=50)
    redirect_location: str | None = Field(default=None, max_length=2048)
    redirect_hop_count: int = Field(default=1, ge=1, le=20)
    resolve_dns: bool = True


class ScopeEvaluationResponse(StrictBaseModel):
    outcome: Literal["ALLOW", "DENY", "REQUIRES_APPROVAL"]
    allowed: bool
    requires_approval: bool
    reasons: list[ScopePolicyReasonOut]
    canonical_target: str | None
    target_type: str
    target_port: int | None
    resolved_ips: list[str]
    redirect_safe: bool
    redirect_canonical_target: str | None = None
    policy_version: str
    snapshot_id: uuid.UUID | None = None
    snapshot_verified: bool | None = None


class ScopeSnapshotOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    asset_id: uuid.UUID
    authorization_id: uuid.UUID
    snapshot_version: int
    asset_version: int
    policy_version: str
    target_type: str
    canonical_locator: str
    resolved_ips: list[str]
    allowed_ports: list[int]
    permitted_capabilities: list[str]
    permitted_intensity: IntensityLevel
    scope_definition: dict[str, Any]
    payload: dict[str, Any]
    payload_sha256: str
    signing_key_id: str
    signature_algorithm: str
    signature: str
    authorization_expires_at: datetime
    created_by: uuid.UUID
    created_at: datetime


class SnapshotVerifyRequest(StrictBaseModel):
    revalidate_dns: bool = True


class SnapshotVerifyResponse(StrictBaseModel):
    snapshot_id: uuid.UUID
    valid: bool
    signature_valid: bool
    signature_reason: str
    policy_version_current: bool
    asset_version_current: bool
    authorization_active: bool
    dns_revalidation_passed: bool | None
    resolved_ips: list[str]
    opa_outcome: Literal["ALLOW", "DENY", "REQUIRES_APPROVAL"]
    reasons: list[ScopePolicyReasonOut]


# --- Scan Profiles ---


class ScanProfileConfiguration(StrictBaseModel):
    stages: list[str] = Field(min_length=1, max_length=20)
    passive_only: bool = True
    max_concurrency: int = Field(default=2, ge=1, le=16)
    request_rate_limit_rps: int = Field(default=5, ge=1, le=200)
    timeout_seconds: int = Field(default=900, ge=60, le=14400)
    include_paths: list[str] = Field(default_factory=list, max_length=100)
    exclude_paths: list[str] = Field(default_factory=list, max_length=100)
    enable_custom_policies: bool = False
    dast_tool: Literal["zap", "nuclei", "dummy"] | None = None
    network_tool: Literal["nmap", "dummy"] | None = None
    tls_tool: Literal["testssl", "dummy"] | None = None
    auth_profile_id: uuid.UUID | None = None
    openapi_spec: str | None = None
    health_check_path: str | None = None
    max_rps: int | None = Field(default=None, ge=1, le=50)
    rule_pack_version_ids: list[uuid.UUID] = Field(default_factory=list, max_length=50)

    @field_validator("stages")
    @classmethod
    def validate_stages(cls, items: list[str]) -> list[str]:
        cleaned = [item.strip().lower() for item in items if item.strip()]
        invalid = set(cleaned) - ALLOWED_TESTING_ACTIVITIES
        if invalid:
            raise ValueError(f"Unsupported scan stages: {sorted(invalid)}")
        return sorted(set(cleaned))


class ScanProfileCreate(StrictBaseModel):
    name: str = Field(min_length=2, max_length=150)
    configuration: ScanProfileConfiguration
    status: ScanProfileStatus = ScanProfileStatus.ACTIVE


class ScanProfileUpdate(StrictBaseModel):
    status: ScanProfileStatus | None = None
    configuration: ScanProfileConfiguration | None = None


class ScanProfileOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    version: int
    configuration: dict[str, Any]
    status: ScanProfileStatus
    created_at: datetime
    updated_at: datetime


# --- Audit Events ---


class AuditEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID | None
    actor_id: uuid.UUID | None
    correlation_id: str | None
    action: str
    resource_type: str | None
    resource_id: uuid.UUID | None
    outcome: str
    metadata: dict[str, Any] = Field(validation_alias="event_metadata")
    created_at: datetime


# --- Phase 3 Orchestration: Scan Runs, Stages, Jobs, Target Leases ---


class ScanRunCreate(StrictBaseModel):
    project_id: uuid.UUID
    environment_id: uuid.UUID
    scan_profile_id: uuid.UUID
    authorization_id: uuid.UUID
    scope_snapshot_id: uuid.UUID
    source_snapshot_id: uuid.UUID | None = None
    auth_profile_id: uuid.UUID | None = None
    requested_intensity: IntensityLevel | None = None
    revalidate_dns: bool = True
    execution_mode: Literal["simulated", "runner"] = "simulated"
    target_pool_id: uuid.UUID | None = None
    runner_image_digest: str | None = Field(default=None, max_length=255)
    simulation_mode: Literal[
        "success",
        "transient_fail_once",
        "permanent_fail",
        "timeout_hold",
    ] = "success"
    simulation_delay_ms: int = Field(default=0, ge=0, le=5000)
    timeout_seconds_override: int | None = Field(default=None, ge=1, le=14400)
    max_attempts: int = Field(default=3, ge=1, le=5)


class ScanCancelRequest(StrictBaseModel):
    reason: str | None = Field(default=None, max_length=500)


class RunnerJobOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_run_id: uuid.UUID
    scan_stage_id: uuid.UUID
    job_type: str
    tool_id: str
    tool_version: str
    image_digest: str
    adapter_version: str
    execution_mode: str = "simulated"
    target_pool_id: uuid.UUID | None = None
    claimed_by_runner_id: uuid.UUID | None = None
    manifest_sha256: str | None = None
    manifest_expires_at: datetime | None = None
    cancel_requested_at: datetime | None = None
    claimed_at: datetime | None = None
    status: RunnerJobStatus
    attempt_count: int
    max_attempts: int
    lease_owner: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    next_retry_at: datetime | None
    timeout_seconds: int
    idempotency_key: str
    execution_count: int
    result_summary: dict[str, Any]
    last_error_code: str | None
    last_error_message: str | None
    dispatched_at: datetime | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanStageOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_run_id: uuid.UUID
    stage_key: str
    stage_order: int
    stage_kind: str
    depends_on_stage_key: str | None
    requires_target_lease: bool
    lease_risk_class: LeaseRiskClass | None
    status: ScanStageStatus
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ScanTargetLeaseOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_run_id: uuid.UUID
    runner_job_id: uuid.UUID | None
    asset_id: uuid.UUID
    target_locator: str
    lease_risk_class: LeaseRiskClass
    lease_owner: str
    status: TargetLeaseStatus
    acquired_at: datetime
    heartbeat_at: datetime
    expires_at: datetime
    released_at: datetime | None


class ScanRunSummaryOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    environment_id: uuid.UUID
    scan_profile_id: uuid.UUID
    authorization_id: uuid.UUID
    scope_snapshot_id: uuid.UUID
    source_snapshot_id: uuid.UUID | None = None
    source_snapshot_hash: str | None = None
    auth_profile_id: uuid.UUID | None = None
    requested_by: uuid.UUID
    status: ScanRunStatus
    coverage_status: CoverageStatus
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    runner_pool: str
    policy_snapshot_hash: str
    policy_version: str
    idempotency_key: str
    cancel_requested_by: uuid.UUID | None
    cancel_reason: str | None
    error_summary: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class TargetHealthProbeCreate(StrictBaseModel):
    probe_type: Literal["baseline", "periodic", "tripwire", "post_scan"]
    target_url: str = Field(min_length=1, max_length=2048)
    status_code: int | None = Field(default=None, ge=100, le=599)
    latency_ms: int = Field(default=0, ge=0, le=600000)
    healthy: bool = True
    error_message: str | None = Field(default=None, max_length=1000)
    probe_metadata: dict[str, Any] = Field(default_factory=dict)


class TargetHealthProbeOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_run_id: uuid.UUID
    runner_job_id: uuid.UUID | None
    asset_id: uuid.UUID
    probe_type: str
    target_url: str
    status_code: int | None
    latency_ms: int
    healthy: bool
    error_message: str | None
    probe_metadata: dict[str, Any]
    created_at: datetime


class RunnerJobTargetAuthOut(StrictBaseModel):
    auth_profile_id: uuid.UUID
    auth_type: str
    name: str
    credentials: dict[str, Any] = Field(default_factory=dict, repr=False)


class ScanRunDetailOut(ScanRunSummaryOut):
    target_snapshot: dict[str, Any]
    profile_snapshot: dict[str, Any]
    plan_manifest: dict[str, Any]
    tool_version_pins: dict[str, Any] = Field(default_factory=dict)
    rule_pack_pins: list[dict[str, Any]] = Field(default_factory=list)
    stages: list[ScanStageOut]
    jobs: list[RunnerJobOut]
    leases: list[ScanTargetLeaseOut]
    health_probes: list[TargetHealthProbeOut] = Field(default_factory=list)


# --- Phase 4: Runner Pools, mTLS Runners, Executions & Encrypted Artifacts ---


class RunnerPoolCreate(StrictBaseModel):
    name: str = Field(min_length=2, max_length=160)
    slug: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
    pool_type: RunnerPoolType = RunnerPoolType.STANDARD
    max_concurrent_jobs: int = Field(default=4, ge=1, le=64)


class RunnerPoolOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    name: str
    slug: str
    pool_type: RunnerPoolType
    max_concurrent_jobs: int
    active: bool
    created_at: datetime
    updated_at: datetime


class RunnerRegisterRequest(StrictBaseModel):
    pool_id: uuid.UUID
    name: str = Field(min_length=2, max_length=160)
    version: str = Field(min_length=1, max_length=64)
    certificate_pem: str = Field(min_length=64, max_length=16384)
    capabilities: dict[str, Any] = Field(default_factory=dict)


class RunnerRevokeRequest(StrictBaseModel):
    reason: str = Field(min_length=3, max_length=500)


class RunnerOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    pool_id: uuid.UUID
    name: str
    runner_identity: str
    cert_sha256: str
    cert_subject: str
    cert_expires_at: datetime
    status: RunnerStatus
    version: str
    capabilities_json: dict[str, Any]
    last_heartbeat_at: datetime | None
    revoked_by: uuid.UUID | None
    revoked_at: datetime | None
    revocation_reason: str | None
    created_at: datetime
    updated_at: datetime


class RunnerEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    runner_id: uuid.UUID
    runner_job_id: uuid.UUID | None
    event_type: str
    severity: RunnerEventSeverity
    details_json: dict[str, Any]
    created_at: datetime


class RunnerJobClaimRequest(StrictBaseModel):
    pool_id: uuid.UUID | None = None
    runner_version: str | None = Field(default=None, max_length=64)
    active_containers: int = Field(default=0, ge=0, le=128)


class RunnerJobClaimOut(StrictBaseModel):
    claimed: bool
    job_id: uuid.UUID | None = None
    scan_run_id: uuid.UUID | None = None
    execution_id: uuid.UUID | None = None
    attempt_number: int | None = None
    manifest: dict[str, Any] | None = None
    manifest_sha256: str | None = None
    manifest_signature: str | None = None
    manifest_signing_key_id: str | None = None
    public_keyring_json: str | None = None
    signed_allowlist_payload: dict[str, Any] | None = None
    allowlist_sha256: str | None = None
    allowlist_signature: str | None = None
    allowlist_signing_key_id: str | None = None


class RunnerHeartbeatRequest(StrictBaseModel):
    attempt_number: int = Field(ge=1, le=20)
    status: str = Field(default="running", max_length=30)
    cpu_percent: int = Field(default=0, ge=0, le=1000)
    memory_mb: int = Field(default=0, ge=0, le=1048576)
    active_containers: int = Field(default=0, ge=0, le=128)
    metrics: dict[str, Any] = Field(default_factory=dict)


class RunnerHeartbeatOut(StrictBaseModel):
    acknowledged: bool
    cancel_requested: bool
    runner_status: RunnerStatus
    lease_expires_at: datetime | None


class RunnerEventCreate(StrictBaseModel):
    event_type: str = Field(min_length=2, max_length=80)
    severity: RunnerEventSeverity = RunnerEventSeverity.INFO
    details: dict[str, Any] = Field(default_factory=dict)


class RunnerArtifactUploadRequest(StrictBaseModel):
    execution_id: uuid.UUID
    attempt_number: int = Field(ge=1, le=20)
    artifact_type: ArtifactType
    content_type: str = Field(min_length=3, max_length=150)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    content_b64: str = Field(min_length=1)


class RunnerArtifactOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    scan_run_id: uuid.UUID
    runner_job_id: uuid.UUID | None
    execution_id: uuid.UUID | None
    artifact_type: ArtifactType
    storage_key: str
    sha256: str
    ciphertext_sha256: str
    encryption_algorithm: str
    encryption_key_id: str
    content_type: str
    size_bytes: int
    created_at: datetime


class RunnerJobCompleteRequest(StrictBaseModel):
    execution_id: uuid.UUID
    attempt_number: int = Field(ge=1, le=20)
    status: Literal["completed", "failed", "timed_out", "cancelled"]
    exit_code: int | None = None
    error_code: str | None = Field(default=None, max_length=80)
    error_message: str | None = Field(default=None, max_length=1000)
    metrics: dict[str, Any] = Field(default_factory=dict)


class RunnerJobCompleteOut(StrictBaseModel):
    job_id: uuid.UUID
    job_status: RunnerJobStatus
    execution_status: ToolExecutionStatus
    scan_run_status: ScanRunStatus


# --- Phase 5: Source Snapshots, Findings & Language Coverage ---


class SourceSnapshotCreate(StrictBaseModel):
    asset_id: uuid.UUID
    source_type: Literal["archive_tar_gz", "archive_zip"] = "archive_tar_gz"
    content_b64: str = Field(min_length=4, max_length=29_000_000)
    commit_sha: str | None = Field(default=None, min_length=7, max_length=64)
    branch: str | None = Field(default=None, max_length=160)


class SourceSnapshotOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    asset_id: uuid.UUID
    source_type: str
    commit_sha: str | None
    branch: str | None
    archive_sha256: str
    file_count: int
    total_bytes: int
    detected_languages: dict[str, Any]
    coverage_report: dict[str, Any]
    status: SourceSnapshotStatus
    created_by: uuid.UUID
    created_at: datetime


class FindingOccurrenceOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    finding_id: uuid.UUID
    scan_run_id: uuid.UUID
    execution_id: uuid.UUID
    evidence_artifact_id: uuid.UUID | None
    scanner_tool_id: str
    scanner_version: str
    image_digest: str
    rule_id: str
    file_path: str | None
    start_line: int | None
    end_line: int | None
    severity: FindingSeverity
    confidence: FindingConfidence
    secret_redacted: bool
    snippet_redacted: str | None
    purl: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    cve_id: str | None = None
    iac_resource: str | None = None
    sbom_document_id: uuid.UUID | None = None
    vulnerability_db_snapshot_id: uuid.UUID | None = None
    raw_finding_sanitized: dict[str, Any]
    observed_at: datetime


class FindingOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    fingerprint: str
    category: FindingCategory
    scanner_tool_id: str
    scanner_version: str
    rule_id: str
    title: str
    description: str | None
    severity: FindingSeverity
    confidence: FindingConfidence
    validation_status: FindingValidationStatus
    status: FindingStatus
    cwe_ids: list[str]
    file_path: str | None
    start_line: int | None
    end_line: int | None
    code_snippet_redacted: str | None
    secret_redacted: bool
    remediation: str | None
    purl: str | None = None
    package_name: str | None = None
    package_version: str | None = None
    fixed_version: str | None = None
    cve_id: str | None = None
    iac_resource: str | None = None
    sbom_document_id: uuid.UUID | None = None
    vulnerability_db_snapshot_id: uuid.UUID | None = None
    sla_due_at: datetime | None = None
    sla_breached: bool = False
    assigned_to: uuid.UUID | None = None
    remediation_notes: str | None = None
    retest_status: RetestStatus | None = None
    business_priority: BusinessPriority = BusinessPriority.MEDIUM
    cvss_score: float | None = None
    cvss_vector: str | None = None
    is_known_exploited: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime


class FindingUpdate(StrictBaseModel):
    status: FindingStatus | None = None
    validation_status: FindingValidationStatus | None = None
    assigned_to: uuid.UUID | None = None
    remediation_notes: str | None = Field(default=None, max_length=10000)
    business_priority: BusinessPriority | None = None
    retest_status: RetestStatus | None = None
    comment: str | None = Field(default=None, max_length=2000)


class FindingEventCreate(StrictBaseModel):
    event_type: FindingEventType
    comment: str | None = Field(default=None, max_length=2000)
    metadata_payload: dict[str, Any] = Field(default_factory=dict)


class FindingEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    finding_id: uuid.UUID
    actor_id: uuid.UUID | None
    event_type: FindingEventType
    previous_status: str | None
    new_status: str | None
    comment: str | None
    metadata_payload: dict[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices("metadata_payload", "metadata"),
        serialization_alias="metadata",
    )
    created_at: datetime


class RiskExceptionCreate(StrictBaseModel):
    reason: str = Field(min_length=10, max_length=5000)
    mitigating_controls: str = Field(min_length=10, max_length=5000)
    expires_at: datetime


class RiskExceptionReview(StrictBaseModel):
    approved: bool
    review_notes: str = Field(min_length=3, max_length=5000)


class RiskExceptionOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    finding_id: uuid.UUID
    status: RiskExceptionStatus
    requested_by: uuid.UUID
    reviewed_by: uuid.UUID | None
    reason: str
    mitigating_controls: str
    review_notes: str | None
    expires_at: datetime
    created_at: datetime
    updated_at: datetime


class ReportGenerateRequest(StrictBaseModel):
    project_id: uuid.UUID
    scan_run_id: uuid.UUID | None = None
    report_type: ReportType = ReportType.EXECUTIVE
    format: ReportFormat = ReportFormat.HTML
    title: str | None = Field(default=None, max_length=255)


class ReportOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    scan_run_id: uuid.UUID | None
    report_type: ReportType
    format: ReportFormat
    title: str
    summary: dict[str, Any]
    artifact_id: uuid.UUID
    generated_by: uuid.UUID
    created_at: datetime


class FindingDetailOut(FindingOut):
    occurrences: list[FindingOccurrenceOut] = Field(default_factory=list)
    events: list[FindingEventOut] = Field(default_factory=list)
    active_risk_exception: RiskExceptionOut | None = None


class SbomDocumentOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    scan_run_id: uuid.UUID
    source_snapshot_id: uuid.UUID
    execution_id: uuid.UUID
    artifact_id: uuid.UUID
    sbom_format: str
    spec_version: str
    serial_number: str | None
    bom_sha256: str
    tool_id: str
    tool_version: str
    image_digest: str
    component_count: int
    created_at: datetime


class SbomDocumentDetailOut(SbomDocumentOut):
    cataloger_config: dict[str, Any] = Field(default_factory=dict)
    components_summary: list[dict[str, Any]] = Field(default_factory=list)


class VulnerabilityDbSnapshotOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    tool_id: str
    schema_version: str
    built_at: datetime
    source_url: str | None
    db_archive_sha256: str
    valid: bool
    providers_metadata: dict[str, Any] = Field(default_factory=dict)
    recorded_at: datetime


class ScannerCapabilityEntryOut(StrictBaseModel):
    language: str
    tool_id: str
    support_status: Literal["supported", "partial", "unsupported"]
    parser_mode: str
    supported_versions: str
    known_blind_spots: str
    last_validated: str


class ScannerCoverageOut(StrictBaseModel):
    phase: int
    scanners_enabled: bool
    tools: list[dict[str, Any]]
    capabilities: list[ScannerCapabilityEntryOut]


# --- Pagination Wrapper ---


class PaginatedResponse(StrictBaseModel):
    items: list[Any]
    total: int
    limit: int
    offset: int


# --- Phase 9 Threat Intelligence Schemas ---


class IntelSourceOut(StrictBaseModel):
    id: uuid.UUID
    slug: str
    name: str
    source_type: str
    provider_url: str
    license_name: str
    license_url: str | None = None
    terms_reference: str | None = None
    is_active: bool
    is_gated: bool
    requires_scope_auth: bool
    allow_binary_upload: bool
    created_at: datetime
    updated_at: datetime


class IntelSyncRunOut(StrictBaseModel):
    id: uuid.UUID
    source_id: uuid.UUID
    sync_mode: str
    cursor_before: str | None = None
    cursor_after: str | None = None
    status: str
    records_fetched: int
    records_persisted: int
    error_message: str | None = None
    raw_payload_hash: str | None = None
    started_at: datetime
    completed_at: datetime | None = None


class IntelRecordOut(StrictBaseModel):
    id: uuid.UUID
    source_id: uuid.UUID
    source_record_id: str
    record_type: str
    title: str | None = None
    summary: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    is_known_exploited: bool = False
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    raw_hash: str
    normalized_hash: str
    published_at: datetime | None = None
    modified_at: datetime | None = None
    retrieved_at: datetime


class CveThreatIntelOut(StrictBaseModel):
    cve_id: str
    is_known_exploited: bool
    epss_score: float | None = None
    epss_percentile: float | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    cwes: list[str] = Field(default_factory=list)
    kev_details: dict[str, Any] | None = None
    exploit_references: list[dict[str, Any]] = Field(default_factory=list)
    advisories: list[dict[str, Any]] = Field(default_factory=list)
    sources_used: list[str] = Field(default_factory=list)


class IntelEnrichmentRequest(StrictBaseModel):
    project_id: uuid.UUID | None = None


class IntelEnrichmentResponse(StrictBaseModel):
    enriched_count: int
    message: str


class OrgThreatIntelSummaryOut(StrictBaseModel):
    organization_id: str
    total_findings: int
    kev_findings_count: int
    high_epss_findings_count: int
    sources: list[dict[str, Any]]


class ExposureSearchRequest(StrictBaseModel):
    query: str = Field(min_length=1, max_length=255)
    query_type: str = Field(
        default="auto",
        pattern="^(auto|domain|email|ip|company|username)$",
    )


class ExposureSourceStatusOut(StrictBaseModel):
    source_slug: str
    source_name: str
    status: str
    http_status: int | None = None
    records_found: int
    latency_ms: int
    raw_sha256: str
    retrieved_at: datetime
    error_message: str | None = None


class ExposureRecordOut(StrictBaseModel):
    record_id: str
    source_slug: str
    source_name: str
    category: str
    severity: str
    title: str
    target: str
    summary: str
    occurred_at: datetime | None = None
    cve_id: str | None = None
    is_known_exploited: bool = False
    epss_score: float | None = None
    remediation: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class HudsonRockOverviewOut(StrictBaseModel):
    total_hits: int = 0
    employees_compromised: int = 0
    users_compromised: int = 0
    third_parties_compromised: int = 0
    last_employee_compromised: str | None = None
    last_user_compromised: str | None = None
    stealer_families: dict[str, int] = Field(default_factory=dict)
    weak_user_password_pct: float | None = None
    employee_urls_count: int = 0
    client_urls_count: int = 0
    third_party_domains: list[dict[str, Any]] = Field(default_factory=list)


class ExposureSearchResponse(StrictBaseModel):
    query: str
    normalized_query: str
    detected_type: str
    resolved_domains: list[str] = Field(default_factory=list)
    resolved_ips: list[str] = Field(default_factory=list)
    discovered_subdomains: list[str] = Field(default_factory=list)
    discovered_emails: list[str] = Field(default_factory=list)
    total_records: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    latest_compromise_at: datetime | None = None
    hudson_rock_overview: HudsonRockOverviewOut
    sources_queried: list[ExposureSourceStatusOut] = Field(default_factory=list)
    records: list[ExposureRecordOut] = Field(default_factory=list)
    searched_at: datetime


class ExposureFindingImportRequest(StrictBaseModel):
    project_id: uuid.UUID
    source_slug: str = Field(min_length=1, max_length=80)
    category: str = Field(
        pattern=(
            "^(infostealer_infection|compromised_endpoint|"
            "credential_breach|network_exposure|attack_surface_url)$"
        )
    )
    severity: str = Field(pattern="^(critical|high|medium|low|info)$")
    title: str = Field(min_length=3, max_length=500)
    target: str = Field(min_length=1, max_length=500)
    summary: str = Field(min_length=3, max_length=4000)
    remediation: str | None = Field(default=None, max_length=4000)
    cve_id: str | None = Field(default=None, max_length=64)


class ExposureFindingImportResponse(StrictBaseModel):
    finding_id: uuid.UUID
    project_id: uuid.UUID
    created: bool
    title: str
    severity: str
    category: str
    status: str
    message: str


class ToolCatalogOut(StrictBaseModel):
    id: uuid.UUID
    tool_slug: str
    display_name: str
    stream: str
    update_channel: str
    adapter_family: str
    source_registry: str
    automerge_allowed: bool
    is_active: bool
    active_stable_version: dict[str, Any] | None = None
    active_canary_version: dict[str, Any] | None = None
    created_at: datetime
    updated_at: datetime


class ToolVersionOut(StrictBaseModel):
    id: uuid.UUID
    tool_id: uuid.UUID
    version_tag: str
    image_repository: str
    image_digest: str
    adapter_version: str
    approval_channel: str
    is_active_stable: bool
    is_active_canary: bool
    previous_stable_version_id: uuid.UUID | None = None
    signature_verified: bool
    sbom_digest: str | None = None
    release_notes_url: str | None = None
    promoted_at: datetime | None = None
    rolled_back_at: datetime | None = None
    created_at: datetime


class UpdateTestResultOut(StrictBaseModel):
    id: uuid.UUID
    update_id: uuid.UUID
    tool_version_id: uuid.UUID
    test_category: str
    outcome: str
    summary: str
    details_json: dict[str, Any] = Field(default_factory=dict)
    executed_by: str
    executed_at: datetime


class ToolUpdateOut(StrictBaseModel):
    id: uuid.UUID
    tool_id: uuid.UUID
    tool_slug: str
    display_name: str
    candidate_version_id: uuid.UUID
    version_tag: str
    image_digest: str
    previous_version_id: uuid.UUID | None = None
    stream: str
    update_channel: str
    change_type: str
    status: str
    is_emergency: bool
    emergency_justification: str | None = None
    detected_from: str
    approved_at: datetime | None = None
    promoted_at: datetime | None = None
    rolled_back_at: datetime | None = None
    rollback_reason: str | None = None
    rejection_reason: str | None = None
    test_results: list[UpdateTestResultOut] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class FeedSnapshotOut(StrictBaseModel):
    id: uuid.UUID
    tool_id: uuid.UUID
    feed_slug: str
    stream: str
    update_channel: str
    snapshot_tag: str
    archive_sha256: str
    schema_version: str
    record_count: int
    approval_channel: str
    is_active_stable: bool
    is_active_canary: bool
    previous_stable_snapshot_id: uuid.UUID | None = None
    source_url: str | None = None
    promoted_at: datetime | None = None
    rolled_back_at: datetime | None = None
    created_at: datetime


class UpdateAuditEventOut(StrictBaseModel):
    id: uuid.UUID
    update_id: uuid.UUID | None = None
    tool_id: uuid.UUID
    tool_version_id: uuid.UUID | None = None
    feed_snapshot_id: uuid.UUID | None = None
    action: str
    actor_email: str | None = None
    reason: str | None = None
    details_json: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class UpdateLifecycleOverviewOut(StrictBaseModel):
    streams: list[str]
    channels: list[str]
    tools: list[ToolCatalogOut]
    versions: list[ToolVersionOut]
    updates: list[ToolUpdateOut]
    feed_snapshots: list[FeedSnapshotOut]
    audit_events: list[UpdateAuditEventOut]
    active_pins: dict[str, Any]


class CandidateRegisterRequest(StrictBaseModel):
    tool_slug: str = Field(min_length=2, max_length=80)
    version_tag: str = Field(min_length=1, max_length=80)
    image_repository: str = Field(min_length=2, max_length=255)
    image_digest: str
    adapter_version: str = "1.0.0"
    change_type: str = "minor"
    detected_from: str = "operator-api"
    release_notes_url: str | None = None
    sbom_digest: str | None = None
    signature_verified: bool = False
    is_emergency: bool = False
    emergency_justification: str | None = None

    @field_validator("version_tag")
    @classmethod
    def _reject_latest_version_tag(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or cleaned.lower() == "latest" or cleaned.lower().endswith(":latest"):
            raise ValueError("Mutable ':latest' version_tag is strictly forbidden")
        return cleaned

    @field_validator("image_repository")
    @classmethod
    def _reject_latest_repository(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or cleaned.lower().endswith(":latest"):
            raise ValueError("Mutable ':latest' image_repository tag is strictly forbidden")
        return cleaned

    @field_validator("image_digest")
    @classmethod
    def _validate_image_sha256(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", cleaned):
            raise ValueError("image_digest must match sha256:<64 lowercase hex chars>")
        return cleaned

    @field_validator("sbom_digest")
    @classmethod
    def _validate_sbom_sha256(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        cleaned = value.strip().lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", cleaned):
            raise ValueError("sbom_digest must match sha256:<64 lowercase hex chars>")
        return cleaned


class GateResultInput(StrictBaseModel):
    test_category: str
    outcome: str
    summary: str
    details_json: dict[str, Any] = Field(default_factory=dict)


class UpdateValidateRequest(StrictBaseModel):
    automated: bool = True
    simulate_failure_gate: str | None = None
    skip_regression_corpus: bool = False
    tests: list[GateResultInput] = Field(default_factory=list)


class UpdateApproveRequest(StrictBaseModel):
    is_emergency: bool = False
    emergency_justification: str | None = None


class UpdatePromoteRequest(StrictBaseModel):
    target_channel: Literal["canary", "stable"]
    reason: str | None = None


class ToolRollbackRequest(StrictBaseModel):
    reason: str
    target_version_id: uuid.UUID | None = None
    channel: Literal["auto", "canary", "stable"] = "auto"


class FeedSnapshotRegisterRequest(StrictBaseModel):
    tool_slug: str = Field(min_length=2, max_length=80)
    feed_slug: str = Field(min_length=2, max_length=80)
    snapshot_tag: str = Field(min_length=1, max_length=100)
    archive_sha256: str
    schema_version: str = "v5"
    record_count: int = Field(default=0, ge=0)
    source_url: str | None = None

    @field_validator("snapshot_tag")
    @classmethod
    def _reject_latest_snapshot_tag(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned or cleaned.lower() == "latest" or cleaned.lower().endswith(":latest"):
            raise ValueError("Mutable ':latest' feed snapshot_tag is strictly forbidden")
        return cleaned

    @field_validator("archive_sha256")
    @classmethod
    def _validate_archive_sha256(cls, value: str) -> str:
        cleaned = value.strip().lower()
        if cleaned.startswith("sha256:"):
            cleaned = cleaned.split(":", 1)[1]
        if not re.fullmatch(r"[0-9a-f]{64}", cleaned):
            raise ValueError("archive_sha256 must be a 64-character lowercase SHA-256 hex digest")
        return cleaned


class FeedSnapshotPromoteRequest(StrictBaseModel):
    target_channel: Literal["canary", "stable"]
    reason: str | None = None


class FeedSnapshotRollbackRequest(StrictBaseModel):
    reason: str


class RollbackResponseOut(StrictBaseModel):
    demoted_version: ToolVersionOut
    restored_version: ToolVersionOut | None = None


class DetectLocksResponseOut(StrictBaseModel):
    detected_count: int
    candidates: list[dict[str, Any]]


# --- Phase 11: Rule & Skill Studio ---


class RuleCreateInput(StrictBaseModel):
    rule_key: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=3, max_length=200)
    engine: Literal["opengrep", "nuclei", "checkov", "gitleaks", "zap", "nmap"]
    native_format: Literal["yaml", "python", "toml", "json", "lua"]
    risk_class: Literal["static", "passive", "active", "privileged_network"]
    severity: Literal["critical", "high", "medium", "low", "info"] = "medium"
    confidence: Literal["high", "medium", "low", "heuristic"] = "high"
    cwe_id: str = Field(min_length=5, max_length=40)
    rationale: str = Field(min_length=10, max_length=4000)
    target_context: str = Field(default="source_code", min_length=1, max_length=120)
    network_requirements: str = Field(default="none", min_length=1, max_length=120)
    known_limitations: str = Field(min_length=5, max_length=4000)
    timeout_seconds: int = Field(default=30, ge=1, le=3600)
    memory_budget_mb: int = Field(default=256, ge=32, le=8192)
    native_content: str = Field(min_length=5, max_length=131_072)
    expected_evidence_fields: list[str] = Field(min_length=1, max_length=30)
    positive_fixtures: list[dict[str, Any]] = Field(min_length=1, max_length=50)
    negative_fixtures: list[dict[str, Any]] = Field(min_length=1, max_length=50)
    near_miss_fixtures: list[dict[str, Any]] = Field(min_length=1, max_length=50)


class RulePackCreateRequest(StrictBaseModel):
    slug: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)
    owner_team: str = Field(default="security-engineering", min_length=1, max_length=120)


class RulePackVersionCreateRequest(StrictBaseModel):
    version: str = Field(min_length=5, max_length=40)
    semver_change_type: Literal["patch", "minor", "major"] = "minor"
    compatibility: dict[str, str] = Field(default_factory=dict)
    rules: list[RuleCreateInput] = Field(min_length=1, max_length=100)


class AiCandidateGenerateRequest(StrictBaseModel):
    version: str = Field(min_length=5, max_length=40)
    engine: Literal["opengrep", "nuclei", "checkov", "gitleaks", "zap", "nmap"] = "opengrep"
    rule_key: str = Field(min_length=3, max_length=120)
    title: str = Field(min_length=3, max_length=200)
    cwe_id: str = Field(min_length=5, max_length=40)
    target_context: str = Field(default="python_backend", min_length=1, max_length=120)
    untrusted_source_snippet: str = Field(default="", max_length=32_768)


class StudioReviewRequest(StrictBaseModel):
    decision: Literal["approved", "rejected", "changes_requested"]
    comment: str | None = Field(default=None, max_length=2000)


class StudioPromoteRequest(StrictBaseModel):
    target_channel: Literal["candidate", "canary", "stable"]


class StudioRollbackRequest(StrictBaseModel):
    target_channel: Literal["canary", "stable"] = "stable"
    reason: str = Field(min_length=5, max_length=1000)
    quarantine: bool = False


class StudioRuleOut(StrictBaseModel):
    id: uuid.UUID
    rule_key: str
    title: str
    engine: str
    native_format: str
    risk_class: str
    severity: str
    confidence: str
    cwe_id: str
    rationale: str
    target_context: str
    network_requirements: str
    known_limitations: str
    timeout_seconds: int
    memory_budget_mb: int
    native_content: str
    content_sha256: str
    expected_evidence_fields: list[str]
    positive_fixtures: list[dict[str, Any]]
    negative_fixtures: list[dict[str, Any]]
    near_miss_fixtures: list[dict[str, Any]]
    static_validation_passed: bool
    static_validation_errors: list[str]
    created_at: datetime


class RuleFixtureRunOut(StrictBaseModel):
    id: uuid.UUID
    rule_pack_version_id: uuid.UUID
    corpus_ref: str
    corpus_sha256: str
    executed_by: uuid.UUID
    actor_type: str
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
    rule_results_json: list[dict[str, Any]]
    created_at: datetime


class RulePackVersionOut(StrictBaseModel):
    id: uuid.UUID
    rule_pack_id: uuid.UUID
    version: str
    semver_change_type: str
    channel: str
    review_status: str
    creation_method: str
    author_id: uuid.UUID
    author_actor_type: str
    reviewer_id: uuid.UUID | None = None
    approved_at: datetime | None = None
    rejection_reason: str | None = None
    compatibility_json: dict[str, Any] = Field(default_factory=dict)
    validation_summary_json: dict[str, Any] = Field(default_factory=dict)
    ai_provenance_json: dict[str, Any] = Field(default_factory=dict)
    manifest_sha256: str | None = None
    signing_key_id: str | None = None
    signed_by: uuid.UUID | None = None
    signed_at: datetime | None = None
    is_active_canary: bool
    is_active_stable: bool
    fixture_regression_passed: bool
    true_positive_count: int
    false_positive_count: int
    false_negative_count: int
    rules: list[StudioRuleOut] = Field(default_factory=list)
    fixture_runs: list[RuleFixtureRunOut] = Field(default_factory=list)
    created_at: datetime


class RulePackOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    slug: str
    title: str
    description: str
    owner_team: str
    created_by: uuid.UUID
    is_active: bool
    versions: list[RulePackVersionOut] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class AssessmentSkillCreateRequest(StrictBaseModel):
    slug: str = Field(min_length=2, max_length=100, pattern=r"^[a-z0-9][a-z0-9-]{1,98}[a-z0-9]$")
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)
    owner_team: str = Field(default="appsec-ai", min_length=1, max_length=120)


class SkillVersionCreateRequest(StrictBaseModel):
    version: str = Field(min_length=5, max_length=40)
    intent_description: str = Field(min_length=10, max_length=4000)
    allowed_capabilities: list[str] = Field(min_length=1, max_length=30)
    forbidden_actions: list[str] = Field(default_factory=list, max_length=50)
    supported_agent_versions: list[str] = Field(min_length=1, max_length=20)
    playbook_steps_json: list[dict[str, Any]] = Field(min_length=1, max_length=50)


class SkillVersionOut(StrictBaseModel):
    id: uuid.UUID
    skill_id: uuid.UUID
    version: str
    intent_description: str
    allowed_capabilities: list[str]
    forbidden_actions: list[str]
    supported_agent_versions: list[str]
    playbook_steps_json: list[dict[str, Any]]
    creation_method: str
    author_id: uuid.UUID
    author_actor_type: str
    review_status: str
    reviewer_id: uuid.UUID | None = None
    approved_at: datetime | None = None
    rejection_reason: str | None = None
    content_sha256: str
    signing_key_id: str | None = None
    signed_by: uuid.UUID | None = None
    signed_at: datetime | None = None
    channel: str
    is_active_canary: bool
    is_active_stable: bool
    created_at: datetime


class AssessmentSkillOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    slug: str
    title: str
    description: str
    owner_team: str
    created_by: uuid.UUID
    is_active: bool
    versions: list[SkillVersionOut] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class StudioAuditEventOut(StrictBaseModel):
    id: uuid.UUID
    entity_type: str
    entity_id: uuid.UUID
    action: str
    actor_email: str
    actor_type: str
    previous_state: str | None = None
    new_state: str | None = None
    details_json: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class StudioOverviewOut(StrictBaseModel):
    supported_engines: list[str]
    rule_packs: list[RulePackOut]
    skills: list[AssessmentSkillOut]
    audit_events: list[StudioAuditEventOut]


# --- Phase 12: AI Provider Governance & Controlled Multi-Agent Workflows ---


class AiModelCatalogOut(StrictBaseModel):
    id: uuid.UUID
    provider_class: str
    model_slug: str
    display_name: str
    capabilities_json: list[str] = Field(default_factory=list)
    is_local: bool
    retention_days: int
    zdr_available: bool
    requires_retention_consent: bool
    cost_per_1k_input_usd: float
    cost_per_1k_output_usd: float
    is_active: bool
    created_at: datetime


class AiProviderConfigCreateRequest(StrictBaseModel):
    provider_class: Literal[
        "managed_zdr",
        "managed_retained",
        "openai",
        "openai_compatible",
        "local_inference",
    ]
    display_name: str = Field(min_length=2, max_length=120)
    endpoint_url: str | None = Field(default=None, max_length=512)
    secret_ref: str | None = Field(default=None, max_length=160)
    local_only_mode: bool = False
    allowed_models: list[str] = Field(min_length=1, max_length=25)
    monthly_budget_usd: float = Field(default=25.0, ge=0.0, le=100000.0)
    max_tokens_per_request: int = Field(default=8192, ge=64, le=1000000)


class AiProviderConfigOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    provider_class: str
    display_name: str
    endpoint_url: str | None = None
    secret_ref: str | None = None
    local_only_mode: bool
    is_enabled: bool
    allowed_models_json: list[str] = Field(default_factory=list)
    monthly_budget_usd: float
    max_tokens_per_request: int
    retention_consent_approved: bool
    retention_consent_approved_by: uuid.UUID | None = None
    retention_consent_approved_at: datetime | None = None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


class AiRetentionConsentRequest(StrictBaseModel):
    approved: bool
    local_only_mode: bool | None = None


class AiToolProposalInput(StrictBaseModel):
    tool_action: str = Field(min_length=2, max_length=80)
    target_resource_type: str = Field(default="unknown", min_length=1, max_length=64)
    target_resource_id: str = Field(default="none", min_length=1, max_length=128)
    arguments_json: dict[str, Any] = Field(default_factory=dict)


class AiTaskExecuteRequest(StrictBaseModel):
    task_type: str = Field(min_length=2, max_length=64)
    role_name: Literal[
        "architect",
        "attack_surface_analyst",
        "rule_author",
        "adversarial_reviewer",
        "evidence_verifier",
        "remediation_reviewer",
        "independent_critic",
    ]
    raw_prompt: str = Field(min_length=3, max_length=40000)
    model_slug: str = Field(min_length=2, max_length=120)
    prior_model_slug: str | None = Field(default=None, min_length=2, max_length=120)
    provider_config_ids: list[uuid.UUID] = Field(min_length=1, max_length=5)
    fallback_model_slugs: dict[uuid.UUID, str] | None = None
    requested_classification: Literal["public", "internal", "confidential", "restricted"] | None = (
        None
    )
    consent_acknowledged: bool = False
    require_local_only: bool = False
    rag_query: str | None = Field(default=None, max_length=500)
    proposed_tools: list[AiToolProposalInput] = Field(default_factory=list, max_length=10)
    max_tokens: int = Field(default=2048, ge=64, le=1000000)


class AiTaskRequestOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    task_type: str
    role_name: str
    data_classification: str
    redaction_applied: bool
    prompt_injection_detected: bool
    consent_acknowledged: bool
    provider_config_id: uuid.UUID | None = None
    model_slug: str
    input_snapshot_sha256: str
    input_summary_redacted: str
    status: str
    block_reason: str | None = None
    requested_by: uuid.UUID
    created_at: datetime


class AiRunOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    task_request_id: uuid.UUID
    provider_config_id: uuid.UUID | None = None
    role_name: str
    provider_class: str
    model_slug: str
    prompt_template_version: str
    fallback_triggered: bool
    input_sha256: str
    output_sha256: str
    structured_output_json: dict[str, Any] = Field(default_factory=dict)
    rationale_summary: str
    uncertainty_notes: str
    token_input_count: int
    token_output_count: int
    estimated_cost_usd: float
    latency_ms: int
    status: str
    error_message: str | None = None
    created_at: datetime


class AiToolProposalOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    ai_run_id: uuid.UUID
    tool_action: str
    target_resource_type: str
    target_resource_id: str
    arguments_json: dict[str, Any] = Field(default_factory=dict)
    opa_allowed: bool
    opa_decision_reason: str
    status: str
    created_at: datetime


class AiToolProposalDecisionRequest(StrictBaseModel):
    decision: Literal["approved", "rejected"]
    comment: str = Field(default="", max_length=2000)


class KnowledgeSearchHitOut(StrictBaseModel):
    document_id: uuid.UUID
    slug: str
    title: str
    source_type: str
    source_uri: str
    chunk_id: uuid.UUID
    chunk_index: int
    chunk_sha256: str
    score: int
    excerpt: str


class AiTaskExecuteResponse(StrictBaseModel):
    task_request: AiTaskRequestOut
    run: AiRunOut
    tool_proposals: list[AiToolProposalOut] = Field(default_factory=list)
    rag_hits: list[KnowledgeSearchHitOut] = Field(default_factory=list)


class KnowledgeDocumentCreateRequest(StrictBaseModel):
    slug: str = Field(min_length=2, max_length=120, pattern=r"^[a-z0-9][a-z0-9._-]{1,119}$")
    title: str = Field(min_length=2, max_length=200)
    source_type: Literal[
        "owasp_asvs",
        "cwe_catalog",
        "internal_runbook",
        "remediation_guide",
        "approved_framework",
    ]
    source_uri: str = Field(
        min_length=2,
        max_length=512,
        pattern=r"^(?:https://|curated://).+$",
    )
    content: str = Field(min_length=10, max_length=200000)


class KnowledgeDocumentOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    slug: str
    title: str
    source_type: str
    source_uri: str
    content_sha256: str
    is_approved: bool
    uploaded_by: uuid.UUID
    created_at: datetime


class AiFeedbackCreateRequest(StrictBaseModel):
    ai_run_id: uuid.UUID
    label: Literal[
        "true_positive",
        "false_positive",
        "needs_review",
        "helpful_remediation",
        "unsafe_suggestion",
    ]
    notes: str = Field(default="", max_length=2000)
    cross_tenant_sharing_enabled: bool = False


class AiFeedbackOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    ai_run_id: uuid.UUID
    label: str
    notes: str
    de_identified: bool
    cross_tenant_sharing_enabled: bool
    labeled_by: uuid.UUID
    created_at: datetime


class ModelEvaluationCreateRequest(StrictBaseModel):
    model_slug: str = Field(min_length=2, max_length=120)
    suite_name: str = Field(min_length=2, max_length=120)
    sample_count: int = Field(ge=1, le=100000)
    true_positive_rate: float = Field(ge=0.0, le=1.0)
    false_positive_rate: float = Field(ge=0.0, le=1.0)


class ModelEvaluationOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    model_slug: str
    suite_name: str
    sample_count: int
    true_positive_rate: float
    false_positive_rate: float
    regression_passed: bool
    evaluated_by: uuid.UUID
    created_at: datetime


class AiAuditEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    action: str
    actor_id: uuid.UUID
    actor_email: str
    provider_class: str | None = None
    model_slug: str | None = None
    data_classification: str | None = None
    details_json: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime


class AiGovernanceOverviewOut(StrictBaseModel):
    model_catalog: list[AiModelCatalogOut]
    provider_configs: list[AiProviderConfigOut]
    recent_runs: list[AiRunOut]
    tool_proposals: list[AiToolProposalOut]
    knowledge_documents: list[KnowledgeDocumentOut]
    evaluations: list[ModelEvaluationOut]
    audit_events: list[AiAuditEventOut]


# ---------------------------------------------------------------------------
# Phase 13 — Isolated Learning Lab & Self-Scan Verification
# ---------------------------------------------------------------------------


class LabChallengeOut(StrictBaseModel):
    id: uuid.UUID
    slug: str
    title: str
    track_level: str
    target_app: str
    cwe_id: str
    learning_goal: str
    preconditions_json: list[str]
    permitted_target: str
    test_identities_json: list[dict[str, Any]]
    test_data_json: dict[str, Any]
    permitted_tools_json: list[str]
    expected_finding_json: dict[str, Any]
    safe_evidence_criteria: str
    remediation_exercise: str
    retest_instructions: str
    explanation: str
    is_active: bool
    created_at: datetime


class LabWorkspaceCreateRequest(StrictBaseModel):
    environment_slug: str = Field(min_length=3, max_length=64)
    display_name: str = Field(min_length=3, max_length=120)
    consent_to_persist_progress: bool = False
    disposable_account_prefix: str = Field(default="lab", min_length=3, max_length=64)


class LabWorkspaceConsentRequest(StrictBaseModel):
    consent_to_persist_progress: bool


class LabWorkspaceOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    environment_slug: str
    display_name: str
    isolation_network_name: str
    egress_denied: bool
    public_exposure_blocked: bool
    consent_to_persist_progress: bool
    disposable_account_prefix: str
    reset_epoch: int
    state: str
    disposable_identities_json: list[dict[str, Any]]
    last_reset_at: datetime | None = None
    created_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


class LabChallengeProgressOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    workspace_id: uuid.UUID
    challenge_id: uuid.UUID
    status: str
    consent_granted: bool
    reset_epoch: int
    validated_evidence_json: dict[str, Any]
    remediation_notes: str
    retest_passed: bool
    attempts_count: int
    updated_by: uuid.UUID
    created_at: datetime
    updated_at: datetime


class LabValidateRequest(StrictBaseModel):
    challenge_id: uuid.UUID
    target_url: str = Field(min_length=10, max_length=255)
    tool_slug: str = Field(min_length=2, max_length=64)
    action_type: str = Field(min_length=3, max_length=48)
    disposable_identity_used: str = Field(min_length=3, max_length=120)
    observed_evidence: str = Field(min_length=12, max_length=4000)


class LabValidationRunOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    workspace_id: uuid.UUID
    challenge_id: uuid.UUID
    reset_epoch: int
    tool_slug: str
    target_url: str
    disposable_identity_used: str
    action_type: str
    safety_boundary_verified: bool
    evidence_summary_redacted: str
    evidence_sha256: str
    finding_confirmed: bool
    remediation_verified: bool
    status: str
    executed_by: uuid.UUID
    created_at: datetime


class LabValidateResponse(StrictBaseModel):
    validation_run: LabValidationRunOut
    progress: LabChallengeProgressOut | None = None


class LabRemediationRequest(StrictBaseModel):
    challenge_id: uuid.UUID
    remediation_notes: str = Field(min_length=10, max_length=4000)


class LabSelfScanRequest(StrictBaseModel):
    target_component: str = Field(min_length=3, max_length=80)
    profile_name: str = Field(default="vforge-self-verify", min_length=3, max_length=80)


class LabSelfScanOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    target_component: str
    profile_name: str
    checks_executed: int
    issues_found: int
    critical_high_count: int
    findings_json: list[dict[str, Any]]
    remediation_summary: str
    regression_verified: bool
    status: str
    executed_by: uuid.UUID
    created_at: datetime


class LabAuditEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    workspace_id: uuid.UUID | None = None
    action: str
    actor_id: uuid.UUID
    actor_email: str
    target_url: str | None = None
    details_json: dict[str, Any]
    occurred_at: datetime


class LabComposeIsolationOut(StrictBaseModel):
    verified: bool
    path: str | None = None
    violations: list[str]
    services_checked: int


class LabOverviewOut(StrictBaseModel):
    challenges: list[LabChallengeOut]
    workspaces: list[LabWorkspaceOut]
    progress: list[LabChallengeProgressOut]
    validation_runs: list[LabValidationRunOut]
    self_scans: list[LabSelfScanOut]
    audit_events: list[LabAuditEventOut]
    compose_isolation: LabComposeIsolationOut


# --- Phase 14: Hardening, Crypto-Agility, Certs & DR ---


class EncryptionKeyRegisterRequest(StrictBaseModel):
    key_id: str = Field(min_length=3, max_length=120)
    purpose: Literal["artifact_envelope", "backup_envelope", "scope_signing", "runner_mtls_ca"]
    algorithm_suite: str = Field(default="aes-256-gcm-v1", min_length=3, max_length=80)
    pqc_readiness_status: Literal["classical_active", "hybrid_planned", "not_enabled"] = (
        "classical_active"
    )
    cryptoperiod_days: int = Field(default=90, ge=1, le=3650)
    key_fingerprint_sha256: str = Field(min_length=64, max_length=64)
    fips_validated_claim: bool = False
    pqc_experimental_custom_protocol: bool = False


class EncryptionKeyRecordOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    key_id: str
    purpose: str
    algorithm_suite: str
    pqc_readiness_status: str
    status: str
    version: int
    key_fingerprint_sha256: str
    owner_role: str
    cryptoperiod_days: int
    activated_at: datetime
    rotate_after_at: datetime
    rotated_at: datetime | None = None
    created_by: uuid.UUID
    created_at: datetime


class KeyRewrapDrillRequest(StrictBaseModel):
    new_kek_id: str = Field(min_length=3, max_length=120)


class KeyRewrapDrillOut(StrictBaseModel):
    old_kek_id: str
    new_kek_id: str
    plaintext_sha256: str
    ciphertext_sha256: str
    rewrap_verified: bool
    decrypt_recovery_verified: bool


class PersistedDekRewrapRequest(StrictBaseModel):
    source_key_id: str = Field(min_length=3, max_length=120)


class PersistedDekRewrapOut(StrictBaseModel):
    source_key_id: str
    target_backup_kek_id: str
    backup_manifests_rewrapped: int
    immutable_artifacts_remaining: int
    immutable_snapshots_remaining: int
    total_rewrapped: int


class BackupManifestCreateRequest(StrictBaseModel):
    backup_scope: Literal[
        "postgres_tenant_snapshot", "artifact_bundle", "full_control_plane_metadata"
    ] = "postgres_tenant_snapshot"
    rpo_target_minutes: int = Field(default=60, ge=1, le=10080)
    rto_target_minutes: int = Field(default=30, ge=1, le=10080)


class BackupManifestOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    backup_scope: str
    storage_key: str
    encryption_key_id: str
    encryption_algorithm: str
    plaintext_sha256: str
    ciphertext_sha256: str
    size_bytes: int
    row_count: int
    status: str
    rpo_target_minutes: int
    rto_target_minutes: int
    created_by: uuid.UUID
    created_at: datetime


class RestoreDrillCreateRequest(StrictBaseModel):
    manifest_id: uuid.UUID
    drill_mode: Literal[
        "isolated_checksum_decrypt", "pg_schema_dry_run", "ephemeral_restore_verify"
    ] = "isolated_checksum_decrypt"


class RestoreDrillRecordOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    manifest_id: uuid.UUID
    drill_mode: str
    rto_observed_seconds: int
    integrity_verified: bool
    decryption_verified: bool
    schema_head_verified: str
    findings_summary: str
    status: str
    executed_by: uuid.UUID
    created_at: datetime


class HardeningAuditEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    category: str
    action: str
    outcome: str
    actor_id: uuid.UUID
    actor_email: str
    details_json: dict[str, Any]
    occurred_at: datetime


class HardeningOverviewOut(StrictBaseModel):
    crypto_agility: dict[str, Any]
    secret_and_runtime_posture: dict[str, Any]
    certificate_posture: dict[str, Any]
    keys: list[EncryptionKeyRecordOut]
    backup_manifests: list[BackupManifestOut]
    restore_drills: list[RestoreDrillRecordOut]
    audit_events: list[HardeningAuditEventOut]


# ---------------------------------------------------------------------------
# Phase 15 — Optional Isolated AI Red-Team Sandbox Schemas
# ---------------------------------------------------------------------------


class RedTeamSessionCreateRequest(StrictBaseModel):
    title: str = Field(min_length=4, max_length=160)
    objective: str = Field(min_length=10, max_length=1000)
    engine: Literal["strix", "pentagi"] = "strix"
    tool_allowlist: list[str] = Field(min_length=1, max_length=10)
    target_urls: list[str] = Field(min_length=1, max_length=5)
    max_duration_seconds: int = Field(default=900, ge=60, le=3600)
    max_tool_calls: int = Field(default=25, ge=1, le=500)
    max_tokens: int = Field(default=50000, ge=1000, le=2000000)


class RedTeamSessionDecisionRequest(StrictBaseModel):
    decision: Literal["approve", "reject"]
    approval_ttl_minutes: int = Field(default=30, ge=5, le=240)
    reason: str = Field(default="", max_length=200)


class RedTeamToolCallRequest(StrictBaseModel):
    tool_name: str = Field(min_length=2, max_length=64)
    target_url: str | None = Field(default=None, max_length=512)
    input_summary: str = Field(default="", max_length=400)
    estimated_tokens: int = Field(default=500, ge=1, le=200000)


class RedTeamToolCallOut(StrictBaseModel):
    event_id: uuid.UUID
    session_id: uuid.UUID
    tool_name: str
    target_host: str | None
    outcome: str
    tool_calls_used: int
    max_tool_calls: int
    tokens_used: int
    max_tokens: int
    classification: str
    output_summary: str


class RedTeamObservationCreateRequest(StrictBaseModel):
    title: str = Field(min_length=4, max_length=200)
    category: str = Field(min_length=2, max_length=64)
    severity: Literal["info", "low", "medium", "high", "critical"] = "medium"
    evidence_summary: str = Field(min_length=10, max_length=4000)


class RedTeamObservationReviewRequest(StrictBaseModel):
    decision: Literal["confirmed", "rejected"]
    review_note: str = Field(min_length=12, max_length=2000)


class RedTeamSessionCloseRequest(StrictBaseModel):
    final_status: Literal["completed", "terminated"] = "completed"
    end_reason: str = Field(default="", max_length=200)
    cleanup_attested: bool = True
    cleanup_summary: str = Field(default="", max_length=1000)


class RedTeamBenchmarkCreateRequest(StrictBaseModel):
    ground_truth_slugs: list[str] = Field(min_length=1, max_length=200)
    ai_detected_slugs: list[str] = Field(default_factory=list, max_length=200)
    zap_detected_slugs: list[str] = Field(default_factory=list, max_length=200)
    nuclei_detected_slugs: list[str] = Field(default_factory=list, max_length=200)


class RedTeamSessionOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    title: str
    objective: str
    engine: str
    status: str
    tool_allowlist: list[str]
    target_urls: list[str]
    max_duration_seconds: int
    max_tool_calls: int
    max_tokens: int
    tool_calls_used: int
    tokens_used: int
    requested_by: uuid.UUID
    approved_by: uuid.UUID | None
    approved_at: datetime | None
    approval_expires_at: datetime | None
    started_at: datetime | None
    ended_at: datetime | None
    end_reason: str | None
    cleanup_attested: bool
    cleanup_summary: str | None
    created_at: datetime
    updated_at: datetime


class RedTeamObservationOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    session_id: uuid.UUID
    title: str
    category: str
    severity: str
    classification: str
    evidence_summary: str
    evidence_sha256: str
    source: str
    recorded_by: uuid.UUID
    reviewed_by: uuid.UUID | None
    reviewed_at: datetime | None
    review_note: str | None
    created_at: datetime


class RedTeamEventOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    session_id: uuid.UUID
    event_type: str
    outcome: str
    actor_id: uuid.UUID | None
    actor_email: str | None
    tool_name: str | None
    target_host: str | None
    details_json: dict[str, Any]
    occurred_at: datetime


class RedTeamBenchmarkOut(StrictBaseModel):
    id: uuid.UUID
    organization_id: uuid.UUID
    session_id: uuid.UUID
    ground_truth_slugs: list[str]
    ai_detected_slugs: list[str]
    zap_detected_slugs: list[str]
    nuclei_detected_slugs: list[str]
    metrics_json: dict[str, Any]
    data_provenance: str
    created_by: uuid.UUID
    created_at: datetime


class RedTeamOverviewOut(StrictBaseModel):
    organization_id: uuid.UUID
    execution_mode: str
    sandbox_isolation: dict[str, Any]
    lab_isolation: dict[str, Any]
    allowed_tools: list[dict[str, Any]]
    forbidden_tools: list[str]
    sessions: list[RedTeamSessionOut]
    observations: list[RedTeamObservationOut]
    events: list[RedTeamEventOut]
    benchmarks: list[RedTeamBenchmarkOut]
