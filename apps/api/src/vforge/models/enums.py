"""Domain enumerations for VForge Phase 1."""

from __future__ import annotations

from enum import StrEnum


class OrgStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"


class UserStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    LOCKED = "locked"


class Role(StrEnum):
    OWNER = "owner"
    ADMIN = "admin"
    SECURITY_LEAD = "security_lead"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class MembershipStatus(StrEnum):
    ACTIVE = "active"
    INVITED = "invited"
    SUSPENDED = "suspended"
    REMOVED = "removed"


class ProjectCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class EnvironmentType(StrEnum):
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"
    ISOLATED_LAB = "isolated_lab"


class EnvironmentStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


class AssetType(StrEnum):
    WEB_APPLICATION = "web_application"
    REST_API = "rest_api"
    SOURCE_REPOSITORY = "source_repository"
    CONTAINER_IMAGE = "container_image"
    IP_ADDRESS = "ip_address"
    CIDR_RANGE = "cidr_range"
    NETWORK_SERVICE = "network_service"
    INFRASTRUCTURE_DEFINITION = "infrastructure_definition"


class RegistrationState(StrEnum):
    REGISTERED = "registered"
    PENDING_VERIFICATION = "pending_verification"
    DECOMMISSIONED = "decommissioned"


class AuthorizationStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class AuthProfileType(StrEnum):
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OIDC_SERVICE_ACCOUNT = "oidc_service_account"
    API_KEY_REF = "api_key_ref"
    BEARER_TOKEN_REF = "bearer_token_ref"  # noqa: S105
    BASIC_AUTH_REF = "basic_auth_ref"
    MTLS_CERT_REF = "mtls_cert_ref"
    SESSION_COOKIE_REF = "session_cookie_ref"


class AuthProfileStatus(StrEnum):
    ACTIVE = "active"
    DISABLED = "disabled"
    REVOKED = "revoked"


class ScanProfileStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    DISABLED = "disabled"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class ScanRunStatus(StrEnum):
    DRAFT = "draft"
    SCOPE_VALIDATION = "scope_validation"
    AWAITING_APPROVAL = "awaiting_approval"
    QUEUED = "queued"
    PROVISIONING = "provisioning"
    RUNNING = "running"
    COLLECTING = "collecting"
    NORMALIZING = "normalizing"
    CORRELATING = "correlating"
    REPORTING = "reporting"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    PARTIAL = "partial"
    FAILED = "failed"
    REJECTED = "rejected"
    CANCELLED = "cancelled"


class CoverageStatus(StrEnum):
    PENDING = "pending"
    COMPLETE = "complete"
    PARTIAL = "partial"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class ScanStageStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class RunnerJobStatus(StrEnum):
    PENDING = "pending"
    DISPATCHED = "dispatched"
    LEASED = "leased"
    RUNNING = "running"
    COMPLETED = "completed"
    RETRY_SCHEDULED = "retry_scheduled"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    ABANDONED = "abandoned"


class LeaseRiskClass(StrEnum):
    ACTIVE_HTTP = "active_http"
    NETWORK_SCAN = "network_scan"
    AI_SANDBOX = "ai_sandbox"


class TargetLeaseStatus(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"
    EXPIRED = "expired"
    REVOKED = "revoked"


class OutboxEventStatus(StrEnum):
    PENDING = "pending"
    PUBLISHED = "published"
    DEAD_LETTER = "dead_letter"


class RunnerPoolType(StrEnum):
    STANDARD = "standard"
    DAST_EGRESS = "dast_egress"
    AIRGAPPED = "airgapped"


class RunnerStatus(StrEnum):
    PENDING = "pending"
    ACTIVE = "active"
    DRAINING = "draining"
    REVOKED = "revoked"


class RunnerEventSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    SECURITY = "security"


class ToolExecutionStatus(StrEnum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class ArtifactType(StrEnum):
    RAW_OUTPUT = "raw_output"
    EXECUTION_LOG = "execution_log"
    MANIFEST = "manifest"
    REPORT = "report"


class SourceSnapshotStatus(StrEnum):
    READY = "ready"
    REJECTED = "rejected"
    PURGED = "purged"


class FindingCategory(StrEnum):
    SAST = "sast"
    SECRET = "secret"  # noqa: S105
    SCA = "sca"
    IAC = "iac"
    DAST = "dast"
    NETWORK = "network"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingValidationStatus(StrEnum):
    UNVERIFIED = "unverified"
    REPRODUCED = "reproduced"
    HUMAN_CONFIRMED = "human_confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    FIXED = "fixed"
    REOPENED = "reopened"


class FindingStatus(StrEnum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"


class RiskExceptionStatus(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class FindingEventType(StrEnum):
    STATUS_CHANGED = "status_changed"
    ASSIGNED = "assigned"
    UNASSIGNED = "unassigned"
    COMMENT_ADDED = "comment_added"
    RISK_EXCEPTION_REQUESTED = "risk_exception_requested"
    RISK_EXCEPTION_APPROVED = "risk_exception_approved"
    RISK_EXCEPTION_REJECTED = "risk_exception_rejected"
    RETEST_REQUESTED = "retest_requested"
    RETEST_PASSED = "retest_passed"
    RETEST_FAILED = "retest_failed"
    SEVERITY_OVERRIDDEN = "severity_overridden"


class RetestStatus(StrEnum):
    PENDING_RETEST = "pending_retest"
    RETEST_PASSED = "retest_passed"
    RETEST_FAILED = "retest_failed"


class BusinessPriority(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ReportType(StrEnum):
    EXECUTIVE = "executive"
    TECHNICAL_VAPT = "technical_vapt"
    COMPLIANCE_SUMMARY = "compliance_summary"
    SARIF_EXPORT = "sarif_export"


class ReportFormat(StrEnum):
    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    SARIF = "sarif"


class IntelSourceType(StrEnum):
    CVE_CATALOG = "cve_catalog"
    EXPLOIT_CATALOG = "exploit_catalog"
    PROBABILITY_FEED = "probability_feed"
    PACKAGE_ADVISORY = "package_advisory"
    EXPOSURE_INTEL = "exposure_intel"
    IOC_FEED = "ioc_feed"


class IntelSyncMode(StrEnum):
    FULL = "full"
    INCREMENTAL = "incremental"
    AD_HOC = "ad_hoc"


class IntelSyncStatus(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    STALE = "stale"
    QUARANTINED = "quarantined"


class IntelRecordType(StrEnum):
    CVE = "cve"
    KEV = "kev"
    EPSS = "epss"
    OSV = "osv"
    GHSA = "ghsa"
    CWE = "cwe"
    EDB = "edb"
    IOC = "ioc"


class IntelRelationshipType(StrEnum):
    CVE_TO_CWE = "cve_to_cwe"
    CVE_TO_EPSS = "cve_to_epss"
    CVE_TO_KEV = "cve_to_kev"
    CVE_TO_PURL = "cve_to_purl"
    CVE_TO_EDB = "cve_to_edb"
    CVE_TO_ATT_CK = "cve_to_att_ck"
    CVE_TO_GHSA = "cve_to_ghsa"


class IntelTargetIdentifierType(StrEnum):
    CVE = "cve"
    CWE = "cwe"
    PURL = "purl"
    EDB = "edb"
    CAPEC = "capec"
    ATT_CK = "att_ck"
    GHSA = "ghsa"


class UpdateStream(StrEnum):
    ENGINES_AND_BASE_IMAGES = "engines_and_base_images"
    RULES_TEMPLATES_ADDONS = "rules_templates_addons"
    VULNERABILITY_INTEL_DBS = "vulnerability_intel_dbs"
    ADAPTERS_AND_DEPENDENCIES = "adapters_and_dependencies"


class UpdateChannel(StrEnum):
    SCANNER_ENGINE_VERSIONS = "scanner_engine_versions"
    CONTAINER_BASE_IMAGES = "container_base_images"
    SCANNER_ADDONS = "scanner_addons"
    SCANNER_RULES_AND_TEMPLATES = "scanner_rules_and_templates"
    VULNERABILITY_DATABASES = "vulnerability_databases"
    THREAT_INTELLIGENCE_FEEDS = "threat_intelligence_feeds"
    AI_MODELS = "ai_models"
    AI_RULE_PACKS_AND_SKILLS = "ai_rule_packs_and_skills"
    APPLICATION_DEPENDENCIES = "application_dependencies"
    CRYPTOGRAPHIC_AND_SECURITY_COMPONENTS = "cryptographic_and_security_components"


class ToolApprovalChannel(StrEnum):
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    APPROVED = "approved"
    CANARY = "canary"
    STABLE = "stable"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class UpdateChangeType(StrEnum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"
    SECURITY = "security"
    FEED_REFRESH = "feed_refresh"


class UpdateRunStatus(StrEnum):
    DETECTED = "detected"
    VALIDATING = "validating"
    VALIDATED = "validated"
    APPROVED = "approved"
    CANARY = "canary"
    STABLE = "stable"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"


class UpdateTestCategory(StrEnum):
    SIGNATURE_PROVENANCE = "signature_provenance"
    SBOM_AND_IMAGE_SCAN = "sbom_and_image_scan"
    ADAPTER_CONTRACT = "adapter_contract"
    REGRESSION_CORPUS = "regression_corpus"


class UpdateTestOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class UpdateAuditAction(StrEnum):
    CANDIDATE_DETECTED = "candidate_detected"
    VALIDATION_RECORDED = "validation_recorded"
    APPROVED = "approved"
    EMERGENCY_APPROVED = "emergency_approved"
    PROMOTED_CANARY = "promoted_canary"
    PROMOTED_STABLE = "promoted_stable"
    REJECTED = "rejected"
    ROLLED_BACK = "rolled_back"
    FEED_PROMOTED = "feed_promoted"
    FEED_ROLLED_BACK = "feed_rolled_back"


class StudioEngine(StrEnum):
    OPENGREP = "opengrep"
    NUCLEI = "nuclei"
    CHECKOV = "checkov"
    GITLEAKS = "gitleaks"
    ZAP = "zap"
    NMAP = "nmap"


class RuleRiskClass(StrEnum):
    STATIC = "static"
    PASSIVE = "passive"
    ACTIVE = "active"
    PRIVILEGED_NETWORK = "privileged_network"


class RuleConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    HEURISTIC = "heuristic"


class SemverChangeType(StrEnum):
    PATCH = "patch"
    MINOR = "minor"
    MAJOR = "major"


class StudioChannel(StrEnum):
    DRAFT = "draft"
    CANDIDATE = "candidate"
    CANARY = "canary"
    STABLE = "stable"
    ROLLED_BACK = "rolled_back"
    QUARANTINED = "quarantined"


class StudioReviewStatus(StrEnum):
    DRAFT = "draft"
    PENDING_REVIEW = "pending_review"
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"


class StudioCreationMethod(StrEnum):
    HUMAN = "human"
    AI_ASSISTED = "ai_assisted"
    UPSTREAM = "upstream"


class StudioActorType(StrEnum):
    HUMAN = "human"
    AI_AGENT = "ai_agent"
    SYSTEM = "system"


class StudioAuditAction(StrEnum):
    PACK_CREATED = "pack_created"
    VERSION_CREATED = "version_created"
    VERSION_UPDATED = "version_updated"
    AI_DRAFT_GENERATED = "ai_draft_generated"
    FIXTURES_EXECUTED = "fixtures_executed"
    REVIEW_REQUESTED = "review_requested"
    REVIEW_APPROVED = "review_approved"
    REVIEW_REJECTED = "review_rejected"
    REVIEW_CHANGES_REQUESTED = "review_changes_requested"
    VERSION_SIGNED = "version_signed"
    PROMOTED_CANDIDATE = "promoted_candidate"
    PROMOTED_CANARY = "promoted_canary"
    PROMOTED_STABLE = "promoted_stable"
    ROLLED_BACK = "rolled_back"
    QUARANTINED = "quarantined"
    SKILL_CREATED = "skill_created"
    SKILL_VERSION_CREATED = "skill_version_created"
    SKILL_REVIEW_APPROVED = "skill_review_approved"
    SKILL_REVIEW_REJECTED = "skill_review_rejected"
    SKILL_SIGNED = "skill_signed"
    SKILL_PROMOTED = "skill_promoted"
    SKILL_ROLLED_BACK = "skill_rolled_back"


class AiProviderClass(StrEnum):
    MANAGED_ZDR = "managed_zdr"
    MANAGED_RETAINED = "managed_retained"
    OPENAI = "openai"
    OPENAI_COMPATIBLE = "openai_compatible"
    LOCAL_INFERENCE = "local_inference"


class DataClassification(StrEnum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class AiAgentRole(StrEnum):
    ARCHITECT = "architect"
    ATTACK_SURFACE_ANALYST = "attack_surface_analyst"
    RULE_AUTHOR = "rule_author"
    ADVERSARIAL_REVIEWER = "adversarial_reviewer"
    EVIDENCE_VERIFIER = "evidence_verifier"
    REMEDIATION_REVIEWER = "remediation_reviewer"
    INDEPENDENT_CRITIC = "independent_critic"


class AiTaskStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class AiToolProposalStatus(StrEnum):
    PROPOSED = "proposed"
    OPA_DENIED = "opa_denied"
    PENDING_HUMAN_APPROVAL = "pending_human_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"


class KnowledgeSourceType(StrEnum):
    OWASP_ASVS = "owasp_asvs"
    CWE_CATALOG = "cwe_catalog"
    INTERNAL_RUNBOOK = "internal_runbook"
    REMEDIATION_GUIDE = "remediation_guide"
    APPROVED_FRAMEWORK = "approved_framework"


class AiAuditAction(StrEnum):
    PROVIDER_CONFIGURED = "provider_configured"
    RETENTION_CONSENT_UPDATED = "retention_consent_updated"
    TASK_EXECUTED = "task_executed"
    TASK_BLOCKED = "task_blocked"
    PROVIDER_FAILOVER = "provider_failover"
    TOOL_PROPOSED = "tool_proposed"
    TOOL_DECIDED = "tool_decided"
    KNOWLEDGE_INDEXED = "knowledge_indexed"
    FEEDBACK_RECORDED = "feedback_recorded"
    EVALUATION_RUN = "evaluation_run"


class LabTrackLevel(StrEnum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    ADVANCED = "advanced"
    EXPERT_PRACTICE = "expert_practice"


class LabTargetApp(StrEnum):
    JUICE_SHOP = "juice_shop"
    CRAPI = "crapi"
    WEBGOAT = "webgoat"
    VFORGE_SAMPLE = "vforge_sample"


class LabWorkspaceState(StrEnum):
    READY = "ready"
    RUNNING = "running"
    RESETTING = "resetting"
    STOPPED = "stopped"


class LabProgressStatus(StrEnum):
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    VALIDATED = "validated"
    REMEDIATED = "remediated"
    RETESTED = "retested"


class LabValidationAction(StrEnum):
    BASELINE_PROBE = "baseline_probe"
    AUTH_TOKEN_CHECK = "auth_token_check"  # noqa: S105
    IDOR_READ_CHECK = "idor_read_check"
    SQLI_ERROR_PROBE = "sqli_error_probe"
    XSS_REFLECTION_PROBE = "xss_reflection_probe"
    REMEDIATION_RETEST = "remediation_retest"


class LabAuditAction(StrEnum):
    WORKSPACE_PROVISIONED = "workspace_provisioned"
    CONSENT_UPDATED = "consent_updated"
    WORKSPACE_RESET = "workspace_reset"
    CHALLENGE_VALIDATED = "challenge_validated"
    CHALLENGE_REMEDIATED = "challenge_remediated"
    CHALLENGE_RETESTED = "challenge_retested"
    SELF_SCAN_EXECUTED = "self_scan_executed"
    BOUNDARY_VIOLATION_BLOCKED = "boundary_violation_blocked"
