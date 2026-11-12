"""Centralized RBAC permission matrix and authorization checks."""

from __future__ import annotations

from enum import StrEnum

from vforge.errors import ForbiddenError
from vforge.models.enums import Role


class Permission(StrEnum):
    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    MEMBERSHIP_READ = "membership:read"
    MEMBERSHIP_MANAGE = "membership:manage"
    PROJECT_READ = "project:read"
    PROJECT_CREATE = "project:create"
    PROJECT_UPDATE = "project:update"
    PROJECT_DELETE = "project:delete"
    ENVIRONMENT_READ = "environment:read"
    ENVIRONMENT_MANAGE = "environment:manage"
    ASSET_READ = "asset:read"
    ASSET_MANAGE = "asset:manage"
    AUTHORIZATION_READ = "authorization:read"
    AUTHORIZATION_REQUEST = "authorization:request"
    AUTHORIZATION_APPROVE = "authorization:approve"
    AUTHORIZATION_REVOKE = "authorization:revoke"
    AUTH_PROFILE_READ = "auth_profile:read"
    AUTH_PROFILE_MANAGE = "auth_profile:manage"
    SCAN_PROFILE_READ = "scan_profile:read"
    SCAN_PROFILE_MANAGE = "scan_profile:manage"
    AUDIT_READ = "audit:read"
    SCOPE_EVALUATE = "scope:evaluate"
    SNAPSHOT_READ = "snapshot:read"
    SNAPSHOT_CREATE = "snapshot:create"
    SNAPSHOT_VERIFY = "snapshot:verify"
    SCAN_READ = "scan:read"
    SCAN_START = "scan:start"
    SCAN_CANCEL = "scan:cancel"
    RUNNER_READ = "runner:read"
    RUNNER_MANAGE = "runner:manage"
    SOURCE_SNAPSHOT_READ = "source_snapshot:read"
    SOURCE_SNAPSHOT_CREATE = "source_snapshot:create"
    FINDING_READ = "finding:read"
    FINDING_TRIAGE = "finding:triage"
    RISK_EXCEPTION_REQUEST = "risk_exception:request"
    RISK_EXCEPTION_APPROVE = "risk_exception:approve"
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    SBOM_READ = "sbom:read"
    VULN_DB_READ = "vuln_db:read"
    INTEL_READ = "intel:read"
    INTEL_MANAGE = "intel:manage"
    UPDATE_READ = "update:read"
    UPDATE_MANAGE = "update:manage"
    STUDIO_READ = "studio:read"
    STUDIO_AUTHOR = "studio:author"
    STUDIO_REVIEW = "studio:review"
    STUDIO_PROMOTE = "studio:promote"
    AI_READ = "ai:read"
    AI_INVOKE = "ai:invoke"
    AI_MANAGE = "ai:manage"
    LAB_READ = "lab:read"
    LAB_PRACTICE = "lab:practice"
    LAB_MANAGE = "lab:manage"
    HARDENING_READ = "hardening:read"
    HARDENING_MANAGE = "hardening:manage"
    REDTEAM_READ = "redteam:read"
    REDTEAM_REQUEST = "redteam:request"
    REDTEAM_APPROVE = "redteam:approve"
    REDTEAM_EXECUTE = "redteam:execute"
    REDTEAM_REVIEW = "redteam:review"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(
        {
            Permission.ORG_READ,
            Permission.ORG_UPDATE,
            Permission.MEMBERSHIP_READ,
            Permission.MEMBERSHIP_MANAGE,
            Permission.PROJECT_READ,
            Permission.PROJECT_CREATE,
            Permission.PROJECT_UPDATE,
            Permission.PROJECT_DELETE,
            Permission.ENVIRONMENT_READ,
            Permission.ENVIRONMENT_MANAGE,
            Permission.ASSET_READ,
            Permission.ASSET_MANAGE,
            Permission.AUTHORIZATION_READ,
            Permission.AUTHORIZATION_REQUEST,
            Permission.AUTH_PROFILE_READ,
            Permission.AUTH_PROFILE_MANAGE,
            Permission.SCAN_PROFILE_READ,
            Permission.SCAN_PROFILE_MANAGE,
            Permission.AUDIT_READ,
            Permission.SCOPE_EVALUATE,
            Permission.SNAPSHOT_READ,
            Permission.SNAPSHOT_VERIFY,
            Permission.SCAN_READ,
            Permission.SCAN_START,
            Permission.SCAN_CANCEL,
            Permission.RUNNER_READ,
            Permission.RUNNER_MANAGE,
            Permission.SOURCE_SNAPSHOT_READ,
            Permission.SOURCE_SNAPSHOT_CREATE,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.RISK_EXCEPTION_REQUEST,
            Permission.RISK_EXCEPTION_APPROVE,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.SBOM_READ,
            Permission.VULN_DB_READ,
            Permission.INTEL_READ,
            Permission.INTEL_MANAGE,
            Permission.UPDATE_READ,
            Permission.UPDATE_MANAGE,
            Permission.STUDIO_READ,
            Permission.STUDIO_AUTHOR,
            Permission.STUDIO_REVIEW,
            Permission.STUDIO_PROMOTE,
            Permission.AI_READ,
            Permission.AI_INVOKE,
            Permission.AI_MANAGE,
            Permission.LAB_READ,
            Permission.LAB_PRACTICE,
            Permission.LAB_MANAGE,
            Permission.HARDENING_READ,
            Permission.HARDENING_MANAGE,
            Permission.REDTEAM_READ,
            Permission.REDTEAM_REQUEST,
            Permission.REDTEAM_APPROVE,
            Permission.REDTEAM_EXECUTE,
            Permission.REDTEAM_REVIEW,
        }
    ),
    Role.SECURITY_LEAD: frozenset(
        {
            Permission.ORG_READ,
            Permission.MEMBERSHIP_READ,
            Permission.PROJECT_READ,
            Permission.PROJECT_CREATE,
            Permission.PROJECT_UPDATE,
            Permission.ENVIRONMENT_READ,
            Permission.ENVIRONMENT_MANAGE,
            Permission.ASSET_READ,
            Permission.ASSET_MANAGE,
            Permission.AUTHORIZATION_READ,
            Permission.AUTHORIZATION_REQUEST,
            Permission.AUTHORIZATION_APPROVE,
            Permission.AUTHORIZATION_REVOKE,
            Permission.AUTH_PROFILE_READ,
            Permission.AUTH_PROFILE_MANAGE,
            Permission.SCAN_PROFILE_READ,
            Permission.SCAN_PROFILE_MANAGE,
            Permission.AUDIT_READ,
            Permission.SCOPE_EVALUATE,
            Permission.SNAPSHOT_READ,
            Permission.SNAPSHOT_CREATE,
            Permission.SNAPSHOT_VERIFY,
            Permission.SCAN_READ,
            Permission.SCAN_START,
            Permission.SCAN_CANCEL,
            Permission.RUNNER_READ,
            Permission.RUNNER_MANAGE,
            Permission.SOURCE_SNAPSHOT_READ,
            Permission.SOURCE_SNAPSHOT_CREATE,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.RISK_EXCEPTION_REQUEST,
            Permission.RISK_EXCEPTION_APPROVE,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.SBOM_READ,
            Permission.VULN_DB_READ,
            Permission.INTEL_READ,
            Permission.INTEL_MANAGE,
            Permission.UPDATE_READ,
            Permission.UPDATE_MANAGE,
            Permission.STUDIO_READ,
            Permission.STUDIO_AUTHOR,
            Permission.STUDIO_REVIEW,
            Permission.STUDIO_PROMOTE,
            Permission.AI_READ,
            Permission.AI_INVOKE,
            Permission.AI_MANAGE,
            Permission.LAB_READ,
            Permission.LAB_PRACTICE,
            Permission.LAB_MANAGE,
            Permission.HARDENING_READ,
            Permission.HARDENING_MANAGE,
            Permission.REDTEAM_READ,
            Permission.REDTEAM_REQUEST,
            Permission.REDTEAM_APPROVE,
            Permission.REDTEAM_EXECUTE,
            Permission.REDTEAM_REVIEW,
        }
    ),
    Role.SECURITY_ANALYST: frozenset(
        {
            Permission.ORG_READ,
            Permission.MEMBERSHIP_READ,
            Permission.PROJECT_READ,
            Permission.ENVIRONMENT_READ,
            Permission.ASSET_READ,
            Permission.ASSET_MANAGE,
            Permission.AUTHORIZATION_READ,
            Permission.AUTHORIZATION_REQUEST,
            Permission.AUTH_PROFILE_READ,
            Permission.SCAN_PROFILE_READ,
            Permission.SCAN_PROFILE_MANAGE,
            Permission.SCOPE_EVALUATE,
            Permission.SNAPSHOT_READ,
            Permission.SNAPSHOT_VERIFY,
            Permission.SCAN_READ,
            Permission.SCAN_START,
            Permission.SCAN_CANCEL,
            Permission.RUNNER_READ,
            Permission.SOURCE_SNAPSHOT_READ,
            Permission.SOURCE_SNAPSHOT_CREATE,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.RISK_EXCEPTION_REQUEST,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.SBOM_READ,
            Permission.VULN_DB_READ,
            Permission.INTEL_READ,
            Permission.INTEL_MANAGE,
            Permission.UPDATE_READ,
            Permission.STUDIO_READ,
            Permission.STUDIO_AUTHOR,
            Permission.AI_READ,
            Permission.AI_INVOKE,
            Permission.LAB_READ,
            Permission.LAB_PRACTICE,
            Permission.HARDENING_READ,
            Permission.REDTEAM_READ,
            Permission.REDTEAM_REQUEST,
            Permission.REDTEAM_EXECUTE,
            Permission.REDTEAM_REVIEW,
        }
    ),
    Role.DEVELOPER: frozenset(
        {
            Permission.ORG_READ,
            Permission.PROJECT_READ,
            Permission.PROJECT_CREATE,
            Permission.PROJECT_UPDATE,
            Permission.ENVIRONMENT_READ,
            Permission.ENVIRONMENT_MANAGE,
            Permission.ASSET_READ,
            Permission.ASSET_MANAGE,
            Permission.AUTHORIZATION_READ,
            Permission.AUTHORIZATION_REQUEST,
            Permission.SCAN_PROFILE_READ,
            Permission.SCOPE_EVALUATE,
            Permission.SNAPSHOT_READ,
            Permission.SCAN_READ,
            Permission.SCAN_START,
            Permission.SCAN_CANCEL,
            Permission.SOURCE_SNAPSHOT_READ,
            Permission.SOURCE_SNAPSHOT_CREATE,
            Permission.FINDING_READ,
            Permission.FINDING_TRIAGE,
            Permission.RISK_EXCEPTION_REQUEST,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.SBOM_READ,
            Permission.VULN_DB_READ,
            Permission.INTEL_READ,
            Permission.UPDATE_READ,
            Permission.STUDIO_READ,
            Permission.STUDIO_AUTHOR,
            Permission.AI_READ,
            Permission.AI_INVOKE,
            Permission.LAB_READ,
            Permission.LAB_PRACTICE,
            Permission.REDTEAM_READ,
        }
    ),
    Role.AUDITOR: frozenset(
        {
            Permission.ORG_READ,
            Permission.MEMBERSHIP_READ,
            Permission.PROJECT_READ,
            Permission.ENVIRONMENT_READ,
            Permission.ASSET_READ,
            Permission.AUTHORIZATION_READ,
            Permission.AUTH_PROFILE_READ,
            Permission.SCAN_PROFILE_READ,
            Permission.AUDIT_READ,
            Permission.SNAPSHOT_READ,
            Permission.SNAPSHOT_VERIFY,
            Permission.SCAN_READ,
            Permission.RUNNER_READ,
            Permission.SOURCE_SNAPSHOT_READ,
            Permission.FINDING_READ,
            Permission.REPORT_GENERATE,
            Permission.REPORT_READ,
            Permission.SBOM_READ,
            Permission.VULN_DB_READ,
            Permission.INTEL_READ,
            Permission.UPDATE_READ,
            Permission.STUDIO_READ,
            Permission.AI_READ,
            Permission.LAB_READ,
            Permission.HARDENING_READ,
            Permission.REDTEAM_READ,
        }
    ),
    Role.VIEWER: frozenset(
        {
            Permission.ORG_READ,
            Permission.PROJECT_READ,
            Permission.ENVIRONMENT_READ,
            Permission.ASSET_READ,
            Permission.SCAN_PROFILE_READ,
            Permission.SCAN_READ,
            Permission.SOURCE_SNAPSHOT_READ,
            Permission.FINDING_READ,
            Permission.REPORT_READ,
            Permission.SBOM_READ,
            Permission.VULN_DB_READ,
            Permission.INTEL_READ,
            Permission.UPDATE_READ,
            Permission.STUDIO_READ,
            Permission.AI_READ,
            Permission.LAB_READ,
            Permission.REDTEAM_READ,
        }
    ),
}


def has_permission(role: Role, permission: Permission) -> bool:
    """Return True if `role` grants `permission`."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def assert_permission(role: Role, permission: Permission) -> None:
    """Raise ForbiddenError if `role` does not grant `permission`."""
    if not has_permission(role, permission):
        raise ForbiddenError(f"Role '{role.value}' lacks permission '{permission.value}'")


def get_permissions_for_role(role: Role) -> list[str]:
    """Return sorted list of permission strings for API responses."""
    return sorted(perm.value for perm in ROLE_PERMISSIONS.get(role, frozenset()))
