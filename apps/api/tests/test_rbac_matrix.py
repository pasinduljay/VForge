"""Unit tests for RBAC permission matrix and domain input validators."""

from __future__ import annotations

import pytest

from vforge.auth.rbac import Permission, assert_permission, has_permission
from vforge.errors import ForbiddenError, ValidationError
from vforge.models.enums import AssetType, Role
from vforge.schemas import ScanProfileCreate
from vforge.security.validators import (
    normalize_asset_locator,
    redact_metadata,
    validate_secret_manager_ref,
)


@pytest.mark.parametrize(
    ("role", "allowed", "denied"),
    [
        (
            Role.OWNER,
            {
                Permission.ORG_DELETE,
                Permission.MEMBERSHIP_MANAGE,
                Permission.AUTHORIZATION_APPROVE,
                Permission.AUDIT_READ,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_CREATE,
                Permission.SNAPSHOT_VERIFY,
                Permission.RUNNER_READ,
                Permission.RUNNER_MANAGE,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.FINDING_READ,
                Permission.REDTEAM_READ,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_APPROVE,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
            set(),
        ),
        (
            Role.ADMIN,
            {
                Permission.ORG_UPDATE,
                Permission.MEMBERSHIP_MANAGE,
                Permission.PROJECT_DELETE,
                Permission.AUDIT_READ,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_VERIFY,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.FINDING_READ,
                Permission.REDTEAM_READ,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_APPROVE,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
            {
                Permission.ORG_DELETE,
                Permission.AUTHORIZATION_APPROVE,
                Permission.AUTHORIZATION_REVOKE,
                Permission.SNAPSHOT_CREATE,
            },
        ),
        (
            Role.SECURITY_LEAD,
            {
                Permission.AUTHORIZATION_APPROVE,
                Permission.AUTHORIZATION_REVOKE,
                Permission.AUTH_PROFILE_MANAGE,
                Permission.AUDIT_READ,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_CREATE,
                Permission.SNAPSHOT_VERIFY,
                Permission.RUNNER_READ,
                Permission.RUNNER_MANAGE,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.FINDING_READ,
                Permission.REDTEAM_READ,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_APPROVE,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
            {Permission.ORG_DELETE, Permission.MEMBERSHIP_MANAGE, Permission.PROJECT_DELETE},
        ),
        (
            Role.SECURITY_ANALYST,
            {
                Permission.ASSET_MANAGE,
                Permission.AUTHORIZATION_REQUEST,
                Permission.SCAN_PROFILE_MANAGE,
                Permission.AUTH_PROFILE_READ,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_VERIFY,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.FINDING_READ,
                Permission.REDTEAM_READ,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
            {
                Permission.AUTHORIZATION_APPROVE,
                Permission.AUTHORIZATION_REVOKE,
                Permission.AUDIT_READ,
                Permission.MEMBERSHIP_MANAGE,
                Permission.SNAPSHOT_CREATE,
                Permission.REDTEAM_APPROVE,
            },
        ),
        (
            Role.DEVELOPER,
            {
                Permission.PROJECT_CREATE,
                Permission.ENVIRONMENT_MANAGE,
                Permission.ASSET_MANAGE,
                Permission.AUTHORIZATION_REQUEST,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_READ,
                Permission.SCAN_READ,
                Permission.SCAN_START,
                Permission.SCAN_CANCEL,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.FINDING_READ,
                Permission.REDTEAM_READ,
            },
            {
                Permission.PROJECT_DELETE,
                Permission.AUTHORIZATION_APPROVE,
                Permission.AUTH_PROFILE_MANAGE,
                Permission.AUDIT_READ,
                Permission.SNAPSHOT_CREATE,
                Permission.SNAPSHOT_VERIFY,
                Permission.RUNNER_MANAGE,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_APPROVE,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
        ),
        (
            Role.AUDITOR,
            {
                Permission.ORG_READ,
                Permission.MEMBERSHIP_READ,
                Permission.AUTHORIZATION_READ,
                Permission.AUDIT_READ,
                Permission.SNAPSHOT_READ,
                Permission.SNAPSHOT_VERIFY,
                Permission.SCAN_READ,
                Permission.RUNNER_READ,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.FINDING_READ,
                Permission.REDTEAM_READ,
            },
            {
                Permission.PROJECT_CREATE,
                Permission.ASSET_MANAGE,
                Permission.AUTHORIZATION_REQUEST,
                Permission.AUTHORIZATION_APPROVE,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_CREATE,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.SCAN_START,
                Permission.SCAN_CANCEL,
                Permission.RUNNER_MANAGE,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_APPROVE,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
        ),
        (
            Role.VIEWER,
            {
                Permission.ORG_READ,
                Permission.PROJECT_READ,
                Permission.ASSET_READ,
                Permission.SCAN_PROFILE_READ,
                Permission.SCAN_READ,
                Permission.SOURCE_SNAPSHOT_READ,
                Permission.FINDING_READ,
                Permission.SBOM_READ,
                Permission.VULN_DB_READ,
                Permission.REDTEAM_READ,
            },
            {
                Permission.MEMBERSHIP_READ,
                Permission.AUTHORIZATION_READ,
                Permission.AUTH_PROFILE_READ,
                Permission.AUDIT_READ,
                Permission.PROJECT_CREATE,
                Permission.SCOPE_EVALUATE,
                Permission.SNAPSHOT_READ,
                Permission.SOURCE_SNAPSHOT_CREATE,
                Permission.SCAN_START,
                Permission.SCAN_CANCEL,
                Permission.REDTEAM_REQUEST,
                Permission.REDTEAM_APPROVE,
                Permission.REDTEAM_EXECUTE,
                Permission.REDTEAM_REVIEW,
            },
        ),
    ],
)
def test_rbac_permission_matrix_all_seven_roles(
    role: Role,
    allowed: set[Permission],
    denied: set[Permission],
) -> None:
    for perm in allowed:
        assert has_permission(role, perm) is True
        assert_permission(role, perm)
    for perm in denied:
        assert has_permission(role, perm) is False
        with pytest.raises(ForbiddenError):
            assert_permission(role, perm)


def test_asset_locator_normalization_and_invalid_inputs() -> None:
    assert (
        normalize_asset_locator(AssetType.WEB_APPLICATION, "HTTPS://App.Example.COM:443/v1")
        == "https://app.example.com/v1"
    )
    assert (
        normalize_asset_locator(AssetType.IP_ADDRESS, "2001:0db8:0000:0000:0000:0000:0000:0001")
        == "2001:db8::1"
    )
    assert normalize_asset_locator(AssetType.CIDR_RANGE, "10.20.30.40/24") == "10.20.30.0/24"
    assert normalize_asset_locator(AssetType.NETWORK_SERVICE, "API.Internal:8443") == (
        "api.internal:8443"
    )
    assert (
        normalize_asset_locator(AssetType.CONTAINER_IMAGE, "GHCR.IO/Org/App:v1.2.3")
        == "ghcr.io/org/app:v1.2.3"
    )
    assert (
        normalize_asset_locator(AssetType.INFRASTRUCTURE_DEFINITION, "./infra/terraform/main.tf")
        == "infra/terraform/main.tf"
    )

    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.WEB_APPLICATION, "https://user:pass@example.com/")
    with pytest.raises(ValidationError):
        normalize_asset_locator(
            AssetType.SOURCE_REPOSITORY, "https://user:ghp_secret@github.com/a/b"
        )
    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.IP_ADDRESS, "999.999.1.1")
    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.CIDR_RANGE, "10.0.0.0/99")
    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.NETWORK_SERVICE, "host:99999")
    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.INFRASTRUCTURE_DEFINITION, "../../etc/passwd")
    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.INFRASTRUCTURE_DEFINITION, "/etc/passwd")
    with pytest.raises(ValidationError):
        normalize_asset_locator(AssetType.INFRASTRUCTURE_DEFINITION, "infra/../secrets.tf")


def test_secret_manager_ref_rejects_plaintext_credentials() -> None:
    assert (
        validate_secret_manager_ref("vault://secret/data/staging/api-token")
        == "vault://secret/data/staging/api-token"
    )
    for bad in (
        "super-secret-password",
        "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig",
        "vault://user:pass@secret/path",
        "https://example.com/secret",
        "aws-sm://AKIAIOSFODNN7EXAMPLE",
    ):
        with pytest.raises(ValidationError):
            validate_secret_manager_ref(bad)


def test_scan_profile_rejects_invalid_stage() -> None:
    with pytest.raises(ValueError):
        ScanProfileCreate.model_validate(
            {
                "name": "bad-profile",
                "configuration": {
                    "stages": ["arbitrary_shell_exec"],
                    "passive_only": True,
                },
            }
        )


def test_redact_metadata_strips_sensitive_keys() -> None:
    sanitized = redact_metadata(
        {
            "password": "my-secret-password",
            "nested": {"token": "tok_123", "url": "https://user:pw@host.local/db"},
            "safe": "ok",
        }
    )
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["nested"]["token"] == "[REDACTED]"
    assert "pw" not in sanitized["nested"]["url"]
    assert sanitized["safe"] == "ok"
