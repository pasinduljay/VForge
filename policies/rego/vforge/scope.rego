package vforge.scope

import rego.v1

import data.vforge.authz

# Default-deny Phase 2 authorization & target-scope policy.
# Every evaluation yields outcome in {"ALLOW", "DENY", "REQUIRES_APPROVAL"}
# with structured rejection/approval reasons.

intensity_rank := {
	"passive": 0,
	"low": 1,
	"medium": 2,
	"high": 3,
}

forbidden_capabilities := {
	"dos_testing",
	"denial_of_service",
	"destructive_testing",
	"unrestricted_exploitation",
	"lateral_movement",
	"persistence",
	"exfiltration",
	"credential_stuffing",
}

active_capabilities := {
	"active_web_testing",
	"network_discovery",
	"approved_exploit_validation",
}

tool_category_capabilities := {
	"sast": {"source_code_analysis"},
	"secrets": {"source_code_analysis"},
	"sca": {"container_assessment", "source_code_analysis"},
	"sbom": {"container_assessment", "source_code_analysis"},
	"container": {"container_assessment"},
	"iac": {"infrastructure_analysis"},
	"passive_dast": {"passive_web_testing", "api_testing", "authenticated_testing"},
	"active_dast": {"active_web_testing", "api_testing", "authenticated_testing"},
	"network": {"network_discovery"},
	"tls": {"tls_assessment"},
	"exploit_validation": {"approved_exploit_validation"},
}

forbidden_tool_categories := {
	"dos",
	"destructive",
	"unrestricted_exploit",
	"brute_force",
}

# --- Hard DENY rules ---

deny_reasons contains reason if {
	not input.subject.authenticated
	reason := {"code": "unauthenticated", "message": "Subject is not authenticated"}
}

deny_reasons contains reason if {
	input.subject.authenticated
	not input.subject.organization_id
	reason := {"code": "missing_organization", "message": "Authenticated subject lacks organization context"}
}

deny_reasons contains reason if {
	input.subject.authenticated
	input.subject.organization_id != input.organization.id
	reason := {"code": "wrong_organization", "message": "Subject organization does not match target organization"}
}

deny_reasons contains reason if {
	input.organization.status != "active"
	reason := {"code": "organization_inactive", "message": "Organization is not active"}
}

deny_reasons contains reason if {
	input.subject.authenticated
	perms := authz.role_permissions[input.subject.role]
	not (input.action in perms)
	reason := {"code": "rbac_denied", "message": sprintf("Role '%s' is not permitted for action '%s'", [input.subject.role, input.action])}
}

deny_reasons contains reason if {
	input.subject.authenticated
	not authz.role_permissions[input.subject.role]
	reason := {"code": "unknown_role", "message": "Subject role is unrecognized"}
}

deny_reasons contains reason if {
	input.project.organization_id != input.organization.id
	reason := {"code": "wrong_project_org", "message": "Project does not belong to target organization"}
}

deny_reasons contains reason if {
	input.project.status != "active"
	reason := {"code": "project_inactive", "message": "Target project is not active"}
}

deny_reasons contains reason if {
	input.environment.organization_id != input.organization.id
	reason := {"code": "wrong_environment_org", "message": "Environment does not belong to target organization"}
}

deny_reasons contains reason if {
	input.environment.project_id != input.project.id
	reason := {"code": "wrong_environment_project", "message": "Environment does not belong to target project"}
}

deny_reasons contains reason if {
	input.environment.status != "active"
	reason := {"code": "environment_inactive", "message": "Target environment is not active"}
}

deny_reasons contains reason if {
	input.asset.organization_id != input.organization.id
	reason := {"code": "wrong_asset_org", "message": "Asset does not belong to target organization"}
}

deny_reasons contains reason if {
	input.asset.environment_id != input.environment.id
	reason := {"code": "wrong_asset_environment", "message": "Asset does not belong to target environment"}
}

deny_reasons contains reason if {
	input.asset.registration_state == "decommissioned"
	reason := {"code": "asset_decommissioned", "message": "Decommissioned asset cannot be tested"}
}

deny_reasons contains reason if {
	input.policy_version != input.expected_policy_version
	reason := {"code": "stale_policy_version", "message": "Evaluation policy version does not match current active policy"}
}

deny_reasons contains reason if {
	input.authorization.policy_version != input.expected_policy_version
	reason := {"code": "stale_authorization_policy_version", "message": "Authorization was issued under a stale policy version"}
}

deny_reasons contains reason if {
	input.authorization.organization_id != input.organization.id
	reason := {"code": "wrong_authorization_org", "message": "Authorization belongs to a different organization"}
}

deny_reasons contains reason if {
	input.authorization.asset_id != input.asset.id
	reason := {"code": "wrong_authorization_asset", "message": "Authorization does not cover the target asset"}
}

deny_reasons contains reason if {
	input.authorization.environment_id != input.environment.id
	reason := {"code": "wrong_authorization_environment", "message": "Authorization does not cover the target environment"}
}

deny_reasons contains reason if {
	input.authorization.project_id != input.project.id
	reason := {"code": "wrong_authorization_project", "message": "Authorization does not cover the target project"}
}

deny_reasons contains reason if {
	input.authorization.status == "revoked"
	reason := {"code": "authorization_revoked", "message": "Authorization has been revoked"}
}

deny_reasons contains reason if {
	input.authorization.status == "rejected"
	reason := {"code": "authorization_rejected", "message": "Authorization was rejected"}
}

deny_reasons contains reason if {
	input.authorization.status == "expired"
	reason := {"code": "authorization_expired", "message": "Authorization has expired"}
}

deny_reasons contains reason if {
	input.authorization.status == "approved"
	input.request.current_epoch >= input.authorization.expires_at_epoch
	reason := {"code": "authorization_expired", "message": "Authorization validity window has expired"}
}

deny_reasons contains reason if {
	input.authorization.status == "approved"
	input.request.current_epoch < input.authorization.valid_from_epoch
	reason := {"code": "authorization_not_yet_valid", "message": "Authorization start window (valid_from) has not begun"}
}

deny_reasons contains reason if {
	input.authorization.status == "approved"
	input.authorization.approved_by == ""
	reason := {"code": "missing_approver", "message": "Approved authorization lacks approver identity"}
}

deny_reasons contains reason if {
	input.authorization.status == "approved"
	input.authorization.approved_by == input.authorization.requested_by
	reason := {"code": "self_approval_forbidden", "message": "Separation of duties violation: requester cannot approve own authorization"}
}

deny_reasons contains reason if {
	some cap in input.request.requested_capabilities
	cap in forbidden_capabilities
	reason := {"code": "forbidden_capability", "message": sprintf("Capability '%s' is permanently forbidden", [cap])}
}

deny_reasons contains reason if {
	count(input.request.requested_capabilities) == 0
	reason := {"code": "missing_capabilities", "message": "At least one testing capability must be requested"}
}

deny_reasons contains reason if {
	some cap in input.request.requested_capabilities
	not (cap in forbidden_capabilities)
	not (cap in input.authorization.capabilities)
	reason := {"code": "unauthorized_capability", "message": sprintf("Capability '%s' is not granted by authorization", [cap])}
}

deny_reasons contains reason if {
	input.request.tool_category != ""
	input.request.tool_category in forbidden_tool_categories
	reason := {"code": "forbidden_tool_category", "message": sprintf("Tool category '%s' is permanently forbidden", [input.request.tool_category])}
}

deny_reasons contains reason if {
	input.request.tool_category != ""
	not (input.request.tool_category in forbidden_tool_categories)
	not tool_category_capabilities[input.request.tool_category]
	reason := {"code": "unknown_tool_category", "message": sprintf("Tool category '%s' is not in approved tool taxonomy", [input.request.tool_category])}
}

deny_reasons contains reason if {
	input.request.tool_category != ""
	allowed_caps := tool_category_capabilities[input.request.tool_category]
	some cap in input.request.requested_capabilities
	not (cap in allowed_caps)
	reason := {"code": "tool_category_capability_mismatch", "message": sprintf("Tool category '%s' is not permitted for capability '%s'", [input.request.tool_category, cap])}
}

deny_reasons contains reason if {
	req_rank := intensity_rank[input.request.requested_intensity]
	auth_rank := intensity_rank[input.authorization.permitted_intensity]
	req_rank > auth_rank
	reason := {"code": "intensity_exceeded", "message": sprintf("Requested intensity '%s' exceeds authorized '%s'", [input.request.requested_intensity, input.authorization.permitted_intensity])}
}

deny_reasons contains reason if {
	not intensity_rank[input.request.requested_intensity]
	input.request.requested_intensity != "passive"
	reason := {"code": "invalid_intensity", "message": "Requested scan intensity is invalid"}
}

deny_reasons contains reason if {
	input.environment.environment_type == "production"
	"approved_exploit_validation" in input.request.requested_capabilities
	reason := {"code": "production_exploit_validation_forbidden", "message": "Exploit validation is forbidden in production environments"}
}

deny_reasons contains reason if {
	input.environment.environment_type == "production"
	input.request.requested_intensity == "high"
	reason := {"code": "production_high_intensity_forbidden", "message": "High-intensity scanning is forbidden in production environments"}
}

deny_reasons contains reason if {
	input.scan_profile.present == true
	input.scan_profile.organization_id != input.organization.id
	reason := {"code": "wrong_scan_profile_org", "message": "Scan profile does not belong to target organization"}
}

deny_reasons contains reason if {
	input.scan_profile.present == true
	input.scan_profile.status in {"disabled", "deprecated"}
	reason := {"code": "scan_profile_inactive", "message": sprintf("Scan profile is '%s' and cannot be used", [input.scan_profile.status])}
}

deny_reasons contains reason if {
	input.scan_profile.present == true
	input.scan_profile.passive_only == true
	input.request.requested_intensity != "passive"
	reason := {"code": "scan_profile_passive_only", "message": "Selected scan profile permits passive intensity only"}
}

deny_reasons contains reason if {
	input.scan_profile.present == true
	input.scan_profile.passive_only == true
	some cap in input.request.requested_capabilities
	cap in active_capabilities
	reason := {"code": "scan_profile_passive_only_capability", "message": sprintf("Scan profile is passive-only and forbids '%s'", [cap])}
}

deny_reasons contains reason if {
	input.request.target_port != null
	count(input.authorization.allowed_ports) > 0
	not (input.request.target_port in input.authorization.allowed_ports)
	reason := {"code": "unauthorized_port", "message": sprintf("Port %d is outside authorization allowed_ports", [input.request.target_port])}
}

# Pre-flight validation facts from vforge_scope
deny_reasons contains reason if {
	not input.request.pre_flight.canonical_valid
	reason := {"code": "invalid_target", "message": "Target failed strict canonicalization and validation"}
}

deny_reasons contains reason if {
	input.request.pre_flight.canonical_valid
	not input.request.pre_flight.scope_matched
	reason := {"code": "target_out_of_scope", "message": "Target falls outside authorized scope boundaries"}
}

deny_reasons contains reason if {
	input.request.pre_flight.canonical_valid
	not input.request.pre_flight.port_allowed
	reason := {"code": "unauthorized_port", "message": "Target port is not authorized"}
}

deny_reasons contains reason if {
	input.request.pre_flight.canonical_valid
	not input.request.pre_flight.dns_safe
	reason := {"code": "unsafe_dns_or_ip", "message": "Resolved network destination failed SSRF/DNS/metadata policy"}
}

deny_reasons contains reason if {
	input.request.pre_flight.canonical_valid
	not input.request.pre_flight.redirect_safe
	reason := {"code": "unsafe_redirect", "message": "Redirect destination failed scope or SSRF policy"}
}

# Snapshot integrity & freshness checks (when snapshot verification is included)
deny_reasons contains reason if {
	input.snapshot.present == true
	not input.snapshot.hash_matches
	reason := {"code": "modified_scope_snapshot", "message": "Scope snapshot cryptographic hash mismatch"}
}

deny_reasons contains reason if {
	input.snapshot.present == true
	not input.snapshot.signature_valid
	reason := {"code": "invalid_snapshot_signature", "message": "Scope snapshot cryptographic signature is invalid or key revoked"}
}

deny_reasons contains reason if {
	input.snapshot.present == true
	input.snapshot.expired == true
	reason := {"code": "expired_scope_snapshot", "message": "Scope snapshot has expired"}
}

deny_reasons contains reason if {
	input.snapshot.present == true
	input.snapshot.policy_version != input.expected_policy_version
	reason := {"code": "stale_snapshot_policy_version", "message": "Scope snapshot references a stale policy version"}
}

deny_reasons contains reason if {
	input.snapshot.present == true
	input.snapshot.asset_version != input.asset.version
	reason := {"code": "stale_snapshot_asset_version", "message": "Asset changed since scope snapshot was signed; re-evaluation required"}
}

# --- REQUIRES_APPROVAL rules (only effective if zero hard DENYs) ---

approval_reasons contains reason if {
	input.authorization.status == "pending"
	reason := {"code": "authorization_pending_approval", "message": "Authorization request is pending second-person approval"}
}

approval_reasons contains reason if {
	input.asset.registration_state == "pending_verification"
	reason := {"code": "asset_pending_verification", "message": "Asset ownership verification is still pending"}
}

approval_reasons contains reason if {
	input.scan_profile.present == true
	input.scan_profile.status == "draft"
	reason := {"code": "scan_profile_draft", "message": "Draft scan profile requires activation before assessment"}
}

approval_reasons contains reason if {
	input.environment.environment_type == "production"
	some cap in input.request.requested_capabilities
	cap in {"active_web_testing", "network_discovery"}
	not input.authorization.production_active_approved
	reason := {"code": "production_active_requires_approval", "message": "Active testing in production requires explicit elevated production approval"}
}

# --- Final Decision (Default Deny) ---

default outcome := "DENY"

outcome := "REQUIRES_APPROVAL" if {
	count(deny_reasons) == 0
	count(approval_reasons) > 0
}

outcome := "ALLOW" if {
	count(deny_reasons) == 0
	count(approval_reasons) == 0
	input.authorization.status == "approved"
	input.authorization.approved_by != ""
	input.authorization.approved_by != input.authorization.requested_by
	input.request.pre_flight.canonical_valid == true
	input.request.pre_flight.scope_matched == true
	input.request.pre_flight.port_allowed == true
	input.request.pre_flight.dns_safe == true
	input.request.pre_flight.redirect_safe == true
}

combined_reasons := [r | some r in deny_reasons] if {
	count(deny_reasons) > 0
} else := [r | some r in approval_reasons] if {
	count(approval_reasons) > 0
} else := [{"code": "default_deny", "message": "Authorization and scope preconditions were not met"}] if {
	outcome == "DENY"
} else := [{"code": "authorized", "message": "All scope, RBAC, and authorization policy checks passed"}]

decision := {
	"outcome": outcome,
	"allowed": outcome == "ALLOW",
	"requires_approval": outcome == "REQUIRES_APPROVAL",
	"reasons": combined_reasons,
	"policy_version": object.get(input, "expected_policy_version", ""),
}
