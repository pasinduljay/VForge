package vforge.scope_test

import rego.v1

import data.vforge.scope

base_input := {
	"policy_version": "2026-11-12.v2",
	"expected_policy_version": "2026-11-12.v2",
	"action": "scope:evaluate",
	"subject": {
		"authenticated": true,
		"user_id": "user-1",
		"organization_id": "org-1",
		"role": "security_analyst",
	},
	"organization": {"id": "org-1", "status": "active"},
	"project": {"id": "proj-1", "organization_id": "org-1", "status": "active", "criticality": "high"},
	"environment": {
		"id": "env-1",
		"organization_id": "org-1",
		"project_id": "proj-1",
		"environment_type": "staging",
		"status": "active",
	},
	"asset": {
		"id": "asset-1",
		"organization_id": "org-1",
		"environment_id": "env-1",
		"asset_type": "web_application",
		"normalized_locator": "https://app.example.com/",
		"registration_state": "registered",
		"version": 1,
	},
	"authorization": {
		"id": "auth-1",
		"organization_id": "org-1",
		"project_id": "proj-1",
		"environment_id": "env-1",
		"asset_id": "asset-1",
		"status": "approved",
		"requested_by": "user-1",
		"approved_by": "user-lead",
		"valid_from_epoch": 1700000000,
		"expires_at_epoch": 1800000000,
		"capabilities": ["passive_web_testing", "api_testing"],
		"allowed_ports": [443],
		"permitted_intensity": "low",
		"policy_version": "2026-11-12.v2",
		"production_active_approved": false,
	},
	"scan_profile": {"present": false},
	"snapshot": {"present": false},
	"request": {
		"requested_capabilities": ["passive_web_testing"],
		"requested_intensity": "passive",
		"tool_category": "passive_dast",
		"target_port": 443,
		"current_epoch": 1750000000,
		"pre_flight": {
			"canonical_valid": true,
			"scope_matched": true,
			"port_allowed": true,
			"dns_safe": true,
			"redirect_safe": true,
		},
	},
}

test_allow_valid_scope_evaluation if {
	res := scope.decision with input as base_input
	res.outcome == "ALLOW"
	res.allowed == true
}

test_default_deny_empty_input if {
	res := scope.decision with input as {}
	res.outcome == "DENY"
	res.allowed == false
}

test_requires_approval_when_pending if {
	pending := json.patch(base_input, [{"op": "replace", "path": "/authorization/status", "value": "pending"}])
	res := scope.decision with input as pending
	res.outcome == "REQUIRES_APPROVAL"
	res.requires_approval == true
}

test_deny_expired_authorization if {
	expired := json.patch(base_input, [{"op": "replace", "path": "/request/current_epoch", "value": 1800000001}])
	res := scope.decision with input as expired
	res.outcome == "DENY"
}

test_deny_revoked_authorization if {
	revoked := json.patch(base_input, [{"op": "replace", "path": "/authorization/status", "value": "revoked"}])
	res := scope.decision with input as revoked
	res.outcome == "DENY"
}

test_deny_self_approval if {
	self_app := json.patch(base_input, [{"op": "replace", "path": "/authorization/approved_by", "value": "user-1"}])
	res := scope.decision with input as self_app
	res.outcome == "DENY"
}

test_deny_wrong_org if {
	wrong_org := json.patch(base_input, [{"op": "replace", "path": "/subject/organization_id", "value": "org-2"}])
	res := scope.decision with input as wrong_org
	res.outcome == "DENY"
}

test_deny_wrong_environment if {
	wrong_env := json.patch(base_input, [{"op": "replace", "path": "/authorization/environment_id", "value": "env-99"}])
	res := scope.decision with input as wrong_env
	res.outcome == "DENY"
}

test_deny_unauthorized_capability if {
	bad_cap := json.patch(base_input, [{"op": "replace", "path": "/request/requested_capabilities", "value": ["active_web_testing"]}])
	res := scope.decision with input as bad_cap
	res.outcome == "DENY"
}

test_deny_forbidden_dos_capability if {
	dos_cap := json.patch(base_input, [{"op": "replace", "path": "/request/requested_capabilities", "value": ["dos_testing"]}])
	res := scope.decision with input as dos_cap
	res.outcome == "DENY"
}

test_deny_unauthorized_port if {
	bad_port := json.patch(base_input, [{"op": "replace", "path": "/request/target_port", "value": 8080}])
	res := scope.decision with input as bad_port
	res.outcome == "DENY"
}

test_deny_production_exploit_validation if {
	prod_exploit := json.patch(base_input, [
		{"op": "replace", "path": "/environment/environment_type", "value": "production"},
		{"op": "replace", "path": "/authorization/capabilities", "value": ["approved_exploit_validation"]},
		{"op": "replace", "path": "/request/requested_capabilities", "value": ["approved_exploit_validation"]},
		{"op": "replace", "path": "/request/tool_category", "value": "exploit_validation"},
	])
	res := scope.decision with input as prod_exploit
	res.outcome == "DENY"
}

test_requires_approval_production_active_testing if {
	prod_active := json.patch(base_input, [
		{"op": "replace", "path": "/environment/environment_type", "value": "production"},
		{"op": "replace", "path": "/authorization/capabilities", "value": ["active_web_testing"]},
		{"op": "replace", "path": "/request/requested_capabilities", "value": ["active_web_testing"]},
		{"op": "replace", "path": "/request/tool_category", "value": "active_dast"},
	])
	res := scope.decision with input as prod_active
	res.outcome == "REQUIRES_APPROVAL"
}

test_deny_modified_or_stale_snapshot if {
	bad_snap := json.patch(base_input, [
		{"op": "replace", "path": "/snapshot", "value": {
			"present": true,
			"hash_matches": false,
			"signature_valid": true,
			"expired": false,
			"policy_version": "2026-11-12.v2",
			"asset_version": 1,
		}},
	])
	res := scope.decision with input as bad_snap
	res.outcome == "DENY"

	stale_asset := json.patch(base_input, [
		{"op": "replace", "path": "/snapshot", "value": {
			"present": true,
			"hash_matches": true,
			"signature_valid": true,
			"expired": false,
			"policy_version": "2026-11-12.v2",
			"asset_version": 0,
		}},
	])
	res_stale := scope.decision with input as stale_asset
	res_stale.outcome == "DENY"
}
