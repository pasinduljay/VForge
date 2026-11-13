package vforge.authz

import rego.v1

# Phase 2 policy: strict default-deny with tenant-scoped RBAC + scope/snapshot permissions.
default allow := false

# Health/readiness metadata queries are permitted only when explicitly marked internal_health.
allow if {
	input.action == "platform:health_read"
	input.subject.authenticated == false
}

role_permissions := {
	"owner": {
		"org:read", "org:update", "org:delete",
		"membership:read", "membership:manage",
		"project:read", "project:create", "project:update", "project:delete",
		"environment:read", "environment:manage",
		"asset:read", "asset:manage",
		"authorization:read", "authorization:request", "authorization:approve", "authorization:revoke",
		"auth_profile:read", "auth_profile:manage",
		"scan_profile:read", "scan_profile:manage",
		"scope:evaluate", "snapshot:read", "snapshot:create", "snapshot:verify",
		"scan:read", "scan:start", "scan:cancel",
		"runner:read", "runner:manage",
		"source_snapshot:read", "source_snapshot:create", "finding:read", "finding:triage", "risk_exception:request", "risk_exception:approve", "report:generate", "report:read", "sbom:read", "vuln_db:read",
		"intel:read", "intel:manage",
		"update:read", "update:manage",
		"studio:read", "studio:author", "studio:review", "studio:promote",
		"ai:read", "ai:invoke", "ai:manage",
		"lab:read", "lab:practice", "lab:manage",
		"hardening:read", "hardening:manage",
		"redteam:read", "redteam:request", "redteam:approve", "redteam:execute", "redteam:review",
		"audit:read",
	},
	"admin": {
		"org:read", "org:update",
		"membership:read", "membership:manage",
		"project:read", "project:create", "project:update", "project:delete",
		"environment:read", "environment:manage",
		"asset:read", "asset:manage",
		"authorization:read", "authorization:request",
		"auth_profile:read", "auth_profile:manage",
		"scan_profile:read", "scan_profile:manage",
		"scope:evaluate", "snapshot:read", "snapshot:verify",
		"scan:read", "scan:start", "scan:cancel",
		"runner:read", "runner:manage",
		"source_snapshot:read", "source_snapshot:create", "finding:read", "finding:triage", "risk_exception:request", "risk_exception:approve", "report:generate", "report:read", "sbom:read", "vuln_db:read",
		"intel:read", "intel:manage",
		"update:read", "update:manage",
		"studio:read", "studio:author", "studio:review", "studio:promote",
		"ai:read", "ai:invoke", "ai:manage",
		"lab:read", "lab:practice", "lab:manage",
		"hardening:read", "hardening:manage",
		"redteam:read", "redteam:request", "redteam:approve", "redteam:execute", "redteam:review",
		"audit:read",
	},
	"security_lead": {
		"org:read",
		"membership:read",
		"project:read", "project:create", "project:update",
		"environment:read", "environment:manage",
		"asset:read", "asset:manage",
		"authorization:read", "authorization:request", "authorization:approve", "authorization:revoke",
		"auth_profile:read", "auth_profile:manage",
		"scan_profile:read", "scan_profile:manage",
		"scope:evaluate", "snapshot:read", "snapshot:create", "snapshot:verify",
		"scan:read", "scan:start", "scan:cancel",
		"runner:read", "runner:manage",
		"source_snapshot:read", "source_snapshot:create", "finding:read", "finding:triage", "risk_exception:request", "risk_exception:approve", "report:generate", "report:read", "sbom:read", "vuln_db:read",
		"intel:read", "intel:manage",
		"update:read", "update:manage",
		"studio:read", "studio:author", "studio:review", "studio:promote",
		"ai:read", "ai:invoke", "ai:manage",
		"lab:read", "lab:practice", "lab:manage",
		"hardening:read", "hardening:manage",
		"redteam:read", "redteam:request", "redteam:approve", "redteam:execute", "redteam:review",
		"audit:read",
	},
	"security_analyst": {
		"org:read",
		"membership:read",
		"project:read",
		"environment:read",
		"asset:read", "asset:manage",
		"authorization:read", "authorization:request",
		"auth_profile:read",
		"scan_profile:read", "scan_profile:manage",
		"scope:evaluate", "snapshot:read", "snapshot:verify",
		"scan:read", "scan:start", "scan:cancel",
		"runner:read",
		"source_snapshot:read", "source_snapshot:create", "finding:read", "finding:triage", "risk_exception:request", "report:generate", "report:read", "sbom:read", "vuln_db:read",
		"intel:read", "intel:manage",
		"update:read",
		"studio:read", "studio:author",
		"ai:read", "ai:invoke",
		"lab:read", "lab:practice",
		"hardening:read",
		"redteam:read", "redteam:request", "redteam:execute", "redteam:review",
	},
	"developer": {
		"org:read",
		"project:read", "project:create", "project:update",
		"environment:read", "environment:manage",
		"asset:read", "asset:manage",
		"authorization:read", "authorization:request",
		"scan_profile:read",
		"scope:evaluate", "snapshot:read",
		"scan:read", "scan:start", "scan:cancel",
		"source_snapshot:read", "source_snapshot:create", "finding:read", "finding:triage", "risk_exception:request", "report:generate", "report:read", "sbom:read", "vuln_db:read",
		"intel:read",
		"update:read",
		"studio:read", "studio:author",
		"ai:read", "ai:invoke",
		"lab:read", "lab:practice",
		"redteam:read",
	},
	"auditor": {
		"org:read",
		"membership:read",
		"project:read",
		"environment:read",
		"asset:read",
		"authorization:read",
		"auth_profile:read",
		"scan_profile:read",
		"snapshot:read", "snapshot:verify",
		"scan:read",
		"runner:read",
		"source_snapshot:read", "finding:read", "report:generate", "report:read", "sbom:read", "vuln_db:read",
		"intel:read",
		"update:read",
		"studio:read",
		"ai:read",
		"lab:read",
		"hardening:read",
		"redteam:read",
		"audit:read",
	},
	"viewer": {
		"org:read",
		"project:read",
		"environment:read",
		"asset:read",
		"scan_profile:read",
		"scan:read",
		"source_snapshot:read", "finding:read", "report:read", "sbom:read", "vuln_db:read",
		"intel:read",
		"update:read",
		"studio:read",
		"ai:read",
		"lab:read",
		"redteam:read",
	},
}

studio_ai_or_sod_forbidden if {
	input.action in {"studio:review", "studio:promote"}
	object.get(input.subject, "actor_type", "human") != "human"
}

studio_ai_or_sod_forbidden if {
	input.action in {"studio:review", "studio:promote"}
	author := object.get(input.resource, "author_id", "")
	author != ""
	input.subject.id == author
}

ai_forbidden_tool_action if {
	input.action in {"ai:invoke", "ai:manage"}
	normalized_tool := lower(trim_space(object.get(input.resource, "tool_action", "")))
	normalized_tool in {
		"scope:modify",
		"opa:modify",
		"rule:sign",
		"rule:promote",
		"finding:auto_confirm",
		"shell:exec",
		"raw_docker_socket",
	}
}

ai_forbidden_tool_action if {
	input.action == "ai:manage"
	requested_by := object.get(input.resource, "requested_by", "")
	requested_by != ""
	input.subject.id == requested_by
}

lab_forbidden_boundary if {
	input.action in {"lab:practice", "lab:manage"}
	normalized_action := lower(trim_space(object.get(input.resource, "lab_action_type", "")))
	normalized_action in {
		"persistence",
		"stealth",
		"credential_theft",
		"malware",
		"destructive_action",
		"lateral_movement",
		"exfiltration",
		"arbitrary_internet_exploit",
		"dos_flood",
	}
}

lab_practice_action_allowed if {
	input.action != "lab:practice"
}

lab_practice_action_allowed if {
	input.action == "lab:practice"
	normalized_action := lower(trim_space(object.get(input.resource, "lab_action_type", "")))
	normalized_action in {
		"baseline_probe",
		"auth_token_check",
		"idor_read_check",
		"sqli_error_probe",
		"xss_reflection_probe",
		"remediation_retest",
	}
}

hardening_policy_forbidden if {
	input.action in {"hardening:read", "hardening:manage"}
	object.get(input.resource, "fips_validated_claim", false) == true
}

hardening_policy_forbidden if {
	input.action == "hardening:manage"
	object.get(input.resource, "pqc_experimental_custom_protocol", false) == true
}

redteam_policy_forbidden if {
	input.action in {"redteam:approve", "redteam:review"}
	object.get(input.subject, "actor_type", "human") != "human"
}

redteam_policy_forbidden if {
	input.action == "redteam:approve"
	trim_space(object.get(input.resource, "requested_by", "")) == ""
}

redteam_policy_forbidden if {
	input.action == "redteam:approve"
	requester := object.get(input.resource, "requested_by", "")
	requester != ""
	input.subject.id == requester
}

redteam_policy_forbidden if {
	input.action == "redteam:review"
	recorder := object.get(input.resource, "recorded_by", "")
	recorder != ""
	input.subject.id == recorder
}

redteam_policy_forbidden if {
	input.action in {"redteam:request", "redteam:execute"}
	object.get(input.resource, "external_network_requested", false) == true
}

redteam_policy_forbidden if {
	input.action in {"redteam:request", "redteam:execute", "redteam:review"}
	object.get(input.resource, "auto_confirm_requested", false) == true
}

redteam_policy_forbidden if {
	input.action in {"redteam:request", "redteam:execute"}
	raw_tool := lower(trim_space(object.get(input.resource, "redteam_tool", "")))
	raw_tool != ""
	not raw_tool in {
		"http_probe",
		"browser_navigate",
		"dom_inspect",
		"template_lookup",
		"note_hypothesis",
	}
}

allow if {
	input.subject.authenticated == true
	input.subject.organization_id != ""
	input.subject.organization_id == input.resource.organization_id
	perms := role_permissions[input.subject.role]
	input.action in perms
	not studio_ai_or_sod_forbidden
	not ai_forbidden_tool_action
	not lab_forbidden_boundary
	lab_practice_action_allowed
	not hardening_policy_forbidden
	not redteam_policy_forbidden
}
