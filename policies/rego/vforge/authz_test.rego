package vforge.authz_test

import rego.v1

import data.vforge.authz

test_default_deny_empty_input if {
	not authz.allow with input as {}
}

test_default_deny_scan_start if {
	not authz.allow with input as {
		"action": "scan:start",
		"subject": {"id": "user-1", "role": "admin", "authenticated": true},
		"target": "https://example.com",
	}
}

test_health_read_allowed if {
	authz.allow with input as {
		"action": "platform:health_read",
		"subject": {"authenticated": false},
	}
}

test_cross_tenant_denied if {
	not authz.allow with input as {
		"action": "project:read",
		"subject": {
			"id": "user-1",
			"role": "owner",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-b"},
	}
}

test_security_lead_can_approve_authorization if {
	authz.allow with input as {
		"action": "authorization:approve",
		"subject": {
			"id": "lead-1",
			"role": "security_lead",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_developer_cannot_approve_authorization if {
	not authz.allow with input as {
		"action": "authorization:approve",
		"subject": {
			"id": "dev-1",
			"role": "developer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_auditor_can_read_audit_but_cannot_mutate if {
	authz.allow with input as {
		"action": "audit:read",
		"subject": {
			"id": "aud-1",
			"role": "auditor",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "project:create",
		"subject": {
			"id": "aud-1",
			"role": "auditor",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_viewer_denied_audit_read if {
	not authz.allow with input as {
		"action": "audit:read",
		"subject": {
			"id": "view-1",
			"role": "viewer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_phase2_scope_and_snapshot_permissions if {
	authz.allow with input as {
		"action": "scope:evaluate",
		"subject": {
			"id": "dev-1",
			"role": "developer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "snapshot:create",
		"subject": {
			"id": "dev-1",
			"role": "developer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "snapshot:verify",
		"subject": {
			"id": "aud-1",
			"role": "auditor",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_phase3_scan_orchestration_permissions if {
	authz.allow with input as {
		"action": "scan:start",
		"subject": {
			"id": "analyst-1",
			"role": "security_analyst",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "scan:start",
		"subject": {
			"id": "aud-1",
			"role": "auditor",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "scan:read",
		"subject": {
			"id": "view-1",
			"role": "viewer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_phase4_runner_management_permissions if {
	authz.allow with input as {
		"action": "runner:manage",
		"subject": {
			"id": "sec-lead-1",
			"role": "security_lead",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "runner:manage",
		"subject": {
			"id": "dev-1",
			"role": "developer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "runner:read",
		"subject": {
			"id": "aud-1",
			"role": "auditor",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_phase5_source_snapshot_and_finding_permissions if {
	authz.allow with input as {
		"action": "source_snapshot:create",
		"subject": {
			"id": "dev-1",
			"role": "developer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "source_snapshot:create",
		"subject": {
			"id": "viewer-1",
			"role": "viewer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "finding:read",
		"subject": {
			"id": "viewer-1",
			"role": "viewer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
}

test_phase6_supply_chain_and_db_snapshot_permissions if {
	authz.allow with input as {
		"action": "sbom:read",
		"subject": {
			"id": "viewer-1",
			"role": "viewer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "vuln_db:read",
		"subject": {
			"id": "auditor-1",
			"role": "auditor",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "sbom:read",
		"subject": {
			"id": "viewer-1",
			"role": "viewer",
			"organization_id": "org-a",
			"authenticated": true,
		},
		"resource": {"organization_id": "org-b"},
	}
}

test_phase8_findings_triage_risk_exceptions_and_reports if {
	# Developer can triage and request exception
	authz.allow with input as {
		"action": "finding:triage",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "risk_exception:request",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	# Developer CANNOT approve risk exceptions
	not authz.allow with input as {
		"action": "risk_exception:approve",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Security Lead CAN approve risk exceptions and generate reports
	authz.allow with input as {
		"action": "risk_exception:approve",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "report:generate",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Auditor can read and generate reports, but cannot triage findings
	authz.allow with input as {
		"action": "report:generate",
		"subject": {"id": "audit-1", "role": "auditor", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "finding:triage",
		"subject": {"id": "audit-1", "role": "auditor", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Viewer can read reports but cannot generate
	authz.allow with input as {
		"action": "report:read",
		"subject": {"id": "viewer-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "report:generate",
		"subject": {"id": "viewer-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Cross-tenant is denied
	not authz.allow with input as {
		"action": "report:read",
		"subject": {"id": "viewer-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-b"},
	}
}

test_phase9_threat_intelligence_permissions if {
	# Security Lead can read and manage threat intel
	authz.allow with input as {
		"action": "intel:manage",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "intel:read",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Developer can read threat intel, but CANNOT manage feeds or sync
	authz.allow with input as {
		"action": "intel:read",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "intel:manage",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Viewer can read intel, but CANNOT manage
	authz.allow with input as {
		"action": "intel:read",
		"subject": {"id": "view-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "intel:manage",
		"subject": {"id": "view-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Cross-tenant denial for threat intel
	not authz.allow with input as {
		"action": "intel:read",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-b"},
	}
}

test_phase10_update_lifecycle_permissions if {
	# Security Lead & Admin can read and manage updates
	authz.allow with input as {
		"action": "update:manage",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "update:manage",
		"subject": {"id": "adm-1", "role": "admin", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Security Analyst & Developer can read updates, but CANNOT approve/promote/rollback
	authz.allow with input as {
		"action": "update:read",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "update:manage",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "update:manage",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Cross-tenant denial for updates
	not authz.allow with input as {
		"action": "update:read",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-b"},
	}
}

test_phase11_rule_studio_permissions if {
	# Security Lead can author, review, and promote rule packs and skills
	authz.allow with input as {
		"action": "studio:review",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	authz.allow with input as {
		"action": "studio:promote",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Developer & Security Analyst can author candidate drafts, CANNOT review/sign/promote
	authz.allow with input as {
		"action": "studio:author",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "studio:review",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "studio:promote",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Cross-tenant denial for studio actions
	not authz.allow with input as {
		"action": "studio:author",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-b"},
	}

	# AI agent cannot review or promote even if holding an elevated role
	not authz.allow with input as {
		"action": "studio:review",
		"subject": {"id": "ai-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true, "actor_type": "ai_agent"},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "studio:promote",
		"subject": {"id": "ai-1", "role": "admin", "organization_id": "org-a", "authenticated": true, "actor_type": "ai_agent"},
		"resource": {"organization_id": "org-a"},
	}

	# Segregation of duties: author cannot review or promote own rule pack
	not authz.allow with input as {
		"action": "studio:review",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true, "actor_type": "human"},
		"resource": {"organization_id": "org-a", "author_id": "lead-1"},
	}
}

test_phase12_ai_governance_permissions if {
	# Admin/Security Lead can manage AI provider configs & approve bounded tool proposals
	authz.allow with input as {
		"action": "ai:manage",
		"subject": {"id": "admin-1", "role": "admin", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "tool_action": "rule:propose_draft"},
	}

	# Developer & Security Analyst can invoke AI tasks, CANNOT configure retention/budgets or approve tools
	authz.allow with input as {
		"action": "ai:invoke",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "tool_action": "knowledge:search"},
	}
	not authz.allow with input as {
		"action": "ai:manage",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "ai:invoke",
		"subject": {"id": "view-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Even Owner/Admin is ALWAYS denied forbidden AI tool actions (modify OPA/scope, sign/promote, shell)
	not authz.allow with input as {
		"action": "ai:manage",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "tool_action": "opa:modify"},
	}
	not authz.allow with input as {
		"action": "ai:invoke",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "tool_action": "scope:modify"},
	}

	# Cross-tenant isolation on AI governance actions
	not authz.allow with input as {
		"action": "ai:invoke",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-b"},
	}

	# Case/whitespace obfuscation on forbidden AI tool actions & SoD self-approval are denied
	not authz.allow with input as {
		"action": "ai:manage",
		"subject": {"id": "admin-1", "role": "admin", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "tool_action": " OPA:MODIFY "},
	}
	not authz.allow with input as {
		"action": "ai:manage",
		"subject": {"id": "admin-1", "role": "admin", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "tool_action": "rule:propose_draft", "requested_by": "admin-1"},
	}
}

test_phase13_learning_lab_permissions if {
	# Admin/Security Lead can manage lab workspaces & self-scans
	authz.allow with input as {
		"action": "lab:manage",
		"subject": {"id": "admin-1", "role": "admin", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Developer & Security Analyst can run controlled practice challenges
	authz.allow with input as {
		"action": "lab:practice",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "lab_action_type": "baseline_probe"},
	}

	# Developer cannot alter workspace consent policy or trigger global self-scans; Viewer is read-only
	not authz.allow with input as {
		"action": "lab:manage",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "lab:practice",
		"subject": {"id": "view-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Exploitation boundary: persistence, exfiltration, dos_flood, or unknown action always denied
	not authz.allow with input as {
		"action": "lab:practice",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "lab_action_type": "persistence"},
	}
	not authz.allow with input as {
		"action": "lab:practice",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "lab_action_type": " EXFILTRATION "},
	}
	not authz.allow with input as {
		"action": "lab:practice",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "lab_action_type": "dos_flood"},
	}
	not authz.allow with input as {
		"action": "lab:practice",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "lab_action_type": "arbitrary_unknown_probe"},
	}

	# Cross-tenant isolation on lab actions
	not authz.allow with input as {
		"action": "lab:read",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-b"},
	}
}

test_phase14_hardening_and_crypto_agility_policies if {
	# Admin and Security Lead can manage keys, certs, and DR backups
	authz.allow with input as {
		"action": "hardening:manage",
		"subject": {"id": "admin-1", "role": "admin", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Auditor can inspect hardening posture and DR drill logs
	authz.allow with input as {
		"action": "hardening:read",
		"subject": {"id": "aud-1", "role": "auditor", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# Viewer and Developer cannot view or manage enterprise key/DR ops
	not authz.allow with input as {
		"action": "hardening:read",
		"subject": {"id": "view-1", "role": "viewer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "hardening:manage",
		"subject": {"id": "dev-1", "role": "developer", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}

	# §26.3 / §26.4 honesty & safety gates: forbid unvalidated FIPS claims or custom PQC protocols
	not authz.allow with input as {
		"action": "hardening:manage",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "fips_validated_claim": true},
	}
	not authz.allow with input as {
		"action": "hardening:manage",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "pqc_experimental_custom_protocol": true},
	}
}

test_phase15_redteam_sandbox_and_sod_policies if {
	# Security Analyst can request, execute allowed tools, and review observations (for other users)
	authz.allow with input as {
		"action": "redteam:request",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "redteam_tool": "http_probe"},
	}
	authz.allow with input as {
		"action": "redteam:execute",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "redteam_tool": "browser_navigate"},
	}

	# Security Analyst CANNOT approve sessions; Security Lead / Admin CAN approve (for another user)
	not authz.allow with input as {
		"action": "redteam:approve",
		"subject": {"id": "ana-1", "role": "security_analyst", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "requested_by": "ana-2"},
	}
	authz.allow with input as {
		"action": "redteam:approve",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "requested_by": "ana-1"},
	}

	# Segregation of Duties: requester cannot approve own session; recorder cannot review own observation
	not authz.allow with input as {
		"action": "redteam:approve",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a"},
	}
	not authz.allow with input as {
		"action": "redteam:approve",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "requested_by": "lead-1"},
	}
	not authz.allow with input as {
		"action": "redteam:review",
		"subject": {"id": "lead-1", "role": "security_lead", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "recorded_by": "lead-1"},
	}

	# AI agent cannot approve sessions or confirm observations
	not authz.allow with input as {
		"action": "redteam:approve",
		"subject": {"id": "ai-1", "role": "owner", "organization_id": "org-a", "authenticated": true, "actor_type": "ai_agent"},
		"resource": {"organization_id": "org-a", "requested_by": "ana-1"},
	}
	not authz.allow with input as {
		"action": "redteam:review",
		"subject": {"id": "ai-1", "role": "owner", "organization_id": "org-a", "authenticated": true, "actor_type": "ai_agent"},
		"resource": {"organization_id": "org-a", "recorded_by": "ana-1"},
	}

	# Forbidden tools (shell:exec, scope:modify, etc.), external network, and auto-confirm are ALWAYS denied
	not authz.allow with input as {
		"action": "redteam:execute",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "redteam_tool": "shell:exec"},
	}
	not authz.allow with input as {
		"action": "redteam:execute",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "redteam_tool": " SCOPE:MODIFY "},
	}
	not authz.allow with input as {
		"action": "redteam:request",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "external_network_requested": true},
	}
	not authz.allow with input as {
		"action": "redteam:review",
		"subject": {"id": "owner-1", "role": "owner", "organization_id": "org-a", "authenticated": true},
		"resource": {"organization_id": "org-a", "auto_confirm_requested": true},
	}
}



