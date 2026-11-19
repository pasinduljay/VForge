export const ROLES = [
  "owner",
  "admin",
  "security_lead",
  "security_analyst",
  "developer",
  "auditor",
  "viewer",
] as const;

export type Role = (typeof ROLES)[number];

export const MEMBERSHIP_STATUSES = [
  "active",
  "invited",
  "suspended",
  "removed",
] as const;
export type MembershipStatus = (typeof MEMBERSHIP_STATUSES)[number];

export const PROJECT_CRITICALITIES = ["critical", "high", "medium", "low"] as const;
export type ProjectCriticality = (typeof PROJECT_CRITICALITIES)[number];

export const PROJECT_STATUSES = ["active", "archived"] as const;
export type ProjectStatus = (typeof PROJECT_STATUSES)[number];

export const ENVIRONMENT_TYPES = [
  "development",
  "testing",
  "staging",
  "production",
  "isolated_lab",
] as const;
export type EnvironmentType = (typeof ENVIRONMENT_TYPES)[number];

export const ENVIRONMENT_STATUSES = ["active", "inactive", "archived"] as const;
export type EnvironmentStatus = (typeof ENVIRONMENT_STATUSES)[number];

export const ASSET_TYPES = [
  "web_application",
  "rest_api",
  "source_repository",
  "container_image",
  "ip_address",
  "cidr_range",
  "network_service",
  "infrastructure_definition",
] as const;
export type AssetType = (typeof ASSET_TYPES)[number];

export const REGISTRATION_STATES = [
  "registered",
  "pending_verification",
  "decommissioned",
] as const;
export type RegistrationState = (typeof REGISTRATION_STATES)[number];

export const AUTH_PROFILE_TYPES = [
  "oauth2_client_credentials",
  "oidc_service_account",
  "api_key_ref",
  "bearer_token_ref",
  "basic_auth_ref",
  "mtls_cert_ref",
  "session_cookie_ref",
] as const;
export type AuthProfileType = (typeof AUTH_PROFILE_TYPES)[number];

export const ALLOWED_ACTIVITIES = [
  "sast",
  "secrets",
  "sbom",
  "sca",
  "iac",
  "passive_dast",
  "active_dast",
  "network_discovery",
  "tls_assessment",
] as const;
export type TestingActivity = (typeof ALLOWED_ACTIVITIES)[number];

export const TESTING_CAPABILITIES = [
  "passive_web_testing",
  "active_web_testing",
  "api_testing",
  "authenticated_testing",
  "network_discovery",
  "tls_assessment",
  "container_assessment",
  "source_code_analysis",
  "infrastructure_analysis",
  "approved_exploit_validation",
] as const;
export type TestingCapability = (typeof TESTING_CAPABILITIES)[number];

export const INTENSITY_LEVELS = ["passive", "low", "medium", "high"] as const;
export type IntensityLevel = (typeof INTENSITY_LEVELS)[number];

export const TARGET_TYPES = [
  "fqdn",
  "domain_and_subdomains",
  "exact_url",
  "url_path_prefix",
  "ipv4",
  "ipv6",
  "cidr_range",
  "network_service",
  "rest_api",
  "source_repository",
  "container_image",
  "infrastructure_definition",
] as const;
export type TargetType = (typeof TARGET_TYPES)[number];

export const TOOL_CATEGORIES = [
  "",
  "passive_dast",
  "active_dast",
  "network",
  "tls",
  "sast",
  "secrets",
  "sca",
  "sbom",
  "container",
  "iac",
  "exploit_validation",
] as const;

export interface PlatformMeta {
  platform: string;
  version: string;
  environment: string;
  phase: number;
  phase_name: string;
  scanners_enabled: boolean;
  supply_chain_enabled?: boolean;
  runner_connected: boolean;
  docker_socket_mounted: boolean;
  oidc_enabled: boolean;
  implemented_capabilities: string[];
  planned_capabilities: string[];
}

export interface UserOut {
  id: string;
  oidc_issuer: string;
  oidc_subject: string;
  email: string;
  display_name: string;
  status: string;
  last_login_at: string | null;
  created_at: string;
}

export interface OrganizationMembershipSummary {
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  organization_status: string;
  role: Role;
  membership_status: MembershipStatus;
  permissions: string[];
}

export interface AuthMe {
  user: UserOut;
  active_organization_id: string | null;
  csrf_token: string | null;
  memberships: OrganizationMembershipSummary[];
}

export interface Organization {
  id: string;
  name: string;
  slug: string;
  status: "active" | "suspended" | "archived";
  created_at: string;
  updated_at: string;
}

export interface Membership {
  id: string;
  organization_id: string;
  user_id: string;
  role: Role;
  status: MembershipStatus;
  user_email: string;
  user_display_name: string;
  oidc_issuer: string;
  oidc_subject: string;
  created_at: string;
  updated_at: string;
}

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  description: string | null;
  criticality: ProjectCriticality;
  status: ProjectStatus;
  created_at: string;
  updated_at: string;
}

export interface Environment {
  id: string;
  organization_id: string;
  project_id: string;
  name: string;
  environment_type: EnvironmentType;
  status: EnvironmentStatus;
  created_at: string;
  updated_at: string;
}

export interface Asset {
  id: string;
  organization_id: string;
  environment_id: string;
  asset_type: AssetType;
  normalized_locator: string;
  scope_metadata: Record<string, unknown>;
  registration_state: RegistrationState;
  version?: number;
  created_at: string;
  updated_at: string;
}

export interface AuthProfile {
  id: string;
  organization_id: string;
  environment_id: string;
  name: string;
  auth_type: AuthProfileType;
  secret_manager_ref: string;
  status: "active" | "disabled" | "revoked";
  created_at: string;
  updated_at: string;
}

export interface Authorization {
  id: string;
  organization_id: string;
  project_id: string;
  environment_id: string;
  asset_id: string;
  requested_by: string;
  approved_by: string | null;
  revoked_by: string | null;
  approved_testing_scope: Record<string, unknown>;
  approved_activities: string[];
  allowed_ports: number[] | null;
  permitted_intensity: IntensityLevel;
  policy_version: string;
  allow_private_networks: boolean;
  authorization_reference: string;
  valid_from: string;
  expires_at: string;
  status: "pending" | "approved" | "rejected" | "revoked" | "expired";
  decision_reason: string | null;
  revocation_reason: string | null;
  approved_at: string | null;
  revoked_at: string | null;
  audit_history: Array<Record<string, unknown>>;
  created_at: string;
  updated_at: string;
}

export interface ScopePolicyReason {
  code: string;
  message: string;
}

export interface ScopeEvaluationResponse {
  outcome: "ALLOW" | "DENY" | "REQUIRES_APPROVAL";
  allowed: boolean;
  requires_approval: boolean;
  reasons: ScopePolicyReason[];
  canonical_target: string | null;
  target_type: string;
  target_port: number | null;
  resolved_ips: string[];
  redirect_safe: boolean;
  redirect_canonical_target?: string | null;
  policy_version: string;
  snapshot_id?: string | null;
  snapshot_verified?: boolean | null;
}

export interface ScopeSnapshot {
  id: string;
  organization_id: string;
  project_id: string;
  environment_id: string;
  asset_id: string;
  authorization_id: string;
  snapshot_version: number;
  asset_version: number;
  policy_version: string;
  target_type: string;
  canonical_locator: string;
  resolved_ips: string[];
  allowed_ports: number[];
  permitted_capabilities: string[];
  permitted_intensity: IntensityLevel;
  scope_definition: Record<string, unknown>;
  payload: Record<string, unknown>;
  payload_sha256: string;
  signing_key_id: string;
  signature_algorithm: string;
  signature: string;
  authorization_expires_at: string;
  created_by: string;
  created_at: string;
}

export interface SnapshotVerifyResponse {
  snapshot_id: string;
  valid: boolean;
  signature_valid: boolean;
  signature_reason: string;
  policy_version_current: boolean;
  asset_version_current: boolean;
  authorization_active: boolean;
  dns_revalidation_passed: boolean | null;
  resolved_ips: string[];
  opa_outcome: "ALLOW" | "DENY" | "REQUIRES_APPROVAL";
  reasons: ScopePolicyReason[];
}

export interface ScanProfileConfiguration {
  stages: string[];
  passive_only: boolean;
  max_concurrency: number;
  request_rate_limit_rps: number;
  timeout_seconds: number;
  include_paths: string[];
  exclude_paths: string[];
}

export interface ScanProfile {
  id: string;
  organization_id: string;
  name: string;
  version: number;
  configuration: ScanProfileConfiguration;
  status: "active" | "deprecated";
  created_at: string;
  updated_at: string;
}

export interface AuditEvent {
  id: string;
  organization_id: string | null;
  actor_id: string | null;
  correlation_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  outcome: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

export interface ScanRunSummary {
  id: string;
  organization_id: string;
  project_id: string;
  environment_id: string;
  scan_profile_id: string;
  authorization_id: string;
  scope_snapshot_id: string;
  source_snapshot_id?: string | null;
  source_snapshot_hash?: string | null;
  auth_profile_id?: string | null;
  coverage_summary?: Record<string, unknown> | null;
  requested_by: string;
  status: string;
  coverage_status: string;
  runner_pool: string;
  policy_snapshot_hash: string;
  policy_version: string;
  idempotency_key: string;
  cancel_requested_by: string | null;
  cancel_reason: string | null;
  error_summary: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanStage {
  id: string;
  organization_id: string;
  scan_run_id: string;
  stage_key: string;
  stage_order: number;
  stage_kind: string;
  depends_on_stage_key: string | null;
  requires_target_lease: boolean;
  lease_risk_class: string | null;
  status: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RunnerJob {
  id: string;
  organization_id: string;
  scan_run_id: string;
  scan_stage_id: string;
  job_type: string;
  tool_id: string;
  tool_version: string;
  image_digest: string;
  adapter_version: string;
  status: string;
  attempt_count: number;
  max_attempts: number;
  lease_owner: string | null;
  lease_expires_at: string | null;
  heartbeat_at: string | null;
  next_retry_at: string | null;
  timeout_seconds: number;
  idempotency_key: string;
  execution_count: number;
  result_summary: Record<string, unknown>;
  last_error_code: string | null;
  last_error_message: string | null;
  dispatched_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ScanTargetLease {
  id: string;
  organization_id: string;
  scan_run_id: string;
  runner_job_id: string | null;
  asset_id: string;
  target_locator: string;
  lease_risk_class: string;
  lease_owner: string;
  status: string;
  acquired_at: string;
  heartbeat_at: string;
  expires_at: string;
  released_at: string | null;
}

export interface TargetHealthProbe {
  id: string;
  organization_id: string;
  scan_run_id: string;
  runner_job_id: string | null;
  asset_id: string;
  probe_type: "baseline" | "periodic" | "tripwire" | "post_scan";
  target_url: string;
  status_code: number | null;
  latency_ms: number;
  healthy: boolean;
  error_message: string | null;
  probe_metadata: Record<string, unknown>;
  created_at: string;
}

export interface ScanRunDetail extends ScanRunSummary {
  target_snapshot: Record<string, unknown>;
  profile_snapshot: Record<string, unknown>;
  plan_manifest: Record<string, unknown>;
  stages: ScanStage[];
  jobs: RunnerJob[];
  leases: ScanTargetLease[];
  health_probes?: TargetHealthProbe[];
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export interface RunnerPool {
  id: string;
  organization_id: string;
  name: string;
  slug: string;
  pool_type: "standard" | "dast_egress" | "airgapped";
  max_concurrent_jobs: number;
  active: boolean;
  created_at: string;
  updated_at: string;
}

export interface RunnerItem {
  id: string;
  organization_id: string;
  pool_id: string;
  name: string;
  runner_identity: string;
  cert_sha256: string;
  cert_subject: string;
  cert_expires_at: string;
  status: "active" | "offline" | "draining" | "revoked";
  version: string;
  last_heartbeat_at: string | null;
  revoked_at: string | null;
  revoked_reason: string | null;
  capabilities_json: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface RunnerEventItem {
  id: string;
  organization_id: string;
  runner_id: string;
  runner_job_id: string | null;
  event_type: string;
  severity: "info" | "warning" | "security";
  details_json: Record<string, unknown>;
  created_at: string;
}

export interface RunnerArtifact {
  id: string;
  organization_id: string;
  scan_run_id: string;
  runner_job_id: string;
  tool_execution_id: string | null;
  artifact_type: string;
  content_type: string;
  size_bytes: number;
  sha256: string;
  kek_key_id: string;
  created_at: string;
}

export interface SourceSnapshotItem {
  id: string;
  organization_id: string;
  project_id: string;
  asset_id: string;
  source_type: string;
  commit_sha: string | null;
  branch: string | null;
  archive_sha256: string;
  file_count: number;
  total_bytes: number;
  detected_languages: Record<string, unknown>;
  coverage_report: Record<string, unknown>;
  status: string;
  created_by: string;
  created_at: string;
}

export interface FindingOccurrenceItem {
  id: string;
  organization_id: string;
  finding_id: string;
  scan_run_id: string;
  execution_id: string;
  evidence_artifact_id: string | null;
  scanner_tool_id: string;
  scanner_version: string;
  image_digest: string;
  rule_id: string;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  severity: "critical" | "high" | "medium" | "low" | "info" | "unknown";
  confidence: "high" | "medium" | "low";
  secret_redacted: boolean;
  snippet_redacted: string | null;
  purl: string | null;
  package_name: string | null;
  package_version: string | null;
  fixed_version: string | null;
  cve_id: string | null;
  iac_resource: string | null;
  sbom_document_id: string | null;
  vulnerability_db_snapshot_id: string | null;
  raw_finding_sanitized: Record<string, unknown>;
  observed_at: string;
}

export interface FindingItem {
  id: string;
  organization_id: string;
  project_id: string;
  fingerprint: string;
  category: string;
  scanner_tool_id: string;
  scanner_version: string;
  rule_id: string;
  title: string;
  description: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info" | "unknown";
  confidence: "high" | "medium" | "low";
  validation_status: string;
  status: string;
  cwe_ids: string[];
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  code_snippet_redacted: string | null;
  secret_redacted: boolean;
  remediation: string | null;
  purl: string | null;
  package_name: string | null;
  package_version: string | null;
  fixed_version: string | null;
  cve_id: string | null;
  iac_resource: string | null;
  sbom_document_id: string | null;
  vulnerability_db_snapshot_id: string | null;
  is_known_exploited?: boolean;
  epss_score?: number | null;
  epss_percentile?: number | null;
  business_priority?: "P0" | "P1" | "P2" | "P3";
  sla_due_at?: string | null;
  sla_breached?: boolean;
  assigned_to?: string | null;
  retest_status?: "none" | "retest_requested" | "retest_in_progress" | "verified_fixed" | "reopened";
  remediation_notes?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  occurrence_count: number;
  first_seen_at: string;
  last_seen_at: string;
  created_at: string;
  updated_at: string;
}

export interface FindingEventItem {
  id: string;
  organization_id: string;
  finding_id: string;
  event_type: string;
  previous_status?: string | null;
  old_status?: string | null;
  new_status?: string | null;
  actor_user_id?: string | null;
  comment?: string | null;
  metadata?: Record<string, unknown>;
  created_at: string;
}

export interface RiskExceptionItem {
  id: string;
  organization_id: string;
  project_id: string;
  finding_id: string;
  status: "pending" | "approved" | "rejected" | "expired" | "revoked";
  reason: string;
  mitigating_controls: string;
  requested_by: string;
  reviewed_by?: string | null;
  expires_at: string;
  review_notes?: string | null;
  created_at: string;
}

export interface ReportItem {
  id: string;
  organization_id: string;
  project_id: string;
  scan_run_id?: string | null;
  report_type: "executive" | "technical_vapt" | "compliance_summary" | "sarif_export";
  format: "html" | "pdf" | "json" | "sarif";
  title: string;
  summary: {
    total_findings?: number;
    severity_counts?: Record<string, number>;
    status_counts?: Record<string, number>;
    sla_breached_count?: number;
    coverage_status?: string;
    failed_stage_count?: number;
  };
  artifact_id: string;
  generated_by: string;
  created_at: string;
}

export interface SbomComponentSummary {
  name: string;
  version: string;
  purl: string | null;
  type: string;
  ecosystem?: string | null;
  locations?: string[];
}

export interface SbomDocumentItem {
  id: string;
  organization_id: string;
  project_id: string;
  scan_run_id: string;
  source_snapshot_id: string;
  execution_id: string;
  artifact_id: string;
  sbom_format: string;
  spec_version: string;
  serial_number: string | null;
  bom_sha256: string;
  tool_id: string;
  tool_version: string;
  image_digest: string;
  component_count: number;
  created_at: string;
}

export interface SbomDocumentDetailItem extends SbomDocumentItem {
  cataloger_config: Record<string, unknown>;
  components_summary: SbomComponentSummary[];
}

export interface VulnerabilityDbSnapshotItem {
  id: string;
  organization_id: string;
  tool_id: string;
  schema_version: string;
  built_at: string;
  source_url: string | null;
  db_archive_sha256: string;
  valid: boolean;
  providers_metadata: Record<string, unknown>;
  recorded_at: string;
}

export interface FindingDetailItem extends FindingItem {
  occurrences: FindingOccurrenceItem[];
}

export interface ScannerCoverageResponse {
  phase: number;
  scanners_enabled: boolean;
  tools: Array<Record<string, unknown>>;
  capabilities: Array<{
    language: string;
    tool_id: string;
    support_status: "supported" | "partial" | "unsupported";
    parser_mode: string;
    supported_versions: string;
    known_blind_spots: string;
    last_validated: string;
  }>;
}

export interface IntelSourceItem {
  id: string;
  slug: string;
  name: string;
  source_type: string;
  provider_url: string;
  license_name: string;
  license_url?: string | null;
  terms_reference?: string | null;
  is_active: boolean;
  is_gated: boolean;
  requires_scope_auth: boolean;
  allow_binary_upload: boolean;
  created_at: string;
  updated_at: string;
}

export interface IntelSyncRunItem {
  id: string;
  source_id: string;
  sync_mode: string;
  cursor_before?: string | null;
  cursor_after?: string | null;
  status: string;
  records_fetched: number;
  records_persisted: number;
  error_message?: string | null;
  raw_payload_hash?: string | null;
  started_at: string;
  completed_at?: string | null;
}

export interface IntelRecordItem {
  id: string;
  source_id: string;
  source_record_id: string;
  record_type: string;
  title?: string | null;
  summary?: string | null;
  description?: string | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  is_known_exploited: boolean;
  raw_payload: Record<string, unknown>;
  raw_hash: string;
  normalized_hash: string;
  published_at?: string | null;
  modified_at?: string | null;
  retrieved_at: string;
}

export interface CveThreatIntelOut {
  cve_id: string;
  is_known_exploited: boolean;
  epss_score?: number | null;
  epss_percentile?: number | null;
  cvss_score?: number | null;
  cvss_vector?: string | null;
  cwes: string[];
  kev_details?: Record<string, unknown> | null;
  exploit_references: Array<Record<string, unknown>>;
  advisories: Array<Record<string, unknown>>;
  sources_used: string[];
}

export interface OrgThreatIntelSummary {
  organization_id: string;
  total_findings: number;
  kev_findings_count: number;
  high_epss_findings_count: number;
  sources: Array<{
    id: string;
    slug: string;
    name: string;
    source_type: string;
    is_active: boolean;
    is_gated: boolean;
    requires_scope_auth: boolean;
    allow_binary_upload: boolean;
    records_persisted: number;
    last_sync_status?: string | null;
    last_sync_at?: string | null;
    is_stale: boolean;
    stale_reason?: string | null;
  }>;
}

export interface IntelEnrichmentResponse {
  enriched_count: number;
  message: string;
}

export type ExposureQueryType =
  | "auto"
  | "domain"
  | "email"
  | "ip"
  | "company"
  | "username";

export interface ExposureSourceStatusItem {
  source_slug: string;
  source_name: string;
  status: string;
  http_status?: number | null;
  records_found: number;
  latency_ms: number;
  raw_sha256: string;
  retrieved_at: string;
  error_message?: string | null;
}

export interface ExposureRecordItem {
  record_id: string;
  source_slug: string;
  source_name: string;
  category:
    | "infostealer_infection"
    | "compromised_endpoint"
    | "credential_breach"
    | "network_exposure"
    | "attack_surface_url";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  target: string;
  summary: string;
  occurred_at?: string | null;
  cve_id?: string | null;
  is_known_exploited: boolean;
  epss_score?: number | null;
  remediation?: string | null;
  metadata: Record<string, unknown>;
}

export interface HudsonRockOverview {
  total_hits: number;
  employees_compromised: number;
  users_compromised: number;
  third_parties_compromised: number;
  last_employee_compromised?: string | null;
  last_user_compromised?: string | null;
  stealer_families: Record<string, number>;
  weak_user_password_pct?: number | null;
  employee_urls_count: number;
  client_urls_count: number;
  third_party_domains: Array<{ domain: string; occurrence: number }>;
}

export interface ExposureSearchResponse {
  query: string;
  normalized_query: string;
  detected_type: string;
  resolved_domains: string[];
  resolved_ips: string[];
  discovered_subdomains: string[];
  discovered_emails: string[];
  total_records: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  latest_compromise_at?: string | null;
  hudson_rock_overview: HudsonRockOverview;
  sources_queried: ExposureSourceStatusItem[];
  records: ExposureRecordItem[];
  searched_at: string;
}

export interface ExposureFindingImportResponse {
  finding_id: string;
  project_id: string;
  created: boolean;
  title: string;
  severity: string;
  category: string;
  status: string;
  message: string;
}

export interface ToolCatalogItem {
  id: string;
  tool_slug: string;
  display_name: string;
  stream: string;
  update_channel: string;
  adapter_family: string;
  source_registry: string;
  automerge_allowed: boolean;
  is_active: boolean;
  active_stable_version?: {
    id: string;
    version_tag: string;
    image_repository: string;
    image_digest: string;
    approval_channel: string;
  } | null;
  active_canary_version?: {
    id: string;
    version_tag: string;
    image_repository: string;
    image_digest: string;
    approval_channel: string;
  } | null;
  created_at: string;
  updated_at: string;
}

export interface ToolVersionItem {
  id: string;
  tool_id: string;
  version_tag: string;
  image_repository: string;
  image_digest: string;
  adapter_version: string;
  approval_channel: string;
  is_active_stable: boolean;
  is_active_canary: boolean;
  previous_stable_version_id?: string | null;
  signature_verified: boolean;
  sbom_digest?: string | null;
  release_notes_url?: string | null;
  promoted_at?: string | null;
  rolled_back_at?: string | null;
  created_at: string;
}

export interface UpdateTestResultItem {
  id: string;
  update_id: string;
  tool_version_id: string;
  test_category: string;
  outcome: string;
  summary: string;
  details_json: Record<string, unknown>;
  executed_by: string;
  executed_at: string;
}

export interface ToolUpdateItem {
  id: string;
  tool_id: string;
  tool_slug: string;
  display_name: string;
  candidate_version_id: string;
  version_tag: string;
  image_digest: string;
  previous_version_id?: string | null;
  stream: string;
  update_channel: string;
  change_type: string;
  status: string;
  is_emergency: boolean;
  emergency_justification?: string | null;
  detected_from: string;
  approved_at?: string | null;
  promoted_at?: string | null;
  rolled_back_at?: string | null;
  rollback_reason?: string | null;
  rejection_reason?: string | null;
  test_results: UpdateTestResultItem[];
  created_at: string;
  updated_at: string;
}

export interface FeedSnapshotItem {
  id: string;
  tool_id: string;
  feed_slug: string;
  stream: string;
  update_channel: string;
  snapshot_tag: string;
  archive_sha256: string;
  schema_version: string;
  record_count: number;
  approval_channel: string;
  is_active_stable: boolean;
  is_active_canary: boolean;
  previous_stable_snapshot_id?: string | null;
  source_url?: string | null;
  promoted_at?: string | null;
  rolled_back_at?: string | null;
  created_at: string;
}

export interface UpdateAuditEventItem {
  id: string;
  update_id?: string | null;
  tool_id: string;
  tool_version_id?: string | null;
  feed_snapshot_id?: string | null;
  action: string;
  actor_email?: string | null;
  reason?: string | null;
  details_json: Record<string, unknown>;
  occurred_at: string;
}

export interface UpdateLifecycleOverview {
  streams: string[];
  channels: string[];
  tools: ToolCatalogItem[];
  versions: ToolVersionItem[];
  updates: ToolUpdateItem[];
  feed_snapshots: FeedSnapshotItem[];
  audit_events: UpdateAuditEventItem[];
  active_pins: Record<string, unknown>;
}

export interface StudioRuleItem {
  id: string;
  rule_key: string;
  title: string;
  engine: "opengrep" | "nuclei" | "checkov" | "gitleaks" | "zap" | "nmap";
  native_format: string;
  risk_class: string;
  severity: string;
  confidence: string;
  cwe_id: string;
  rationale: string;
  target_context: string;
  network_requirements: string;
  known_limitations: string;
  timeout_seconds: number;
  memory_budget_mb: number;
  native_content: string;
  content_sha256: string;
  expected_evidence_fields: string[];
  positive_fixtures: Array<Record<string, unknown>>;
  negative_fixtures: Array<Record<string, unknown>>;
  near_miss_fixtures: Array<Record<string, unknown>>;
  static_validation_passed: boolean;
  static_validation_errors: string[];
  created_at: string;
}

export interface RuleFixtureRunItem {
  id: string;
  rule_pack_version_id: string;
  corpus_ref: string;
  corpus_sha256: string;
  executed_by: string;
  actor_type: string;
  total_positive: number;
  passed_positive: number;
  total_negative: number;
  passed_negative: number;
  total_near_miss: number;
  passed_near_miss: number;
  false_positives: number;
  false_negatives: number;
  total_duration_ms: number;
  regression_passed: boolean;
  rule_results_json: Array<Record<string, unknown>>;
  created_at: string;
}

export interface RulePackVersionItem {
  id: string;
  rule_pack_id: string;
  version: string;
  semver_change_type: string;
  channel: string;
  review_status: string;
  creation_method: string;
  author_id: string;
  author_actor_type: string;
  reviewer_id?: string | null;
  approved_at?: string | null;
  rejection_reason?: string | null;
  compatibility_json: Record<string, unknown>;
  validation_summary_json: Record<string, unknown>;
  ai_provenance_json: Record<string, unknown>;
  manifest_sha256?: string | null;
  signing_key_id?: string | null;
  signed_by?: string | null;
  signed_at?: string | null;
  is_active_canary: boolean;
  is_active_stable: boolean;
  fixture_regression_passed: boolean;
  true_positive_count: number;
  false_positive_count: number;
  false_negative_count: number;
  rules: StudioRuleItem[];
  fixture_runs: RuleFixtureRunItem[];
  created_at: string;
}

export interface RulePackItem {
  id: string;
  organization_id: string;
  slug: string;
  title: string;
  description: string;
  owner_team: string;
  created_by: string;
  is_active: boolean;
  versions: RulePackVersionItem[];
  created_at: string;
  updated_at: string;
}

export interface SkillVersionItem {
  id: string;
  skill_id: string;
  version: string;
  intent_description: string;
  allowed_capabilities: string[];
  forbidden_actions: string[];
  supported_agent_versions: string[];
  playbook_steps_json: Array<Record<string, unknown>>;
  creation_method: string;
  author_id: string;
  author_actor_type: string;
  review_status: string;
  reviewer_id?: string | null;
  approved_at?: string | null;
  rejection_reason?: string | null;
  content_sha256: string;
  signing_key_id?: string | null;
  signed_by?: string | null;
  signed_at?: string | null;
  channel: string;
  is_active_canary: boolean;
  is_active_stable: boolean;
  created_at: string;
}

export interface AssessmentSkillItem {
  id: string;
  organization_id: string;
  slug: string;
  title: string;
  description: string;
  owner_team: string;
  created_by: string;
  is_active: boolean;
  versions: SkillVersionItem[];
  created_at: string;
  updated_at: string;
}

export interface StudioAuditEventItem {
  id: string;
  entity_type: string;
  entity_id: string;
  action: string;
  actor_email: string;
  actor_type: string;
  previous_state?: string | null;
  new_state?: string | null;
  details_json: Record<string, unknown>;
  occurred_at: string;
}

export interface StudioOverview {
  supported_engines: string[];
  rule_packs: RulePackItem[];
  skills: AssessmentSkillItem[];
  audit_events: StudioAuditEventItem[];
}

export interface AiModelCatalogItem {
  id: string;
  provider_class: string;
  model_slug: string;
  display_name: string;
  capabilities_json: string[];
  is_local: boolean;
  retention_days: number;
  zdr_available: boolean;
  requires_retention_consent: boolean;
  cost_per_1k_input_usd: number;
  cost_per_1k_output_usd: number;
  is_active: boolean;
  created_at: string;
}

export interface AiProviderConfigItem {
  id: string;
  organization_id: string;
  provider_class: string;
  display_name: string;
  endpoint_url?: string | null;
  secret_ref?: string | null;
  local_only_mode: boolean;
  is_enabled: boolean;
  allowed_models_json: string[];
  monthly_budget_usd: number;
  max_tokens_per_request: number;
  retention_consent_approved: boolean;
  retention_consent_approved_by?: string | null;
  retention_consent_approved_at?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface AiTaskRequestItem {
  id: string;
  organization_id: string;
  task_type: string;
  role_name: string;
  data_classification: string;
  redaction_applied: boolean;
  prompt_injection_detected: boolean;
  consent_acknowledged: boolean;
  provider_config_id?: string | null;
  model_slug: string;
  input_snapshot_sha256: string;
  input_summary_redacted: string;
  status: string;
  block_reason?: string | null;
  requested_by: string;
  created_at: string;
}

export interface AiRunItem {
  id: string;
  organization_id: string;
  task_request_id: string;
  provider_config_id?: string | null;
  role_name: string;
  provider_class: string;
  model_slug: string;
  prompt_template_version: string;
  fallback_triggered: boolean;
  input_sha256: string;
  output_sha256: string;
  structured_output_json: Record<string, unknown>;
  rationale_summary: string;
  uncertainty_notes: string;
  token_input_count: number;
  token_output_count: number;
  estimated_cost_usd: number;
  latency_ms: number;
  status: string;
  error_message?: string | null;
  created_at: string;
}

export interface AiToolProposalItem {
  id: string;
  organization_id: string;
  ai_run_id: string;
  tool_action: string;
  target_resource_type: string;
  target_resource_id: string;
  arguments_json: Record<string, unknown>;
  opa_allowed: boolean;
  opa_decision_reason: string;
  status: string;
  created_at: string;
}

export interface KnowledgeDocumentItem {
  id: string;
  organization_id: string;
  slug: string;
  title: string;
  source_type: string;
  source_uri: string;
  content_sha256: string;
  is_approved: boolean;
  uploaded_by: string;
  created_at: string;
}

export interface KnowledgeSearchHitItem {
  document_id: string;
  slug: string;
  title: string;
  source_type: string;
  source_uri: string;
  chunk_id: string;
  chunk_index: number;
  chunk_sha256: string;
  score: number;
  excerpt: string;
}

export interface AiFeedbackItem {
  id: string;
  organization_id: string;
  ai_run_id: string;
  label: string;
  notes: string;
  de_identified: boolean;
  cross_tenant_sharing_enabled: boolean;
  labeled_by: string;
  created_at: string;
}

export interface ModelEvaluationItem {
  id: string;
  organization_id: string;
  model_slug: string;
  suite_name: string;
  sample_count: number;
  true_positive_rate: number;
  false_positive_rate: number;
  regression_passed: boolean;
  evaluated_by: string;
  created_at: string;
}

export interface AiAuditEventItem {
  id: string;
  organization_id: string;
  action: string;
  actor_id: string;
  actor_email: string;
  provider_class?: string | null;
  model_slug?: string | null;
  data_classification?: string | null;
  details_json: Record<string, unknown>;
  occurred_at: string;
}

export interface AiTaskExecuteResult {
  task_request: AiTaskRequestItem;
  run: AiRunItem;
  tool_proposals: AiToolProposalItem[];
  rag_hits: KnowledgeSearchHitItem[];
}

export interface AiGovernanceOverview {
  model_catalog: AiModelCatalogItem[];
  provider_configs: AiProviderConfigItem[];
  recent_runs: AiRunItem[];
  tool_proposals: AiToolProposalItem[];
  knowledge_documents: KnowledgeDocumentItem[];
  evaluations: ModelEvaluationItem[];
  audit_events: AiAuditEventItem[];
}

export interface LabChallengeItem {
  id: string;
  slug: string;
  title: string;
  track_level: string;
  target_app: string;
  cwe_id: string;
  learning_goal: string;
  preconditions_json: string[];
  permitted_target: string;
  test_identities_json: Array<Record<string, unknown>>;
  test_data_json: Record<string, unknown>;
  permitted_tools_json: string[];
  expected_finding_json: Record<string, unknown>;
  safe_evidence_criteria: string;
  remediation_exercise: string;
  retest_instructions: string;
  explanation: string;
  is_active: boolean;
  created_at: string;
}

export interface LabWorkspaceItem {
  id: string;
  organization_id: string;
  environment_slug: string;
  display_name: string;
  isolation_network_name: string;
  egress_denied: boolean;
  public_exposure_blocked: boolean;
  consent_to_persist_progress: boolean;
  disposable_account_prefix: string;
  reset_epoch: number;
  state: string;
  disposable_identities_json: Array<Record<string, string>>;
  last_reset_at?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface LabChallengeProgressItem {
  id: string;
  organization_id: string;
  workspace_id: string;
  challenge_id: string;
  status: string;
  consent_granted: boolean;
  reset_epoch: number;
  validated_evidence_json: Record<string, unknown>;
  remediation_notes: string;
  retest_passed: boolean;
  attempts_count: number;
  updated_by: string;
  created_at: string;
  updated_at: string;
}

export interface LabValidationRunItem {
  id: string;
  organization_id: string;
  workspace_id: string;
  challenge_id: string;
  reset_epoch: number;
  tool_slug: string;
  target_url: string;
  disposable_identity_used: string;
  action_type: string;
  safety_boundary_verified: boolean;
  evidence_summary_redacted: string;
  evidence_sha256: string;
  finding_confirmed: boolean;
  remediation_verified: boolean;
  status: string;
  executed_by: string;
  created_at: string;
}

export interface LabSelfScanItem {
  id: string;
  organization_id: string;
  target_component: string;
  profile_name: string;
  checks_executed: number;
  issues_found: number;
  critical_high_count: number;
  findings_json: Array<Record<string, unknown>>;
  remediation_summary: string;
  regression_verified: boolean;
  status: string;
  executed_by: string;
  created_at: string;
}

export interface LabAuditEventItem {
  id: string;
  organization_id: string;
  workspace_id?: string | null;
  action: string;
  actor_id: string;
  actor_email: string;
  target_url?: string | null;
  details_json: Record<string, unknown>;
  occurred_at: string;
}

export interface LabComposeIsolationStatus {
  verified: boolean;
  path?: string | null;
  violations: string[];
  services_checked: number;
}

export interface LabOverview {
  challenges: LabChallengeItem[];
  workspaces: LabWorkspaceItem[];
  progress: LabChallengeProgressItem[];
  validation_runs: LabValidationRunItem[];
  self_scans: LabSelfScanItem[];
  audit_events: LabAuditEventItem[];
  compose_isolation: LabComposeIsolationStatus;
}

export interface EncryptionKeyRecordItem {
  id: string;
  organization_id: string;
  key_id: string;
  purpose: string;
  algorithm_suite: string;
  pqc_readiness_status: string;
  status: string;
  version: number;
  key_fingerprint_sha256: string;
  owner_role: string;
  cryptoperiod_days: number;
  activated_at: string;
  rotate_after_at: string;
  rotated_at?: string | null;
  created_by: string;
  created_at: string;
}

export interface KeyRewrapDrillItem {
  old_kek_id: string;
  new_kek_id: string;
  plaintext_sha256: string;
  ciphertext_sha256: string;
  rewrap_verified: boolean;
  decrypt_recovery_verified: boolean;
}

export interface BackupManifestItem {
  id: string;
  organization_id: string;
  backup_scope: string;
  storage_key: string;
  encryption_key_id: string;
  encryption_algorithm: string;
  plaintext_sha256: string;
  ciphertext_sha256: string;
  size_bytes: number;
  row_count: number;
  status: string;
  rpo_target_minutes: number;
  rto_target_minutes: number;
  created_by: string;
  created_at: string;
}

export interface RestoreDrillItem {
  id: string;
  organization_id: string;
  manifest_id: string;
  drill_mode: string;
  rto_observed_seconds: number;
  integrity_verified: boolean;
  decryption_verified: boolean;
  schema_head_verified: string;
  findings_summary: string;
  status: string;
  executed_by: string;
  created_at: string;
}

export interface HardeningAuditEventItem {
  id: string;
  organization_id: string;
  category: string;
  action: string;
  outcome: string;
  actor_id: string;
  actor_email: string;
  details_json: Record<string, unknown>;
  occurred_at: string;
}

export interface HardeningOverview {
  crypto_agility: {
    envelope_algorithm: string;
    active_artifact_kek_id: string;
    backup_kek_id: string;
    keyring_key_count: number;
    pqc_hybrid_live_enabled: boolean;
    custom_hybrid_protocol_allowed: boolean;
    fips_validated_claim: boolean;
    fips_notice: string;
    profiles: Array<{
      purpose: string;
      classical_algorithm: string;
      pqc_migration_target: string;
      nist_standard: string;
      pqc_live_enabled: boolean;
      notes: string;
    }>;
  };
  secret_and_runtime_posture: {
    secret_provider: Record<string, unknown>;
    docker_socket_mounted: boolean;
    rls_forced_mode: boolean;
    metrics_enabled: boolean;
    observability_stack_path: string;
    dr_runbook_path: string;
  };
  certificate_posture: {
    warning_threshold_days: number;
    total_runners: number;
    healthy_count: number;
    expiring_soon_count: number;
    expired_count: number;
    revoked_count: number;
    ca_cert: Record<string, unknown>;
    gateway_cert: Record<string, unknown>;
    runners: Array<{
      runner_id: string;
      runner_name: string;
      runner_status: string;
      cert_sha256: string;
      cert_expires_at: string;
      days_remaining: number;
      cert_health: string;
    }>;
  };
  keys: EncryptionKeyRecordItem[];
  backup_manifests: BackupManifestItem[];
  restore_drills: RestoreDrillItem[];
  audit_events: HardeningAuditEventItem[];
}

export interface RedTeamSessionItem {
  id: string;
  organization_id: string;
  title: string;
  objective: string;
  engine: string;
  status: string;
  tool_allowlist: string[];
  target_urls: string[];
  max_duration_seconds: number;
  max_tool_calls: number;
  max_tokens: number;
  tool_calls_used: number;
  tokens_used: number;
  requested_by: string;
  approved_by?: string | null;
  approved_at?: string | null;
  approval_expires_at?: string | null;
  started_at?: string | null;
  ended_at?: string | null;
  end_reason?: string | null;
  cleanup_attested: boolean;
  cleanup_summary?: string | null;
  created_at: string;
  updated_at: string;
}

export interface RedTeamObservationItem {
  id: string;
  organization_id: string;
  session_id: string;
  title: string;
  category: string;
  severity: string;
  classification: "hypothesis" | "confirmed" | "rejected";
  evidence_summary: string;
  evidence_sha256: string;
  source: string;
  recorded_by: string;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  review_note?: string | null;
  created_at: string;
}

export interface RedTeamEventItem {
  id: string;
  organization_id: string;
  session_id: string;
  event_type: string;
  outcome: string;
  actor_id?: string | null;
  actor_email?: string | null;
  tool_name?: string | null;
  target_host?: string | null;
  details_json: Record<string, unknown>;
  occurred_at: string;
}

export interface RedTeamBenchmarkItem {
  id: string;
  organization_id: string;
  session_id: string;
  ground_truth_slugs: string[];
  ai_detected_slugs: string[];
  zap_detected_slugs: string[];
  nuclei_detected_slugs: string[];
  metrics_json: {
    ground_truth_count: number;
    recall: {
      ai_redteam: number;
      zap: number;
      nuclei: number;
      zap_plus_nuclei: number;
      all_engines: number;
    };
    ai_unique_true_positives: string[];
    scanner_unique_true_positives: string[];
    missed_by_all: string[];
    claims_outside_ground_truth: Record<string, number>;
    notes: string;
  };
  data_provenance: string;
  created_by: string;
  created_at: string;
}

export interface RedTeamOverview {
  organization_id: string;
  execution_mode: string;
  sandbox_isolation: {
    verified: boolean;
    path?: string | null;
    violations: string[];
    services_checked: number;
  };
  lab_isolation: {
    verified: boolean;
    path?: string | null;
    violations: string[];
    services_checked: number;
  };
  allowed_tools: Array<{
    name: string;
    description: string;
    requires_target_url: boolean;
  }>;
  forbidden_tools: string[];
  sessions: RedTeamSessionItem[];
  observations: RedTeamObservationItem[];
  events: RedTeamEventItem[];
  benchmarks: RedTeamBenchmarkItem[];
}

