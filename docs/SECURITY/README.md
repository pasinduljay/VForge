# VForge Security Documentation Index

Security engineering standards, threat models, secret governance, and verification procedures live across the following authoritative files:

- **[Security Baseline](../SECURITY_BASELINE.md):** Mandatory runtime hardening, cryptography, auth/RBAC/RLS, and HTTP security header standards.
- **[Threat Model](../THREAT_MODEL.md):** Trust-boundary decomposition (`TB-1..TB-6`), STRIDE analysis (`TM-01..TM-09`), and negative security abuse cases.
- **[Secret Management & OpenBao Architecture](../SECRET_MANAGEMENT_AND_OPENBAO.md):** Credential rotation, three-way PostgreSQL separation, RabbitMQ/Valkey ACL hardening, `SecretProvider` hierarchy, and rollback procedures.
- **[AI Data Governance](../AI_DATA_GOVERNANCE.md):** Provider separation, data retention gates (e.g., 30-day rule enforcement), pre-egress consent, and prompt-injection rules.
- **[Risk Register](../RISK_REGISTER.md):** Active and mitigated risks (`RISK-01..RISK-12`) with status and owners.
- **[Verification Procedures](VERIFICATION_PROCEDURES.md):** Executable non-destructive security checks and redaction audits run before every phase commit.
