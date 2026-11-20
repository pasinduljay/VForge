# ADR-0005: Phase 3 Orchestration — Transactional Outbox, Least-Privilege RLS Workers & PostgreSQL Target Leases

- **Status:** Accepted
- **Date:** 2026-11-12
- **Phase:** Phase 3 — Queue, Orchestrator and State Machine

## Context

Phase 3 introduces durable scan orchestration (`scan_runs`, `scan_stages`, `runner_jobs`, `scan_target_leases`, `outbox_events`), declarative scan planning, RabbitMQ queuing, bounded retries, heartbeats, cancellation, and mutually exclusive target leases.

Following the Security Preflight (ADR-0004), the runtime application role (`vforge_app`) executes with `NOSUPERUSER`, `NOBYPASSRLS`, and `FORCE ROW LEVEL SECURITY` on all tenant-owned tables. However, the orchestration worker/reconciler service needs to discover pending outbox events, due retries, and expired leases across multiple tenants without granting `BYPASSRLS` to any runtime database login.

## Decision

1. **Narrow Cross-Tenant Work Discovery (`orchestration_wakeups` + `SECURITY DEFINER`) + Strict RLS Execution**
   - Because even `vforge_migrator` runs without `BYPASSRLS` (`NOBYPASSRLS` + `FORCE ROW LEVEL SECURITY`), `AFTER INSERT OR UPDATE OR DELETE` `SECURITY DEFINER` triggers on `outbox_events`, `runner_jobs`, `scan_target_leases`, and `scan_runs` maintain a minimal unprivileged-inaccessible wakeup table `orchestration_wakeups` (`(work_kind, record_id, organization_id, due_at)` — zero tenant payload, `REVOKE ALL` from `PUBLIC` and `vforge_app`).
   - A minimal SQL function `public.list_due_orchestration_work(p_limit integer DEFAULT 100, p_work_kinds text[] DEFAULT NULL)` (`SECURITY DEFINER`, owned by `vforge_migrator`, pinned with `SET search_path = pg_catalog, public`, clamped at `1..500`, granted only to `vforge_app`) returns due `(work_kind, record_id, organization_id)` tuples filtered by `p_work_kinds` so no `work_kind` (such as long-running cancellations) can starve outbox dispatch or lease reconciliation.
   - `orchestrator` connects exclusively as `vforge_app` (`NOSUPERUSER`, `NOBYPASSRLS`), invokes `list_due_orchestration_work`, then opens a separate per-item transaction, binds `set_config('app.current_org_id', org_id, true)`, and performs all reads/locks/writes through RLS-enforced queries in a single canonical lock order (`ScanRun -> ScanStage -> RunnerJob -> ScanTargetLease -> OutboxEvent`) with `FOR UPDATE SKIP LOCKED`.

2. **Transactional Outbox -> Durable RabbitMQ Topology & Attempt Fencing**
   - Creating a scan run (or unblocking the next dependent stage) writes `outbox_events` in the same ACID PostgreSQL transaction as `scan_runs` / `scan_stages` / `runner_jobs` / `audit_events`. Concurrent `POST /scans` requests sharing an `(organization_id, idempotency_key)` serialize via transaction-scoped `pg_advisory_xact_lock`.
   - RabbitMQ topology (`vforge.events` topic exchange, `vforge.dlx` dead-letter exchange, `vforge.orchestration.dispatch` queue, `vforge.orchestration.dlq` queue) strictly obeys `vforge_` naming and `durable=True` constraints enforced by RabbitMQ 4.x and `vforge_app` vhost ACLs, using separate publisher/consumer channels and requeuing transient infrastructure errors while rejecting malformed payloads to DLQ.
   - Consumers enforce idempotency on `RunnerJob.status` inside `FOR UPDATE` row locks so message redelivery never increments `execution_count` or re-executes completed work, and fence completion against `(lease_owner, attempt_count, lease_expires_at > now)` plus atomic `UPDATE ScanTargetLease ... WHERE status = 'active' RETURNING id`.

3. **PostgreSQL Partial Unique Target Leases**
   - `scan_target_leases` enforces mutual exclusion via partial unique index `uq_active_target_lease ON (asset_id, lease_risk_class) WHERE status = 'active'`.
   - Acquiring a lease uses `INSERT ... ON CONFLICT DO NOTHING`; contention schedules a bounded deferral (`retry_scheduled`, `last_error_code = 'target_lease_busy'`) without burning execution retry budget.

4. **Strict Control-Plane Execution Boundary**
   - All Phase 3 jobs run `dummy_orchestration_task` (`simulated=True`, `findings_count=0`). Neither `api` nor `orchestrator` mounts `/var/run/docker.sock`, runs privileged containers, or launches real scanners.

## Consequences

- Cross-tenant data isolation remains cryptographically and structurally enforced at PostgreSQL RLS layer even inside the background worker.
- Outbox durability + idempotent job locking eliminate dual-write anomalies and duplicate job execution on broker redelivery.
- No real scanning occurs until Phase 4 (isolated Runner Agent) and Phases 5–7 (scanner adapters).
