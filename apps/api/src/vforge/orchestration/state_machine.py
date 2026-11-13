"""Validated state machine transitions for scan runs, stages, and runner jobs."""

from __future__ import annotations

from vforge.errors import ConflictError
from vforge.models.enums import RunnerJobStatus, ScanRunStatus, ScanStageStatus

RUN_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        ScanRunStatus.COMPLETED.value,
        ScanRunStatus.COMPLETED_WITH_ERRORS.value,
        ScanRunStatus.PARTIAL.value,
        ScanRunStatus.FAILED.value,
        ScanRunStatus.REJECTED.value,
        ScanRunStatus.CANCELLED.value,
    }
)

STAGE_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        ScanStageStatus.COMPLETED.value,
        ScanStageStatus.FAILED.value,
        ScanStageStatus.SKIPPED.value,
        ScanStageStatus.CANCELLED.value,
    }
)

JOB_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        RunnerJobStatus.COMPLETED.value,
        RunnerJobStatus.FAILED.value,
        RunnerJobStatus.TIMED_OUT.value,
        RunnerJobStatus.CANCELLED.value,
        RunnerJobStatus.ABANDONED.value,
    }
)

_RUN_TRANSITIONS: dict[str, frozenset[str]] = {
    ScanRunStatus.DRAFT.value: frozenset(
        {
            ScanRunStatus.SCOPE_VALIDATION.value,
            ScanRunStatus.REJECTED.value,
            ScanRunStatus.CANCELLED.value,
        }
    ),
    ScanRunStatus.SCOPE_VALIDATION.value: frozenset(
        {
            ScanRunStatus.AWAITING_APPROVAL.value,
            ScanRunStatus.QUEUED.value,
            ScanRunStatus.REJECTED.value,
            ScanRunStatus.CANCELLED.value,
        }
    ),
    ScanRunStatus.AWAITING_APPROVAL.value: frozenset(
        {
            ScanRunStatus.QUEUED.value,
            ScanRunStatus.REJECTED.value,
            ScanRunStatus.CANCELLED.value,
        }
    ),
    ScanRunStatus.QUEUED.value: frozenset(
        {
            ScanRunStatus.PROVISIONING.value,
            ScanRunStatus.RUNNING.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.CANCELLED.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.PROVISIONING.value: frozenset(
        {
            ScanRunStatus.RUNNING.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.RUNNING.value: frozenset(
        {
            ScanRunStatus.COLLECTING.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.COMPLETED.value,
            ScanRunStatus.COMPLETED_WITH_ERRORS.value,
            ScanRunStatus.PARTIAL.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.COLLECTING.value: frozenset(
        {
            ScanRunStatus.NORMALIZING.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.COMPLETED_WITH_ERRORS.value,
            ScanRunStatus.PARTIAL.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.NORMALIZING.value: frozenset(
        {
            ScanRunStatus.CORRELATING.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.PARTIAL.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.CORRELATING.value: frozenset(
        {
            ScanRunStatus.REPORTING.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.PARTIAL.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.REPORTING.value: frozenset(
        {
            ScanRunStatus.COMPLETED.value,
            ScanRunStatus.COMPLETED_WITH_ERRORS.value,
            ScanRunStatus.PARTIAL.value,
            ScanRunStatus.CANCELLING.value,
            ScanRunStatus.FAILED.value,
        }
    ),
    ScanRunStatus.CANCELLING.value: frozenset(
        {
            ScanRunStatus.CANCELLED.value,
        }
    ),
}

_STAGE_TRANSITIONS: dict[str, frozenset[str]] = {
    ScanStageStatus.PENDING.value: frozenset(
        {
            ScanStageStatus.QUEUED.value,
            ScanStageStatus.RUNNING.value,
            ScanStageStatus.SKIPPED.value,
            ScanStageStatus.CANCELLED.value,
        }
    ),
    ScanStageStatus.QUEUED.value: frozenset(
        {
            ScanStageStatus.RUNNING.value,
            ScanStageStatus.FAILED.value,
            ScanStageStatus.SKIPPED.value,
            ScanStageStatus.CANCELLED.value,
        }
    ),
    ScanStageStatus.RUNNING.value: frozenset(
        {
            ScanStageStatus.COMPLETED.value,
            ScanStageStatus.FAILED.value,
            ScanStageStatus.CANCELLED.value,
        }
    ),
}

_JOB_TRANSITIONS: dict[str, frozenset[str]] = {
    RunnerJobStatus.PENDING.value: frozenset(
        {
            RunnerJobStatus.DISPATCHED.value,
            RunnerJobStatus.FAILED.value,
            RunnerJobStatus.CANCELLED.value,
        }
    ),
    RunnerJobStatus.DISPATCHED.value: frozenset(
        {
            RunnerJobStatus.LEASED.value,
            RunnerJobStatus.RETRY_SCHEDULED.value,
            RunnerJobStatus.FAILED.value,
            RunnerJobStatus.TIMED_OUT.value,
            RunnerJobStatus.ABANDONED.value,
            RunnerJobStatus.CANCELLED.value,
        }
    ),
    RunnerJobStatus.LEASED.value: frozenset(
        {
            RunnerJobStatus.RUNNING.value,
            RunnerJobStatus.RETRY_SCHEDULED.value,
            RunnerJobStatus.TIMED_OUT.value,
            RunnerJobStatus.ABANDONED.value,
            RunnerJobStatus.CANCELLED.value,
        }
    ),
    RunnerJobStatus.RUNNING.value: frozenset(
        {
            RunnerJobStatus.COMPLETED.value,
            RunnerJobStatus.RETRY_SCHEDULED.value,
            RunnerJobStatus.FAILED.value,
            RunnerJobStatus.TIMED_OUT.value,
            RunnerJobStatus.ABANDONED.value,
            RunnerJobStatus.CANCELLED.value,
        }
    ),
    RunnerJobStatus.RETRY_SCHEDULED.value: frozenset(
        {
            RunnerJobStatus.PENDING.value,
            RunnerJobStatus.DISPATCHED.value,
            RunnerJobStatus.LEASED.value,
            RunnerJobStatus.FAILED.value,
            RunnerJobStatus.TIMED_OUT.value,
            RunnerJobStatus.CANCELLED.value,
        }
    ),
}


def validate_run_transition(current: str, target: str) -> str:
    """Validate and return a legal scan-run status transition."""
    if current == target:
        return target
    allowed = _RUN_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise ConflictError(f"Illegal scan run status transition: {current} -> {target}")
    return target


def validate_stage_transition(current: str, target: str) -> str:
    """Validate and return a legal scan-stage status transition."""
    if current == target:
        return target
    allowed = _STAGE_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise ConflictError(f"Illegal scan stage status transition: {current} -> {target}")
    return target


def validate_job_transition(current: str, target: str) -> str:
    """Validate and return a legal runner-job status transition."""
    if current == target:
        return target
    allowed = _JOB_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise ConflictError(f"Illegal runner job status transition: {current} -> {target}")
    return target
