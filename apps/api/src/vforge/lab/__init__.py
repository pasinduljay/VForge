"""Phase 13 Isolated Learning Lab & Self-Scan package."""

from vforge.lab.safety import (
    ALLOWED_SAFE_VALIDATION_ACTIONS,
    FORBIDDEN_EXPLOITATION_MODES,
    evaluate_lab_action_with_opa,
    validate_lab_target_url,
    validate_safe_action_and_tool,
    verify_lab_compose_isolation,
)
from vforge.lab.service import (
    get_lab_overview,
    list_challenges,
    provision_lab_workspace,
    record_challenge_remediation,
    reset_lab_workspace,
    run_vforge_self_scan,
    update_lab_consent,
    validate_challenge_safely,
)

__all__ = [
    "ALLOWED_SAFE_VALIDATION_ACTIONS",
    "FORBIDDEN_EXPLOITATION_MODES",
    "evaluate_lab_action_with_opa",
    "get_lab_overview",
    "list_challenges",
    "provision_lab_workspace",
    "record_challenge_remediation",
    "reset_lab_workspace",
    "run_vforge_self_scan",
    "update_lab_consent",
    "validate_challenge_safely",
    "validate_lab_target_url",
    "validate_safe_action_and_tool",
    "verify_lab_compose_isolation",
]
