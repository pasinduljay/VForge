"""Network egress policy enforcement and pinned DNS/redirect proxy."""

from vforge_runner.network_policy.egress_gateway import (
    EgressBlockedError,
    ScopedEgressGateway,
    build_scope_definition_from_manifest,
)

__all__ = [
    "EgressBlockedError",
    "ScopedEgressGateway",
    "build_scope_definition_from_manifest",
]
