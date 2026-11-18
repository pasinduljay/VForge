"""Normalize AI model catalog entries to vendor-neutral provider classes and slugs."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0018_clean_ai_model_catalog"
down_revision: str | None = "0017_auth_session_oidc_id_token"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Normalize the three deterministic Phase 12 catalog entries by UUID PK so both
    # fresh and previously seeded databases stay strictly vendor-neutral.
    op.execute(
        sa.text(
            """
            UPDATE ai_model_catalog
            SET provider_class = 'managed_zdr',
                model_slug = 'managed-fast-v1',
                display_name = 'Managed Cloud ZDR Fast v1'
            WHERE id = '12000000-0000-0000-0000-000000000001'::uuid
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE ai_model_catalog
            SET provider_class = 'managed_zdr',
                model_slug = 'managed-reasoning-v2',
                display_name = 'Managed Cloud ZDR Reasoning v2'
            WHERE id = '12000000-0000-0000-0000-000000000002'::uuid
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE ai_model_catalog
            SET provider_class = 'managed_retained',
                model_slug = 'enterprise-30d-v1',
                display_name = 'Enterprise Cloud 30d Retained v1'
            WHERE id = '12000000-0000-0000-0000-000000000003'::uuid
            """
        )
    )


def downgrade() -> None:
    # Intentionally a no-op to preserve normalized vendor-neutral catalog metadata.
    pass
