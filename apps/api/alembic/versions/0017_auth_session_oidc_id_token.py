"""Add nullable oidc_id_token column on auth_sessions for OIDC RP-initiated logout."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0017_auth_session_oidc_id_token"
down_revision: str | None = "0016_phase15_ai_redteam"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("auth_sessions", sa.Column("oidc_id_token", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("auth_sessions", "oidc_id_token")
