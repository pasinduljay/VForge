"""Phase 0 foundation schema

Revision ID: 0001_phase0_foundation
Revises:
Create Date: 2026-11-12 08:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001_phase0_foundation"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto;")
    op.create_table(
        "platform_metadata",
        sa.Column("id", sa.Integer(), primary_key=True, nullable=False),
        sa.Column("phase", sa.String(length=32), nullable=False),
        sa.Column("architecture_version", sa.String(length=32), nullable=False),
        sa.Column(
            "initialized_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def downgrade() -> None:
    op.drop_table("platform_metadata")
