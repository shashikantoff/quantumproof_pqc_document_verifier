"""Persist admin login rate-limit buckets.

Revision ID: 0002_login_rate_limits
Revises: 0001_initial
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_login_rate_limits"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_rate_limits",
        sa.Column("bucket_key", sa.String(length=64), nullable=False),
        sa.Column("window_started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint("bucket_key"),
    )


def downgrade() -> None:
    op.drop_table("login_rate_limits")
