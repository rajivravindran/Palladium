"""early warning: agent log intake and drift tiers

Revision ID: a41c9d2e7b10
Revises: cce76aa444fa
Create Date: 2026-10-20 12:00:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a41c9d2e7b10'
down_revision: Union[str, None] = 'cce76aa444fa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('agent_log',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('workload_id', sa.String(length=128), nullable=False),
    sa.Column('session', sa.String(length=128), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('tool', sa.String(length=128), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('target', sa.String(length=512), nullable=False),
    sa.Column('text', sa.Text(), nullable=False),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('agent_log', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_agent_log_workload_id'), ['workload_id'], unique=False)

    op.create_table('drift_state',
    sa.Column('workload_id', sa.String(length=128), nullable=False),
    sa.Column('tier', sa.String(length=16), nullable=False),
    sa.Column('previous_tier', sa.String(length=16), nullable=True),
    sa.Column('trend', sa.String(length=8), nullable=False),
    sa.Column('reasons', sa.JSON(), nullable=False),
    sa.Column('features', sa.JSON(), nullable=False),
    sa.Column('model', sa.JSON(), nullable=False),
    sa.Column('computed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('changed_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('workload_id')
    )

    op.create_table('drift_history',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('workload_id', sa.String(length=128), nullable=False),
    sa.Column('tier', sa.String(length=16), nullable=False),
    sa.Column('at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('summary', sa.String(length=512), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('drift_history', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_drift_history_workload_id'), ['workload_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('drift_history', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_drift_history_workload_id'))
    op.drop_table('drift_history')
    op.drop_table('drift_state')
    with op.batch_alter_table('agent_log', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_agent_log_workload_id'))
    op.drop_table('agent_log')
