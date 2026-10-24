"""Stage B: sessions, session_id on events and incidents, approval gate, teams

Revision ID: d4f8a2c61e37
Revises: b7c3e1d94f20
Create Date: 2026-10-21 18:00:00

docs/CONTRACTS.md §1 (sessions), §3 (workload_gates, approvals), §6 (workloads.team).

New tables are created plainly. Columns added to existing tables go through batch mode so SQLite
(which cannot ALTER a column in place) rebuilds the table; on PostgreSQL batch mode is a no-op wrapper.
`workloads.team` and the two `session_id` columns carry defaults/NULL so existing rows need no backfill:
a workload with no team is visible to admins and unscoped operators, an incident with no session simply
cannot be revoked by session (the API refuses with 409 rather than guessing).
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'd4f8a2c61e37'
down_revision: Union[str, None] = 'b7c3e1d94f20'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('sessions',
    sa.Column('id', sa.String(length=128), nullable=False),
    sa.Column('workload_id', sa.String(length=128), nullable=False),
    sa.Column('principal', sa.String(length=128), nullable=False),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('revoked_by', sa.String(length=128), nullable=True),
    sa.Column('revoke_reason', sa.Text(), nullable=False),
    sa.Column('labels', sa.JSON(), nullable=False),
    sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['workload_id'], ['workloads.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_sessions_state'), ['state'], unique=False)
        batch_op.create_index(batch_op.f('ix_sessions_workload_id'), ['workload_id'], unique=False)

    op.create_table('workload_gates',
    sa.Column('workload_id', sa.String(length=128), nullable=False),
    sa.Column('risky_tools', sa.JSON(), nullable=False),
    sa.Column('hold_at', sa.String(length=8), nullable=False),
    sa.Column('ttl_s', sa.Integer(), nullable=False),
    sa.Column('updated_by', sa.String(length=128), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['workload_id'], ['workloads.id'], ),
    sa.PrimaryKeyConstraint('workload_id')
    )

    op.create_table('approvals',
    sa.Column('id', sa.String(length=64), nullable=False),
    sa.Column('workload_id', sa.String(length=128), nullable=False),
    sa.Column('session_id', sa.String(length=128), nullable=False),
    sa.Column('tool', sa.String(length=64), nullable=False),
    sa.Column('args_summary', sa.String(length=512), nullable=False),
    sa.Column('tier', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('requested_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('decided_by', sa.String(length=128), nullable=True),
    sa.Column('decided_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('reason', sa.Text(), nullable=False),
    sa.ForeignKeyConstraint(['workload_id'], ['workloads.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_approvals_session_id'), ['session_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_approvals_status'), ['status'], unique=False)
        batch_op.create_index(batch_op.f('ix_approvals_workload_id'), ['workload_id'], unique=False)

    with op.batch_alter_table('workloads', schema=None) as batch_op:
        batch_op.add_column(sa.Column('team', sa.String(length=64), server_default='', nullable=False))

    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.add_column(sa.Column('session_id', sa.String(length=128), nullable=True))
        batch_op.create_index(batch_op.f('ix_events_session_id'), ['session_id'], unique=False)

    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('session_id', sa.String(length=128), nullable=True))
        batch_op.create_index(batch_op.f('ix_incidents_session_id'), ['session_id'], unique=False)


def downgrade() -> None:
    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_incidents_session_id'))
        batch_op.drop_column('session_id')

    with op.batch_alter_table('events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_events_session_id'))
        batch_op.drop_column('session_id')

    with op.batch_alter_table('workloads', schema=None) as batch_op:
        batch_op.drop_column('team')

    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_approvals_workload_id'))
        batch_op.drop_index(batch_op.f('ix_approvals_status'))
        batch_op.drop_index(batch_op.f('ix_approvals_session_id'))
    op.drop_table('approvals')
    op.drop_table('workload_gates')
    with op.batch_alter_table('sessions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_sessions_workload_id'))
        batch_op.drop_index(batch_op.f('ix_sessions_state'))
    op.drop_table('sessions')
