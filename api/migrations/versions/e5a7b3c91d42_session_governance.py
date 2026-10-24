"""Session governance: tool_call_id on the agent log, approvals per the 22 Oct contract, revoke target on actions

Revision ID: e5a7b3c91d42
Revises: d4f8a2c61e37
Create Date: 2026-10-22 09:00:00

CONTRACTS.md (22 Oct build wave) §1-3.

- `agent_log.tool_call_id`: the gateway's id for one tool call; "" for everything already stored.
- `approvals` takes the contract's vocabulary. Columns are renamed rather than re-created so the holds
  already recorded keep their ids (a gateway may still be polling one): `args_summary` -> `summary`,
  `tier` -> `tier_at_request`, `reason` -> `decision_reason`. New: `tool_call_id`, `risk` (existing holds
  were raised because the tool was on the risky list, so "risky"), `requested_by` ("" = unknown; before
  this the requester was only in the audit log). Status `approved` becomes `allowed`.
- `operator_actions.session_id`: which session a `revoke` request targets.

Column changes go through batch mode so SQLite rebuilds the table; on PostgreSQL it is a plain ALTER.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'e5a7b3c91d42'
down_revision: Union[str, None] = 'd4f8a2c61e37'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('agent_log', schema=None) as batch_op:
        batch_op.add_column(sa.Column('tool_call_id', sa.String(length=128), server_default='', nullable=False))

    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.alter_column('args_summary', new_column_name='summary', existing_type=sa.String(length=512),
                              existing_nullable=False)
        batch_op.alter_column('tier', new_column_name='tier_at_request', existing_type=sa.String(length=16),
                              existing_nullable=False)
        batch_op.alter_column('reason', new_column_name='decision_reason', existing_type=sa.Text(),
                              existing_nullable=False)
        batch_op.add_column(sa.Column('tool_call_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('risk', sa.String(length=8), server_default='risky', nullable=False))
        batch_op.add_column(sa.Column('requested_by', sa.String(length=128), server_default='', nullable=False))
    op.execute(sa.text("UPDATE approvals SET status = 'allowed' WHERE status = 'approved'"))

    with op.batch_alter_table('operator_actions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('session_id', sa.String(length=128), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('operator_actions', schema=None) as batch_op:
        batch_op.drop_column('session_id')

    op.execute(sa.text("UPDATE approvals SET status = 'approved' WHERE status = 'allowed'"))
    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.drop_column('requested_by')
        batch_op.drop_column('risk')
        batch_op.drop_column('tool_call_id')
        batch_op.alter_column('decision_reason', new_column_name='reason', existing_type=sa.Text(),
                              existing_nullable=False)
        batch_op.alter_column('tier_at_request', new_column_name='tier', existing_type=sa.String(length=16),
                              existing_nullable=False)
        batch_op.alter_column('summary', new_column_name='args_summary', existing_type=sa.String(length=512),
                              existing_nullable=False)

    with op.batch_alter_table('agent_log', schema=None) as batch_op:
        batch_op.drop_column('tool_call_id')
