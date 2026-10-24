"""agent log ids are unique per workload: widen agent_log.id for "<workload_id>:<client_id>" keys

Revision ID: b7c3e1d94f20
Revises: a41c9d2e7b10
Create Date: 2026-10-21 10:00:00

Before this, a log id already stored for workload A made the same id from workload B a silent
no-op. The API now keys client-supplied ids as "<workload_id>:<id>" (Ident is up to 128 chars each),
which needs 257 characters. Existing rows keep their bare ids: they stay unique and are returned
as-is, and a re-send of one of them under the new key is stored as a separate entry once.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b7c3e1d94f20'
down_revision: Union[str, None] = 'a41c9d2e7b10'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table('agent_log', schema=None) as batch_op:
        batch_op.alter_column('id', existing_type=sa.String(length=64), type_=sa.String(length=257),
                              existing_nullable=False)


def downgrade() -> None:
    # Rows with a composite key longer than 64 characters would be truncated by this; delete them
    # first so the old width holds (the log is an advisory input, never the system of record).
    op.execute(sa.text("DELETE FROM agent_log WHERE LENGTH(id) > 64"))
    with op.batch_alter_table('agent_log', schema=None) as batch_op:
        batch_op.alter_column('id', existing_type=sa.String(length=257), type_=sa.String(length=64),
                              existing_nullable=False)
