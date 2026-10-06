"""add traffic risk fields

Revision ID: c1f2a3b4d5e6
Revises: 28beb33b0616
Create Date: 2026-06-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1f2a3b4d5e6'
down_revision = '28beb33b0616'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('traffic_results', schema=None) as batch_op:
        batch_op.add_column(sa.Column('malicious_ratio', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('risk_score', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('severity', sa.String(length=50), nullable=True))
        batch_op.add_column(sa.Column('confidence', sa.Float(), nullable=True))
        batch_op.add_column(sa.Column('evidence_json', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('traffic_results', schema=None) as batch_op:
        batch_op.drop_column('evidence_json')
        batch_op.drop_column('confidence')
        batch_op.drop_column('severity')
        batch_op.drop_column('risk_score')
        batch_op.drop_column('malicious_ratio')
