"""add login protection fields

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-06-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('failed_login_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('last_login_ip', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('last_login_time', sa.DateTime(), nullable=True))

    with op.batch_alter_table('admin', schema=None) as batch_op:
        batch_op.add_column(sa.Column('failed_login_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('locked_until', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('last_login_ip', sa.String(length=100), nullable=True))
        batch_op.add_column(sa.Column('last_login_time', sa.DateTime(), nullable=True))


def downgrade():
    with op.batch_alter_table('admin', schema=None) as batch_op:
        batch_op.drop_column('last_login_time')
        batch_op.drop_column('last_login_ip')
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_count')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('last_login_time')
        batch_op.drop_column('last_login_ip')
        batch_op.drop_column('locked_until')
        batch_op.drop_column('failed_login_count')
