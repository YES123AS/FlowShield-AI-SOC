"""add security incident model

Revision ID: d4e5f6a7b8c9
Revises: c1f2a3b4d5e6
Create Date: 2026-06-12 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4e5f6a7b8c9'
down_revision = 'c1f2a3b4d5e6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'security_incident',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('traffic_id', sa.Integer(), nullable=True),
        sa.Column('incident_no', sa.String(length=100), nullable=False),
        sa.Column('title', sa.String(length=255), nullable=False),
        sa.Column('attack_type', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=50), nullable=False),
        sa.Column('risk_score', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=True),
        sa.Column('summary', sa.Text(), nullable=True),
        sa.Column('cause_analysis', sa.Text(), nullable=True),
        sa.Column('impact_analysis', sa.Text(), nullable=True),
        sa.Column('attack_chain', sa.Text(), nullable=True),
        sa.Column('recommendations', sa.Text(), nullable=True),
        sa.Column('evidence_json', sa.Text(), nullable=True),
        sa.Column('ai_report', sa.Text(), nullable=True),
        sa.Column('llm_used', sa.Boolean(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['traffic_id'], ['traffic_results.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('incident_no')
    )


def downgrade():
    op.drop_table('security_incident')
