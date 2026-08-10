# migrations/versions/xxxx_add_evidence_tables.py
"""Add evidence tables

Revision ID: xxxx
Revises: previous_revision
Create Date: 2026-08-10 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

# revision identifiers, used by Alembic.
revision = 'xxxx'  # Replace with the generated ID
down_revision = None  # Replace with your last migration or None
branch_labels = None
depends_on = None


def upgrade():
    # Create evidence_artifacts table
    op.create_table(
        'evidence_artifacts',
        sa.Column('id', UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), primary_key=True),
        sa.Column('incident_id', UUID(as_uuid=True), nullable=False),
        sa.Column('artifact_type', sa.String(50), nullable=False),
        sa.Column('source', sa.String(50), nullable=False),
        sa.Column('provider', sa.String(20), server_default='aws'),
        sa.Column('region', sa.String(50)),
        sa.Column('collector', sa.String(100), nullable=False),
        sa.Column('collected_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('content', JSONB, nullable=False),
        sa.Column('metadata', JSONB),
        sa.Column('hash', sa.String(128)),
        sa.Column('hash_algorithm', sa.String(20), server_default='SHA-256'),
        sa.Column('collection_status', sa.String(20), server_default='PENDING'),
        sa.Column('error_message', sa.Text),
        sa.Column('integrity_verified', sa.Boolean, server_default='false'),
        sa.Column('verified_at', sa.DateTime),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # Create evidence_playbooks table
    op.create_table(
        'evidence_playbooks',
        sa.Column('id', UUID(as_uuid=True), server_default=sa.text('gen_random_uuid()'), primary_key=True),
        sa.Column('name', sa.String(100), nullable=False, unique=True),
        sa.Column('description', sa.Text),
        sa.Column('trigger_events', JSONB, nullable=False),
        sa.Column('evidence_required', JSONB, nullable=False),
        sa.Column('enabled', sa.Boolean, server_default='true'),
        sa.Column('version', sa.String(10), server_default='1.0.0'),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime, server_default=sa.func.now(), onupdate=sa.func.now()),
    )
    
    # Add foreign key
    op.create_foreign_key(
        'fk_evidence_incident',
        'evidence_artifacts',
        'incidents',
        ['incident_id'],
        ['id'],
        ondelete='CASCADE'
    )
    
    # Add indexes
    op.create_index('idx_evidence_incident_id', 'evidence_artifacts', ['incident_id'])
    op.create_index('idx_evidence_type', 'evidence_artifacts', ['artifact_type'])
    op.create_index('idx_evidence_status', 'evidence_artifacts', ['collection_status'])
    op.create_index('idx_playbook_name', 'evidence_playbooks', ['name'])
    op.create_index('idx_playbook_enabled', 'evidence_playbooks', ['enabled'])


def downgrade():
    op.drop_table('evidence_artifacts')
    op.drop_table('evidence_playbooks')