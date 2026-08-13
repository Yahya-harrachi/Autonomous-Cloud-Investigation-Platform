"""Fix tags column to ARRAY

Revision ID: 32aa4f0bfb5e
Revises: xxxx
Create Date: 2026-08-13 13:51:04.481927

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '32aa4f0bfb5e'
down_revision: Union[str, Sequence[str], None] = 'xxxx'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    pass


def downgrade() -> None:
    """Downgrade schema."""
    pass
