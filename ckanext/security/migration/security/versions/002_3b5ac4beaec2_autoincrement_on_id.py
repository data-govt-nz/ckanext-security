"""Autoincrement on ID

Revision ID: 3b5ac4beaec2
Revises: 5ad63b021ed4
Create Date: 2025-01-28 19:30:03.491176

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '3b5ac4beaec2'
down_revision = '5ad63b021ed4'
branch_labels = None
depends_on = None


def upgrade():
    # change text to integer
    op.alter_column('user_security_totp', 'id', type_=sa.Integer)
    op.alter_column('user_security_totp', 'id', autoincrement=True)


def downgrade():
    op.alter_column('user_security_totp', 'id', autoincrement=False)
    op.alter_column('user_security_totp', 'id', type_=sa.UnicodeText)
