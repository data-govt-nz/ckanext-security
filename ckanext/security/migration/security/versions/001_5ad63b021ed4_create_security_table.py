"""empty message

Revision ID: 5ad63b021ed4
Revises: 
Create Date: 2025-01-24 18:36:01.318092

"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "5ad63b021ed4"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    engine = op.get_bind()
    inspector = sa.inspect(engine)
    tables = inspector.get_table_names()
    if "user_security_totp" not in tables:
        op.create_table(
            "user_security_totp",
            sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
            sa.Column("user_id", sa.UnicodeText, default=""),
            sa.Column("secret", sa.UnicodeText, default=""),
            sa.Column("last_successful_challenge", sa.DateTime),
        )


def downgrade():
    op.drop_table("user_security_totp")
