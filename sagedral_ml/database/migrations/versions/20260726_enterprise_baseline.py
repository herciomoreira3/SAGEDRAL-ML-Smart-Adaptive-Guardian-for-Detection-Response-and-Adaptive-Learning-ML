"""Enterprise schema baseline.

Revision ID: 20260726_enterprise
Revises:
"""

from alembic import op

revision = "20260726_enterprise"
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # Idempotent baseline for both a fresh database and an existing v1 schema.
    from sagedral_ml.database.connection import Base
    import sagedral_ml.database.models  # noqa: F401

    Base.metadata.create_all(bind=op.get_bind())


def downgrade():
    # A security/audit database is never destructively downgraded implicitly.
    pass
