"""add kev columns

Revision ID: 8286516a26c8
Revises: e97f085df9ec
Create Date: 2026-10-24 17:16:58.318178

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "8286516a26c8"
down_revision: Union[str, Sequence[str], None] = "e97f085df9ec"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "cve",
        sa.Column("is_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "cve", sa.Column("kev_date_added", sa.DateTime(timezone=True), nullable=True)
    )
    op.add_column("cve", sa.Column("kev_ransomware", sa.Boolean(), nullable=True))
    op.create_index("ix_cve_is_kev", "cve", ["is_kev"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_cve_is_kev", table_name="cve")
    op.drop_column("cve", "kev_ransomware")
    op.drop_column("cve", "kev_date_added")
    op.drop_column("cve", "is_kev")
