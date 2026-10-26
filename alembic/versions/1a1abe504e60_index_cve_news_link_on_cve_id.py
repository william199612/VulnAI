"""index cve_news_link on cve_id

Revision ID: 1a1abe504e60
Revises: 8286516a26c8
Create Date: 2026-10-26 15:46:14.632766

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "1a1abe504e60"
down_revision: Union[str, Sequence[str], None] = "8286516a26c8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index("ix_cve_news_link_cve_id", "cve_news_link", ["cve_id"])


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_cve_news_link_cve_id", table_name="cve_news_link")
