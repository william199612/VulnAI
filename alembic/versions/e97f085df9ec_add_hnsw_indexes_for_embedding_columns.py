"""add hnsw indexes for embedding columns

Revision ID: e97f085df9ec
Revises: 62e7f27319ee
Create Date: 2026-10-05 18:09:37.230153

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "e97f085df9ec"
down_revision: Union[str, Sequence[str], None] = "62e7f27319ee"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        "CREATE INDEX ix_cve_embedding_hnsw ON cve "
        "USING hnsw (embedding vector_cosine_ops)"
    )
    op.execute(
        "CREATE INDEX ix_cve_news_embedding_hnsw ON cve_news "
        "USING hnsw (embedding vector_cosine_ops)"
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_cve_embedding_hnsw")
    op.execute("DROP INDEX IF EXISTS ix_cve_news_embedding_hnsw")
