from decimal import Decimal
from datetime import datetime

import sqlalchemy as sa
from sqlalchemy import ARRAY, DateTime, JSON, Numeric, String, func, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from pgvector.sqlalchemy import Vector

from data_pipeline.shared.db import Base


class CVE(Base):
    __tablename__ = "cve"

    cve_id: Mapped[str] = mapped_column(String, primary_key=True)
    description: Mapped[str | None] = mapped_column(String)
    cvss_score: Mapped[Decimal | None] = mapped_column(Numeric)
    cvss_vector: Mapped[str | None] = mapped_column(String)
    cwe: Mapped[str | None] = mapped_column(String)
    affected_products: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    published_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    source: Mapped[str | None] = mapped_column(String, default="NVD")
    raw_references: Mapped[dict | None] = mapped_column(JSON)
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    embedding: Mapped[list[float] | None] = mapped_column(Vector(1536))

    is_kev: Mapped[bool] = mapped_column(
        Boolean, server_default=sa.false(), default=False
    )
    kev_date_added: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    kev_ransomware: Mapped[bool | None] = mapped_column(Boolean)
