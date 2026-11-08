from sqlalchemy import ForeignKey, Integer, String, Index
from sqlalchemy.orm import Mapped, mapped_column

from data_pipeline.shared.db import Base


class CVENewsLink(Base):
    __tablename__ = "cve_news_link"
    __table_args__ = (Index("ix_cve_news_link_cve_id", "cve_id"),)

    cve_news_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("cve_news.id"),
        primary_key=True,
    )

    cve_id: Mapped[str] = mapped_column(
        String,
        ForeignKey("cve.cve_id"),
        primary_key=True,
    )
