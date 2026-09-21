from sqlalchemy import String, Integer, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from data_pipeline.shared.db import Base


class PendingCVENewsLink(Base):
    __tablename__ = "pending_cve_news_link"

    cve_news_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("cve_news.id"), primary_key=True
    )
    cve_id: Mapped[str] = mapped_column(
        String, primary_key=True
    )  # no FK — CVE may not exist yet

    __table_args__ = (Index("ix_pending_cve_news_link_cve_id", "cve_id"),)
