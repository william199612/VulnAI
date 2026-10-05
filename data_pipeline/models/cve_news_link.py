from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from data_pipeline.shared.db import Base


class CVENewsLink(Base):
    __tablename__ = "cve_news_link"

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
