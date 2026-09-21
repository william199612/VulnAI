from sqlalchemy import Integer, String, DateTime, func
from sqlalchemy.orm import Mapped, mapped_column
from data_pipeline.shared.db import Base


class CVENews(Base):
    __tablename__ = "cve_news"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String)
    source_domain: Mapped[str] = mapped_column(String)
    published_at: Mapped[DateTime] = mapped_column(DateTime(timezone=True))
    content: Mapped[str] = mapped_column(String)
    crawl_method: Mapped[str] = mapped_column(String)
    fetched_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
    updated_at: Mapped[DateTime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
    )
