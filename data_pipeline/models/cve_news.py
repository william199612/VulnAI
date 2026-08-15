from sqlalchemy import Column, Integer, String, DateTime, func
from data_pipeline.shared.db import Base


class CVENews(Base):
    __tablename__ = "cve_news"

    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False)
    title = Column(String)
    source_domain = Column(String)
    published_at = Column(DateTime(timezone=True))
    content = Column(String)
    crawl_method = Column(String)  # 'static' or 'dynamic'
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
