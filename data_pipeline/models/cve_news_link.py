from sqlalchemy import Column, Integer, String, ForeignKey
from data_pipeline.shared.db import Base


class CVENewsLink(Base):
    __tablename__ = "cve_news_link"

    cve_news_id = Column(Integer, ForeignKey("cve_news.id"), primary_key=True)
    cve_id = Column(String, ForeignKey("cve.cve_id"), primary_key=True)
