from sqlalchemy import Column, String, Numeric, DateTime, JSON, ARRAY, func
from data_pipeline.shared.db import Base


class CVE(Base):
    __tablename__ = "cve"

    cve_id = Column(String, primary_key=True)
    description = Column(String)
    cvss_score = Column(Numeric)
    cvss_vector = Column(String)
    cwe = Column(String)
    affected_products = Column(ARRAY(String))
    published_date = Column(DateTime(timezone=True))
    modified_date = Column(DateTime(timezone=True))
    source = Column(String, default="NVD")
    raw_references = Column(JSON)
    fetched_at = Column(DateTime(timezone=True), server_default=func.now())
