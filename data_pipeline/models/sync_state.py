from sqlalchemy import Column, String, DateTime

from data_pipeline.shared.db import Base


class SyncState(Base):
    __tablename__ = "sync_state"

    source = Column(String, primary_key=True)  # e.g. "nvd"
    last_synced_at = Column(DateTime(timezone=True))
