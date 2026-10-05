import time

from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from data_pipeline.models import CVE, CVENewsLink, PendingCVENewsLink
from data_pipeline.nvd_sync.client import fetch_cve_by_id
from data_pipeline.nvd_sync.sync import _upsert_batch
from data_pipeline.shared.db import SessionLocal
from data_pipeline.shared.logging import get_logger

logger = get_logger("reconcile_pending_links", "reconcile_pending_links.log")


def _move_links(session, cve_id: str):
    """Promote every pending (article, cve_id) pair into cve_news_link."""
    news_ids = session.scalars(
        select(PendingCVENewsLink.cve_news_id).where(
            PendingCVENewsLink.cve_id == cve_id
        )
    ).all()

    for news_id in news_ids:
        session.execute(
            pg_insert(CVENewsLink)
            .values(cve_news_id=news_id, cve_id=cve_id)
            .on_conflict_do_nothing()
        )

    session.execute(
        delete(PendingCVENewsLink).where(PendingCVENewsLink.cve_id == cve_id)
    )


def reconcile_pending_links(batch_size: int = 100):
    session = SessionLocal()
    fetched = 0
    resolved = 0
    still_pending = 0

    try:
        # random order so CVEs NVD never publishes can't permanently
        # occupy the batch and starve newer pending ones
        pending_ids = session.scalars(
            select(PendingCVENewsLink.cve_id)
            .group_by(PendingCVENewsLink.cve_id)
            .order_by(func.random())
            .limit(batch_size)
        ).all()

        for cve_id in pending_ids:
            try:
                # nvd_sync may already have picked this CVE up; only call NVD if we truly lack it
                if session.get(CVE, cve_id) is None:
                    data = fetch_cve_by_id(cve_id)
                    fetched += 1
                    time.sleep(0.7)  # stay under NVD's rate limit

                    vulns = data.get("vulnerabilities", [])
                    if not vulns:
                        still_pending += (
                            1  # NVD hasn't published it yet, retry next run
                        )
                        continue

                    _upsert_batch(session, vulns)  # commits internally

                _move_links(session, cve_id)
                session.commit()
                resolved += 1

            except Exception as e:
                session.rollback()
                still_pending += 1
                logger.warning(f"Skipping {cve_id}, reconcile failed: {e}")

        logger.info(
            f"Reconciliation: {resolved}/{len(pending_ids)} resolved, "
            f"{still_pending} still pending, {fetched} NVD fetches"
        )
    finally:
        session.close()


if __name__ == "__main__":
    reconcile_pending_links()
