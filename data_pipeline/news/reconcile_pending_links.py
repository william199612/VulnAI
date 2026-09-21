import time
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from data_pipeline.shared.db import SessionLocal
from data_pipeline.models import CVENewsLink
from data_pipeline.nvd_sync.client import fetch_cve_by_id
from data_pipeline.nvd_sync.sync import _upsert_batch


def reconcile_pending_links(max_fetches_per_run=100):
    session = SessionLocal()
    try:
        pending_cve_ids = (
            session.execute(
                text("""
            SELECT DISTINCT cve_id FROM pending_cve_news_link LIMIT :limit
        """),
                {"limit": max_fetches_per_run},
            )
            .scalars()
            .all()
        )

        resolved_count = 0
        for cve_id in pending_cve_ids:
            data = fetch_cve_by_id(cve_id)
            time.sleep(0.7)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                continue  # still not published in NVD — leave pending, retry next run

            _upsert_batch(session, vulns)  # now exists in `cve`, satisfies the FK

            affected_news_ids = (
                session.execute(
                    text("""
                SELECT cve_news_id FROM pending_cve_news_link WHERE cve_id = :cid
            """),
                    {"cid": cve_id},
                )
                .scalars()
                .all()
            )

            for news_id in affected_news_ids:
                link_stmt = (
                    pg_insert(CVENewsLink)
                    .values(cve_news_id=news_id, cve_id=cve_id)
                    .on_conflict_do_nothing()
                )
                session.execute(link_stmt)

            session.execute(
                text("""
                DELETE FROM pending_cve_news_link WHERE cve_id = :cid
            """),
                {"cid": cve_id},
            )

            resolved_count += 1

        session.commit()
        print(f"Reconciliation: {resolved_count}/{len(pending_cve_ids)} CVEs resolved")
    finally:
        session.close()


if __name__ == "__main__":
    reconcile_pending_links()
