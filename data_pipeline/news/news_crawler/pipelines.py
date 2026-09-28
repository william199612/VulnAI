from urllib.parse import urlparse
from sqlalchemy import delete, func, or_, select
from sqlalchemy.dialects.postgresql import insert

from data_pipeline.shared.db import SessionLocal
from data_pipeline.models import CVENews, CVENewsLink, CVE, PendingCVENewsLink


class CveNewsPipeline:
    def open_spider(self, spider):
        self.session = SessionLocal()

    def close_spider(self, spider):
        self.session.close()

    def process_item(self, item, spider):

        try:
            news_id = self._upsert_news(item)
            self._link_cves(news_id, item.get("cve_ids", []), spider)
            self.session.commit()
        except Exception:
            # a failed statement leaves the session unusable until rolled back,
            # so reset it before Scrapy moves on to the next item
            self.session.rollback()
            raise
        return item

    def _upsert_news(self, item) -> int:
        stmt = insert(CVENews).values(
            url=item["url"],
            title=item.get("title"),
            source_domain=item.get("source_domain") or urlparse(item["url"]).netloc,
            published_at=item.get("pub_date"),
            content=item.get("content"),
            crawl_method=item.get("crawl_method"),
        )
        stmt = stmt.on_conflict_do_update(
            index_elements=["url"],
            set_={
                "content": stmt.excluded.content,
                "title": stmt.excluded.title,
                "updated_at": func.now(),
            },
            # only touch the row (and updated_at) if something actually changed
            where=or_(
                CVENews.content.is_distinct_from(stmt.excluded.content),
                CVENews.title.is_distinct_from(stmt.excluded.title),
            ),
        ).returning(CVENews.id)

        news_id = self.session.execute(stmt).scalar()

        if news_id is None:
            # conflict happened but the WHERE was false: nothing updated,
            # so RETURNING gave back no row. Look up the existing id instead.
            news_id = self.session.execute(
                select(CVENews.id).where(CVENews.url == item["url"])
            ).scalar_one()

        return news_id

    def _link_cves(self, news_id: int, cve_ids: list[str], spider):
        cve_ids = sorted(set(cve_ids))
        if not cve_ids:
            return

        # one query to find which of this article's CVEs already exist in `cve`
        existing = set(
            self.session.scalars(select(CVE.cve_id).where(CVE.cve_id.in_(cve_ids)))
        )

        for cve_id in cve_ids:
            table = CVENewsLink if cve_id in existing else PendingCVENewsLink
            self.session.execute(
                insert(table)
                .values(cve_news_id=news_id, cve_id=cve_id)
                .on_conflict_do_nothing()
            )

        # if a CVE that used to be pending now exists (e.g. nvd_sync picked it
        # up), drop the stale pending row for this article
        if existing:
            self.session.execute(
                delete(PendingCVENewsLink).where(
                    PendingCVENewsLink.cve_news_id == news_id,
                    PendingCVENewsLink.cve_id.in_(existing),
                )
            )

        pending_count = len(cve_ids) - len(existing)
        if pending_count:
            spider.logger.info(
                f"{pending_count} CVE(s) not in cve table yet, parked as pending "
                f"(news_id={news_id})"
            )
