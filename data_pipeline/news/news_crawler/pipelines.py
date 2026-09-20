# Define your item pipelines here
#
# Don't forget to add your pipeline to the ITEM_PIPELINES setting
# See: https://docs.scrapy.org/en/latest/topics/item-pipeline.html


# useful for handling different item types with a single interface
from itemadapter import ItemAdapter

from urllib.parse import urlparse
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert

from data_pipeline.shared.db import SessionLocal
from data_pipeline.models import CVENews, CVENewsLink, CVE

class CveNewsPipeline:
    def open_spider(self, spider):
        self.session = SessionLocal()

    def close_spider(self, spider):
        self.session.close()

    def process_item(self, item, spider):

        stmt = insert(CVENews).values(
            url=item.get("url"),
            title=item.get("title"),
            source_domain=item.get("source_domain"),
            published_at=item.get("pub_date"),
            content=item.get("content"),
            crawl_method=item.get("crawl_method"),
        ).on_conflict_do_update(
            index_elements=["url"],
            set_={
                "content": item.get("content"),
                "title": item.get("title"),
                "updated_at": func.now(),
            },
        ).returning(CVENews.id)

        result = self.session.execute(stmt)
        news_id = result.scalar()
        self.session.commit()
        
        for cve_id in item.get("cve_ids", []):
            exists = self.session.get(CVE, cve_id)
            if not exists:
                spider.log(f"CVE {cve_id} mentioned but not in cve table, skipping link")
                continue

            link_stmt = insert(CVENewsLink).values(
                cve_news_id=news_id, cve_id=cve_id
            ).on_conflict_do_nothing()
            self.session.execute(link_stmt)

        self.session.commit()
        return item
