import scrapy
from html import unescape
from urllib.parse import urlparse

from data_pipeline.constants import CVE_PATTERN


class ZDIPublishedSpider(scrapy.Spider):
    name = "zdi_published"
    allowed_domains = ["zerodayinitiative.com"]
    start_urls = ["https://www.zerodayinitiative.com/rss/published/"]

    def parse(self, response):
        response.selector.remove_namespaces()
        items = response.xpath("//item")
        self.log(f"Found {len(items)} ZDI advisories")

        for item in items:
            title = item.xpath("title/text()").get(default="").strip()
            link = item.xpath("link/text()").get(default="").strip()
            pub_date = item.xpath("pubDate/text()").get()
            description = item.xpath("description/text()").get(default="")

            text = unescape(description)
            cve_ids = sorted(set(m.upper() for m in CVE_PATTERN.findall(text or "")))
            if not cve_ids:
                self.log(f"Skipping (no CVE assigned yet): {title}")
                continue

            yield {
                "url": link,
                "title": title,
                "source_domain": urlparse(link).netloc,
                "pub_date": pub_date,
                "content": description.strip(),
                "cve_ids": cve_ids,
                "crawl_method": "static",
            }
