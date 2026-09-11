import re
from html import unescape
import scrapy
from urllib.parse import urlparse

from data_pipeline.constants.cve import CVE_PATTERN

class CveFeedSpider(scrapy.Spider):
    # CVE Feed: RSS Feed
    name = "cvefeed"
    allowed_domains = ["cvefeed.io"]
    start_urls = ["https://cvefeed.io/rssfeed/newsroom.xml"]
    
    def parse(self, response):
        response.selector.remove_namespaces()
        items = response.xpath("//item")
        self.log(f"Found {len(items)} newsroom items")

        for item in items:
            title = item.xpath("title/text()").get(default="").strip()
            link = item.xpath("link/text()").get(default="").strip()
            pub_date = item.xpath("pubDate/text()").get()
            description_html = item.xpath("description/text()").get(default="")

            if not link:
                continue

            cve_ids = sorted(set(CVE_PATTERN.findall(description_html)))
            if not cve_ids:
                self.log(f"Skipping (no CVE tagged): {title}")
                continue

            summary = self._extract_summary(description_html)

            yield {
                "url": link,
                "title": title,
                "source_domain": urlparse(link).netloc,
                "pub_date": pub_date,
                "content": summary,
                "cve_ids": cve_ids,
                "crawl_method": "static",
            }

    def _extract_summary(self, description_html):
        """Pull the teaser paragraph out of CVEFeed's embedded HTML snippet."""
        text = unescape(description_html)
        # grab text inside the first <p>...</p> before "Read more"
        match = re.search(r"<p>\s*(.*?)\s*<a", text, re.DOTALL)
        if not match:
            return None
        raw = match.group(1)
        # strip any remaining tags
        clean = re.sub(r"<[^>]+>", " ", raw)
        clean = re.sub(r"\s+", " ", clean).strip()
        return clean