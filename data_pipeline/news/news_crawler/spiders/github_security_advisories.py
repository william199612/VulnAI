import scrapy
from html import unescape
from urllib.parse import urlparse

from data_pipeline.constants import CVE_PATTERN


class GitHubSecurityAdvisoriesSpider(scrapy.Spider):
    name = "github_security_advisories"
    allowed_domains = ["github.com"]
    start_urls = ["https://github.com/security-advisories.atom"]

    def parse(self, response):
        response.selector.remove_namespaces()
        entries = response.xpath("//entry")
        self.log(f"Found {len(entries)} GitHub security advisories")

        for entry in entries:
            title = entry.xpath("title/text()").get(default="").strip()
            link = entry.xpath("link/@href").get(default="").strip()
            pub_date = entry.xpath("published/text()").get()
            content_html = entry.xpath("content/text()").get(default="")

            text = unescape(content_html)
            cve_ids = sorted(set(m.upper() for m in CVE_PATTERN.findall(text or "")))
            if not cve_ids:
                self.log(f"Skipping (no CVE referenced): {title}")
                continue

            yield {
                "url": link,
                "title": title,
                "source_domain": urlparse(link).netloc if link else "github.com",
                "pub_date": pub_date,
                "content": text.strip(),
                "cve_ids": cve_ids,
                "crawl_method": "static",
            }
