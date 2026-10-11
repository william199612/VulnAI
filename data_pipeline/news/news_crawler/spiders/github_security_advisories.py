import scrapy
import json
from html import unescape
from urllib.parse import urlparse

from data_pipeline.constants import CVE_PATTERN

MAX_PAGES = 3


class GitHubSecurityAdvisoriesSpider(scrapy.Spider):
    name = "github_security_advisories"
    allowed_domains = ["github.com"]

    HEADERS = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    async def start(self):
        self.logger.info("start() called")
        yield scrapy.Request(
            "https://api.github.com/advisories?type=reviewed&per_page=100&sort=published&direction=desc",
            headers=self.HEADERS,
            callback=self.parse,
            cb_kwargs={"page": 1},
        )

    def parse(self, response, page):
        advisories = json.loads(response.text)
        kept = 0

        for adv in advisories:
            cve_id = adv.get("cve_id")
            if not cve_id:
                continue  # GHSA-only advisory: nothing to link to

            link = adv.get("html_url") or ""
            summary = adv.get("summary") or ""
            description = adv.get("description") or ""
            pkgs = sorted(
                {
                    f"{v['package']['ecosystem']}:{v['package']['name']}"
                    for v in (adv.get("vulnerabilities") or [])
                    if v.get("package")
                }
            )
            content = f"{summary}\n\n{description}"
            if pkgs:
                content += f"\n\nAffected packages: {', '.join(pkgs)}"

            kept += 1
            yield {
                "url": link,
                "title": f"{adv.get('ghsa_id')}: {summary}",
                "source_domain": urlparse(link).netloc or "github.com",
                "pub_date": adv.get("published_at"),
                "content": content.strip(),
                "cve_ids": [cve_id.upper()],
                "crawl_method": "static",
            }

        self.logger.info(
            f"page {page}: {len(advisories)} advisories, {kept} with a CVE ID"
        )

        next_link = response.headers.get("Link", b"").decode()
        if page < MAX_PAGES and 'rel="next"' in next_link:
            next_url = next_link.split(";")[0].strip("<> ")
            yield scrapy.Request(
                next_url,
                headers=self.HEADERS,
                callback=self.parse,
                cb_kwargs={"page": page + 1},
            )
