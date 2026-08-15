import scrapy


class CveNewsSpider(scrapy.Spider):
    name = "cve_news"
    allowed_domains = ["thehackernews.com"]
    start_urls = ["https://thehackernews.com"]

    def parse(self, response):
        self.log(f"Got {len(response.text)} chars from {response.url}")
        yield {"url": response.url, "html_length": len(response.text)}
