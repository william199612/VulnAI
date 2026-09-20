# Scrapy settings for news_crawler project

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

BOT_NAME = "news_crawler"

SPIDER_MODULES = ["news_crawler.spiders"]
NEWSPIDER_MODULE = "news_crawler.spiders"

ADDONS = {}

# Obey robots.txt rules
ROBOTSTXT_OBEY = True

PLAYWRIGHT_BROWSER_TYPE = "chromium"
PLAYWRIGHT_LAUNCH_OPTIONS = {"headless": True}
PLAYWRIGHT_DEFAULT_NAVIGATION_TIMEOUT = 30000  # 30s

# Concurrency and throttling settings
DOWNLOAD_DELAY = 1
CONCURRENT_REQUESTS_PER_DOMAIN = 4

# Enable Playwright as an available download handler (not default — only used per-request)
DOWNLOAD_HANDLERS = {
    "https": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
    "http": "scrapy_playwright.handler.ScrapyPlaywrightDownloadHandler",
}

TWISTED_REACTOR = "twisted.internet.asyncioreactor.AsyncioSelectorReactor"

# Configure item pipelines
# See https://docs.scrapy.org/en/latest/topics/item-pipeline.html
ITEM_PIPELINES = {
    "data_pipeline.news.news_crawler.pipelines.CveNewsPipeline": 300,
}

# Set settings whose default value is deprecated to a future-proof value
FEED_EXPORT_ENCODING = "utf-8"
