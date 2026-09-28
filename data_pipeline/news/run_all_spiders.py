import yaml
from pathlib import Path
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings

SOURCES_FILE = Path(__file__).resolve().parent / "sources.yaml"


def load_enabled_spiders():
    with open(SOURCES_FILE) as f:
        config = yaml.safe_load(f)
    return [s["name"] for s in config["sources"] if s.get("enabled", True)]


def main():
    spider_names = load_enabled_spiders()
    print(f"Running spiders: {spider_names}")

    process = CrawlerProcess(get_project_settings())
    for name in spider_names:
        process.crawl(name)

    process.start()  # blocks until ALL crawls finish; reactor starts once, for this one process run


if __name__ == "__main__":
    main()
