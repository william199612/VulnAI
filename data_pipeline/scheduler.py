import subprocess
from pathlib import Path

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.executors.pool import ThreadPoolExecutor

from data_pipeline.shared.logging import get_logger

from data_pipeline.nvd_sync.sync import run_incremental_sync
from data_pipeline.news.reconcile_pending_links import reconcile_pending_links

from data_pipeline.rag.backfill_embeddings import (
    backfill_cve_embeddings,
    backfill_news_embeddings,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
NEWS_DIR = PROJECT_ROOT / "data_pipeline" / "news"

logger = get_logger("scheduler", "scheduler.log")


def run_news_crawl():
    # scrapy runs in a separate process, since Twisted's reactor can only
    # start once per process — running it in-process would crash on the
    # second scheduled invocation (ReactorNotRestartable)
    try:
        subprocess.run(
            [
                "uv",
                "run",
                "python",
                "-m",
                "data_pipeline.news.run_all_spiders",
            ],
            cwd=str(PROJECT_ROOT),
            check=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        logger.error("News crawl timed out after 10 minutes — killed")
    except subprocess.CalledProcessError as e:
        logger.error(f"News crawl failed with exit code {e.returncode}")


executors = {"default": ThreadPoolExecutor(5)}
scheduler = BlockingScheduler(executors=executors)

scheduler.add_job(run_incremental_sync, "interval", hours=6, id="nvd_sync")
scheduler.add_job(run_news_crawl, "interval", minutes=30, id="news_crawl")
scheduler.add_job(reconcile_pending_links, "interval", minutes=35, id="reconcile_links")
# reconcile runs 5 min after news_crawl on the same cadence, so it's usually working
# with freshly-crawled pending links rather than racing the crawl itself

scheduler.add_job(backfill_cve_embeddings, "interval", hours=6, id="embed_cve")
scheduler.add_job(backfill_news_embeddings, "interval", minutes=35, id="embed_news")

if __name__ == "__main__":
    scheduler.start()
