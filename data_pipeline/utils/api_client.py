import time
import requests

from data_pipeline.nvd_sync.config import MAX_RETRY, BACKOFF, TIMEOUT


def fetch_json(url, params=None, headers=None, max_retries=MAX_RETRY, backoff=BACKOFF):
    try:
        for attempt in range(max_retries):
            resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
            if resp.status_code == 429:
                wait = backoff**attempt
                print(f"Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            resp.raise_for_status()
            return resp.json()
    except Exception as e:
        raise Exception(
            f"Failed to fetch data after {max_retries} retry attempts, from {url}: {e}"
        )
