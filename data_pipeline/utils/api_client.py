import time
import requests

from data_pipeline.constants import MAX_RETRIES, TIMEOUT
from data_pipeline.shared.logging import get_logger

logger = get_logger("nvd_sync", "nvd_sync.log")


def fetch_json(url, params=None, headers=None):
    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
            if resp.status_code in (
                403,
                404,
                429,
                503,
            ):  # NVD uses these for throttling/overload
                raise requests.HTTPError(f"{resp.status_code} from NVD", response=resp)
            resp.raise_for_status()
            return resp.json()
        except (requests.Timeout, requests.ConnectionError, requests.HTTPError) as e:
            last_err = e
            wait = min(2**attempt * 5, 60)  # 10s, 20s, 40s, 60s, 60s
            logger.warning(
                f"attempt {attempt}/{MAX_RETRIES} failed ({e}); retrying in {wait}s"
            )
            time.sleep(wait)
    raise Exception(
        f"Failed to fetch data after {MAX_RETRIES} attempts from {url}: {last_err}"
    )
