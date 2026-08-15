import os

from data_pipeline.utils.api_client import fetch_json

from .config import NVD_BASE


def fetch_cve_page(
    start_index=0, results_per_page=200, last_mod_start=None, last_mod_end=None
):
    params = {"startIndex": start_index, "resultsPerPage": results_per_page}
    if last_mod_start and last_mod_end:
        params["lastModStartDate"] = last_mod_start
        params["lastModEndDate"] = last_mod_end

    headers = {}
    api_key = os.getenv("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key

    return fetch_json(NVD_BASE, params=params, headers=headers)
