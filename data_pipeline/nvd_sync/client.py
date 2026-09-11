import os

from data_pipeline.utils.api_client import fetch_json
from data_pipeline.schemas.cve import NVDParamsSchema

from .config import NVD_BASE


def fetch_cve_page(params: NVDParamsSchema):
    headers = {}
    api_key = os.getenv("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key

    return fetch_json(
        NVD_BASE,
        params=params.model_dump(exclude_none=True),
        headers=headers
    )
