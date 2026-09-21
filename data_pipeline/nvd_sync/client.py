import os

from data_pipeline.utils.api_client import fetch_json
from data_pipeline.schemas.cve import NVDParamsSchema
from data_pipeline.constants.cve import CVE_PATTERN

from .config import NVD_BASE, NVD_API_KEY


def fetch_cve_page(params: NVDParamsSchema):
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    else:
        raise ValueError("NVD_API_KEY environment variable is not set")

    return fetch_json(
        NVD_BASE, params=params.model_dump(exclude_none=True), headers=headers
    )


def fetch_cve_by_id(cve_id: str):
    if not CVE_PATTERN.match(cve_id):
        raise ValueError("Invalid CVE ID format")

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    else:
        raise ValueError("NVD_API_KEY environment variable is not set")
    return fetch_json(NVD_BASE, params={"cveId": cve_id}, headers=headers)
