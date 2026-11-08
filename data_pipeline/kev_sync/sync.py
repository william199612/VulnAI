import logging
from datetime import date

import requests
from sqlalchemy import text

from data_pipeline.shared.db import SessionLocal
from data_pipeline.constants import TIMEOUT

logger = logging.getLogger("kev_sync")

KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


def run_kev_sync() -> int:
    resp = requests.get(KEV_URL, timeout=TIMEOUT)
    resp.raise_for_status()
    vulns = resp.json()["vulnerabilities"]

    rows = [
        {
            "cve_id": v["cveID"],
            "added": date.fromisoformat(v["dateAdded"]),
            "ransom": v.get("knownRansomwareCampaignUse", "").lower() == "known",
        }
        for v in vulns
    ]

    stmt = text("""
        UPDATE cve
        SET is_kev = true, kev_date_added = :added, kev_ransomware = :ransom
        WHERE cve_id = :cve_id
    """)
    matched = 0
    with SessionLocal() as session:
        for r in rows:
            matched += session.execute(stmt, r).rowcount
        session.commit()

    logger.info(
        f"KEV feed={len(rows)} matched_locally={matched} "
        f"missing={len(rows) - matched}"
    )
    return matched


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    run_kev_sync()
