from datetime import datetime, timezone, timedelta
from sqlalchemy.dialects.postgresql import insert

from data_pipeline.shared.db import SessionLocal

from data_pipeline.models import CVE, SyncState
from data_pipeline.schemas.cve import NVDParamsSchema

from data_pipeline.nvd_sync.client import fetch_cve_page
from data_pipeline.nvd_sync.config import *


def _extract_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            data = metrics[key][0]["cvssData"]
            return float(data.get("baseScore", 0)), data.get("vectorString")
    return None, None


def _normalize(item):
    cve = item["cve"]
    cve_id = cve["id"]
    description = next(
        (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"), ""
    )
    cvss_score, cvss_vector = _extract_cvss(cve.get("metrics", {}))
    cwe = next(
        (
            w["description"][0]["value"]
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ),
        None,
    )
    references = [r["url"] for r in cve.get("references", [])]

    return {
        "cve_id": cve_id,
        "description": description,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cwe": cwe,
        "affected_products": [],
        "published_date": cve.get("published"),
        "modified_date": cve.get("lastModified"),
        "source": "NVD",
        "raw_references": references,
    }


def _upsert_batch(session, vulnerabilities):
    for item in vulnerabilities:
        row = _normalize(item)
        stmt = insert(CVE).values(**row)
        stmt = stmt.on_conflict_do_update(
            index_elements=["cve_id"],
            set_={k: v for k, v in row.items() if k != "cve_id"},
        )
        session.execute(stmt)
    session.commit()


def _get_last_synced(session, source="nvd"):
    state = session.get(SyncState, source)
    return state.last_synced_at if state else None


def _set_last_synced(session, timestamp, source="nvd"):
    stmt = insert(SyncState).values(source=source, last_synced_at=timestamp)
    stmt = stmt.on_conflict_do_update(
        index_elements=["source"],
        set_={"last_synced_at": timestamp},
    )
    session.execute(stmt)
    session.commit()


def run_full_sync(results_per_page=200, max_pages=None):
    session = SessionLocal()
    start_index = 0
    page = 0

    try:
        while True:
            params = NVDParamsSchema(
                start_index=start_index,
                results_per_page=results_per_page
            )
            data = fetch_cve_page(params)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            _upsert_batch(session, vulnerabilities)
            print(f"Synced {len(vulnerabilities)} CVEs (start_index={start_index})")

            start_index += results_per_page
            page += 1
            if start_index >= data.get("totalResults", 0):
                break
            if max_pages and page >= max_pages:
                break
    finally:
        session.close()


def run_incremental_sync():
    session = SessionLocal()
    try:
        since = _get_last_synced(session)
        now = datetime.now(timezone.utc)

        if since is None:
            # first run ever — no checkpoint yet, fall back to full sync
            print("No previous sync found, running full sync instead")
            session.close()
            run_full_sync()
            session = SessionLocal()
            _set_last_synced(session, now)
            return

        start_index = 0
        while True:
            params = NVDParamsSchema(
                start_index=start_index,
                results_per_page=200,
                last_mod_start_date=since.strftime("%Y-%m-%dT%H:%M:%S.000"),
                last_mod_end_date=now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            )
            data = fetch_cve_page(params)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            _upsert_batch(session, vulnerabilities)
            start_index += 200
            if start_index >= data.get("totalResults", 0):
                break

        _set_last_synced(
            session, now
        )  # only advance checkpoint after a full successful pass
    finally:
        session.close()


def run_seed_sync(years_back=1, results_per_page=200):
    """One-time bounded initial load — recent CVEs only, not full NVD history."""
    session = SessionLocal()
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=365 * years_back)
    start_index = 0

    try:
        while True:
            params = NVDParamsSchema(
                start_index=start_index,
                results_per_page=results_per_page,
                pub_start_date=start_date.strftime("%Y-%m-%dT%H:%M:%S.000"),
                pub_end_date=now.strftime("%Y-%m-%dT%H:%M:%S.000"),
            )
            data = fetch_cve_page(params)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            _upsert_batch(session, vulnerabilities)
            total = data.get("totalResults", 0)
            print(f"Synced {len(vulnerabilities)} CVEs (start_index={start_index}/{total})")

            start_index += results_per_page
            if start_index >= total:
                break
        _set_last_synced(session, now)
    finally:
        session.close()
