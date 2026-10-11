from datetime import datetime, timezone, timedelta
from sqlalchemy.dialects.postgresql import insert

from data_pipeline.shared.db import SessionLocal
from data_pipeline.shared.logging import get_logger

from data_pipeline.models import CVE, SyncState
from data_pipeline.schemas.cve import NVDParamsSchema

from data_pipeline.nvd_sync.client import fetch_cve_page
from data_pipeline.nvd_sync.config import *

MAX_WINDOW_DAYS = 119
logger = get_logger("nvd_sync", "nvd_sync.log")


def _date_windows(start: datetime, end: datetime, days: int = MAX_WINDOW_DAYS):
    """Split [start, end] into consecutive windows of at most `days` days."""
    cur = start
    while cur < end:
        nxt = min(cur + timedelta(days=days), end)
        yield cur, nxt
        cur = nxt


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000")


def _sync_range(
    session, start, end, *, date_field, results_per_page=200, max_pages=None
):
    """Fetch every CVE in [start, end], one <=119-day window at a time.

    date_field is "pub" (seed: by publish date) or "last_mod" (incremental).
    Returns True if it finished, False if it stopped early because of max_pages.
    """
    pages = 0
    for w_start, w_end in _date_windows(start, end):
        start_index = 0
        while True:
            params = NVDParamsSchema(
                startIndex=start_index,
                resultsPerPage=results_per_page,
                **{
                    f"{date_field}StartDate": _fmt(w_start),
                    f"{date_field}EndDate": _fmt(w_end),
                },
            )
            data = fetch_cve_page(params)
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break

            _upsert_batch(session, vulns)  # commits internally
            total = data.get("totalResults", 0)
            logger.info(
                f"[{date_field} {w_start:%Y-%m-%d}..{w_end:%Y-%m-%d}] "
                f"synced {len(vulns)} CVEs (start_index={start_index}/{total})"
            )

            pages += 1
            start_index += results_per_page
            if start_index >= total:
                break
            if max_pages and pages >= max_pages:
                return False
    return True


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
                startIndex=start_index, resultsPerPage=results_per_page
            )
            data = fetch_cve_page(params)
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            _upsert_batch(session, vulnerabilities)
            logger.info(
                f"Synced {len(vulnerabilities)} CVEs (start_index={start_index})"
            )

            start_index += results_per_page
            page += 1
            if start_index >= data.get("totalResults", 0):
                break
            if max_pages and page >= max_pages:
                break
    finally:
        session.close()


def run_incremental_sync(max_pages: int | None = None):
    with SessionLocal() as session:
        since = _get_last_synced(session)
        if since is None:
            logger.error("No sync checkpoint found. Run `seed` first.")
            return

        now = datetime.now(timezone.utc)  # taken before fetching, so nothing is missed
        done = _sync_range(
            session, since, now, date_field="last_mod", max_pages=max_pages
        )
        if done:
            _set_last_synced(session, now)
        else:
            logger.info(f"stopped at max_pages={max_pages}, checkpoint NOT advanced")


def run_seed_sync(years_back=1, results_per_page=200, max_pages=None):
    """One-time bounded initial load — recent CVEs only, not full NVD history."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=365 * years_back)
    with SessionLocal() as session:
        done = _sync_range(
            session,
            start,
            now,
            date_field="pub",
            results_per_page=results_per_page,
            max_pages=max_pages,
        )
        if done:
            _set_last_synced(session, now)
        else:
            logger.info(f"stopped at max_pages={max_pages}, checkpoint NOT advanced")
