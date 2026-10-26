"""Agent tools: read-only wrappers over the VulnAI database.

Three tools, each returning a JSON-serializable dict:

    get_cve(cve_id)         exact lookup, every field incl. KEV status + linked news
    search_cve(...)         semantic search with filters (days, min_cvss, kev_only)
                            and a real sort (relevance | cvss | date)
    search_news(...)        news search, optionally restricted to one CVE

Design rules
    - Tools never raise to the agent loop. Bad arguments and failures come backas {"error": ..., "message": ...} so the model can correct itself.
    - Outputs are bounded (limit <= 10, trimmed text) so one call cannot flood the context window.
    - Every item carries a stable "id" (CVE ID, or "news:<id>" plus its URL). The final answer cites these, and Phase 2's validity / coverage checks run against the set of ids the tools returned.

Usage (loop side):
    from agent.tools import TOOL_SPECS, run_tool
    # pass TOOL_SPECS as `tools=` to the chat completion call, then for every
    # tool call the model makes:  result_str = run_tool(call.function.name,
    #                                                   call.function.arguments)
Quick manual test:
    uv run python -m agent.tools search_cve '{"query":"apache","days":30,"sort_by":"cvss"}'
"""

import json
import logging
import re
import sys
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from data_pipeline.models import CVE, CVENews, CVENewsLink
from data_pipeline.rag.retriever import embed_query, retrieve_news
from data_pipeline.shared.db import SessionLocal
from data_pipeline.shared.logging import get_logger

logger = get_logger("agent.tools", "agent_tools.log")

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
SORT_OPTIONS = ("relevance", "cvss", "date")

MAX_LIMIT = 10
SEARCH_DESC_CHARS = 400
NEWS_SNIPPET_CHARS = 300
MAX_REFERENCES = 5
MAX_LINKED_NEWS = 3
# When sorting by CVSS/date, rank within the N most relevant matches. Sorting
# the whole table by CVSS would return high-scoring but unrelated CVEs.
POOL_FACTOR = 10
MIN_POOL = 50


class ToolInputError(ValueError):
    """The model passed arguments the tool cannot use."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _clip(text: str | None, n: int) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= n else text[: n - 1].rstrip() + "…"


def _day(value) -> str | None:
    return value.isoformat()[:10] if value else None


def _as_int(value, name: str, lo: int, hi: int | None = None) -> int | None:
    if value is None or value == "":
        return None
    try:
        out = int(value)
    except (TypeError, ValueError):
        raise ToolInputError(f"{name} must be an integer")
    out = max(lo, out)
    return min(out, hi) if hi is not None else out


def _as_float(value, name: str) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        raise ToolInputError(f"{name} must be a number")


def _as_bool(value, name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.lower() in ("true", "false"):
        return value.lower() == "true"
    if value is None:
        return False
    raise ToolInputError(f"{name} must be true or false")


def _cutoff(days: int | None) -> datetime | None:
    return datetime.now(timezone.utc) - timedelta(days=days) if days else None


def _score(row) -> float | None:
    return float(row.cvss_score) if row.cvss_score is not None else None


def _cve_summary(row, similarity: float | None = None) -> dict:
    out = {
        "id": row.cve_id,
        "cvss": _score(row),
        "cwe": row.cwe,
        "published": _day(row.published_date),
        "is_kev": bool(row.is_kev),
        "description": _clip(row.description, SEARCH_DESC_CHARS),
    }
    if similarity is not None:
        out["similarity"] = round(similarity, 3)
    return out


def _dump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


# --------------------------------------------------------------------------
# tool 1: get_cve
# --------------------------------------------------------------------------
def get_cve(cve_id: str) -> dict:
    cve_id = (cve_id or "").strip().upper()
    if not CVE_PATTERN.match(cve_id):
        raise ToolInputError("cve_id must look like CVE-yyyy-xxxxx")

    with SessionLocal() as session:
        row = session.scalars(select(CVE).where(CVE.cve_id == cve_id)).first()
        if row is None:
            return {
                "error": "not_found",
                "id": cve_id,
                "message": "This CVE is not in the local database. "
                "Do not guess its details.",
            }
        news_rows = session.scalars(
            select(CVENews)
            .join(CVENewsLink, CVENewsLink.cve_news_id == CVENews.id)
            .where(CVENewsLink.cve_id == cve_id)
            .order_by(CVENews.published_at.desc().nulls_last())
            .limit(MAX_LINKED_NEWS)
        ).all()

        return {
            "id": row.cve_id,
            "description": _clip(row.description, 2000),
            "cvss": _score(row),
            "cvss_vector": row.cvss_vector,
            "cwe": row.cwe,
            "published": _day(row.published_date),
            "modified": _day(row.modified_date),
            "references": list(row.raw_references or [])[:MAX_REFERENCES],
            "kev": {
                "is_kev": bool(row.is_kev),
                "date_added": _day(getattr(row, "kev_date_added", None)),
                "ransomware_use": getattr(row, "kev_ransomware", None),
                "note": "is_kev=false means not listed in the CISA KEV catalog "
                "at the last sync; it does not prove the CVE is not exploited.",
            },
            "linked_news": [
                {
                    "id": f"news:{n.id}",
                    "title": n.title,
                    "url": n.url,
                    "source": n.source_domain,
                    "published": _day(n.published_at),
                }
                for n in news_rows
            ],
        }


# --------------------------------------------------------------------------
# tool 2: search_cve
# --------------------------------------------------------------------------
def search_cve(
    query: str | None = None,
    days=None,
    min_cvss=None,
    kev_only=False,
    sort_by: str = "relevance",
    limit=5,
) -> dict:
    days = _as_int(days, "days", 1, 3650)
    limit = _as_int(limit, "limit", 1, MAX_LIMIT) or 5
    min_cvss = _as_float(min_cvss, "min_cvss")
    kev_only = _as_bool(kev_only, "kev_only")
    query = (query or "").strip()
    sort_by = (sort_by or "relevance").strip().lower()

    if sort_by not in SORT_OPTIONS:
        raise ToolInputError(f"sort_by must be one of {list(SORT_OPTIONS)}")
    if sort_by == "relevance" and not query:
        raise ToolInputError("query is required when sort_by is 'relevance'")

    conds = []
    if days:
        conds.append(CVE.published_date >= _cutoff(days))
    if min_cvss is not None:
        conds.append(CVE.cvss_score >= min_cvss)
    if kev_only:
        conds.append(CVE.is_kev.is_(True))

    note = None
    with SessionLocal() as session:
        if query:
            qvec = embed_query(query)
            distance = CVE.embedding.cosine_distance(qvec).label("distance")
            stmt = select(CVE, distance).where(CVE.embedding.is_not(None), *conds)
            pool = (
                limit if sort_by == "relevance" else max(limit * POOL_FACTOR, MIN_POOL)
            )
            rows = [
                (r, 1.0 - float(d))
                for r, d in session.execute(stmt.order_by(distance).limit(pool))
            ]
            if sort_by != "relevance":
                note = (
                    f"Sorted by {sort_by} within the {pool} most relevant "
                    f"matches for the query, not across the whole database."
                )
        else:
            order = (
                CVE.cvss_score.desc().nulls_last()
                if sort_by == "cvss"
                else CVE.published_date.desc().nulls_last()
            )
            stmt = select(CVE)
            if conds:
                stmt = stmt.where(*conds)
            rows = [
                (r, None) for r in session.scalars(stmt.order_by(order).limit(limit))
            ]

        if query and sort_by == "cvss":
            rows.sort(key=lambda x: (x[0].cvss_score is None, -(_score(x[0]) or 0.0)))
        elif query and sort_by == "date":
            floor = datetime.min.replace(tzinfo=timezone.utc)
            rows.sort(key=lambda x: x[0].published_date or floor, reverse=True)

        results = [_cve_summary(r, sim) for r, sim in rows[:limit]]

    out = {"count": len(results), "sort_by": sort_by, "results": results}
    if note:
        out["note"] = note
    if kev_only and not results:
        out["note"] = (
            "No KEV-listed CVE matched these filters in the local "
            "database. Unscored or older CVEs may be outside the dataset."
        )
    return out


# --------------------------------------------------------------------------
# tool 3: search_news
# --------------------------------------------------------------------------
def search_news(
    query: str | None = None, cve_id: str | None = None, days=None, limit=5
) -> dict:
    days = _as_int(days, "days", 1, 3650)
    limit = _as_int(limit, "limit", 1, MAX_LIMIT) or 5
    query = (query or "").strip()
    cve_id = (cve_id or "").strip().upper() or None

    if cve_id and not CVE_PATTERN.match(cve_id):
        raise ToolInputError("cve_id must look like CVE-2026-12345")
    if not query and not cve_id:
        raise ToolInputError("provide a query, a cve_id, or both")

    ids = (
        [cve_id]
        if cve_id
        else sorted({m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,}", query, re.I)})
    )

    hits = retrieve_news(
        query or cve_id,
        limit,
        exact_ids=ids,  # [] = do not auto-extract IDs
        published_after=_cutoff(days),
    )
    if ids:
        linked = [h for h in hits if h.exact_match]
        hits = linked or hits  # fall back to semantic if nothing is linked

    results = [
        {
            "id": f"news:{h.id}",
            "title": h.title,
            "url": h.url,
            "source": h.source_domain,
            "published": _day(h.published_at),
            "linked_to_cve": bool(h.exact_match),
            "snippet": _clip(h.content, NEWS_SNIPPET_CHARS),
        }
        for h in hits[:limit]
    ]
    return {"count": len(results), "results": results}


# --------------------------------------------------------------------------
# registry: schemas for the model + a safe dispatcher for the loop
# --------------------------------------------------------------------------
TOOLS = {"get_cve": get_cve, "search_cve": search_cve, "search_news": search_news}

TOOL_SPECS = [
    {
        "type": "function",
        "function": {
            "name": "get_cve",
            "description": (
                "Fetch ONE CVE by its exact ID. Returns the full record: description, "
                "CVSS score and vector, CWE, published/modified dates, references, "
                "CISA KEV status (known exploited in the wild, date added, ransomware "
                "use) and up to 3 linked news articles. Use this whenever a specific "
                "CVE ID is known, and to check whether a CVE is exploited. Returns "
                "error 'not_found' if the CVE is not in the database."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "cve_id": {"type": "string", "description": "e.g. CVE-2026-93546"}
                },
                "required": ["cve_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_cve",
            "description": (
                "Search CVEs by topic (product, vendor, vulnerability type) with "
                "optional filters. Returns up to `limit` short summaries with CVSS, "
                "CWE, published date and is_kev. Use sort_by='cvss' for 'most "
                "dangerous' questions (highest score first, unscored last; ranked "
                "within the most relevant matches). Use kev_only=true for 'exploited "
                "in the wild' questions. Does not take a CVE ID; use get_cve for that."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Topic, e.g. 'apache http server'. Required unless sort_by is cvss or date.",
                    },
                    "days": {
                        "type": "integer",
                        "description": "Only CVEs published in the last N days.",
                    },
                    "min_cvss": {
                        "type": "number",
                        "description": "Minimum CVSS score, 0-10.",
                    },
                    "kev_only": {
                        "type": "boolean",
                        "description": "Only CVEs in the CISA KEV catalog.",
                    },
                    "sort_by": {
                        "type": "string",
                        "enum": list(SORT_OPTIONS),
                        "description": "Default 'relevance'.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": f"1-{MAX_LIMIT}, default 5.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_news",
            "description": (
                "Search security news articles (The Hacker News, ZDI, GitHub "
                "advisories, etc.). Pass cve_id to get articles about that CVE. "
                "Pass a query for topic search. Returns title, URL, source, date and "
                "a short snippet. Use it for exploitation reports and context that "
                "the CVE record itself does not contain."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "cve_id": {
                        "type": "string",
                        "description": "Restrict to articles linked to this CVE.",
                    },
                    "days": {
                        "type": "integer",
                        "description": "Only articles from the last N days.",
                    },
                    "limit": {
                        "type": "integer",
                        "description": f"1-{MAX_LIMIT}, default 5.",
                    },
                },
                "required": [],
            },
        },
    },
]


def run_tool(name: str, arguments: str | dict | None) -> str:
    """Execute one tool call and always return a JSON string, never raise."""
    fn = TOOLS.get(name)
    if fn is None:
        return _dump(
            {
                "error": "unknown_tool",
                "message": f"No tool named {name!r}.",
                "available": list(TOOLS),
            }
        )
    try:
        if isinstance(arguments, str):
            args = json.loads(arguments) if arguments.strip() else {}
        else:
            args = arguments or {}
        if not isinstance(args, dict):
            raise ValueError("arguments must be a JSON object")
    except (ValueError, json.JSONDecodeError) as e:
        return _dump(
            {"error": "invalid_arguments", "message": f"Could not parse arguments: {e}"}
        )

    try:
        return _dump(fn(**args))
    except ToolInputError as e:
        return _dump({"error": "invalid_arguments", "message": str(e)})
    except TypeError as e:  # unexpected / missing argument names
        return _dump({"error": "invalid_arguments", "message": str(e)})
    except Exception as e:  # DB down, embedding API failure, ...
        logger.exception(f"tool {name} failed")
        return _dump(
            {
                "error": "tool_failed",
                "message": "The tool failed internally. Try different arguments "
                "or answer with what you already have. "
                f"{str(e)}",
            }
        )


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        sys.exit("usage: python -m agent.tools <tool_name> ['<json args>']")
    print(
        json.dumps(
            json.loads(
                run_tool(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "{}")
            ),
            indent=2,
            ensure_ascii=False,
        )
    )
