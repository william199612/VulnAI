from sqlalchemy import select
from datetime import datetime

from data_pipeline.models import CVE, CVENews, CVENewsLink
from data_pipeline.rag.embeddings import embed_texts
from data_pipeline.shared.db import SessionLocal
from data_pipeline.schemas.cve import CVE_ID_PATTERN, CVEHit, NewsHit

from .config import TOP_K_DEFAULT


def _extract_cve_ids(query: str) -> list[str]:
    return sorted({m.upper() for m in CVE_ID_PATTERN.findall(query)})


def embed_query(query: str) -> list[float]:
    return embed_texts([query])[0]


def retrieve_cves(
    query: str,
    top_k: int = TOP_K_DEFAULT,
    *,
    min_cvss: float | None = None,
    published_after: datetime | None = None,
    query_embedding: list[float] | None = None,
) -> list[CVEHit]:
    """
    Top CVEs for a question.

    CVE IDs written in the question are looked up directly and returned first,
    because embeddings are weak at exact identifiers. The rest of the slots are
    filled by cosine similarity on cve.embedding.
    """
    qvec = query_embedding if query_embedding is not None else embed_query(query)
    exact_ids = _extract_cve_ids(query)

    with SessionLocal() as session:
        hits: list[CVEHit] = []
        seen: set[str] = set()

        # exact lookup by ID
        if exact_ids:
            for row in session.scalars(select(CVE).where(CVE.cve_id.in_(exact_ids))):
                hits.append(
                    CVEHit(
                        cve_id=row.cve_id,
                        description=row.description,
                        cvss_score=(
                            float(row.cvss_score)
                            if row.cvss_score is not None
                            else None
                        ),
                        published_date=row.published_date,
                        similarity=1.0,
                        exact_match=True,
                    )
                )
                seen.add(row.cve_id)

        # similarity search
        distance = CVE.embedding.cosine_distance(qvec).label("distance")
        stmt = select(CVE, distance).where(CVE.embedding.is_not(None))
        if min_cvss is not None:
            stmt = stmt.where(CVE.cvss_score >= min_cvss)
        if published_after is not None:
            stmt = stmt.where(CVE.published_date >= published_after)
        stmt = stmt.order_by(distance).limit(top_k + len(seen))

        for row, dist in session.execute(stmt):
            if row.cve_id in seen:
                continue
            hits.append(
                CVEHit(
                    cve_id=row.cve_id,
                    description=row.description,
                    cvss_score=(
                        float(row.cvss_score) if row.cvss_score is not None else None
                    ),
                    published_date=row.published_date,
                    similarity=1.0 - float(dist),
                )
            )

        return hits[: max(top_k, len(seen))]


def retrieve_news(
    query: str,
    top_k: int = 5,
    *,
    published_after: datetime | None = None,
    query_embedding: list[float] | None = None,
) -> list[NewsHit]:
    """
    Top news articles for a question.

    If the question names CVE IDs, articles already linked to them through
    cve_news_link come first. The rest is cosine similarity on cve_news.embedding.
    """
    qvec = query_embedding if query_embedding is not None else embed_query(query)
    exact_ids = _extract_cve_ids(query)

    def to_hit(row: CVENews, similarity: float, exact: bool) -> NewsHit:
        return NewsHit(
            id=row.id,
            url=row.url,
            title=row.title,
            source_domain=row.source_domain,
            content=row.content,
            published_at=row.published_at,
            similarity=similarity,
            exact_match=exact,
        )

    with SessionLocal() as session:
        hits: list[NewsHit] = []
        seen: set[int] = set()

        if exact_ids:
            linked = (
                select(CVENews)
                .join(CVENewsLink, CVENewsLink.cve_news_id == CVENews.id)
                .where(CVENewsLink.cve_id.in_(exact_ids))
                .distinct()
                .order_by(CVENews.id.desc())
                .limit(top_k)
            )
            for row in session.scalars(linked):
                hits.append(to_hit(row, 1.0, True))
                seen.add(row.id)

        distance = CVENews.embedding.cosine_distance(qvec).label("distance")
        stmt = select(CVENews, distance).where(CVENews.embedding.is_not(None))
        if published_after is not None:
            stmt = stmt.where(CVENews.published_at >= published_after)
        stmt = stmt.order_by(distance).limit(top_k + len(seen))

        for row, dist in session.execute(stmt):
            if row.id in seen:
                continue
            hits.append(to_hit(row, 1.0 - float(dist), False))

        return hits[: max(top_k, len(seen))]


def retrieve(query: str, top_k_cves: int = 5, top_k_news: int = 5) -> dict:
    """Embed the question once and search both tables."""
    qvec = embed_query(query)
    return {
        "cves": retrieve_cves(query, top_k_cves, query_embedding=qvec),
        "news": retrieve_news(query, top_k_news, query_embedding=qvec),
    }
