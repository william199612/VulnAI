from data_pipeline.models import CVE, CVENews

from .config import MAX_EMBEDDING_CHARS


def _finalize(text: str) -> str:
    """
    Trim whitespace and cap length.
    Returns "" when there is nothing to embed.
    """
    return text.strip()[:MAX_EMBEDDING_CHARS]


def build_cve_embedding_text(cve: CVE) -> str:
    parts = [
        cve.cve_id,
        cve.description or "",
        f"CWE: {cve.cwe}" if cve.cwe else "",
    ]
    return _finalize("\n".join(p for p in parts if p))


def build_news_embedding_text(news: CVENews) -> str:
    title = (news.title or "").strip()
    body = (news.content or "").strip()[:MAX_EMBEDDING_CHARS]
    parts = [p for p in (title, body) if p]
    return _finalize("\n".join(parts))
