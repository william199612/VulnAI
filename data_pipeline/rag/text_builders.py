from data_pipeline.models import CVE, CVENews


def build_cve_embedding_text(cve: CVE) -> str:
    parts = [
        cve.cve_id,
        cve.description or "",
        f"CWE: {cve.cwe}" if cve.cwe else "",
    ]
    return "\n".join(p for p in parts if p)


def build_news_embedding_text(news: CVENews) -> str:
    parts = [news.title or "", news.content or ""]
    return "\n".join(p for p in parts if p)
