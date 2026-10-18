import re
import time
from datetime import datetime, timedelta, timezone
from typing import List
from dataclasses import dataclass

from data_pipeline.rag.config import LLM_MODEL, NEWS_SNIPPET_CHARS, TEMPERATURE
from data_pipeline.shared.logging import get_logger

from data_pipeline.rag.embeddings import get_client
from data_pipeline.rag.retriever import retrieve
from data_pipeline.rag.prompt import SYSTEM_PROMPT_VERSION, SYSTEM_PROMPT

logger = get_logger("rag", "rag_answer.log")


@dataclass
class RAGAnswer:
    question: str
    text: str
    sources: List[str]
    cited: List[str]
    invalid_citations: List[str]
    latency: float
    prompt_tokens: int
    completion_tokens: int


def _clean(text: str) -> str:
    # stop a source from closing its own tag and escaping the data block
    return (text or "").replace("</source", "<\\/source")


def _date(dt) -> str:
    return dt.date().isoformat() if dt else "unknown"


def build_context(cves, news) -> str:
    blocks, sources, n = [], [], 0

    for cve in cves:
        n += 1
        tag = f"S{n}"

        cvss = cve.cvss_score or "unscored"
        blocks.append(
            f'<source id="{tag}" type="cve" cve_id="{cve.cve_id}" cvss="{cvss}" '
            f'published="{_date(cve.published_date)}">\n{_clean(cve.description)}\n</source>'
        )
        sources.append(
            {
                "tag": tag,
                "type": "cve",
                "id": cve.cve_id,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}",
            }
        )

    for piece in news:
        n += 1
        tag = f"S{n}"
        body = _clean((piece.content or "")[:NEWS_SNIPPET_CHARS])
        blocks.append(
            f'<source id="{tag}" type="news" domain="{piece.source_domain}" '
            f'published="{_date(piece.published_at)}" title="{_clean(piece.title)}">\n{body}\n</source>'
        )
        sources.append(
            {
                "tag": tag,
                "type": "news",
                "id": piece.title,
                "url": piece.url,
            }
        )

    return "\n".join(blocks), sources


def _extract_citations(text: str) -> List[str]:
    """Extracts citation tags from the text."""
    tags = []
    for group in re.findall(r"\[([^\]]*)\]", text):
        tags += re.findall(r"S\d+", group)
    return tags


def answer_question(
    question: str, *, top_k_cves: int = 5, top_k_news: int = 5, days=None, model=None
) -> RAGAnswer:
    t0 = time.perf_counter()
    published_after = (
        datetime.now(timezone.utc) - timedelta(days=days) if days else None
    )

    result = retrieve(question, top_k_cves, top_k_news, published_after=published_after)
    cves, news = result["cves"], result["news"]

    if not cves and not news:
        return RAGAnswer(
            question=question,
            text="No relevant sources were found for this question.",
            sources=[],
            cited=[],
            invalid_citation=[],
            latency=time.perf_counter() - t0,
            prompt_tokens=0,
            completion_tokens=0,
        )

    context, sources = build_context(cves, news)
    resp = get_client().chat.completions.create(
        model=model or LLM_MODEL,
        temperature=TEMPERATURE,
        messages=[
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": f"<sources>\n{context}\n</sources>\n\nQuestion: {question}",
            },
        ],
    )

    text = resp.choices[0].message.content or ""
    valid = {s["tag"] for s in sources}
    cited = _extract_citations(text)
    invalid = sorted(set(cited) - valid)
    latency = time.perf_counter() - t0

    logger.info(
        f"prompt_version={SYSTEM_PROMPT_VERSION} "
        f"q={question!r} sources={len(sources)} cited={len(set(cited))} "
        f"invalid={invalid} latency={latency:.1f}s "
        f"tokens={resp.usage.prompt_tokens}+{resp.usage.completion_tokens}"
    )
    return RAGAnswer(
        question,
        text,
        sources,
        sorted(set(cited)),
        invalid,
        latency,
        resp.usage.prompt_tokens,
        resp.usage.completion_tokens,
    )
