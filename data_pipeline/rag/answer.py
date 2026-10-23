import re
import time
from datetime import datetime, timedelta, timezone
from typing import List

from data_pipeline.rag.config import (
    LLM_MODEL,
    NEWS_SNIPPET_CHARS,
    TEMPERATURE,
    MAX_REFERENCES,
)
from data_pipeline.rag.embeddings import get_client
from data_pipeline.rag.retriever import retrieve
from data_pipeline.rag.prompt import SYSTEM_PROMPT_VERSION, SYSTEM_PROMPT

from data_pipeline.schemas import RAGAnswer
from data_pipeline.shared.logging import get_logger

logger = get_logger("rag", "rag_answer.log")


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
        attrs = (
            f'id="{tag}" type="cve" cve_id="{cve.cve_id}" cvss="{cvss}" '
            f'published="{_date(cve.published_date)}" modified="{_date(cve.modified_date)}"'
        )
        if cve.cwe:
            attrs += f' cwe="{cve.cwe}"'
        if cve.cvss_vector:
            attrs += f' cvss_vector="{cve.cvss_vector}"'
        body = _clean(cve.description)
        if cve.references:
            body += "\nReferences: " + ", ".join(cve.references[:MAX_REFERENCES])
        blocks.append(f"<source {attrs}>\n{body}\n</source>")
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


def find_uncited_blocks(text: str) -> list[str]:
    """Top-level list items / paragraphs that state something but carry no [S#] tag.

    An unindented line starts a new block; indented lines (sub-bullets) belong
    to the block above, so a tag anywhere in an item covers the whole item.
    """
    blocks, cur = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line[0].isspace() and cur:
            blocks.append(cur)
            cur = []
        cur.append(line)
    if cur:
        blocks.append(cur)

    out = []
    for b in blocks:
        flat = " ".join(" ".join(b).split())
        if (
            len(flat) < 40
            or flat.endswith(":")
            or flat.startswith("The sources do not")
        ):
            continue
        if not re.search(r"\[S\d+\]", flat):
            out.append(flat)
    return out


def answer_question(
    question: str,
    *,
    history=None,
    search_query=None,
    top_k_cves: int = 5,
    top_k_news: int = 5,
    days=None,
    model=None,
) -> RAGAnswer:
    t0 = time.perf_counter()
    published_after = (
        datetime.now(timezone.utc) - timedelta(days=days) if days else None
    )

    result = retrieve(
        search_query or question,
        top_k_cves,
        top_k_news,
        published_after=published_after,
    )
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
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for q, a in history or []:  # earlier turns, tags already resolved
        messages += [
            {"role": "user", "content": q},
            {"role": "assistant", "content": a},
        ]
    messages.append(
        {
            "role": "user",
            "content": f"<sources>\n{context}\n</sources>\n\nQuestion: {question}",
        }
    )
    resp = get_client().chat.completions.create(
        model=model or LLM_MODEL,
        temperature=TEMPERATURE,
        messages=messages,
    )

    text = resp.choices[0].message.content or ""
    valid = {s["tag"] for s in sources}
    cited = _extract_citations(text)
    uncited = find_uncited_blocks(text)
    invalid = sorted(set(cited) - valid)
    latency = time.perf_counter() - t0

    logger.info(
        f"prompt_version={SYSTEM_PROMPT_VERSION} "
        f"q={question!r} sources={len(sources)} cited={len(set(cited))} uncited={len(uncited)} "
        f"invalid={invalid} latency={latency:.1f}s "
        f"tokens={resp.usage.prompt_tokens}+{resp.usage.completion_tokens}"
    )
    return RAGAnswer(
        question,
        text,
        sources,
        sorted(set(cited)),
        invalid,
        uncited,
        latency,
        resp.usage.prompt_tokens,
        resp.usage.completion_tokens,
    )
