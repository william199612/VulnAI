"""Manual retrieval check: run a fixed set of questions and save the results.

    uv run python -m data_pipeline.rag.try_retriever
    uv run python -m data_pipeline.rag.try_retriever --out retrieval_samples.md

Read the output by eye. For each question, are the top results relevant, and do
the similarity scores clearly separate good matches from bad ones? Keep the
saved file: these questions are the seed of the Phase 5 evaluation set.
"""

import argparse
from datetime import datetime

from sqlalchemy import func, select

from data_pipeline.models import CVE
from data_pipeline.rag.retriever import retrieve
from data_pipeline.shared.db import SessionLocal

QUESTIONS = [
    # broad
    "Apache vulnerabilities",
    "critical remote code execution vulnerabilities",
    # conceptual
    "memory corruption that allows remote code execution",
    "authentication bypass in a web application",
    "SQL injection in a content management system",
    # product / ecosystem
    "WordPress plugin flaws",
    "Linux kernel privilege escalation",
    # news-style
    "vulnerabilities exploited in the wild",
    "zero-day advisories from vendors",
]


def _random_cve_id() -> str | None:
    with SessionLocal() as session:
        return session.scalar(
            select(CVE.cve_id)
            .where(CVE.embedding.is_not(None))
            .order_by(func.random())
            .limit(1)
        )


def _short(text: str | None, n: int = 110) -> str:
    return " ".join((text or "").split())[:n]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="retrieval_samples.md")
    parser.add_argument("--top-k", type=int, default=5)
    args = parser.parse_args()

    questions = list(QUESTIONS)
    cve_id = _random_cve_id()
    if cve_id:
        # exact-ID case: the named CVE should come back first
        questions.append(f"Tell me about {cve_id}")

    lines = [f"# Retrieval samples ({datetime.now():%Y-%m-%d %H:%M})", ""]

    for q in questions:
        result = retrieve(q, args.top_k, args.top_k)

        print(f"\n=== {q}")
        lines += [f"## {q}", "", "**CVEs**", ""]

        print("  CVEs:")
        for h in result["cves"]:
            tag = " [exact]" if h.exact_match else ""
            cvss = h.cvss_score if h.cvss_score is not None else "-"
            print(
                f"   {h.similarity:.3f}{tag} {h.cve_id} (CVSS {cvss}) {_short(h.description)}"
            )
            lines.append(
                f"- {h.similarity:.3f}{tag} `{h.cve_id}` (CVSS {cvss}) {_short(h.description, 200)}"
            )

        print("  News:")
        lines += ["", "**News**", ""]
        for h in result["news"]:
            tag = " [exact]" if h.exact_match else ""
            print(
                f"   {h.similarity:.3f}{tag} [{h.source_domain}] {_short(h.title, 90)}"
            )
            lines.append(
                f"- {h.similarity:.3f}{tag} [{h.source_domain}] {_short(h.title, 200)} <{h.url}>"
            )
        lines.append("")

    with open(args.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"\nSaved to {args.out}")


if __name__ == "__main__":
    main()
