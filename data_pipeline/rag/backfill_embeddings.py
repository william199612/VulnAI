from data_pipeline.shared.db import SessionLocal
from data_pipeline.models import CVE, CVENews
from data_pipeline.rag.embeddings import embed_texts
from data_pipeline.rag.text_builders import (
    build_cve_embedding_text,
    build_news_embedding_text,
)

from .config import BATCH_SIZE


def backfill_cve_embeddings():
    session = SessionLocal()
    try:
        total = 0
        while True:
            rows = (
                session.query(CVE)
                .filter(CVE.embedding.is_(None))
                .limit(BATCH_SIZE)
                .all()
            )
            if not rows:
                break

            texts = [build_cve_embedding_text(r) for r in rows]
            vectors = embed_texts(texts)

            for row, vec in zip(rows, vectors):
                row.embedding = vec

            session.commit()
            total += len(rows)
            print(f"Embedded {len(rows)} CVE rows (total {total})")
    finally:
        session.close()


def backfill_news_embeddings():
    session = SessionLocal()
    try:
        total = 0
        while True:
            rows = (
                session.query(CVENews)
                .filter(CVENews.embedding.is_(None))
                .limit(BATCH_SIZE)
                .all()
            )
            if not rows:
                break

            texts = [build_news_embedding_text(r) for r in rows]
            vectors = embed_texts(texts)

            for row, vec in zip(rows, vectors):
                row.embedding = vec

            session.commit()
            total += len(rows)
            print(f"Embedded {len(rows)} news rows (total {total})")
    finally:
        session.close()


if __name__ == "__main__":
    backfill_cve_embeddings()
    backfill_news_embeddings()
