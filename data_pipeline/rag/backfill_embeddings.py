from sqlalchemy import select

from data_pipeline.shared.db import SessionLocal
from data_pipeline.shared.logging import get_logger
from data_pipeline.models import CVE, CVENews
from data_pipeline.rag.embeddings import embed_texts
from data_pipeline.rag.text_builders import (
    build_cve_embedding_text,
    build_news_embedding_text,
)

from .config import BATCH_SIZE, MAX_CONSECUTIVE_FAILURES

logger = get_logger("embed", "embed_backfill.log")


def _backfill(model, pk_column, build_text, label: str, batch_size: int = BATCH_SIZE):
    """
    Embed every row of `model` whose embedding is still NULL.

    Walks the table by primary key (keyset pagination) instead of re-querying
    "WHERE embedding IS NULL LIMIT n" each loop. Rows that are skipped or fail
    stay NULL, and a naive loop would fetch those same rows forever. Keyset
    pagination moves past them, so every run terminates, and the next
    scheduled run retries whatever is still NULL.
    """
    session = SessionLocal()
    last_pk = None
    embedded = skipped_empty = failed_rows = consecutive_failures = 0

    try:
        while True:
            stmt = (
                select(model)
                .where(model.embedding.is_(None))
                .order_by(pk_column)
                .limit(batch_size)
            )
            if last_pk is not None:
                stmt = stmt.where(pk_column > last_pk)

            rows = session.scalars(stmt).all()
            if not rows:
                break

            # capture before commit/rollback expires the row objects
            last_pk = getattr(rows[-1], pk_column.key)

            candidates = []
            for row in rows:
                text = build_text(row)
                if text:
                    candidates.append((row, text))
                else:
                    skipped_empty += 1  # the embeddings API rejects empty input
            if not candidates:
                continue

            try:
                vectors = embed_texts([text for _, text in candidates])
                if len(vectors) != len(candidates):
                    raise ValueError(
                        f"expected {len(candidates)} vectors, got {len(vectors)}"
                    )
                for (row, _), vec in zip(candidates, vectors):
                    row.embedding = vec
                session.commit()
            except Exception as e:
                session.rollback()
                failed_rows += len(candidates)
                consecutive_failures += 1
                logger.error(
                    f"[{label}] batch of {len(candidates)} failed "
                    f"({consecutive_failures}/{MAX_CONSECUTIVE_FAILURES} in a row): {e}"
                )
                if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    logger.error(f"[{label}] aborting run, will retry next schedule")
                    break
                continue

            consecutive_failures = 0
            embedded += len(candidates)
            logger.info(
                f"[{label}] embedded {len(candidates)} rows (run total {embedded})"
            )
    finally:
        session.close()

    logger.info(
        f"[{label}] done: {embedded} embedded, {skipped_empty} skipped (empty text), "
        f"{failed_rows} failed (left NULL for the next run)"
    )
    return embedded


def backfill_cve_embeddings():
    return _backfill(CVE, CVE.cve_id, build_cve_embedding_text, "cve")


def backfill_news_embeddings():
    return _backfill(CVENews, CVENews.id, build_news_embedding_text, "cve_news")
