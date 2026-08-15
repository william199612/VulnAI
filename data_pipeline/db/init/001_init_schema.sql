-- db/init/001_init_schema.sql

CREATE TABLE IF NOT EXISTS cve (
    cve_id            TEXT PRIMARY KEY,
    description       TEXT,
    cvss_score        NUMERIC,
    cvss_vector       TEXT,
    cwe               TEXT,
    affected_products TEXT[],
    published_date    TIMESTAMPTZ,
    modified_date     TIMESTAMPTZ,
    source            TEXT DEFAULT 'NVD',
    raw_references    JSONB,
    fetched_at        TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_news (
    id             SERIAL PRIMARY KEY,
    url            TEXT UNIQUE NOT NULL,
    title          TEXT,
    source_domain  TEXT,
    published_at   TIMESTAMPTZ,
    content        TEXT,
    crawl_method   TEXT CHECK (crawl_method IN ('static', 'dynamic')),
    fetched_at     TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cve_news_link (
    cve_news_id  INTEGER REFERENCES cve_news(id),
    cve_id       TEXT REFERENCES cve(cve_id),
    PRIMARY KEY (cve_news_id, cve_id)
);

CREATE TABLE IF NOT EXISTS sync_state (
    source          TEXT PRIMARY KEY,
    last_synced_at  TIMESTAMPTZ
);