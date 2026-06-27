-- OmniSight Postgres schema (Phase 0)
-- Postgres is the system of record. Redis (separate) handles the job queue and
-- short-lived caches. OpenSearch is an optional later add-on for scale, not now.

CREATE TABLE IF NOT EXISTS sources (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  kind          TEXT NOT NULL CHECK (kind IN ('builtin','rss','json','taxii')),
  signal_type   TEXT NOT NULL CHECK (signal_type IN ('vulnerability','indicator','actor','advisory')),
  url           TEXT,
  schedule      TEXT NOT NULL DEFAULT '0 */6 * * *',
  enabled       BOOLEAN NOT NULL DEFAULT TRUE,
  requires_auth BOOLEAN NOT NULL DEFAULT FALSE,
  config        JSONB NOT NULL DEFAULT '{}',
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_run_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id              TEXT NOT NULL,
  source          TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  cve_id          TEXT,
  title           TEXT NOT NULL,
  description     TEXT NOT NULL DEFAULT '',
  vendor          TEXT,
  product         TEXT,
  known_exploited BOOLEAN NOT NULL DEFAULT FALSE,
  ransomware_use  BOOLEAN NOT NULL DEFAULT FALSE,
  cvss            REAL,
  epss            REAL,
  cwes            JSONB NOT NULL DEFAULT '[]',
  required_action TEXT,
  due_date        DATE,
  date_added      DATE,
  references_json JSONB NOT NULL DEFAULT '[]',
  risk_score      INTEGER NOT NULL DEFAULT 0,
  fetched_at      TIMESTAMPTZ NOT NULL,
  -- A given CVE can appear from multiple sources; key on (source, id).
  PRIMARY KEY (source, id)
);

CREATE INDEX IF NOT EXISTS idx_vuln_risk    ON vulnerabilities (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_vuln_cve     ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_vendor  ON vulnerabilities (vendor);
-- Full-text search over title+description (Postgres FTS covers Phase 0; no ElasticSearch needed).
CREATE INDEX IF NOT EXISTS idx_vuln_fts
  ON vulnerabilities
  USING gin (to_tsvector('english', title || ' ' || description));

CREATE TABLE IF NOT EXISTS indicators (
  id              TEXT NOT NULL,
  source          TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  type            TEXT NOT NULL CHECK (type IN ('ip','domain','url','hash','other')),
  value           TEXT NOT NULL,
  malware         TEXT,
  threat_type     TEXT,
  confidence      INTEGER,
  references_json JSONB NOT NULL DEFAULT '[]',
  tags            JSONB NOT NULL DEFAULT '[]',
  first_seen      TIMESTAMPTZ,
  last_seen       TIMESTAMPTZ,
  fetched_at      TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (source, id)
);

CREATE INDEX IF NOT EXISTS idx_ioc_lastseen   ON indicators (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_type       ON indicators (type);
CREATE INDEX IF NOT EXISTS idx_ioc_malware    ON indicators (malware);
CREATE INDEX IF NOT EXISTS idx_ioc_value      ON indicators (value);

-- "My Stack": software/vendors the user runs. A vuln is "in stack" when its
-- vendor, product, or title matches one of these terms.
CREATE TABLE IF NOT EXISTS watchlist (
  term       TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
