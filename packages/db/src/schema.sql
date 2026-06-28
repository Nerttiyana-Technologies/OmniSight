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
  reliability   TEXT NOT NULL DEFAULT 'C',
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
  country         TEXT,
  country_code    TEXT,
  lat             DOUBLE PRECISION,
  lng             DOUBLE PRECISION,
  fetched_at      TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (source, id)
);

-- Self-migration: add reliability to sources created before it existed.
ALTER TABLE sources ADD COLUMN IF NOT EXISTS reliability TEXT NOT NULL DEFAULT 'C';

-- Self-migration: add geo columns to indicators tables created before they existed.
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS country      TEXT;
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS country_code TEXT;
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS lat          DOUBLE PRECISION;
ALTER TABLE indicators ADD COLUMN IF NOT EXISTS lng          DOUBLE PRECISION;

CREATE INDEX IF NOT EXISTS idx_ioc_lastseen   ON indicators (last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_type       ON indicators (type);
CREATE INDEX IF NOT EXISTS idx_ioc_malware    ON indicators (malware);
CREATE INDEX IF NOT EXISTS idx_ioc_value      ON indicators (value);
CREATE INDEX IF NOT EXISTS idx_ioc_country    ON indicators (country_code);

CREATE TABLE IF NOT EXISTS advisories (
  id          TEXT NOT NULL,
  source      TEXT NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
  title       TEXT NOT NULL,
  summary     TEXT NOT NULL DEFAULT '',
  url         TEXT NOT NULL DEFAULT '',
  category    TEXT,
  published   TIMESTAMPTZ,
  tags        JSONB NOT NULL DEFAULT '[]',
  fetched_at  TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (source, id)
);

CREATE INDEX IF NOT EXISTS idx_adv_published ON advisories (published DESC);
CREATE INDEX IF NOT EXISTS idx_adv_source    ON advisories (source);

-- "My Stack": software/vendors the user runs. A vuln is "in stack" when its
-- vendor, product, or title matches one of these terms.
CREATE TABLE IF NOT EXISTS watchlist (
  term       TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Records which stack-affecting vulns have already been alerted (dedupe).
CREATE TABLE IF NOT EXISTS alert_log (
  id         TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Analyst investigation notes attached to a CVE or IOC (ref = "cve:..."/"ioc:...").
CREATE TABLE IF NOT EXISTS notes (
  id         TEXT PRIMARY KEY,
  ref        TEXT NOT NULL,
  tlp        TEXT NOT NULL DEFAULT 'amber' CHECK (tlp IN ('clear','green','amber','red')),
  body       TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notes_ref ON notes (ref);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('viewer','analyst','admin')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Analyst feedback: a verdict on a CVE or IOC ref ("cve:..."/"ioc:...").
CREATE TABLE IF NOT EXISTS feedback (
  ref        TEXT PRIMARY KEY,
  verdict    TEXT NOT NULL CHECK (verdict IN ('confirmed','false_positive')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Saved searches: named filter sets for the vuln/IOC grids.
CREATE TABLE IF NOT EXISTS saved_searches (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  kind       TEXT NOT NULL CHECK (kind IN ('vuln','ioc')),
  params     JSONB NOT NULL DEFAULT '{}',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Automation rules: when a vuln matches the trigger, run the action.
CREATE TABLE IF NOT EXISTS rules (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  enabled        BOOLEAN NOT NULL DEFAULT TRUE,
  min_risk       INTEGER NOT NULL DEFAULT 75,
  exploited_only BOOLEAN NOT NULL DEFAULT FALSE,
  stack_only     BOOLEAN NOT NULL DEFAULT TRUE,
  action         TEXT NOT NULL CHECK (action IN ('webhook','email','jira')),
  config         JSONB NOT NULL DEFAULT '{}',
  created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Breach / leaked-credential exposure for monitored domains (Have I Been Pwned).
CREATE TABLE IF NOT EXISTS breaches (
  id           TEXT PRIMARY KEY,
  domain       TEXT NOT NULL,
  title        TEXT NOT NULL,
  breach_date  DATE,
  added_date   TIMESTAMPTZ,
  pwn_count    BIGINT NOT NULL DEFAULT 0,
  data_classes JSONB NOT NULL DEFAULT '[]',
  description  TEXT NOT NULL DEFAULT '',
  verified     BOOLEAN NOT NULL DEFAULT FALSE,
  fetched_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_breaches_domain ON breaches (domain);

-- Audit trail: who did what (mutating actions), for security/compliance review.
CREATE TABLE IF NOT EXISTS audit_log (
  id         TEXT PRIMARY KEY,
  at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  username   TEXT,
  role       TEXT,
  action     TEXT NOT NULL,
  method     TEXT NOT NULL,
  path       TEXT NOT NULL,
  status     INTEGER
);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_log (at DESC);
