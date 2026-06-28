# OmniSight

**Open-source real-time cyber situational-awareness platform.** OmniSight fuses
vulnerability, exploitation, and threat-actor signals into one correlated,
glanceable dashboard — self-hostable in minutes, no heavyweight search cluster
required.

> Think "WorldMonitor for cyber": fast, opinionated, and easy to run — the
> lightweight alternative to OpenCTI/MISP for teams who want to *see what's on
> fire right now*, then drill in.

Licensed under **Apache-2.0**.

---

## Status

Phase 0 scaffold — a working vertical slice. Two built-in connectors —
**CISA KEV** (known-exploited vulns) and **NVD Recent CVEs** — ingest live data,
which is enriched with **EPSS** (exploit probability) and **NVD CVSS**, scored,
and streamed to an executive dashboard (dark/light) that updates in real time.
The grid supports server-side filtering, sorting, and pagination over the full
dataset.

The same CVE can appear from multiple sources (e.g. a CVE in both KEV and NVD);
records are keyed on `(source, id)` so each is preserved, and enrichment applies
to all of them — the seed of cross-source correlation.

Beyond vulnerabilities, OmniSight also ingests **indicators of compromise** via
the **abuse.ch ThreatFox**, **AlienVault OTX**, and **Pulsedive** connectors (IPs,
domains, URLs, hashes with malware context — need `ABUSECH_AUTH_KEY` /
`OTX_API_KEY` / `PULSEDIVE_API_KEY`). Pulsedive uses its **free REST Explore API**
(a free key works; the paid TAXII server isn't required). The
dashboard has a **Vulnerabilities** and an **Indicators** tab, each with its own
filter/sort/paginate grid.

### My Stack

Declare the vendors and products you run (the **My Stack** panel). CVEs whose
vendor, product, or title match are flagged in the grid, filterable with
"My Stack only", and counted in a dedicated stat card — turning the global feed
into "what affects *us*". Matching is server-side, so it scales and paginates.

### News & AI threats

A **News** tab ingests security news and advisories via an RSS connector
(**The Hacker News**, **Dark Reading**, **SecurityWeek — AI**) plus **MITRE
ATLAS** (the authoritative adversarial-ML knowledge base, via its STIX 2.1
bundle). Items render as cards with source, date, and summary, filterable by
source and search. New RSS feeds can be added at runtime as `kind: "rss"`
sources — no code required.

### Auth & roles (opt-in)

Off by default (open). Set `AUTH_ENABLED=true` + `JWT_SECRET` and seed an admin
(`ADMIN_USER`/`ADMIN_PASS`) to require login. Three roles — **viewer** (read-only),
**analyst** (notes, watchlist, enrich, import), **admin** (+ manage sources &
users). Local username/password (scrypt-hashed) with JWTs; RBAC enforced
server-side and reflected in the UI. **SSO** is supported via a generic OIDC
authorization-code flow — set the `OIDC_*` vars to show a "Sign in with SSO"
button; first-time users are auto-provisioned as viewers. An **audit log**
(admin-only) records mutating actions and logins for compliance review.

### AI layer (optional, local-first)

Point OmniSight at any OpenAI-compatible endpoint — including a **local Ollama**
(`LLM_BASE_URL=http://localhost:11434/v1`, no key, nothing leaves your machine).
Two features light up when configured: a **Summarize** button on any CVE that
turns the raw advisory into a 2–3 sentence SOC-ready brief, and an **Ask AI**
box that translates a natural-language question ("exploited Cisco bugs, highest
risk first") into structured filters and runs them against the live data. The
model only ever produces *filters*; OmniSight executes the query, so results are
grounded in real records. Everything degrades gracefully when no LLM is set.

### Actor & campaign profiles

An **Actors** tab aggregates indicators by malware family / campaign into
profiles: IOC counts by type, contributing sources, first/last activity, and the
related CVEs and ATT&CK/ATLAS techniques extracted from their intel — with
sample IOCs you can pivot into enrichment. Assembled entirely from ingested
feeds, so it grows as you connect more sources.

### SOAR-lite ticketing & automation rules

Beyond webhook and email alerts, the worker can **open a Jira issue per
stack-affecting vulnerability** (`JIRA_*` vars, Jira Cloud REST v2) — turning
"a KEV just hit my stack" into an actionable, de-duplicated ticket automatically.
For finer control, admins define **automation rules** in the dashboard: each rule
is a trigger (risk threshold, exploited-only, My-Stack-only) plus an action
(webhook / email / Jira). When any rule exists it replaces the env defaults, so
you can route, say, "exploited + my-stack → Jira" and "critical anywhere → Slack"
independently.

### TAXII 2.1 polling

Add a **TAXII** feed from the dashboard (or `POST /api/sources` with
`kind: "taxii"`): OmniSight polls the collection's objects endpoint on a schedule,
parses the STIX 2.1 bundle, and ingests the indicators — complementing the
existing STIX file import with live, scheduled pulls from OpenCTI / MISP / ISAC /
government TAXII servers. Bearer-token or basic auth, per feed.

### Breach exposure (Have I Been Pwned)

An **Exposure** tab monitors the domains you list in `HIBP_DOMAINS` for known
breaches via Have I Been Pwned — which breaches hit your brands, when, how many
accounts, and what data classes leaked. It pulls HIBP's **free public breaches
collection** (no API key, no subscription) and filters it to your domains
locally, rather than the paid domain-search API; the worker refreshes daily.
`HIBP_API_KEY` is optional and only raises rate limits.

### Map

A **Map** tab plots geolocated attack origins on a world projection. IP
indicators are geolocated (keyless ipwho.is) during the worker's enrichment
cycle; the map aggregates them by country with a Top Origins panel alongside.

### Overview & daily brief

An **Overview** command-center tab leads the dashboard: a DEFCON-style
**threat-level** header derived from current signal volume, plus the **Daily
Brief** — top risks, newly-added KEV, what's hitting your stack, and top
indicators. The brief renders as Markdown and as an **executive HTML email**
(`/api/digest?format=html`), and a worker job composes it automatically each
morning (07:00) — schedule-ready for delivery.

### Export / interop

Both grids export the **current filtered view**. Vulnerabilities export to CSV;
indicators export to **CSV**, a **STIX 2.1 bundle** (importable into OpenCTI /
MISP), a plain **blocklist** (IPs/domains/URLs/hashes) for firewalls and IDS, or
**Sigma detection rules** for your SIEM — so OmniSight pushes intel into the rest
of your stack rather than trapping it.

### Analyst workflow

- **IOC enrichment / pivoting** — click any IP to enrich live via Shodan
  InternetDB (ports, hostnames, host CVEs), plus GreyNoise/AbuseIPDB when keyed,
  with pivot links to VirusTotal/Shodan.
- **My Stack alerts** — the worker notifies (Slack-style webhook and/or email)
  when an exploited or high-risk CVE matches your stack; de-duplicated.
- **Investigation notes + TLP** — attach TLP-marked notes to any CVE or IOC.
- **ATT&CK techniques in intel** — ATT&CK/ATLAS technique IDs referenced across
  ingested advisories and indicators, ranked by frequency and linked out.

### Cross-source correlation

The Overview surfaces **CVE↔IOC correlations**: CVE references found inside
indicator tags/threat context are linked to tracked vulnerabilities (risk-ranked),
showing which CVEs the active indicators relate to. (Linkage is only as rich as
the feeds — IOC sources cite CVEs intermittently.) When an LLM is configured, an
**AI correlation** view goes further — reasoning over the top CVEs and indicators
to propose CVE↔IOC / campaign relationships with a confidence and rationale
(suggestions to verify, not ground truth).

### Daily brief email

When SMTP is configured (`SMTP_HOST` + `DIGEST_TO` in `.env`), the worker emails
the executive HTML brief each morning. Set `DIGEST_ON_START=true` to send a test
on boot.

### Real-time & enrichment

- **Live updates** — the dashboard subscribes to `GET /api/stream` (Server-Sent
  Events). When a feed ingests or enrichment runs, the change is pushed
  instantly; if the stream drops, the client falls back to 15s polling. In
  Postgres mode the worker signals the API via `LISTEN/NOTIFY`, so a separate
  worker process still pushes to connected dashboards.
- **EPSS** (keyless, bulk) runs in the worker every 30 min, and on demand via
  `POST /api/enrich` (the dashboard's gauge button) so the no-worker demo can
  pull live scores too.
- **NVD CVSS** runs in the worker, throttled to the rate limit. Set `NVD_API_KEY`
  in `.env` to raise it from 5→50 requests / 30s.

## Architecture

```
apps/web      React + Vite dashboard (executive dark/light theme, icon buttons + tooltips)
apps/api      Fastify REST API (+ admin "add feed" endpoints)
apps/worker   BullMQ ingestion worker (schedules connectors on cron)
packages/shared       Domain model + zod schemas + risk scoring (the shared language)
packages/connectors   Connector SDK + CISA KEV + generic config-driven JSON connector
packages/db           Repository: Postgres (prod) with an in-memory fallback (demo)
```

**Where data lives:** PostgreSQL is the system of record (sources + normalized
signals, with full-text search built in — no ElasticSearch needed at this
stage). Redis backs the job queue and short-lived caches. See
[`docs/STORAGE.md`](docs/STORAGE.md).

## Quick start

### Zero-dependency demo (no database)

```bash
pnpm install
pnpm start:api          # seeds demo data from the CISA KEV fixture (in-memory)
pnpm --filter @omnisight/web dev   # dashboard at http://localhost:5173
```

### Full stack (Postgres + Redis + live ingestion)

```bash
cp .env.example .env
docker compose up -d            # Postgres + Redis
pnpm install
pnpm start:api                  # API on :4000
pnpm start:worker               # ingests CISA KEV live, on a 6h cron
pnpm --filter @omnisight/web dev
```

### Verify the ingest pipeline without anything running

```bash
pnpm connector:dry-run --fixture   # offline, uses bundled sample
pnpm connector:dry-run             # live fetch from CISA
```

## Adding feeds (admin)

High-value feeds ship as built-in connectors. For the long tail, an admin can
register a feed at runtime — no code, no redeploy — via the dashboard's **Add
feed** panel or the API:

```bash
curl -X POST localhost:4000/api/sources -H 'content-type: application/json' -d '{
  "name": "Example CVE feed",
  "kind": "json",
  "signalType": "vulnerability",
  "url": "https://example.com/feed.json",
  "config": { "itemsPath": "vulnerabilities",
              "map": { "id": "cveID", "title": "name", "vendor": "vendorProject" } }
}'
```

The generic JSON connector fetches the URL, walks `itemsPath` to the array, and
maps fields into OmniSight's model.

## Docs

- [`docs/SPEC.md`](docs/SPEC.md) — product spec, positioning, roadmap
- [`docs/DATA_SOURCES.md`](docs/DATA_SOURCES.md) — feed catalog with access details
- [`docs/FEATURES.md`](docs/FEATURES.md) — feature backlog for security pros
- [`docs/STORAGE.md`](docs/STORAGE.md) — data storage model

## License

Apache-2.0 — see [LICENSE](LICENSE).
