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
the **abuse.ch ThreatFox** connector (IPs, domains, URLs, hashes with malware
context — needs `ABUSECH_AUTH_KEY`). The dashboard has a **Vulnerabilities** and
an **Indicators** tab, each with its own filter/sort/paginate grid.

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
