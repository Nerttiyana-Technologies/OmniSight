import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import cors from "@fastify/cors";
import {
  NewSourceSchema, SourceSchema, type Source,
  vulnerabilitiesToCsv, indicatorsToCsv, indicatorsToStix, indicatorsToBlocklist,
} from "@omnisight/shared";
import { createRepository, composeDigest } from "@omnisight/db";
import {
  cisaKevConnector, resolveConnector, resolveIndicatorConnector, resolveAdvisoryConnector,
  seedSources, fetchEpss,
} from "@omnisight/connectors";

// Load the repo-root .env (pnpm runs scripts from the package dir, so resolve up).
const envFile = fileURLToPath(new URL("../../../.env", import.meta.url));
if (existsSync(envFile) && typeof process.loadEnvFile === "function") process.loadEnvFile(envFile);

const repo = createRepository();
const usingPostgres = Boolean(process.env.DATABASE_URL);

async function bootstrap() {
  await repo.init();

  // Seed source registry.
  for (const s of seedSources) await repo.upsertSource(s);

  // Zero-dependency demo: with no Postgres, seed the in-memory store from the
  // bundled CISA KEV fixture so the dashboard has data on first load.
  if (!usingPostgres) {
    const { readFileSync } = await import("node:fs");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    const fixturePath = join(here, "../../../packages/connectors/fixtures/cisa-kev.sample.json");
    try {
      const fixture = JSON.parse(readFileSync(fixturePath, "utf8"));
      const vulns = await cisaKevConnector.fetchVulnerabilities({ fixture });
      await repo.upsertVulnerabilities(vulns);
      await repo.signalChange("seed");
      app.log.info(`seeded ${vulns.length} demo vulnerabilities (in-memory mode)`);
    } catch (e) {
      app.log.warn(`could not seed demo data: ${(e as Error).message}`);
    }
  }
}

const app = Fastify({ logger: true });
await app.register(cors, { origin: true });

// --- Server-Sent Events: push an "update" the instant data changes ---
const sseClients = new Set<import("node:http").ServerResponse>();

function broadcast(payload: string) {
  const msg = `data: ${JSON.stringify({ changed: true, source: payload, at: Date.now() })}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(msg);
    } catch {
      sseClients.delete(res);
    }
  }
}

app.get("/api/stream", (req, reply) => {
  reply.hijack();
  const res = reply.raw;
  res.writeHead(200, {
    "content-type": "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  });
  res.write("retry: 5000\n\n");
  sseClients.add(res);
  const keepAlive = setInterval(() => res.write(": ping\n\n"), 25000);
  req.raw.on("close", () => {
    clearInterval(keepAlive);
    sseClients.delete(res);
  });
});

app.get("/health", async () => ({ ok: true, store: usingPostgres ? "postgres" : "memory" }));

app.get("/api/stats", async () => repo.stats());

app.get("/api/map", async () => repo.mapData());

app.get("/api/map/indicators", async (req) => {
  const code = (req.query as { code?: string }).code;
  if (!code) return [];
  return repo.mapIndicators(code, 500);
});

app.get("/api/digest", async (req, reply) => {
  const digest = await composeDigest(repo);
  const format = (req.query as { format?: string }).format;
  if (format === "md") {
    return reply.header("content-type", "text/markdown; charset=utf-8").send(digest.markdown);
  }
  if (format === "html") {
    return reply
      .header("content-type", "text/html; charset=utf-8")
      .header("content-disposition", 'inline; filename="omnisight-brief.html"')
      .send(digest.html);
  }
  return digest;
});

app.get("/api/vulnerabilities", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(200, Math.max(1, Number(q.pageSize ?? 50)));
  const terms = q.myStack === "true" ? await repo.listWatchlist() : undefined;
  const result = await repo.page({
    limit: pageSize,
    offset: (page - 1) * pageSize,
    minRisk: q.minRisk ? Number(q.minRisk) : undefined,
    q: q.q || undefined,
    vendor: q.vendor || undefined,
    source: q.source || undefined,
    exploited: q.exploited === "true" ? true : undefined,
    ransomware: q.ransomware === "true" ? true : undefined,
    terms,
    sort: q.sort || undefined,
    dir: q.dir === "asc" ? "asc" : q.dir === "desc" ? "desc" : undefined,
  });
  return { ...result, page, pageSize };
});

app.get("/api/vulnerabilities/export", async (req, reply) => {
  const q = req.query as Record<string, string | undefined>;
  const terms = q.myStack === "true" ? await repo.listWatchlist() : undefined;
  const { items } = await repo.page({
    limit: 10000, offset: 0,
    minRisk: q.minRisk ? Number(q.minRisk) : undefined,
    q: q.q || undefined, vendor: q.vendor || undefined, source: q.source || undefined,
    exploited: q.exploited === "true" ? true : undefined,
    ransomware: q.ransomware === "true" ? true : undefined,
    terms,
    sort: q.sort || undefined,
    dir: q.dir === "asc" ? "asc" : q.dir === "desc" ? "desc" : undefined,
  });
  return reply
    .header("content-type", "text/csv; charset=utf-8")
    .header("content-disposition", 'attachment; filename="omnisight-vulnerabilities.csv"')
    .send(vulnerabilitiesToCsv(items));
});

app.get("/api/indicators/export", async (req, reply) => {
  const q = req.query as Record<string, string | undefined>;
  const format = q.format ?? "csv";
  const { items } = await repo.pageIndicators({
    limit: 10000, offset: 0,
    type: q.type || undefined, malware: q.malware || undefined, q: q.q || undefined,
    source: q.source || undefined, sort: q.sort || undefined,
    dir: q.dir === "asc" ? "asc" : q.dir === "desc" ? "desc" : undefined,
  });
  if (format === "stix") {
    return reply
      .header("content-type", "application/json")
      .header("content-disposition", 'attachment; filename="omnisight-indicators.stix.json"')
      .send(indicatorsToStix(items));
  }
  if (format === "blocklist") {
    return reply
      .header("content-type", "text/plain; charset=utf-8")
      .header("content-disposition", 'attachment; filename="omnisight-blocklist.txt"')
      .send(indicatorsToBlocklist(items));
  }
  return reply
    .header("content-type", "text/csv; charset=utf-8")
    .header("content-disposition", 'attachment; filename="omnisight-indicators.csv"')
    .send(indicatorsToCsv(items));
});

app.get("/api/indicators", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(200, Math.max(1, Number(q.pageSize ?? 50)));
  const result = await repo.pageIndicators({
    limit: pageSize,
    offset: (page - 1) * pageSize,
    type: q.type || undefined,
    malware: q.malware || undefined,
    q: q.q || undefined,
    source: q.source || undefined,
    sort: q.sort || undefined,
    dir: q.dir === "asc" ? "asc" : q.dir === "desc" ? "desc" : undefined,
  });
  return { ...result, page, pageSize };
});

// --- My Stack watchlist ---
app.get("/api/watchlist", async () => repo.listWatchlist());

app.post("/api/watchlist", async (req, reply) => {
  const body = req.body as { term?: string };
  if (!body.term || !body.term.trim()) return reply.status(400).send({ error: "term required" });
  await repo.addWatchTerm(body.term);
  await repo.signalChange("watchlist");
  return repo.listWatchlist();
});

app.delete("/api/watchlist/:term", async (req) => {
  const { term } = req.params as { term: string };
  await repo.removeWatchTerm(decodeURIComponent(term));
  await repo.signalChange("watchlist");
  return repo.listWatchlist();
});

app.get("/api/advisories", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(200, Math.max(1, Number(q.pageSize ?? 30)));
  const result = await repo.pageAdvisories({
    limit: pageSize,
    offset: (page - 1) * pageSize,
    source: q.source || undefined,
    q: q.q || undefined,
  });
  return { ...result, page, pageSize };
});

app.get("/api/sources", async () => repo.listSources());

/**
 * Admin: register a new feed at runtime — no code, no redeploy.
 * Built-in connectors handle high-value feeds; `kind: "json"` sources are
 * driven entirely by this config via the generic connector.
 */
app.post("/api/sources", async (req, reply) => {
  const parsed = NewSourceSchema.safeParse(req.body);
  if (!parsed.success) {
    return reply.status(400).send({ error: parsed.error.flatten() });
  }
  const data = parsed.data;
  const id = data.id ?? slugify(data.name);
  const source: Source = SourceSchema.parse({ ...data, id });
  await repo.upsertSource(source);
  return reply.status(201).send(source);
});

/** Admin: trigger an immediate fetch for a source (otherwise it runs on schedule). */
app.post("/api/sources/:id/run", async (req, reply) => {
  const { id } = req.params as { id: string };
  const source = (await repo.listSources()).find((s) => s.id === id);
  if (!source) return reply.status(404).send({ error: "source not found" });
  try {
    if (source.signalType === "indicator") {
      const connector = resolveIndicatorConnector(source);
      const iocs = await connector.fetchIndicators({
        credentials: {
          authKey: process.env.ABUSECH_AUTH_KEY?.trim() || undefined,
          otxApiKey: process.env.OTX_API_KEY?.trim() || undefined,
        },
      });
      const n = await repo.upsertIndicators(iocs);
      await repo.signalChange(id);
      return { source: id, ingested: n };
    }
    if (source.signalType === "advisory") {
      const connector = resolveAdvisoryConnector(source);
      const items = await connector.fetchAdvisories();
      const n = await repo.upsertAdvisories(items);
      await repo.signalChange(id);
      return { source: id, ingested: n };
    }
    const connector = resolveConnector(source);
    const vulns = await connector.fetchVulnerabilities({
      credentials: {
        authKey: process.env.ABUSECH_AUTH_KEY?.trim() || undefined,
        nvdApiKey: process.env.NVD_API_KEY?.trim() || undefined,
      },
    });
    const n = await repo.upsertVulnerabilities(vulns);
    await repo.signalChange(id);
    return { source: id, ingested: n };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

/**
 * Enrich tracked CVEs with EPSS scores (keyless, bulk, fast). Lets the no-worker
 * demo pull live exploit-probability scores on demand. NVD/CVSS enrichment runs
 * in the worker because it's rate-limited.
 */
app.post("/api/enrich", async (_req, reply) => {
  try {
    const ids = await repo.distinctCveIds("epss", 500);
    if (ids.length === 0) return { enriched: 0 };
    const scores = await fetchEpss(ids);
    const n = await repo.enrich(scores.map((s) => ({ cveId: s.cveId, epss: s.epss })));
    await repo.signalChange("epss");
    return { enriched: n };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

function slugify(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}

const port = Number(process.env.API_PORT ?? 4000);
await bootstrap();
// Fan every change signal (from this API, or a worker NOTIFY in Postgres mode)
// out to all connected SSE clients.
await repo.subscribeChanges((payload) => broadcast(payload));
await app.listen({ port, host: "0.0.0.0" });
