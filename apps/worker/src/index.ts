import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Queue, Worker, type Job } from "bullmq";
import IORedis from "ioredis";
import { createRepository } from "@omnisight/db";
import {
  resolveConnector, resolveIndicatorConnector, seedSources, fetchEpss, fetchNvdCvss, sleep,
} from "@omnisight/connectors";

// Load the repo-root .env so DATABASE_URL/REDIS_URL match the API process.
const envFile = fileURLToPath(new URL("../../../.env", import.meta.url));
if (existsSync(envFile) && typeof process.loadEnvFile === "function") process.loadEnvFile(envFile);

/**
 * Ingestion worker.
 * - Reads the source registry from the DB (admin-managed feeds included).
 * - Schedules each enabled source on its cron via a BullMQ repeatable job.
 * - On each run: resolve connector -> fetch -> normalize -> upsert into Postgres.
 */
const connection = new IORedis(process.env.REDIS_URL ?? "redis://localhost:6379", {
  maxRetriesPerRequest: null,
});
const repo = createRepository();
const QUEUE = "ingest";

const queue = new Queue(QUEUE, { connection });

async function scheduleAll() {
  await repo.init();
  for (const s of seedSources) await repo.upsertSource(s);

  const sources = (await repo.listSources()).filter((s) => s.enabled);
  for (const source of sources) {
    await queue.add(
      source.id,
      { sourceId: source.id },
      {
        repeat: { pattern: source.schedule },
        jobId: `repeat:${source.id}`,
        removeOnComplete: 50,
        removeOnFail: 50,
      },
    );
    // Kick an immediate first run so data lands without waiting for the cron.
    await queue.add(source.id, { sourceId: source.id }, { removeOnComplete: true });
  }

  // Enrichment: every 30 min, plus once shortly after the initial ingest.
  await queue.add("enrich", {}, {
    repeat: { pattern: "*/30 * * * *" },
    jobId: "repeat:enrich",
    removeOnComplete: 20,
    removeOnFail: 20,
  });
  await queue.add("enrich", {}, { delay: 8000, removeOnComplete: true });

  console.log(`[worker] scheduled ${sources.length} source(s) + enrichment`);
}

/** Enrich tracked CVEs with EPSS (bulk) and CVSS from NVD (throttled). */
async function runEnrichment(): Promise<void> {
  // EPSS — keyless, up to 100 CVEs/request.
  const epssIds = await repo.distinctCveIds("epss", 500);
  if (epssIds.length) {
    const scores = await fetchEpss(epssIds);
    const n = await repo.enrich(scores.map((s) => ({ cveId: s.cveId, epss: s.epss })));
    if (n) {
      await repo.signalChange("epss");
      console.log(`[worker] epss: enriched ${n} record(s)`);
    }
  }

  // NVD — one CVE per request; respect the rate limit (50/30s with key, 5/30s without).
  const apiKey = process.env.NVD_API_KEY?.trim() || undefined;
  const delayMs = apiKey ? 700 : 6500;
  const nvdCap = apiKey ? 200 : 25; // a key raises the rate limit 10x, so backfill faster
  const nvdIds = await repo.distinctCveIds("cvss", nvdCap);
  const patches: { cveId: string; cvss: number }[] = [];
  for (const cveId of nvdIds) {
    try {
      const cvss = await fetchNvdCvss(cveId, { apiKey });
      if (cvss != null) patches.push({ cveId, cvss });
    } catch (e) {
      console.warn(`[worker] nvd ${cveId}: ${(e as Error).message}`);
    }
    await sleep(delayMs);
  }
  if (patches.length) {
    const n = await repo.enrich(patches);
    await repo.signalChange("nvd");
    console.log(`[worker] nvd: enriched ${n} record(s)`);
  }
}

new Worker(
  QUEUE,
  async (job: Job<{ sourceId?: string }>) => {
    if (job.name === "enrich") {
      await runEnrichment();
      return { enriched: true };
    }
    const source = (await repo.listSources()).find((s) => s.id === job.data.sourceId);
    if (!source) throw new Error(`source ${job.data.sourceId} not found`);
    const credentials = {
      authKey: process.env.ABUSECH_AUTH_KEY?.trim() || undefined,
      nvdApiKey: process.env.NVD_API_KEY?.trim() || undefined,
      otxApiKey: process.env.OTX_API_KEY?.trim() || undefined,
    };

    if (source.signalType === "indicator") {
      const connector = resolveIndicatorConnector(source);
      const iocs = await connector.fetchIndicators({ credentials });
      const n = await repo.upsertIndicators(iocs);
      await repo.signalChange(source.id);
      console.log(`[worker] ${source.id}: ingested ${n} IOC(s)`);
      return { ingested: n };
    }

    const connector = resolveConnector(source);
    const vulns = await connector.fetchVulnerabilities({ credentials });
    const n = await repo.upsertVulnerabilities(vulns);
    await repo.signalChange(source.id); // wakes the API's SSE stream
    console.log(`[worker] ${source.id}: ingested ${n}`);
    return { ingested: n };
  },
  { connection },
);

await scheduleAll();
console.log("[worker] running");
