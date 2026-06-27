import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Queue, Worker, type Job } from "bullmq";
import IORedis from "ioredis";
import nodemailer from "nodemailer";
import { createRepository, composeDigest } from "@omnisight/db";
import type { Digest } from "@omnisight/shared";
import {
  resolveConnector, resolveIndicatorConnector, resolveAdvisoryConnector,
  seedSources, fetchEpss, fetchNvdCvss, fetchGeo, sleep,
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
    // Stable jobId so repeated restarts don't stack duplicate immediate runs.
    await queue.add(source.id, { sourceId: source.id }, { jobId: `now-${source.id}`, removeOnComplete: true });
  }

  // Enrichment: every 30 min, plus once shortly after the initial ingest.
  await queue.add("enrich", {}, {
    repeat: { pattern: "*/30 * * * *" },
    jobId: "repeat:enrich",
    removeOnComplete: 20,
    removeOnFail: 20,
  });
  await queue.add("enrich", {}, { delay: 8000, jobId: "now-enrich", removeOnComplete: true });

  // Geolocation: every 15 min, plus shortly after the first indicator ingest.
  await queue.add("geo", {}, {
    repeat: { pattern: "*/15 * * * *" },
    jobId: "repeat:geo",
    removeOnComplete: 10,
    removeOnFail: 10,
  });
  await queue.add("geo", {}, { delay: 20000, jobId: "now-geo", removeOnComplete: true });

  // Daily brief at 07:00.
  await queue.add("digest", {}, {
    repeat: { pattern: "0 7 * * *" },
    jobId: "repeat:digest",
    removeOnComplete: 5,
    removeOnFail: 5,
  });
  // Opt-in: send one brief shortly after start to test the email setup.
  if (process.env.DIGEST_ON_START === "true") {
    await queue.add("digest", {}, { delay: 30000, jobId: "now-digest", removeOnComplete: true });
  }

  console.log(`[worker] scheduled ${sources.length} source(s) + enrichment + daily brief`);
}

/** Email the daily brief if SMTP is configured (no-op otherwise). */
async function sendDigestEmail(d: Digest): Promise<void> {
  const host = process.env.SMTP_HOST?.trim();
  const to = process.env.DIGEST_TO?.trim();
  if (!host || !to) {
    console.log("[worker] digest email: SMTP_HOST/DIGEST_TO not set — skipping send");
    return;
  }
  const transport = nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER.trim(), pass: (process.env.SMTP_PASS ?? "").trim() }
      : undefined,
  });
  await transport.sendMail({
    from: process.env.SMTP_FROM?.trim() || process.env.SMTP_USER?.trim() || "omnisight@localhost",
    to,
    subject: `OmniSight Daily Brief — ${d.date}`,
    html: d.html,
    text: d.markdown,
  });
  console.log(`[worker] digest email sent to ${to}`);
}

let enrichRunning = false;
let geoRunning = false;

/** Enrich tracked CVEs with EPSS (bulk) and CVSS from NVD (throttled). */
async function runEnrichment(): Promise<void> {
  if (enrichRunning) { console.log("[worker] enrich: already running, skipping"); return; }
  enrichRunning = true;
  try {
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
  } finally {
    enrichRunning = false;
  }
}

/** Geolocate IP indicators (keyless ipwho.is; throttled). Its own job so the
 *  map populates quickly without waiting on the slow NVD loop. */
async function runGeo(): Promise<void> {
  if (geoRunning) { console.log("[worker] geo: already running, skipping"); return; }
  geoRunning = true;
  try {
    let ips: string[] = [];
    try {
      ips = await repo.ipsNeedingGeo(150);
    } catch (e) {
      console.error(`[worker] geo: query failed — ${(e as Error).message}`);
      return;
    }
    console.log(`[worker] geo: ${ips.length} IP(s) to locate`);
    if (ips.length === 0) return;
    let located = 0;
    let failed = 0;
    let firstErr = "";
    for (const ip of ips) {
      try {
        const geo = await fetchGeo(ip);
        if (geo) { await repo.setGeo(ip, geo); located++; }
        else failed++;
      } catch (e) {
        failed++;
        if (!firstErr) firstErr = (e as Error).message;
      }
      await sleep(350);
    }
    console.log(`[worker] geo: located ${located}, failed ${failed}${firstErr ? ` (${firstErr})` : ""}`);
    if (located) await repo.signalChange("geo");
  } finally {
    geoRunning = false;
  }
}

new Worker(
  QUEUE,
  async (job: Job<{ sourceId?: string }>) => {
    if (job.name === "enrich") {
      await runEnrichment();
      return { enriched: true };
    }
    if (job.name === "geo") {
      await runGeo();
      return { ok: true };
    }
    if (job.name === "digest") {
      const d = await composeDigest(repo);
      console.log(`[worker] daily brief — ${d.headline}`);
      await sendDigestEmail(d).catch((e) => console.warn(`[worker] digest email failed: ${(e as Error).message}`));
      return { ok: true };
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
      // Kick a geo pass now that fresh IPs have landed (avoids racing the timer).
      if (n > 0) await queue.add("geo", {}, { removeOnComplete: true, jobId: `geo-after-${source.id}` });
      return { ingested: n };
    }

    if (source.signalType === "advisory") {
      const connector = resolveAdvisoryConnector(source);
      const items = await connector.fetchAdvisories({ credentials });
      const n = await repo.upsertAdvisories(items);
      await repo.signalChange(source.id);
      console.log(`[worker] ${source.id}: ingested ${n} advisory item(s)`);
      return { ingested: n };
    }

    const connector = resolveConnector(source);
    const vulns = await connector.fetchVulnerabilities({ credentials });
    const n = await repo.upsertVulnerabilities(vulns);
    await repo.signalChange(source.id); // wakes the API's SSE stream
    console.log(`[worker] ${source.id}: ingested ${n}`);
    return { ingested: n };
  },
  // Concurrency >1 so the quick jobs (geo, news, ingest) aren't blocked behind
  // the slow NVD enrichment loop. lockDuration covers multi-minute jobs.
  { connection, concurrency: 4, lockDuration: 120000 },
);

await scheduleAll();
console.log("[worker] running");
