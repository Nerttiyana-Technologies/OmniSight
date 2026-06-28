import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { Queue, Worker, type Job } from "bullmq";
import IORedis from "ioredis";
import nodemailer from "nodemailer";
import { createRepository, composeDigest } from "@omnisight/db";
import type { Digest, Vulnerability } from "@omnisight/shared";
import {
  resolveConnector, resolveIndicatorConnector, resolveAdvisoryConnector,
  seedSources, fetchEpss, fetchNvdCvss, fetchGeo, sleep, fetchBreaches,
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

  // Stack alerts: every 30 min (plus triggered after each vuln ingest).
  await queue.add("alerts", {}, {
    repeat: { pattern: "*/30 * * * *" },
    jobId: "repeat:alerts",
    removeOnComplete: 20,
    removeOnFail: 20,
  });

  // IOC decay: prune stale indicators daily at 04:00.
  await queue.add("decay", {}, {
    repeat: { pattern: "0 4 * * *" },
    jobId: "repeat:decay",
    removeOnComplete: 5,
    removeOnFail: 5,
  });

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

  // Breach exposure check daily at 05:00 (only does work when HIBP_DOMAINS set).
  if ((process.env.HIBP_DOMAINS ?? "").trim()) {
    await queue.add("breaches", {}, {
      repeat: { pattern: "0 5 * * *" },
      jobId: "repeat:breaches",
      removeOnComplete: 5,
      removeOnFail: 5,
    });
    await queue.add("breaches", {}, { delay: 25000, jobId: "now-breaches", removeOnComplete: true });
  }

  console.log(`[worker] scheduled ${sources.length} source(s) + enrichment + daily brief`);
}

/** Shared SMTP transport (null when SMTP isn't configured). */
function mailTransport() {
  const host = process.env.SMTP_HOST?.trim();
  if (!host) return null;
  return nodemailer.createTransport({
    host,
    port: Number(process.env.SMTP_PORT ?? 587),
    secure: process.env.SMTP_SECURE === "true",
    auth: process.env.SMTP_USER
      ? { user: process.env.SMTP_USER.trim(), pass: (process.env.SMTP_PASS ?? "").trim() }
      : undefined,
  });
}
const mailFrom = () => process.env.SMTP_FROM?.trim() || process.env.SMTP_USER?.trim() || "omnisight@localhost";

/** Email the daily brief if SMTP is configured (no-op otherwise). */
async function sendDigestEmail(d: Digest): Promise<void> {
  const to = process.env.DIGEST_TO?.trim();
  const transport = mailTransport();
  if (!transport || !to) {
    console.log("[worker] digest email: SMTP_HOST/DIGEST_TO not set — skipping send");
    return;
  }
  await transport.sendMail({ from: mailFrom(), to, subject: `OmniSight Daily Brief — ${d.date}`, html: d.html, text: d.markdown });
  console.log(`[worker] digest email sent to ${to}`);
}

/**
 * SOAR-lite ticketing: open a Jira issue per stack-affecting vuln.
 * Configure JIRA_URL, JIRA_EMAIL, JIRA_API_TOKEN, JIRA_PROJECT_KEY (optional
 * JIRA_ISSUE_TYPE, default "Task"). Uses Jira Cloud REST v2 (plain-text body).
 */
async function createJiraTickets(hits: Vulnerability[]): Promise<number> {
  const base = process.env.JIRA_URL?.trim().replace(/\/$/, "");
  const email = process.env.JIRA_EMAIL?.trim();
  const apiToken = process.env.JIRA_API_TOKEN?.trim();
  const project = process.env.JIRA_PROJECT_KEY?.trim();
  if (!base || !email || !apiToken || !project) return 0;
  const issueType = process.env.JIRA_ISSUE_TYPE?.trim() || "Task";
  const max = Number(process.env.JIRA_MAX_TICKETS ?? 10);
  const auth = Buffer.from(`${email}:${apiToken}`).toString("base64");

  let created = 0;
  for (const v of hits.slice(0, max)) {
    const summary = `[OmniSight] ${v.cveId ?? v.id} (risk ${v.riskScore})${v.knownExploited ? " — EXPLOITED" : ""} — ${v.title}`.slice(0, 240);
    const description =
      `${v.title}\n\n` +
      `Risk score: ${v.riskScore}\nCVSS: ${v.cvss ?? "n/a"}  EPSS: ${v.epss ?? "n/a"}\n` +
      `Vendor/Product: ${v.vendor ?? "?"}${v.product ? " / " + v.product : ""}\n` +
      `Known exploited: ${v.knownExploited ? "yes" : "no"}  Ransomware: ${v.ransomwareUse ? "yes" : "no"}\n` +
      `Source: ${v.source}\n${v.requiredAction ? `\nRequired action: ${v.requiredAction}\n` : ""}` +
      `\nReferences:\n${(v.references ?? []).slice(0, 5).join("\n")}`;
    try {
      const res = await fetch(`${base}/rest/api/2/issue`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Basic ${auth}` },
        body: JSON.stringify({ fields: { project: { key: project }, summary, description, issuetype: { name: issueType } } }),
      });
      if (res.ok) created++;
      else console.warn(`[worker] Jira create failed: HTTP ${res.status} ${await res.text().catch(() => "")}`);
    } catch (e) {
      console.warn(`[worker] Jira create error: ${(e as Error).message}`);
    }
  }
  return created;
}

function alertText(hits: Vulnerability[]): string {
  const lines = hits.slice(0, 25).map(
    (v) => `• [${v.riskScore}] ${v.cveId ?? v.id} — ${v.title}` +
      `${v.vendor ? ` (${v.vendor}${v.product ? "/" + v.product : ""})` : ""}${v.knownExploited ? " — EXPLOITED" : ""}`,
  );
  return `OmniSight: ${hits.length} vulnerability(ies)\n${lines.join("\n")}`;
}
function alertHtml(hits: Vulnerability[]): string {
  return `<h3 style="font-family:sans-serif">OmniSight — ${hits.length} vulnerability(ies)</h3>` +
    `<ul style="font-family:sans-serif;font-size:14px">${hits.slice(0, 25).map((v) =>
      `<li><b>[${v.riskScore}] ${v.cveId ?? v.id}</b> — ${v.title}${v.knownExploited ? " · <span style='color:#c5343a'>EXPLOITED</span>" : ""}</li>`).join("")}</ul>`;
}
async function sendWebhook(url: string, hits: Vulnerability[]): Promise<void> {
  try {
    await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text: alertText(hits) }) });
  } catch (e) { console.warn(`[worker] webhook failed: ${(e as Error).message}`); }
}
async function sendEmailAlert(to: string, hits: Vulnerability[]): Promise<void> {
  const transport = mailTransport();
  if (!transport || !to) return;
  try {
    await transport.sendMail({ from: mailFrom(), to, subject: `OmniSight Alert — ${hits.length} vuln(s)`, html: alertHtml(hits), text: alertText(hits) });
  } catch (e) { console.warn(`[worker] email alert failed: ${(e as Error).message}`); }
}

/** True if a vuln matches any "My Stack" term (vendor/product/title). */
function inStack(v: Vulnerability, terms: string[]): boolean {
  if (terms.length === 0) return false;
  const hay = `${v.vendor ?? ""} ${v.product ?? ""} ${v.title}`.toLowerCase();
  return terms.some((t) => hay.includes(t));
}

/**
 * Alerting. If the user has defined automation rules, evaluate them
 * (event→action); otherwise fall back to the env-configured stack alert.
 */
async function runAlerts(): Promise<void> {
  const rules = (await repo.listRules().catch(() => [])).filter((r) => r.enabled);

  if (rules.length === 0) {
    // Legacy/default path: stack-affecting vulns → env webhook/email/Jira.
    const minRisk = Number(process.env.ALERT_MIN_RISK ?? 75);
    const hits = await repo.pendingStackAlerts(minRisk);
    if (hits.length === 0) return;
    const webhook = process.env.ALERT_WEBHOOK?.trim();
    if (webhook) await sendWebhook(webhook, hits);
    const to = process.env.ALERT_TO?.trim() || process.env.DIGEST_TO?.trim();
    if (to) await sendEmailAlert(to, hits);
    const jiraCreated = await createJiraTickets(hits);
    await repo.markAlerted(hits.map((v) => `${v.source}:${v.id}`));
    console.log(`[worker] alerts: ${hits.length} stack vuln(s)${webhook ? " (webhook)" : ""}${to ? " (email)" : ""}${jiraCreated ? ` (${jiraCreated} Jira)` : ""}`);
    return;
  }

  // Rules path: fetch candidates above the lowest rule threshold, then match.
  const floor = Math.min(...rules.map((r) => r.minRisk));
  const candidates = await repo.pendingRuleCandidates(floor);
  if (candidates.length === 0) return;
  const terms = await repo.listWatchlist();
  const alerted = new Set<string>();
  let fired = 0;

  for (const rule of rules) {
    const hits = candidates.filter((v) =>
      (v.knownExploited || v.riskScore >= rule.minRisk) &&
      (!rule.exploitedOnly || v.knownExploited) &&
      (v.riskScore >= rule.minRisk) &&
      (!rule.stackOnly || inStack(v, terms)),
    );
    if (hits.length === 0) continue;
    fired++;
    if (rule.action === "webhook" && typeof rule.config.url === "string") await sendWebhook(rule.config.url, hits);
    else if (rule.action === "email") await sendEmailAlert(String(rule.config.to ?? process.env.ALERT_TO ?? process.env.DIGEST_TO ?? ""), hits);
    else if (rule.action === "jira") await createJiraTickets(hits);
    for (const v of hits) alerted.add(`${v.source}:${v.id}`);
    console.log(`[worker] rule "${rule.name}" (${rule.action}): ${hits.length} match(es)`);
  }

  if (alerted.size) await repo.markAlerted([...alerted]);
  console.log(`[worker] alerts: ${rules.length} rule(s), ${fired} fired, ${alerted.size} vuln(s) actioned`);
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

/** Check configured domains for known breaches via Have I Been Pwned. */
async function runBreaches(): Promise<void> {
  const domains = (process.env.HIBP_DOMAINS ?? "").split(",").map((d) => d.trim().toLowerCase()).filter(Boolean);
  if (domains.length === 0) return;
  try {
    const items = await fetchBreaches(domains, { credentials: { hibpApiKey: process.env.HIBP_API_KEY?.trim() || undefined } });
    const n = await repo.upsertBreaches(items);
    if (n > 0) { await repo.signalChange("breaches"); console.log(`[worker] breaches: ${n} record(s) across ${domains.length} domain(s)`); }
  } catch (e) {
    console.warn(`[worker] breaches: ${(e as Error).message}`);
  }
}

new Worker(
  QUEUE,
  async (job: Job<{ sourceId?: string }>) => {
    if (job.name === "enrich") {
      await runEnrichment();
      return { enriched: true };
    }
    if (job.name === "breaches") {
      await runBreaches();
      return { ok: true };
    }
    if (job.name === "geo") {
      await runGeo();
      return { ok: true };
    }
    if (job.name === "alerts") {
      await runAlerts();
      return { ok: true };
    }
    if (job.name === "decay") {
      const days = Number(process.env.DECAY_PRUNE_DAYS ?? 180);
      const n = await repo.pruneStaleIndicators(days);
      if (n > 0) { await repo.signalChange("decay"); console.log(`[worker] decay: pruned ${n} indicator(s) older than ${days}d`); }
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
      taxiiToken: process.env.TAXII_TOKEN?.trim() || undefined,
      taxiiUser: process.env.TAXII_USER?.trim() || undefined,
      taxiiPass: process.env.TAXII_PASS?.trim() || undefined,
      pulsediveKey: process.env.PULSEDIVE_API_KEY?.trim() || undefined,
      pulsediveQuery: process.env.PULSEDIVE_QUERY?.trim() || undefined,
      pulsediveLimit: process.env.PULSEDIVE_LIMIT?.trim() || undefined,
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
    // New vulns may affect My Stack — check for alerts.
    if (n > 0) await queue.add("alerts", {}, { removeOnComplete: true, jobId: `alerts-after-${source.id}` });
    return { ingested: n };
  },
  // Concurrency >1 so the quick jobs (geo, news, ingest) aren't blocked behind
  // the slow NVD enrichment loop. lockDuration covers multi-minute jobs.
  { connection, concurrency: 4, lockDuration: 120000 },
);

await scheduleAll();
console.log("[worker] running");
