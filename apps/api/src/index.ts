import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Fastify from "fastify";
import cors from "@fastify/cors";
import {
  NewSourceSchema, SourceSchema, IndicatorSchema, type Source, type Indicator,
  vulnerabilitiesToCsv, indicatorsToCsv, indicatorsToStix, indicatorsToBlocklist, indicatorsToSigma,
  indicatorsToYara, indicatorsToSnort, parseStixIndicators, typosquatVariants,
  ATTACK_TACTICS, tacticForTechnique,
  NewAssetSchema, assetsToCsv, parseAssetsCsv, parseEvents, NewScanTargetSchema, type NewAsset,
} from "@omnisight/shared";
import { createRepository, composeDigest } from "@omnisight/db";
import { runAndStoreScan, availableAdapters, type ScanRequest } from "@omnisight/scanner";
import { roleAtLeast, type Role } from "@omnisight/shared";
import { hashPassword, verifyPassword, signJwt, verifyJwt, type TokenPayload } from "./auth.js";
import { llmConfigured, llmChat, coerceVulnFilters } from "./llm.js";
import {
  cisaKevConnector, resolveConnector, resolveIndicatorConnector, resolveAdvisoryConnector,
  seedSources, fetchEpss, enrichIoc, parseSbom, queryOsvBatch, fetchBreaches,
} from "@omnisight/connectors";

// Load the repo-root .env (pnpm runs scripts from the package dir, so resolve up).
const envFile = fileURLToPath(new URL("../../../.env", import.meta.url));
if (existsSync(envFile) && typeof process.loadEnvFile === "function") process.loadEnvFile(envFile);

const repo = createRepository();
const usingPostgres = Boolean(process.env.DATABASE_URL);

// --- Auth config (opt-in) ---
const AUTH_ENABLED = process.env.AUTH_ENABLED === "true";
const JWT_SECRET = process.env.JWT_SECRET?.trim() || "";
const JWT_TTL_HOURS = Number(process.env.JWT_EXPIRY_HOURS ?? 12);

// --- SSO / OIDC (optional; generic authorization-code flow) ---
const OIDC_AUTH_URL = process.env.OIDC_AUTH_URL?.trim() || "";
const OIDC_TOKEN_URL = process.env.OIDC_TOKEN_URL?.trim() || "";
const OIDC_USERINFO_URL = process.env.OIDC_USERINFO_URL?.trim() || "";
const OIDC_CLIENT_ID = process.env.OIDC_CLIENT_ID?.trim() || "";
const OIDC_CLIENT_SECRET = process.env.OIDC_CLIENT_SECRET?.trim() || "";
const OIDC_REDIRECT_URI = process.env.OIDC_REDIRECT_URI?.trim() || "";
const OIDC_SCOPE = process.env.OIDC_SCOPE?.trim() || "openid email profile";
const SSO_LABEL = process.env.OIDC_LABEL?.trim() || "SSO";
const APP_URL = process.env.APP_URL?.trim() || "http://localhost:5173";
const SSO_ENABLED = AUTH_ENABLED && Boolean(OIDC_AUTH_URL && OIDC_TOKEN_URL && OIDC_USERINFO_URL && OIDC_CLIENT_ID && OIDC_REDIRECT_URI);

async function bootstrap() {
  await repo.init();

  // Seed source registry.
  for (const s of seedSources) await repo.upsertSource(s);

  // Seed an initial admin user when auth is on and no users exist.
  if (AUTH_ENABLED) {
    if (!JWT_SECRET) app.log.warn("AUTH_ENABLED but JWT_SECRET is not set — logins will fail. Set JWT_SECRET.");
    if ((await repo.countUsers()) === 0) {
      const u = process.env.ADMIN_USER?.trim() || "admin";
      const p = process.env.ADMIN_PASS?.trim();
      if (p) { await repo.createUser(u, hashPassword(p), "admin"); app.log.info(`seeded admin user '${u}'`); }
      else app.log.warn("AUTH_ENABLED with no users — set ADMIN_USER/ADMIN_PASS to seed an admin account");
    }
  }

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

const app = Fastify({ logger: true, bodyLimit: 20 * 1024 * 1024 }); // SBOMs/log uploads can be large
await app.register(cors, { origin: true });

// Accept raw text bodies for CSV asset imports and plain-text log/event uploads.
app.addContentTypeParser(["text/plain", "text/csv", "application/x-ndjson"], { parseAs: "string" }, (_req, body, done) => done(null, body));

// --- Auth + RBAC gate (only active when AUTH_ENABLED) ---
app.addHook("onRequest", async (req, reply) => {
  if (!AUTH_ENABLED) return;
  const url = (req.raw.url ?? "").split("?")[0];
  if (url === "/health" || url === "/api/auth/login" || url === "/api/auth/config") return;
  if (url === "/api/auth/sso/login" || url === "/api/auth/sso/callback") return;

  let token = "";
  const authz = req.headers.authorization;
  if (authz?.startsWith("Bearer ")) token = authz.slice(7);
  else if (url === "/api/stream") token = (req.query as { token?: string }).token ?? ""; // EventSource can't set headers

  const user = JWT_SECRET ? verifyJwt(token, JWT_SECRET) : null;
  if (!user) return reply.status(401).send({ error: "unauthorized" });
  (req as { user?: TokenPayload }).user = user;

  const write = !["GET", "HEAD", "OPTIONS"].includes(req.method);
  const isAdminPath = url.startsWith("/api/users") || url.startsWith("/api/audit") || url.startsWith("/api/rules") || (url.startsWith("/api/sources") && write && !url.endsWith("/run"));
  if (isAdminPath && !roleAtLeast(user.role, "admin")) return reply.status(403).send({ error: "admin role required" });
  // /api/ai/* is read-only analysis — viewers may use it.
  if (write && !url.startsWith("/api/ai/") && !roleAtLeast(user.role, "analyst")) return reply.status(403).send({ error: "analyst role required" });
});

// --- Audit log: record mutating actions (and logins) when auth is enabled ---
app.addHook("onResponse", async (req, reply) => {
  if (!AUTH_ENABLED) return;
  const url = (req.raw.url ?? "").split("?")[0];
  const write = !["GET", "HEAD", "OPTIONS"].includes(req.method);
  const isLogin = url === "/api/auth/login";
  if (!write && !isLogin) return;
  if (url.startsWith("/api/ai/")) return; // read-only analysis, skip noise
  const u = (req as { user?: TokenPayload }).user;
  const action = isLogin ? (reply.statusCode < 400 ? "login.success" : "login.failure") : `${req.method} ${url}`;
  try {
    await repo.appendAudit({
      user: u?.username ?? (isLogin ? ((req.body as { username?: string })?.username ?? null) : null),
      role: u?.role ?? null,
      action,
      method: req.method,
      path: url,
      status: reply.statusCode,
    });
  } catch (e) {
    app.log.warn({ err: e }, "audit append failed");
  }
});

app.get("/api/auth/config", async () => ({ authEnabled: AUTH_ENABLED, sso: SSO_ENABLED, ssoLabel: SSO_LABEL }));

// --- Audit log (admin) ---
app.get("/api/audit", async () => repo.listAudit(300));

app.post("/api/auth/login", async (req, reply) => {
  if (!AUTH_ENABLED) return reply.status(400).send({ error: "auth is disabled" });
  const { username, password } = (req.body ?? {}) as { username?: string; password?: string };
  if (!username || !password) return reply.status(400).send({ error: "username and password required" });
  const rec = await repo.getUserByUsername(username);
  if (!rec || !verifyPassword(password, rec.passwordHash)) return reply.status(401).send({ error: "invalid credentials" });
  const token = signJwt({ sub: rec.id, username: rec.username, role: rec.role }, JWT_SECRET, JWT_TTL_HOURS);
  return { token, user: { id: rec.id, username: rec.username, role: rec.role } };
});

// --- SSO / OIDC (generic authorization-code flow; auto-provisions viewers) ---
const ssoStates = new Map<string, number>(); // state -> expiry (ms)
function newState(): string {
  const s = (globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random()}`).replace(/-/g, "");
  ssoStates.set(s, Date.now() + 10 * 60_000);
  return s;
}
function takeState(s: string): boolean {
  const exp = ssoStates.get(s);
  ssoStates.delete(s);
  // prune
  const now = Date.now();
  for (const [k, v] of ssoStates) if (v < now) ssoStates.delete(k);
  return Boolean(exp && exp > now);
}

app.get("/api/auth/sso/login", async (req, reply) => {
  if (!SSO_ENABLED) return reply.status(400).send({ error: "SSO not configured" });
  const state = newState();
  const u = new URL(OIDC_AUTH_URL);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", OIDC_CLIENT_ID);
  u.searchParams.set("redirect_uri", OIDC_REDIRECT_URI);
  u.searchParams.set("scope", OIDC_SCOPE);
  u.searchParams.set("state", state);
  return reply.redirect(u.toString());
});

app.get("/api/auth/sso/callback", async (req, reply) => {
  if (!SSO_ENABLED) return reply.status(400).send({ error: "SSO not configured" });
  const { code, state } = (req.query ?? {}) as { code?: string; state?: string };
  if (!code || !state || !takeState(state)) return reply.redirect(`${APP_URL}/#sso_error=invalid_state`);
  try {
    // 1) Exchange the authorization code for tokens.
    const tokenRes = await fetch(OIDC_TOKEN_URL, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: OIDC_REDIRECT_URI,
        client_id: OIDC_CLIENT_ID,
        ...(OIDC_CLIENT_SECRET ? { client_secret: OIDC_CLIENT_SECRET } : {}),
      }),
    });
    if (!tokenRes.ok) throw new Error(`token endpoint HTTP ${tokenRes.status}`);
    const tokens = (await tokenRes.json()) as { access_token?: string };
    if (!tokens.access_token) throw new Error("no access_token");

    // 2) Fetch the user profile.
    const infoRes = await fetch(OIDC_USERINFO_URL, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    if (!infoRes.ok) throw new Error(`userinfo HTTP ${infoRes.status}`);
    const info = (await infoRes.json()) as { email?: string; preferred_username?: string; sub?: string };
    const username = (info.email || info.preferred_username || info.sub || "").trim();
    if (!username) throw new Error("no identity in userinfo");

    // 3) Find or auto-provision (as viewer) the local user, then issue a JWT.
    let rec = await repo.getUserByUsername(username);
    if (!rec) {
      const created = await repo.createUser(username, hashPassword(globalThis.crypto.randomUUID()), "viewer");
      rec = { ...created, passwordHash: "" };
    }
    const token = signJwt({ sub: rec.id, username: rec.username, role: rec.role }, JWT_SECRET, JWT_TTL_HOURS);
    await repo.appendAudit({ user: rec.username, role: rec.role, action: "login.sso", method: "GET", path: "/api/auth/sso/callback", status: 200 });
    return reply.redirect(`${APP_URL}/#sso_token=${encodeURIComponent(token)}`);
  } catch (e) {
    app.log.warn({ err: e }, "SSO callback failed");
    return reply.redirect(`${APP_URL}/#sso_error=${encodeURIComponent((e as Error).message)}`);
  }
});

app.get("/api/auth/me", async (req) => {
  const u = (req as { user?: TokenPayload }).user;
  return { authEnabled: AUTH_ENABLED, user: u ? { id: u.sub, username: u.username, role: u.role } : null };
});

// --- User management (admin) ---
app.get("/api/users", async () => repo.listUsers());
app.post("/api/users", async (req, reply) => {
  const b = (req.body ?? {}) as { username?: string; password?: string; role?: string };
  if (!b.username || !b.password) return reply.status(400).send({ error: "username and password required" });
  if (await repo.getUserByUsername(b.username)) return reply.status(409).send({ error: "username already exists" });
  const role: Role = ["viewer", "analyst", "admin"].includes(b.role ?? "") ? (b.role as Role) : "viewer";
  return repo.createUser(b.username, hashPassword(b.password), role);
});
app.patch("/api/users/:id", async (req, reply) => {
  const role = (req.body as { role?: string }).role;
  if (!["viewer", "analyst", "admin"].includes(role ?? "")) return reply.status(400).send({ error: "invalid role" });
  await repo.setUserRole((req.params as { id: string }).id, role as Role);
  return { ok: true };
});
app.delete("/api/users/:id", async (req) => {
  await repo.deleteUser((req.params as { id: string }).id);
  return { ok: true };
});

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

app.get("/api/correlations", async () => repo.cveCorrelations(50));

app.get("/api/attack", async () => repo.attackTechniques(60));

// --- Actor / campaign profiles ---
app.get("/api/actors", async () => repo.actorProfiles(80));
app.get("/api/actors/:name", async (req, reply) => {
  const name = decodeURIComponent((req.params as { name: string }).name);
  const profile = await repo.actorProfile(name);
  if (!profile) return reply.status(404).send({ error: "not found" });
  return profile;
});

// --- Breach exposure (Have I Been Pwned) ---
function breachDomains(): string[] {
  return (process.env.HIBP_DOMAINS ?? "").split(",").map((d) => d.trim().toLowerCase()).filter(Boolean);
}
app.get("/api/breaches", async () => repo.listBreaches(200));
app.post("/api/breaches/run", async (_req, reply) => {
  const domains = breachDomains();
  if (domains.length === 0) return reply.status(400).send({ error: "no domains configured (set HIBP_DOMAINS)" });
  try {
    const items = await fetchBreaches(domains, { credentials: { hibpApiKey: process.env.HIBP_API_KEY?.trim() || undefined } });
    const n = await repo.upsertBreaches(items);
    await repo.signalChange("breaches");
    return { ingested: n };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

// --- Brand mentions (paste/dark-web-style cross-ref over ingested intel) ---
app.get("/api/mentions", async () => {
  const terms = await repo.listWatchlist();
  const out: { term: string; advisories: { title: string; url: string; source: string; published: string | null }[]; indicators: { value: string; source: string; malware: string | null }[] }[] = [];
  for (const term of terms) {
    const [adv, ioc] = await Promise.all([
      repo.pageAdvisories({ q: term, limit: 25 }),
      repo.pageIndicators({ q: term, pageSize: 25 }),
    ]);
    if (adv.items.length === 0 && ioc.items.length === 0) continue;
    out.push({
      term,
      advisories: adv.items.map((a) => ({ title: a.title, url: a.url, source: a.source, published: a.published })),
      indicators: ioc.items.map((i) => ({ value: i.value, source: i.source, malware: i.malware })),
    });
  }
  return out;
});

// --- Detection-rule library + gap analysis ---
app.get("/api/detection-rules", async () => repo.listDetectionRules());
app.post("/api/detection-rules", async (req, reply) => {
  const b = (req.body ?? {}) as Partial<import("@omnisight/db").DetectionRule>;
  if (!b.name?.trim()) return reply.status(400).send({ error: "name required" });
  if (!["sigma", "yara", "snort", "other"].includes(b.format ?? "")) return reply.status(400).send({ error: "invalid format" });
  return repo.createDetectionRule({
    name: b.name.trim(), format: b.format as "sigma" | "yara" | "snort" | "other",
    content: b.content ?? "", techniques: (b.techniques ?? []).map((t) => String(t).toUpperCase()), enabled: b.enabled ?? true,
  });
});
app.patch("/api/detection-rules/:id", async (req) => {
  await repo.updateDetectionRule((req.params as { id: string }).id, (req.body ?? {}) as Partial<import("@omnisight/db").DetectionRule>);
  return { ok: true };
});
app.delete("/api/detection-rules/:id", async (req) => {
  await repo.deleteDetectionRule((req.params as { id: string }).id);
  return { ok: true };
});
/** Techniques referenced in intel that no enabled rule covers. */
app.get("/api/detection-gaps", async () => {
  const [techniques, rules] = await Promise.all([repo.attackTechniques(200), repo.listDetectionRules()]);
  const covered = new Set<string>();
  for (const r of rules) if (r.enabled) for (const t of r.techniques) covered.add(t.toUpperCase());
  const gaps = techniques.filter((t) => !covered.has(t.id.toUpperCase()));
  return { covered: [...covered], gaps, ruleCount: rules.length };
});

// --- ATT&CK coverage matrix (tactic-grouped) ---
app.get("/api/attack/matrix", async () => {
  const techniques = await repo.attackTechniques(300);
  const byTactic = new Map<string, { id: string; count: number }[]>();
  for (const t of techniques) {
    const tactic = tacticForTechnique(t.id);
    const arr = byTactic.get(tactic) ?? [];
    arr.push({ id: t.id, count: t.count });
    byTactic.set(tactic, arr);
  }
  return ATTACK_TACTICS.map((tac) => ({ tactic: tac.id, name: tac.name, techniques: byTactic.get(tac.id) ?? [] }));
});

// --- Entity resolution: same CVE across sources ---
app.get("/api/entities", async () => repo.cveEntities(150));

// --- RFI workflow ---
app.get("/api/rfis", async () => repo.listRfis());
app.post("/api/rfis", async (req, reply) => {
  const b = (req.body ?? {}) as { question?: string; context?: string };
  if (!b.question?.trim()) return reply.status(400).send({ error: "question required" });
  return repo.createRfi(b.question.trim(), b.context ?? "");
});
app.patch("/api/rfis/:id", async (req) => {
  await repo.updateRfi((req.params as { id: string }).id, (req.body ?? {}) as Record<string, never>);
  return { ok: true };
});
app.delete("/api/rfis/:id", async (req) => {
  await repo.deleteRfi((req.params as { id: string }).id);
  return { ok: true };
});

// --- Analyst feedback / verdicts ---
app.get("/api/feedback", async () => repo.getFeedback());
app.post("/api/feedback", async (req, reply) => {
  const { ref, verdict } = (req.body ?? {}) as { ref?: string; verdict?: string | null };
  if (!ref) return reply.status(400).send({ error: "ref required" });
  if (verdict != null && verdict !== "confirmed" && verdict !== "false_positive") {
    return reply.status(400).send({ error: "verdict must be confirmed | false_positive | null" });
  }
  await repo.setFeedback(ref, (verdict ?? null) as "confirmed" | "false_positive" | null);
  await repo.signalChange("feedback");
  return { ok: true };
});

// --- Saved searches ---
app.get("/api/searches", async () => repo.listSavedSearches());
app.post("/api/searches", async (req, reply) => {
  const b = (req.body ?? {}) as { name?: string; kind?: string; params?: Record<string, unknown> };
  if (!b.name?.trim()) return reply.status(400).send({ error: "name required" });
  if (b.kind !== "vuln" && b.kind !== "ioc") return reply.status(400).send({ error: "kind must be vuln | ioc" });
  return repo.createSavedSearch({ name: b.name.trim(), kind: b.kind, params: b.params ?? {} });
});
app.delete("/api/searches/:id", async (req) => {
  await repo.deleteSavedSearch((req.params as { id: string }).id);
  return { ok: true };
});

// --- Typosquat / look-alike domain monitoring ---
app.get("/api/typosquat", async () => {
  const terms = await repo.listWatchlist();
  const domains = terms.filter((t) => /^[a-z0-9-]+\.[a-z]{2,}$/i.test(t.trim()));
  const out: { brand: string; seen: { value: string; source: string; malware: string | null }[]; candidates: string[] }[] = [];
  for (const brand of domains) {
    const name = brand.slice(0, brand.indexOf("."));
    // Look-alikes already in our intel: domain indicators containing the brand
    // name but not the official domain itself.
    const page = await repo.pageIndicators({ type: "domain", q: name, pageSize: 100 });
    const seen = page.items
      .filter((i) => i.value.toLowerCase() !== brand.toLowerCase() && i.value.toLowerCase().includes(name.toLowerCase()))
      .map((i) => ({ value: i.value, source: i.source, malware: i.malware }));
    out.push({ brand, seen, candidates: typosquatVariants(brand).slice(0, 40) });
  }
  return out;
});

// --- Automation rules (admin) ---
app.get("/api/rules", async () => repo.listRules());
app.post("/api/rules", async (req, reply) => {
  const b = (req.body ?? {}) as Partial<import("@omnisight/db").Rule>;
  if (!b.name?.trim()) return reply.status(400).send({ error: "name required" });
  if (!["webhook", "email", "jira"].includes(b.action ?? "")) return reply.status(400).send({ error: "invalid action" });
  return repo.createRule({
    name: b.name.trim(),
    enabled: b.enabled ?? true,
    minRisk: Number(b.minRisk ?? 75),
    exploitedOnly: Boolean(b.exploitedOnly),
    stackOnly: b.stackOnly ?? true,
    action: b.action as "webhook" | "email" | "jira",
    config: (b.config as Record<string, unknown>) ?? {},
  });
});
app.patch("/api/rules/:id", async (req) => {
  await repo.updateRule((req.params as { id: string }).id, (req.body ?? {}) as Partial<import("@omnisight/db").Rule>);
  return { ok: true };
});
app.delete("/api/rules/:id", async (req) => {
  await repo.deleteRule((req.params as { id: string }).id);
  return { ok: true };
});

// --- AI layer (optional LLM) ---
app.get("/api/ai/config", async () => ({ enabled: llmConfigured() }));

app.post("/api/ai/summarize", async (req, reply) => {
  const { text } = (req.body ?? {}) as { text?: string };
  if (!text?.trim()) return reply.status(400).send({ error: "text required" });
  if (!llmConfigured()) return reply.status(400).send({ error: "AI not configured (set LLM_BASE_URL)" });
  try {
    const summary = await llmChat(
      "You are a concise cyber threat analyst. In 2–3 sentences for a SOC analyst, summarize: what this is, who/what is affected, and the recommended action. No preamble.",
      text.slice(0, 6000),
    );
    return { summary };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

app.post("/api/ai/query", async (req, reply) => {
  const { q } = (req.body ?? {}) as { q?: string };
  if (!q?.trim()) return reply.status(400).send({ error: "q required" });
  if (!llmConfigured()) return reply.status(400).send({ error: "AI not configured (set LLM_BASE_URL)" });
  const sys =
    'Translate the user request into JSON filters for a vulnerability search. ' +
    'Output ONLY a JSON object with optional keys: minRisk (0-100 number), q (keyword string), ' +
    'vendor (string), exploited (boolean), ransomware (boolean), sort ("risk"|"cvss"|"epss"|"reported"), dir ("asc"|"desc"). ' +
    'Example: {"vendor":"cisco","exploited":true,"sort":"risk","dir":"desc"}';
  try {
    const raw = await llmChat(sys, q.slice(0, 500), { json: true });
    let parsed: unknown = {};
    try { parsed = JSON.parse(raw); } catch { /* model returned non-JSON */ }
    const filters = coerceVulnFilters(parsed);
    const { items, total } = await repo.page({ ...filters, limit: 25 });
    return { filters, items, total };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

// AI-proposed CVE<->IOC relationships beyond the regex correlation, with rationale.
app.post("/api/ai/correlate", async (_req, reply) => {
  if (!llmConfigured()) return reply.status(400).send({ error: "AI not configured (set LLM_BASE_URL)" });
  try {
    const [top, iocPage] = await Promise.all([
      repo.page({ sort: "risk", dir: "desc", limit: 20 }).then((r) => r.items),
      repo.pageIndicators({ sort: "confidence", dir: "desc", limit: 40 }),
    ]);
    const vulns = top.map((v) => ({ cve: v.cveId ?? v.id, title: v.title, vendor: v.vendor, risk: v.riskScore, exploited: v.knownExploited }));
    const iocs = iocPage.items.map((i) => ({ value: i.value, type: i.type, malware: i.malware, threat: i.threatType, tags: i.tags?.slice(0, 6) }));
    const sys =
      "You are a threat-intel analyst. Given a list of vulnerabilities and indicators of compromise, " +
      "propose plausible relationships between them (e.g. an IOC associated with exploitation of a CVE, " +
      "or IOCs/CVEs tied to the same malware/campaign). Use ONLY the provided data; do not invent CVE or IOC values. " +
      'Output ONLY JSON: {"links":[{"cve":"CVE-...","ioc":"<value>","malware":"<name|null>","confidence":"high|medium|low","rationale":"<short>"}]}. ' +
      "Return an empty links array if nothing is well-supported.";
    const user = JSON.stringify({ vulnerabilities: vulns, indicators: iocs }).slice(0, 8000);
    const rawOut = await llmChat(sys, user, { json: true });
    let parsed: { links?: unknown[] } = {};
    try { parsed = JSON.parse(rawOut); } catch { /* non-JSON */ }
    const links = Array.isArray(parsed.links) ? parsed.links.slice(0, 25) : [];
    return { links };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

app.post("/api/import/stix", async (req, reply) => {
  const parsed = parseStixIndicators(req.body);
  if (parsed.length === 0) return reply.status(400).send({ error: "No STIX indicator patterns found." });
  await repo.upsertSource(SourceSchema.parse({
    id: "stix-import", name: "Imported (STIX)", kind: "json", signalType: "indicator",
    url: null, schedule: "0 0 * * *", enabled: false, requiresAuth: false, reliability: "C", config: {},
  }));
  const now = new Date().toISOString();
  const items: Indicator[] = parsed.map((p) => IndicatorSchema.parse({
    id: p.value, source: "stix-import", type: p.type, value: p.value,
    malware: p.name, threatType: null, confidence: null, references: [], tags: p.tags,
    firstSeen: null, lastSeen: now, country: null, countryCode: null, lat: null, lng: null, fetchedAt: now,
  }));
  const n = await repo.upsertIndicators(items);
  await repo.signalChange("stix-import");
  return { imported: n };
});

app.post("/api/sbom", async (req, reply) => {
  const comps = parseSbom(req.body);
  if (comps.length === 0) return reply.status(400).send({ error: "No purl-bearing components found (CycloneDX or SPDX with purls)." });
  try {
    const results = await queryOsvBatch(comps);
    return {
      total: results.length,
      vulnerable: results.filter((r) => r.vulns.length > 0).length,
      components: results.sort((a, b) => b.vulns.length - a.vulns.length),
    };
  } catch (e) {
    return reply.status(502).send({ error: (e as Error).message });
  }
});

app.get("/api/enrich/ioc", async (req, reply) => {
  const q = req.query as { value?: string; type?: string };
  if (!q.value) return reply.status(400).send({ error: "value required" });
  return enrichIoc(q.value, q.type ?? "ip", {
    greynoiseKey: process.env.GREYNOISE_API_KEY?.trim() || undefined,
    abuseKey: process.env.ABUSEIPDB_API_KEY?.trim() || undefined,
    pulsediveKey: process.env.PULSEDIVE_API_KEY?.trim() || undefined,
  });
});

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

// ===========================================================================
// Phase 2 — Defensive monitoring: asset inventory
// ===========================================================================
app.get("/api/assets", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(200, Math.max(1, Number(q.pageSize ?? 50)));
  const result = await repo.listAssets({
    limit: pageSize, offset: (page - 1) * pageSize,
    q: q.q || undefined, kind: q.kind || undefined,
    criticality: q.criticality || undefined, origin: q.origin || undefined,
  });
  return { ...result, page, pageSize };
});
app.post("/api/assets", async (req, reply) => {
  const parsed = NewAssetSchema.safeParse(req.body);
  if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
  const a = await repo.createAsset(parsed.data);
  await repo.signalChange("assets");
  return reply.status(201).send(a);
});
app.patch("/api/assets/:id", async (req) => {
  await repo.updateAsset((req.params as { id: string }).id, (req.body ?? {}) as Partial<NewAsset>);
  await repo.signalChange("assets");
  return { ok: true };
});
app.delete("/api/assets/:id", async (req) => {
  await repo.deleteAsset((req.params as { id: string }).id);
  await repo.signalChange("assets");
  return { ok: true };
});
app.get("/api/assets/export", async (_req, reply) => {
  const { items } = await repo.listAssets({ limit: 100000 });
  return reply
    .header("content-type", "text/csv; charset=utf-8")
    .header("content-disposition", 'attachment; filename="omnisight-assets.csv"')
    .send(assetsToCsv(items));
});
app.post("/api/assets/import/csv", async (req, reply) => {
  const body = req.body as unknown;
  const csv = typeof body === "string" ? body : (body as { csv?: string })?.csv;
  if (!csv?.trim()) return reply.status(400).send({ error: "CSV body required (send as text/csv or JSON { csv })" });
  const assets = parseAssetsCsv(csv);
  if (assets.length === 0) return reply.status(400).send({ error: "No asset rows parsed. A header row is required (name, vendor, product, version, cpe, …)." });
  const n = await repo.upsertAssets(assets);
  await repo.signalChange("assets");
  return { imported: n };
});
app.post("/api/assets/import/sbom", async (req, reply) => {
  const comps = parseSbom(req.body);
  if (comps.length === 0) return reply.status(400).send({ error: "No purl-bearing components found (CycloneDX or SPDX with purls)." });
  const assets: NewAsset[] = comps.map((c) => NewAssetSchema.parse({
    name: c.name, kind: "software", product: c.name, version: c.version || null,
    tags: [c.ecosystem], origin: "sbom",
  }));
  const n = await repo.upsertAssets(assets);
  await repo.signalChange("assets");
  return { imported: n, components: comps.length };
});
/** Vulnerabilities matched to inventory assets (CPE / vendor-product / term). */
app.get("/api/asset-matches", async () => repo.assetMatches(300));

// ===========================================================================
// Phase 2 — Defensive monitoring: environment events (log / IOC matching)
// ===========================================================================
/** Ingest event(s): JSON object/array, NDJSON, or raw log text. Matches IOCs. */
app.post("/api/events", async (req, reply) => {
  const obs = parseEvents(req.body);
  if (obs.length === 0) return reply.status(400).send({ error: "No observables (IP/domain/URL/hash) found in the submitted event(s)." });
  const r = await repo.ingestEvents(obs);
  await repo.signalChange("events");
  return r;
});
app.get("/api/events", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(500, Math.max(1, Number(q.pageSize ?? 100)));
  const result = await repo.listEvents({
    limit: pageSize, offset: (page - 1) * pageSize,
    matchedOnly: q.matchedOnly === "true", kind: q.kind || undefined, q: q.q || undefined,
  });
  return { ...result, page, pageSize };
});
app.get("/api/events/stats", async () => repo.eventStats());

// ===========================================================================
// Phase 3 — Vulnerability scanning
// ===========================================================================
app.get("/api/scan/config", async () => ({ adapters: await availableAdapters() }));
app.get("/api/scan/targets", async () => repo.listScanTargets());
app.post("/api/scan/targets", async (req, reply) => {
  const parsed = NewScanTargetSchema.safeParse(req.body);
  if (!parsed.success) return reply.status(400).send({ error: parsed.error.flatten() });
  const t = await repo.createScanTarget(parsed.data);
  await repo.signalChange("scan");
  return reply.status(201).send(t);
});
app.patch("/api/scan/targets/:id", async (req) => {
  await repo.updateScanTarget((req.params as { id: string }).id, (req.body ?? {}) as Record<string, never>);
  return { ok: true };
});
app.delete("/api/scan/targets/:id", async (req) => {
  await repo.deleteScanTarget((req.params as { id: string }).id);
  await repo.signalChange("scan");
  return { ok: true };
});
/** Run a scan now: by saved target id, or an ad-hoc { target, kind, adapter }. */
app.post("/api/scan/run", async (req, reply) => {
  const b = (req.body ?? {}) as { targetId?: string; target?: string; kind?: string; adapter?: string };
  let request: ScanRequest;
  if (b.targetId) {
    const t = await repo.getScanTarget(b.targetId);
    if (!t) return reply.status(404).send({ error: "scan target not found" });
    request = { targetId: t.id, target: t.target, kind: t.kind, adapter: t.adapter };
  } else {
    if (!b.target?.trim()) return reply.status(400).send({ error: "target or targetId required" });
    request = { targetId: null, target: b.target.trim(), kind: b.kind === "url" ? "url" : "host", adapter: b.adapter || "builtin" };
  }
  return runAndStoreScan(repo, request, { timeoutMs: 1500 });
});
app.get("/api/scans", async (req) => repo.listScans(Number((req.query as { limit?: string }).limit ?? 50)));
app.get("/api/scans/:id", async (req, reply) => {
  const scan = await repo.getScan((req.params as { id: string }).id);
  if (!scan) return reply.status(404).send({ error: "not found" });
  const { items } = await repo.listFindings({ scanId: scan.id, limit: 1000 });
  return { scan, findings: items };
});
app.get("/api/findings", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(500, Math.max(1, Number(q.pageSize ?? 100)));
  const result = await repo.listFindings({
    limit: pageSize, offset: (page - 1) * pageSize,
    scanId: q.scanId || undefined, cve: q.cve || undefined,
    severity: q.severity || undefined, withCveOnly: q.withCveOnly === "true",
  });
  return { ...result, page, pageSize };
});
app.get("/api/findings/stats", async () => repo.findingStats());

app.get("/api/vulnerabilities", async (req) => {
  const q = req.query as Record<string, string | undefined>;
  const page = Math.max(1, Number(q.page ?? 1));
  const pageSize = Math.min(200, Math.max(1, Number(q.pageSize ?? 50)));
  const terms = q.myStack === "true" ? await repo.stackTerms() : undefined;
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
  const terms = q.myStack === "true" ? await repo.stackTerms() : undefined;
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
  if (format === "sigma") {
    return reply
      .header("content-type", "application/x-yaml; charset=utf-8")
      .header("content-disposition", 'attachment; filename="omnisight-sigma.yml"')
      .send(indicatorsToSigma(items));
  }
  if (format === "yara") {
    return reply
      .header("content-type", "text/plain; charset=utf-8")
      .header("content-disposition", 'attachment; filename="omnisight.yar"')
      .send(indicatorsToYara(items));
  }
  if (format === "snort") {
    return reply
      .header("content-type", "text/plain; charset=utf-8")
      .header("content-disposition", 'attachment; filename="omnisight.rules"')
      .send(indicatorsToSnort(items));
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
    maxAgeDays: q.maxAgeDays ? Number(q.maxAgeDays) : undefined,
    minConfidence: q.minConfidence ? Number(q.minConfidence) : undefined,
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

// --- Investigation notes (TLP) ---
app.get("/api/notes", async (req, reply) => {
  const ref = (req.query as { ref?: string }).ref;
  if (!ref) return reply.status(400).send({ error: "ref required" });
  return repo.listNotes(ref);
});
app.post("/api/notes", async (req, reply) => {
  const b = req.body as { ref?: string; tlp?: string; body?: string };
  if (!b.ref || !b.body?.trim()) return reply.status(400).send({ error: "ref and body required" });
  const tlp = ["clear", "green", "amber", "red"].includes(b.tlp ?? "") ? b.tlp! : "amber";
  return repo.addNote(b.ref, tlp, b.body.trim());
});
app.delete("/api/notes/:id", async (req) => {
  await repo.deleteNote((req.params as { id: string }).id);
  return { ok: true };
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

/** Admin: enable/disable a source (takes effect on the worker's next schedule cycle). */
app.patch("/api/sources/:id", async (req, reply) => {
  const body = (req.body ?? {}) as { enabled?: boolean; sector?: string | null };
  const id = (req.params as { id: string }).id;
  if (typeof body.enabled === "boolean") await repo.setSourceEnabled(id, body.enabled);
  if ("sector" in body) {
    const src = (await repo.listSources()).find((s) => s.id === id);
    if (!src) return reply.status(404).send({ error: "source not found" });
    await repo.upsertSource({ ...src, sector: body.sector?.trim() || null });
  }
  if (typeof body.enabled !== "boolean" && !("sector" in body)) {
    return reply.status(400).send({ error: "enabled (boolean) or sector (string) required" });
  }
  return { ok: true };
});

/** Admin: delete a source and its ingested rows (cascade). */
app.delete("/api/sources/:id", async (req, reply) => {
  const id = (req.params as { id: string }).id;
  const exists = (await repo.listSources()).some((s) => s.id === id);
  if (!exists) return reply.status(404).send({ error: `source "${id}" not found` });
  await repo.deleteSource(id);
  await repo.signalChange("source-deleted");
  return { ok: true };
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
          taxiiToken: process.env.TAXII_TOKEN?.trim() || undefined,
          taxiiUser: process.env.TAXII_USER?.trim() || undefined,
          taxiiPass: process.env.TAXII_PASS?.trim() || undefined,
          pulsediveKey: process.env.PULSEDIVE_API_KEY?.trim() || undefined,
          pulsediveQuery: process.env.PULSEDIVE_QUERY?.trim() || undefined,
          pulsediveLimit: process.env.PULSEDIVE_LIMIT?.trim() || undefined,
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
