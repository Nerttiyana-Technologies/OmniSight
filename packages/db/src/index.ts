import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { EventEmitter } from "node:events";
import pg from "pg";
import {
  computeRiskScore, buildDigest,
  type Source, type Vulnerability, type Indicator, type Advisory, type Digest, type User, type Role, type Breach,
} from "@omnisight/shared";

export interface ListOptions {
  limit?: number;
  offset?: number;
  minRisk?: number;
  q?: string;
  vendor?: string;
  source?: string;
  exploited?: boolean;
  ransomware?: boolean;
  terms?: string[]; // "My Stack" — match vendor/product/title against any term
  sort?: string; // risk | cve | threat | vendor | cvss | epss | source
  dir?: "asc" | "desc";
}

export interface Page {
  items: Vulnerability[];
  total: number;
}

export interface Stats {
  total: number;
  knownExploited: number;
  ransomware: number;
  critical: number;
  high: number;
  sources: number;
  indicators: number;
  advisories: number;
  inStack: number;
}

export interface IndicatorListOptions {
  limit?: number;
  offset?: number;
  type?: string;
  malware?: string;
  q?: string;
  source?: string;
  maxAgeDays?: number; // "fresh only": drop indicators last seen older than this
  minConfidence?: number; // noise control: drop indicators below this confidence
  sort?: string; // confidence | lastseen | type | malware | value | source
  dir?: "asc" | "desc";
}

export interface IndicatorPage {
  items: Indicator[];
  total: number;
}

export interface GeoPatch {
  country: string | null;
  countryCode: string | null;
  lat: number | null;
  lng: number | null;
}

export interface MapPoint {
  country: string;
  code: string | null;
  lat: number;
  lng: number;
  count: number;
}

export interface MapIndicator {
  value: string;
  lat: number;
  lng: number;
  malware: string | null;
  type: string;
  source: string;
}

export interface Correlation {
  cveId: string;
  title: string | null;   // populated when the CVE is also a tracked vulnerability
  riskScore: number | null;
  indicators: { value: string; source: string; malware: string | null; type: string }[];
}

export interface Note {
  id: string;
  ref: string;            // "cve:CVE-..." or "ioc:<value>"
  tlp: string;            // clear | green | amber | red
  body: string;
  createdAt: string;
}

export interface UserRecord extends User {
  passwordHash: string;
}

function newId(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return c?.randomUUID ? c.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export interface AttackTechnique {
  id: string;
  count: number;
  framework: "attack" | "atlas";
}

export interface ActorProfile {
  /** Malware family / campaign label (the grouping key). */
  name: string;
  indicatorCount: number;
  types: Record<string, number>;
  sources: string[];
  firstSeen: string | null;
  lastSeen: string | null;
  cves: string[];
  techniques: string[];
  sampleIocs: { value: string; type: string }[];
}

export interface AuditEntry {
  id: string;
  at: string;
  user: string | null;
  role: string | null;
  action: string;
  method: string;
  path: string;
  status: number | null;
}

export type Verdict = "confirmed" | "false_positive";

/** An editable detection rule in the library, tagged to ATT&CK techniques. */
export interface DetectionRule {
  id: string;
  name: string;
  format: "sigma" | "yara" | "snort" | "other";
  content: string;
  techniques: string[];
  enabled: boolean;
  createdAt: string;
}

/** A request-for-information ticket. */
export interface Rfi {
  id: string;
  question: string;
  context: string;
  status: "open" | "answered" | "closed";
  answer: string;
  createdAt: string;
  updatedAt: string;
}

/** One CVE resolved across all the sources that reported it. */
export interface CveEntity {
  cveId: string;
  title: string;
  riskScore: number;
  knownExploited: boolean;
  sources: { source: string; reliability: string }[];
}

/** A saved, named filter set for the vuln or IOC grid. */
export interface SavedSearch {
  id: string;
  name: string;
  kind: "vuln" | "ioc";
  params: Record<string, unknown>;
  createdAt: string;
}

export type RuleAction = "webhook" | "email" | "jira";

/** A user-defined automation rule: when a vuln matches, run an action. */
export interface Rule {
  id: string;
  name: string;
  enabled: boolean;
  /** Trigger: risk_score ≥ minRisk. */
  minRisk: number;
  /** Trigger: require known_exploited. */
  exploitedOnly: boolean;
  /** Trigger: require a "My Stack" match. */
  stackOnly: boolean;
  action: RuleAction;
  /** Action params, e.g. { url } for webhook, { to } for email. */
  config: Record<string, unknown>;
  createdAt: string;
}

// AML.T#### (ATLAS) must come first so it isn't split into a bare T####.
const ATTACK_RE = /\bAML\.T\d{4}(?:\.\d{3})?\b|\bT\d{4}(?:\.\d{3})?\b/g;

function tallyTechniques(haystacks: Iterable<string>, limit: number): AttackTechnique[] {
  const counts = new Map<string, number>();
  for (const hay of haystacks) {
    const m = hay.match(ATTACK_RE);
    if (!m) continue;
    for (const raw of m) {
      const id = raw.toUpperCase();
      counts.set(id, (counts.get(id) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([id, count]) => ({ id, count, framework: (id.startsWith("AML") ? "atlas" : "attack") as "attack" | "atlas" }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

const CVE_RE = /CVE-\d{4}-\d{4,}/gi;

/** Aggregate indicators into per-malware-family actor/campaign profiles. */
function buildActorProfiles(indicators: Iterable<Indicator>): ActorProfile[] {
  const groups = new Map<string, {
    name: string;
    count: number;
    types: Map<string, number>;
    sources: Set<string>;
    first: string | null;
    last: string | null;
    cves: Set<string>;
    techniques: Set<string>;
    samples: { value: string; type: string }[];
  }>();
  for (const i of indicators) {
    const name = (i.malware ?? "").trim();
    if (!name) continue;
    const key = name.toLowerCase();
    let g = groups.get(key);
    if (!g) {
      g = { name, count: 0, types: new Map(), sources: new Set(), first: null, last: null, cves: new Set(), techniques: new Set(), samples: [] };
      groups.set(key, g);
    }
    g.count++;
    g.types.set(i.type, (g.types.get(i.type) ?? 0) + 1);
    g.sources.add(i.source);
    if (i.firstSeen && (!g.first || i.firstSeen < g.first)) g.first = i.firstSeen;
    if (i.lastSeen && (!g.last || i.lastSeen > g.last)) g.last = i.lastSeen;
    const hay = `${i.value} ${i.malware ?? ""} ${i.threatType ?? ""} ${i.tags.join(" ")}`;
    for (const c of hay.match(CVE_RE) ?? []) g.cves.add(c.toUpperCase());
    for (const t of hay.match(ATTACK_RE) ?? []) g.techniques.add(t.toUpperCase());
    if (g.samples.length < 10) g.samples.push({ value: i.value, type: i.type });
  }
  return [...groups.values()]
    .map((g) => ({
      name: g.name,
      indicatorCount: g.count,
      types: Object.fromEntries(g.types),
      sources: [...g.sources],
      firstSeen: g.first,
      lastSeen: g.last,
      cves: [...g.cves].slice(0, 25),
      techniques: [...g.techniques].slice(0, 25),
      sampleIocs: g.samples,
    }))
    .sort((a, b) => b.indicatorCount - a.indicatorCount);
}

export interface AdvisoryListOptions {
  limit?: number;
  offset?: number;
  source?: string;
  q?: string;
}

export interface AdvisoryPage {
  items: Advisory[];
  total: number;
}

/** Patch applied to every row matching a CVE id (used by enrichers). */
export interface EnrichPatch {
  cveId: string;
  cvss?: number | null;
  epss?: number | null;
}

/** Storage contract. Two implementations: Postgres (prod) and in-memory (demo/tests). */
export interface Repository {
  init(): Promise<void>;
  upsertVulnerabilities(items: Vulnerability[]): Promise<number>;
  listVulnerabilities(opts?: ListOptions): Promise<Vulnerability[]>;
  /** Filtered + paginated query returning items and the total match count. */
  page(opts?: ListOptions): Promise<Page>;
  upsertIndicators(items: Indicator[]): Promise<number>;
  pageIndicators(opts?: IndicatorListOptions): Promise<IndicatorPage>;
  /** Delete indicators last seen older than `days` (decay). Returns count removed. */
  pruneStaleIndicators(days: number): Promise<number>;
  upsertAdvisories(items: Advisory[]): Promise<number>;
  pageAdvisories(opts?: AdvisoryListOptions): Promise<AdvisoryPage>;
  listWatchlist(): Promise<string[]>;
  addWatchTerm(term: string): Promise<void>;
  removeWatchTerm(term: string): Promise<void>;
  /** Stack-affecting, alert-worthy vulns not yet alerted. */
  pendingStackAlerts(minRisk?: number): Promise<Vulnerability[]>;
  markAlerted(keys: string[]): Promise<void>;
  listNotes(ref: string): Promise<Note[]>;
  addNote(ref: string, tlp: string, body: string): Promise<Note>;
  deleteNote(id: string): Promise<void>;
  getUserByUsername(username: string): Promise<UserRecord | null>;
  createUser(username: string, passwordHash: string, role: Role): Promise<User>;
  listUsers(): Promise<User[]>;
  setUserRole(id: string, role: Role): Promise<void>;
  deleteUser(id: string): Promise<void>;
  countUsers(): Promise<number>;
  /** Distinct IP-indicator values still missing geolocation. */
  ipsNeedingGeo(limit?: number): Promise<string[]>;
  /** Apply geolocation to all indicator rows sharing a value. */
  setGeo(value: string, geo: GeoPatch): Promise<void>;
  /** Indicator counts aggregated by country for the map. */
  mapData(): Promise<MapPoint[]>;
  /** Individual geolocated indicators for one country (drill-down). */
  mapIndicators(country: string, limit?: number): Promise<MapIndicator[]>;
  /** CVE references found inside indicators, linked to tracked CVEs where possible. */
  cveCorrelations(limit?: number): Promise<Correlation[]>;
  /** ATT&CK / ATLAS technique IDs referenced across ingested intel, by frequency. */
  attackTechniques(limit?: number): Promise<AttackTechnique[]>;
  /** Indicators aggregated by malware family into actor/campaign profiles. */
  actorProfiles(limit?: number): Promise<ActorProfile[]>;
  /** One actor/campaign profile by malware family name. */
  actorProfile(name: string): Promise<ActorProfile | null>;
  /** Append an audit-log entry (who did what). */
  appendAudit(entry: Omit<AuditEntry, "id" | "at">): Promise<void>;
  /** Recent audit-log entries, newest first. */
  listAudit(limit?: number): Promise<AuditEntry[]>;
  /** Upsert breach-exposure records (keyed on breach id). */
  upsertBreaches(items: Breach[]): Promise<number>;
  /** Breach-exposure records, newest first. */
  listBreaches(limit?: number): Promise<Breach[]>;
  /** Automation rules (event→action). */
  listRules(): Promise<Rule[]>;
  createRule(rule: Omit<Rule, "id" | "createdAt">): Promise<Rule>;
  updateRule(id: string, patch: Partial<Omit<Rule, "id" | "createdAt">>): Promise<void>;
  deleteRule(id: string): Promise<void>;
  /** Un-alerted vulns that could trigger a rule (exploited or risk ≥ floor). */
  pendingRuleCandidates(floorRisk: number): Promise<Vulnerability[]>;
  upsertSource(source: Source): Promise<void>;
  listSources(): Promise<Source[]>;
  /** Enable/disable a source. */
  setSourceEnabled(id: string, enabled: boolean): Promise<void>;
  /** Delete a source and (via cascade) its ingested rows. */
  deleteSource(id: string): Promise<void>;
  /** Set an analyst verdict (confirmed / false_positive) on a CVE or IOC ref. */
  setFeedback(ref: string, verdict: Verdict | null): Promise<void>;
  /** Verdicts keyed by ref, for the given refs (or all when omitted). */
  getFeedback(refs?: string[]): Promise<Record<string, Verdict>>;
  listSavedSearches(): Promise<SavedSearch[]>;
  createSavedSearch(s: Omit<SavedSearch, "id" | "createdAt">): Promise<SavedSearch>;
  deleteSavedSearch(id: string): Promise<void>;
  listDetectionRules(): Promise<DetectionRule[]>;
  createDetectionRule(r: Omit<DetectionRule, "id" | "createdAt">): Promise<DetectionRule>;
  updateDetectionRule(id: string, patch: Partial<Omit<DetectionRule, "id" | "createdAt">>): Promise<void>;
  deleteDetectionRule(id: string): Promise<void>;
  listRfis(): Promise<Rfi[]>;
  createRfi(question: string, context: string): Promise<Rfi>;
  updateRfi(id: string, patch: Partial<Pick<Rfi, "status" | "answer" | "question" | "context">>): Promise<void>;
  deleteRfi(id: string): Promise<void>;
  /** Same CVE grouped across the sources that reported it. */
  cveEntities(limit?: number): Promise<CveEntity[]>;
  stats(): Promise<Stats>;
  /** Distinct CVE ids, optionally only those missing a given enrichment field. */
  distinctCveIds(missing?: "cvss" | "epss", limit?: number): Promise<string[]>;
  /** Apply enrichment to all rows of a CVE and recompute their risk score. */
  enrich(patches: EnrichPatch[]): Promise<number>;
  /** Emit a change signal (Postgres NOTIFY / in-memory event). */
  signalChange(payload?: string): Promise<void>;
  /** Subscribe to change signals (Postgres LISTEN / in-memory event). */
  subscribeChanges(cb: (payload: string) => void): Promise<void>;
}

/** Picks Postgres when DATABASE_URL is set, otherwise an in-memory store. */
export function createRepository(databaseUrl = process.env.DATABASE_URL): Repository {
  return databaseUrl
    ? new PostgresRepository(databaseUrl)
    : new InMemoryRepository();
}

// ---------------------------------------------------------------------------

/** Gather the day's signals from any repository and build the brief. */
export async function composeDigest(repo: Repository): Promise<Digest> {
  const [stats, terms] = await Promise.all([repo.stats(), repo.listWatchlist()]);
  const [topVulns, recentKev, topIocs] = await Promise.all([
    repo.page({ sort: "risk", dir: "desc", limit: 10 }).then((r) => r.items),
    repo.page({ source: "cisa-kev", sort: "reported", dir: "desc", limit: 10 }).then((r) => r.items),
    repo.pageIndicators({ sort: "confidence", dir: "desc", limit: 10 }).then((r) => r.items),
  ]);
  const stackVulns = terms.length
    ? (await repo.page({ terms, sort: "risk", dir: "desc", limit: 10 })).items
    : [];
  return buildDigest({ stats, terms, topVulns, recentKev, stackVulns, topIocs });
}

/** True if a vulnerability matches any "My Stack" term (vendor/product/title). */
export function matchesTerms(v: Vulnerability, terms: string[]): boolean {
  if (terms.length === 0) return false;
  const hay = `${v.vendor ?? ""} ${v.product ?? ""} ${v.title}`.toLowerCase();
  return terms.some((t) => hay.includes(t.toLowerCase()));
}

export class InMemoryRepository implements Repository {
  private vulns = new Map<string, Vulnerability>();
  private indicators = new Map<string, Indicator>();
  private advisories = new Map<string, Advisory>();
  private sources = new Map<string, Source>();
  private watch = new Set<string>();
  private bus = new EventEmitter();

  async init(): Promise<void> {}

  async upsertAdvisories(items: Advisory[]): Promise<number> {
    for (const a of items) this.advisories.set(`${a.source}:${a.id}`, a);
    return items.length;
  }

  async pageAdvisories(opts: AdvisoryListOptions = {}): Promise<AdvisoryPage> {
    let rows = [...this.advisories.values()];
    if (opts.source) rows = rows.filter((a) => a.source === opts.source);
    if (opts.q) {
      const q = opts.q.toLowerCase();
      rows = rows.filter((a) => a.title.toLowerCase().includes(q) || a.summary.toLowerCase().includes(q));
    }
    rows.sort((a, b) => (b.published ?? "").localeCompare(a.published ?? ""));
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 50;
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }

  async listWatchlist(): Promise<string[]> {
    return [...this.watch];
  }
  async addWatchTerm(term: string): Promise<void> {
    const t = term.trim().toLowerCase();
    if (t) this.watch.add(t);
  }
  async removeWatchTerm(term: string): Promise<void> {
    this.watch.delete(term.trim().toLowerCase());
  }

  private alertLog = new Set<string>();

  async pendingStackAlerts(minRisk = 75): Promise<Vulnerability[]> {
    const terms = [...this.watch];
    if (terms.length === 0) return [];
    const out: Vulnerability[] = [];
    for (const v of this.vulns.values()) {
      if (!matchesTerms(v, terms)) continue;
      if (!(v.knownExploited || v.riskScore >= minRisk)) continue;
      if (this.alertLog.has(`${v.source}:${v.id}`)) continue;
      out.push(v);
    }
    return out.sort((a, b) => b.riskScore - a.riskScore);
  }

  async markAlerted(keys: string[]): Promise<void> {
    for (const k of keys) this.alertLog.add(k);
  }

  private notes = new Map<string, Note>();
  async listNotes(ref: string): Promise<Note[]> {
    return [...this.notes.values()].filter((n) => n.ref === ref).sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  async addNote(ref: string, tlp: string, body: string): Promise<Note> {
    const note: Note = { id: newId(), ref, tlp, body, createdAt: new Date().toISOString() };
    this.notes.set(note.id, note);
    return note;
  }
  async deleteNote(id: string): Promise<void> {
    this.notes.delete(id);
  }

  private users = new Map<string, UserRecord>();
  async getUserByUsername(username: string): Promise<UserRecord | null> {
    return [...this.users.values()].find((u) => u.username === username) ?? null;
  }
  async createUser(username: string, passwordHash: string, role: Role): Promise<User> {
    const rec: UserRecord = { id: newId(), username, passwordHash, role, createdAt: new Date().toISOString() };
    this.users.set(rec.id, rec);
    return { id: rec.id, username, role, createdAt: rec.createdAt };
  }
  async listUsers(): Promise<User[]> {
    return [...this.users.values()].map((u) => ({ id: u.id, username: u.username, role: u.role, createdAt: u.createdAt }));
  }
  async setUserRole(id: string, role: Role): Promise<void> {
    const u = this.users.get(id);
    if (u) u.role = role;
  }
  async deleteUser(id: string): Promise<void> {
    this.users.delete(id);
  }
  async countUsers(): Promise<number> {
    return this.users.size;
  }

  async attackTechniques(limit = 60): Promise<AttackTechnique[]> {
    const hays: string[] = [];
    for (const a of this.advisories.values()) hays.push(`${a.title} ${a.summary} ${a.category ?? ""} ${a.tags.join(" ")}`);
    for (const i of this.indicators.values()) hays.push(`${i.value} ${i.malware ?? ""} ${i.threatType ?? ""} ${i.tags.join(" ")}`);
    return tallyTechniques(hays, limit);
  }

  async actorProfiles(limit = 60): Promise<ActorProfile[]> {
    return buildActorProfiles(this.indicators.values()).slice(0, limit);
  }

  async actorProfile(name: string): Promise<ActorProfile | null> {
    const key = name.trim().toLowerCase();
    const rows = [...this.indicators.values()].filter((i) => (i.malware ?? "").trim().toLowerCase() === key);
    return buildActorProfiles(rows)[0] ?? null;
  }

  private audit: AuditEntry[] = [];
  async appendAudit(entry: Omit<AuditEntry, "id" | "at">): Promise<void> {
    this.audit.unshift({ ...entry, id: newId(), at: new Date().toISOString() });
    if (this.audit.length > 1000) this.audit.length = 1000;
  }
  async listAudit(limit = 200): Promise<AuditEntry[]> {
    return this.audit.slice(0, limit);
  }

  private breaches = new Map<string, Breach>();
  async upsertBreaches(items: Breach[]): Promise<number> {
    for (const b of items) this.breaches.set(b.id, b);
    return items.length;
  }
  async listBreaches(limit = 200): Promise<Breach[]> {
    return [...this.breaches.values()]
      .sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""))
      .slice(0, limit);
  }

  private rules = new Map<string, Rule>();
  async listRules(): Promise<Rule[]> {
    return [...this.rules.values()].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  }
  async createRule(rule: Omit<Rule, "id" | "createdAt">): Promise<Rule> {
    const r: Rule = { ...rule, id: newId(), createdAt: new Date().toISOString() };
    this.rules.set(r.id, r);
    return r;
  }
  async updateRule(id: string, patch: Partial<Omit<Rule, "id" | "createdAt">>): Promise<void> {
    const r = this.rules.get(id);
    if (r) this.rules.set(id, { ...r, ...patch });
  }
  async deleteRule(id: string): Promise<void> {
    this.rules.delete(id);
  }
  async pendingRuleCandidates(floorRisk: number): Promise<Vulnerability[]> {
    const out: Vulnerability[] = [];
    for (const v of this.vulns.values()) {
      if (this.alertLog.has(`${v.source}:${v.id}`)) continue;
      if (!(v.knownExploited || v.riskScore >= floorRisk)) continue;
      out.push(v);
    }
    return out.sort((a, b) => b.riskScore - a.riskScore).slice(0, 200);
  }

  async upsertIndicators(items: Indicator[]): Promise<number> {
    for (const i of items) this.indicators.set(`${i.source}:${i.id}`, i);
    return items.length;
  }

  async pruneStaleIndicators(days: number): Promise<number> {
    const cutoff = Date.now() - days * 86400000;
    let removed = 0;
    for (const [key, i] of this.indicators) {
      if (i.lastSeen && new Date(i.lastSeen).getTime() < cutoff) {
        this.indicators.delete(key);
        removed++;
      }
    }
    return removed;
  }

  async ipsNeedingGeo(limit = 200): Promise<string[]> {
    const ips = new Set<string>();
    for (const i of this.indicators.values()) {
      if (i.type === "ip" && i.lat == null) {
        ips.add(i.value);
        if (ips.size >= limit) break;
      }
    }
    return [...ips];
  }

  async setGeo(value: string, geo: GeoPatch): Promise<void> {
    for (const i of this.indicators.values()) {
      if (i.value === value) {
        i.country = geo.country;
        i.countryCode = geo.countryCode;
        i.lat = geo.lat;
        i.lng = geo.lng;
      }
    }
  }

  async mapData(): Promise<MapPoint[]> {
    const byCountry = new Map<string, { country: string; code: string | null; lat: number; lng: number; count: number }>();
    for (const i of this.indicators.values()) {
      if (i.lat == null || i.lng == null) continue;
      const key = i.countryCode ?? i.country ?? `${i.lat},${i.lng}`;
      const cur = byCountry.get(key);
      if (cur) cur.count++;
      else byCountry.set(key, { country: i.country ?? "Unknown", code: i.countryCode, lat: i.lat, lng: i.lng, count: 1 });
    }
    return [...byCountry.values()].sort((a, b) => b.count - a.count);
  }

  async mapIndicators(country: string, limit = 500): Promise<MapIndicator[]> {
    const out: MapIndicator[] = [];
    for (const i of this.indicators.values()) {
      if (i.lat == null || i.lng == null) continue;
      if (i.countryCode !== country && i.country !== country) continue;
      out.push({ value: i.value, lat: i.lat, lng: i.lng, malware: i.malware, type: i.type, source: i.source });
      if (out.length >= limit) break;
    }
    return out;
  }

  async cveCorrelations(limit = 50): Promise<Correlation[]> {
    const byCve = new Map<string, Correlation["indicators"]>();
    for (const i of this.indicators.values()) {
      const hay = `${i.value} ${i.malware ?? ""} ${i.threatType ?? ""} ${i.tags.join(" ")}`;
      const found = hay.match(CVE_RE);
      if (!found) continue;
      for (const raw of found) {
        const cve = raw.toUpperCase();
        const arr = byCve.get(cve) ?? [];
        if (arr.length < 25) arr.push({ value: i.value, source: i.source, malware: i.malware, type: i.type });
        byCve.set(cve, arr);
      }
    }
    const out: Correlation[] = [];
    for (const [cveId, indicators] of byCve) {
      const v = [...this.vulns.values()].find((x) => x.cveId === cveId);
      out.push({ cveId, title: v?.title ?? null, riskScore: v?.riskScore ?? null, indicators });
    }
    out.sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || b.indicators.length - a.indicators.length);
    return out.slice(0, limit);
  }

  async pageIndicators(opts: IndicatorListOptions = {}): Promise<IndicatorPage> {
    let rows = [...this.indicators.values()];
    if (opts.type) rows = rows.filter((i) => i.type === opts.type);
    if (opts.source) rows = rows.filter((i) => i.source === opts.source);
    if (opts.malware) {
      const m = opts.malware.toLowerCase();
      rows = rows.filter((i) => (i.malware ?? "").toLowerCase().includes(m));
    }
    if (opts.q) {
      const q = opts.q.toLowerCase();
      rows = rows.filter(
        (i) =>
          i.value.toLowerCase().includes(q) ||
          (i.malware ?? "").toLowerCase().includes(q) ||
          (i.threatType ?? "").toLowerCase().includes(q),
      );
    }
    if (opts.maxAgeDays) {
      const cutoff = Date.now() - opts.maxAgeDays * 86400000;
      rows = rows.filter((i) => !i.lastSeen || new Date(i.lastSeen).getTime() >= cutoff);
    }
    if (opts.minConfidence) rows = rows.filter((i) => (i.confidence ?? 0) >= opts.minConfidence!);
    const dir = opts.dir === "asc" ? 1 : -1;
    const val = (i: Indicator): string | number | null => {
      switch (opts.sort) {
        case "confidence": return i.confidence;
        case "type": return i.type;
        case "malware": return i.malware ?? "";
        case "value": return i.value;
        case "source": return i.source;
        default: return i.lastSeen ?? "";
      }
    };
    rows.sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 50;
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }

  async signalChange(payload = ""): Promise<void> {
    this.bus.emit("change", payload);
  }

  async subscribeChanges(cb: (payload: string) => void): Promise<void> {
    this.bus.setMaxListeners(0);
    this.bus.on("change", cb);
  }

  async distinctCveIds(missing?: "cvss" | "epss", limit = 1000): Promise<string[]> {
    const ids = new Set<string>();
    for (const v of this.vulns.values()) {
      if (!v.cveId) continue;
      if (missing === "cvss" && v.cvss != null) continue;
      if (missing === "epss" && v.epss != null) continue;
      ids.add(v.cveId);
      if (ids.size >= limit) break;
    }
    return [...ids];
  }

  async enrich(patches: EnrichPatch[]): Promise<number> {
    let n = 0;
    const byCve = new Map(patches.map((p) => [p.cveId, p]));
    for (const v of this.vulns.values()) {
      if (!v.cveId) continue;
      const p = byCve.get(v.cveId);
      if (!p) continue;
      if (p.cvss !== undefined) v.cvss = p.cvss;
      if (p.epss !== undefined) v.epss = p.epss;
      v.riskScore = computeRiskScore(v);
      n++;
    }
    return n;
  }

  async upsertVulnerabilities(items: Vulnerability[]): Promise<number> {
    for (const v of items) this.vulns.set(`${v.source}:${v.id}`, v);
    return items.length;
  }

  private filtered(opts: ListOptions): Vulnerability[] {
    let rows = [...this.vulns.values()];
    if (opts.minRisk != null) rows = rows.filter((v) => v.riskScore >= opts.minRisk!);
    if (opts.source) rows = rows.filter((v) => v.source === opts.source);
    if (opts.exploited) rows = rows.filter((v) => v.knownExploited);
    if (opts.ransomware) rows = rows.filter((v) => v.ransomwareUse);
    if (opts.terms && opts.terms.length) rows = rows.filter((v) => matchesTerms(v, opts.terms!));
    if (opts.vendor) {
      const vq = opts.vendor.toLowerCase();
      rows = rows.filter(
        (v) => (v.vendor ?? "").toLowerCase().includes(vq) || (v.product ?? "").toLowerCase().includes(vq) || v.title.toLowerCase().includes(vq),
      );
    }
    if (opts.q) {
      const q = opts.q.toLowerCase();
      rows = rows.filter(
        (v) =>
          v.title.toLowerCase().includes(q) ||
          v.description.toLowerCase().includes(q) ||
          (v.cveId ?? "").toLowerCase().includes(q) ||
          (v.vendor ?? "").toLowerCase().includes(q),
      );
    }
    return rows;
  }

  private sorted(rows: Vulnerability[], opts: ListOptions): Vulnerability[] {
    const dir = opts.dir === "asc" ? 1 : -1;
    const val = (v: Vulnerability): string | number | null => {
      switch (opts.sort) {
        case "cve": return v.cveId ?? "";
        case "threat": return v.title;
        case "vendor": return v.vendor ?? "";
        case "cvss": return v.cvss;
        case "epss": return v.epss;
        case "reported": return v.dateAdded ?? "";
        case "source": return v.source;
        default: return v.riskScore;
      }
    };
    return [...rows].sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1; // nulls last regardless of direction
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }

  async listVulnerabilities(opts: ListOptions = {}): Promise<Vulnerability[]> {
    return this.sorted(this.filtered(opts), opts).slice(0, opts.limit ?? 100);
  }

  async page(opts: ListOptions = {}): Promise<Page> {
    const rows = this.sorted(this.filtered(opts), opts);
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 50;
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }

  async upsertSource(source: Source): Promise<void> {
    const existing = this.sources.get(source.id);
    this.sources.set(source.id, { ...source, createdAt: source.createdAt ?? existing?.createdAt ?? new Date().toISOString() });
  }

  async listSources(): Promise<Source[]> {
    return [...this.sources.values()];
  }

  async setSourceEnabled(id: string, enabled: boolean): Promise<void> {
    const s = this.sources.get(id);
    if (s) s.enabled = enabled;
  }
  async deleteSource(id: string): Promise<void> {
    this.sources.delete(id);
    for (const [k, v] of this.vulns) if (v.source === id) this.vulns.delete(k);
    for (const [k, i] of this.indicators) if (i.source === id) this.indicators.delete(k);
    for (const [k, a] of this.advisories) if (a.source === id) this.advisories.delete(k);
  }

  private feedback = new Map<string, Verdict>();
  async setFeedback(ref: string, verdict: Verdict | null): Promise<void> {
    if (verdict) this.feedback.set(ref, verdict);
    else this.feedback.delete(ref);
  }
  async getFeedback(refs?: string[]): Promise<Record<string, Verdict>> {
    const out: Record<string, Verdict> = {};
    if (refs) { for (const r of refs) { const v = this.feedback.get(r); if (v) out[r] = v; } }
    else for (const [k, v] of this.feedback) out[k] = v;
    return out;
  }

  private savedSearches = new Map<string, SavedSearch>();
  async listSavedSearches(): Promise<SavedSearch[]> {
    return [...this.savedSearches.values()].sort((a, b) => a.name.localeCompare(b.name));
  }
  async createSavedSearch(s: Omit<SavedSearch, "id" | "createdAt">): Promise<SavedSearch> {
    const rec: SavedSearch = { ...s, id: newId(), createdAt: new Date().toISOString() };
    this.savedSearches.set(rec.id, rec);
    return rec;
  }
  async deleteSavedSearch(id: string): Promise<void> {
    this.savedSearches.delete(id);
  }

  private detRules = new Map<string, DetectionRule>();
  async listDetectionRules(): Promise<DetectionRule[]> {
    return [...this.detRules.values()].sort((a, b) => a.name.localeCompare(b.name));
  }
  async createDetectionRule(r: Omit<DetectionRule, "id" | "createdAt">): Promise<DetectionRule> {
    const rec: DetectionRule = { ...r, id: newId(), createdAt: new Date().toISOString() };
    this.detRules.set(rec.id, rec);
    return rec;
  }
  async updateDetectionRule(id: string, patch: Partial<Omit<DetectionRule, "id" | "createdAt">>): Promise<void> {
    const r = this.detRules.get(id);
    if (r) this.detRules.set(id, { ...r, ...patch });
  }
  async deleteDetectionRule(id: string): Promise<void> {
    this.detRules.delete(id);
  }

  private rfis = new Map<string, Rfi>();
  async listRfis(): Promise<Rfi[]> {
    return [...this.rfis.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
  async createRfi(question: string, context: string): Promise<Rfi> {
    const now = new Date().toISOString();
    const rec: Rfi = { id: newId(), question, context, status: "open", answer: "", createdAt: now, updatedAt: now };
    this.rfis.set(rec.id, rec);
    return rec;
  }
  async updateRfi(id: string, patch: Partial<Pick<Rfi, "status" | "answer" | "question" | "context">>): Promise<void> {
    const r = this.rfis.get(id);
    if (r) this.rfis.set(id, { ...r, ...patch, updatedAt: new Date().toISOString() });
  }
  async deleteRfi(id: string): Promise<void> {
    this.rfis.delete(id);
  }

  async cveEntities(limit = 100): Promise<CveEntity[]> {
    const byCve = new Map<string, CveEntity>();
    for (const v of this.vulns.values()) {
      const cve = v.cveId ?? v.id;
      const rel = this.sources.get(v.source)?.reliability ?? "C";
      const cur = byCve.get(cve);
      if (cur) {
        cur.riskScore = Math.max(cur.riskScore, v.riskScore);
        cur.knownExploited = cur.knownExploited || v.knownExploited;
        if (!cur.sources.some((s) => s.source === v.source)) cur.sources.push({ source: v.source, reliability: rel });
      } else {
        byCve.set(cve, { cveId: cve, title: v.title, riskScore: v.riskScore, knownExploited: v.knownExploited, sources: [{ source: v.source, reliability: rel }] });
      }
    }
    return [...byCve.values()]
      .sort((a, b) => b.sources.length - a.sources.length || b.riskScore - a.riskScore)
      .slice(0, limit);
  }

  async stats(): Promise<Stats> {
    const rows = [...this.vulns.values()];
    const terms = [...this.watch];
    return {
      total: rows.length,
      knownExploited: rows.filter((v) => v.knownExploited).length,
      ransomware: rows.filter((v) => v.ransomwareUse).length,
      critical: rows.filter((v) => v.riskScore >= 75).length,
      high: rows.filter((v) => v.riskScore >= 50 && v.riskScore < 75).length,
      sources: this.sources.size,
      indicators: this.indicators.size,
      advisories: this.advisories.size,
      inStack: terms.length ? rows.filter((v) => matchesTerms(v, terms)).length : 0,
    };
  }
}

// ---------------------------------------------------------------------------

export class PostgresRepository implements Repository {
  private pool: pg.Pool;
  private connectionString: string;
  private static CHANNEL = "omnisight_ingest";

  constructor(connectionString: string) {
    this.connectionString = connectionString;
    this.pool = new pg.Pool({ connectionString });
  }

  async signalChange(payload = ""): Promise<void> {
    await this.pool.query("SELECT pg_notify($1, $2)", [PostgresRepository.CHANNEL, payload]);
  }

  async subscribeChanges(cb: (payload: string) => void): Promise<void> {
    // Dedicated long-lived client (LISTEN can't share a pooled connection).
    const client = new pg.Client({ connectionString: this.connectionString });
    await client.connect();
    client.on("notification", (msg) => cb(msg.payload ?? ""));
    client.on("error", (err) => console.error("[db] listen error:", err.message));
    await client.query(`LISTEN ${PostgresRepository.CHANNEL}`);
  }

  async distinctCveIds(missing?: "cvss" | "epss", limit = 1000): Promise<string[]> {
    const cond =
      missing === "cvss" ? "AND cvss IS NULL" : missing === "epss" ? "AND epss IS NULL" : "";
    const { rows } = await this.pool.query(
      `SELECT DISTINCT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL ${cond} LIMIT $1`,
      [limit],
    );
    return rows.map((r) => r.cve_id as string);
  }

  async enrich(patches: EnrichPatch[]): Promise<number> {
    if (patches.length === 0) return 0;
    const client = await this.pool.connect();
    let n = 0;
    try {
      await client.query("BEGIN");
      for (const p of patches) {
        // Fetch affected rows, recompute risk in JS (keeps scoring logic in one place).
        const { rows } = await client.query(
          `SELECT source, id, known_exploited, ransomware_use, cvss, epss
             FROM vulnerabilities WHERE cve_id = $1`,
          [p.cveId],
        );
        for (const r of rows) {
          const cvss = p.cvss !== undefined ? p.cvss : r.cvss;
          const epss = p.epss !== undefined ? p.epss : r.epss;
          const risk = computeRiskScore({
            knownExploited: r.known_exploited,
            ransomwareUse: r.ransomware_use,
            cvss,
            epss,
          });
          await client.query(
            `UPDATE vulnerabilities SET cvss=$1, epss=$2, risk_score=$3 WHERE source=$4 AND id=$5`,
            [cvss, epss, risk, r.source, r.id],
          );
          n++;
        }
      }
      await client.query("COMMIT");
      return n;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async init(): Promise<void> {
    const here = dirname(fileURLToPath(import.meta.url));
    const sql = readFileSync(join(here, "schema.sql"), "utf8");
    await this.pool.query(sql);
  }

  async listWatchlist(): Promise<string[]> {
    const { rows } = await this.pool.query(`SELECT term FROM watchlist ORDER BY term`);
    return rows.map((r) => r.term as string);
  }
  async addWatchTerm(term: string): Promise<void> {
    const t = term.trim().toLowerCase();
    if (!t) return;
    await this.pool.query(`INSERT INTO watchlist (term) VALUES ($1) ON CONFLICT DO NOTHING`, [t]);
  }
  async removeWatchTerm(term: string): Promise<void> {
    await this.pool.query(`DELETE FROM watchlist WHERE term = $1`, [term.trim().toLowerCase()]);
  }

  async pendingStackAlerts(minRisk = 75): Promise<Vulnerability[]> {
    const terms = await this.listWatchlist();
    if (terms.length === 0) return [];
    const params: unknown[] = [];
    const ors = terms.map((t) => {
      params.push(`%${t}%`);
      const p = `$${params.length}`;
      return `(vendor ILIKE ${p} OR product ILIKE ${p} OR title ILIKE ${p})`;
    });
    params.push(minRisk);
    const sql = `SELECT * FROM vulnerabilities
                 WHERE (${ors.join(" OR ")})
                   AND (known_exploited = TRUE OR risk_score >= $${params.length})
                   AND (source || ':' || id) NOT IN (SELECT id FROM alert_log)
                 ORDER BY risk_score DESC LIMIT 100`;
    const { rows } = await this.pool.query(sql, params);
    return rows.map(rowToVuln);
  }

  async markAlerted(keys: string[]): Promise<void> {
    if (keys.length === 0) return;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const k of keys) {
        await client.query(`INSERT INTO alert_log (id) VALUES ($1) ON CONFLICT DO NOTHING`, [k]);
      }
      await client.query("COMMIT");
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async listNotes(ref: string): Promise<Note[]> {
    const { rows } = await this.pool.query(`SELECT * FROM notes WHERE ref = $1 ORDER BY created_at DESC`, [ref]);
    return rows.map((r) => ({
      id: r.id as string,
      ref: r.ref as string,
      tlp: r.tlp as string,
      body: r.body as string,
      createdAt: new Date(r.created_at as string).toISOString(),
    }));
  }
  async addNote(ref: string, tlp: string, body: string): Promise<Note> {
    const id = newId();
    const { rows } = await this.pool.query(
      `INSERT INTO notes (id, ref, tlp, body) VALUES ($1,$2,$3,$4) RETURNING created_at`,
      [id, ref, tlp, body],
    );
    return { id, ref, tlp, body, createdAt: new Date(rows[0].created_at as string).toISOString() };
  }
  async deleteNote(id: string): Promise<void> {
    await this.pool.query(`DELETE FROM notes WHERE id = $1`, [id]);
  }

  async getUserByUsername(username: string): Promise<UserRecord | null> {
    const { rows } = await this.pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
    if (rows.length === 0) return null;
    const r = rows[0];
    return { id: r.id, username: r.username, role: r.role, passwordHash: r.password_hash, createdAt: new Date(r.created_at).toISOString() };
  }
  async createUser(username: string, passwordHash: string, role: Role): Promise<User> {
    const id = newId();
    const { rows } = await this.pool.query(
      `INSERT INTO users (id, username, password_hash, role) VALUES ($1,$2,$3,$4) RETURNING created_at`,
      [id, username, passwordHash, role],
    );
    return { id, username, role, createdAt: new Date(rows[0].created_at).toISOString() };
  }
  async listUsers(): Promise<User[]> {
    const { rows } = await this.pool.query(`SELECT id, username, role, created_at FROM users ORDER BY username`);
    return rows.map((r) => ({ id: r.id, username: r.username, role: r.role, createdAt: new Date(r.created_at).toISOString() }));
  }
  async setUserRole(id: string, role: Role): Promise<void> {
    await this.pool.query(`UPDATE users SET role = $2 WHERE id = $1`, [id, role]);
  }
  async deleteUser(id: string): Promise<void> {
    await this.pool.query(`DELETE FROM users WHERE id = $1`, [id]);
  }
  async countUsers(): Promise<number> {
    const { rows } = await this.pool.query(`SELECT COUNT(*)::int AS n FROM users`);
    return rows[0].n as number;
  }

  async upsertSource(s: Source): Promise<void> {
    await this.pool.query(
      `INSERT INTO sources (id,name,kind,signal_type,url,schedule,enabled,requires_auth,reliability,sector,config)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
       ON CONFLICT (id) DO UPDATE SET
         name=EXCLUDED.name, kind=EXCLUDED.kind, signal_type=EXCLUDED.signal_type,
         url=EXCLUDED.url, schedule=EXCLUDED.schedule, enabled=EXCLUDED.enabled,
         requires_auth=EXCLUDED.requires_auth, reliability=EXCLUDED.reliability,
         sector=EXCLUDED.sector, config=EXCLUDED.config`,
      [s.id, s.name, s.kind, s.signalType, s.url, s.schedule, s.enabled, s.requiresAuth, s.reliability, s.sector ?? null, s.config],
    );
  }

  async listSources(): Promise<Source[]> {
    const { rows } = await this.pool.query(`SELECT * FROM sources ORDER BY name`);
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      kind: r.kind,
      signalType: r.signal_type,
      url: r.url,
      schedule: r.schedule,
      enabled: r.enabled,
      requiresAuth: r.requires_auth,
      reliability: (r.reliability as Source["reliability"]) ?? "C",
      sector: (r.sector as string) ?? null,
      config: r.config,
      createdAt: r.created_at ? new Date(r.created_at as string).toISOString() : null,
      lastRunAt: r.last_run_at ? new Date(r.last_run_at as string).toISOString() : null,
    }));
  }

  async setSourceEnabled(id: string, enabled: boolean): Promise<void> {
    await this.pool.query(`UPDATE sources SET enabled = $1 WHERE id = $2`, [enabled, id]);
  }
  async deleteSource(id: string): Promise<void> {
    // FK ON DELETE CASCADE removes this source's vulns/indicators/advisories.
    await this.pool.query(`DELETE FROM sources WHERE id = $1`, [id]);
  }

  async setFeedback(ref: string, verdict: Verdict | null): Promise<void> {
    if (verdict) {
      await this.pool.query(
        `INSERT INTO feedback (ref, verdict) VALUES ($1,$2)
           ON CONFLICT (ref) DO UPDATE SET verdict = EXCLUDED.verdict, created_at = now()`,
        [ref, verdict],
      );
    } else {
      await this.pool.query(`DELETE FROM feedback WHERE ref = $1`, [ref]);
    }
  }
  async getFeedback(refs?: string[]): Promise<Record<string, Verdict>> {
    const { rows } = refs && refs.length
      ? await this.pool.query(`SELECT ref, verdict FROM feedback WHERE ref = ANY($1)`, [refs])
      : await this.pool.query(`SELECT ref, verdict FROM feedback`);
    const out: Record<string, Verdict> = {};
    for (const r of rows) out[r.ref as string] = r.verdict as Verdict;
    return out;
  }

  async listSavedSearches(): Promise<SavedSearch[]> {
    const { rows } = await this.pool.query(`SELECT * FROM saved_searches ORDER BY name`);
    return rows.map((r) => ({
      id: r.id as string,
      name: r.name as string,
      kind: r.kind as "vuln" | "ioc",
      params: (r.params as Record<string, unknown>) ?? {},
      createdAt: new Date(r.created_at as string).toISOString(),
    }));
  }
  async createSavedSearch(s: Omit<SavedSearch, "id" | "createdAt">): Promise<SavedSearch> {
    const id = newId();
    const { rows } = await this.pool.query(
      `INSERT INTO saved_searches (id,name,kind,params) VALUES ($1,$2,$3,$4) RETURNING *`,
      [id, s.name, s.kind, JSON.stringify(s.params ?? {})],
    );
    const r = rows[0];
    return { id: r.id, name: r.name, kind: r.kind, params: r.params ?? {}, createdAt: new Date(r.created_at).toISOString() };
  }
  async deleteSavedSearch(id: string): Promise<void> {
    await this.pool.query(`DELETE FROM saved_searches WHERE id = $1`, [id]);
  }

  private rowToDetRule(r: Record<string, unknown>): DetectionRule {
    return {
      id: r.id as string,
      name: r.name as string,
      format: r.format as DetectionRule["format"],
      content: (r.content as string) ?? "",
      techniques: (r.techniques as string[]) ?? [],
      enabled: Boolean(r.enabled),
      createdAt: new Date(r.created_at as string).toISOString(),
    };
  }
  async listDetectionRules(): Promise<DetectionRule[]> {
    const { rows } = await this.pool.query(`SELECT * FROM detection_rules ORDER BY name`);
    return rows.map((r) => this.rowToDetRule(r));
  }
  async createDetectionRule(r: Omit<DetectionRule, "id" | "createdAt">): Promise<DetectionRule> {
    const { rows } = await this.pool.query(
      `INSERT INTO detection_rules (id,name,format,content,techniques,enabled) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [newId(), r.name, r.format, r.content, JSON.stringify(r.techniques ?? []), r.enabled],
    );
    return this.rowToDetRule(rows[0]);
  }
  async updateDetectionRule(id: string, patch: Partial<Omit<DetectionRule, "id" | "createdAt">>): Promise<void> {
    const sets: string[] = []; const params: unknown[] = [];
    const col: Record<string, string> = { name: "name", format: "format", content: "content", techniques: "techniques", enabled: "enabled" };
    for (const [k, v] of Object.entries(patch)) {
      const c = col[k]; if (!c) continue;
      params.push(k === "techniques" ? JSON.stringify(v) : v);
      sets.push(`${c} = $${params.length}`);
    }
    if (!sets.length) return;
    params.push(id);
    await this.pool.query(`UPDATE detection_rules SET ${sets.join(", ")} WHERE id = $${params.length}`, params);
  }
  async deleteDetectionRule(id: string): Promise<void> {
    await this.pool.query(`DELETE FROM detection_rules WHERE id = $1`, [id]);
  }

  private rowToRfi(r: Record<string, unknown>): Rfi {
    return {
      id: r.id as string,
      question: r.question as string,
      context: (r.context as string) ?? "",
      status: r.status as Rfi["status"],
      answer: (r.answer as string) ?? "",
      createdAt: new Date(r.created_at as string).toISOString(),
      updatedAt: new Date(r.updated_at as string).toISOString(),
    };
  }
  async listRfis(): Promise<Rfi[]> {
    const { rows } = await this.pool.query(`SELECT * FROM rfis ORDER BY created_at DESC`);
    return rows.map((r) => this.rowToRfi(r));
  }
  async createRfi(question: string, context: string): Promise<Rfi> {
    const { rows } = await this.pool.query(
      `INSERT INTO rfis (id,question,context) VALUES ($1,$2,$3) RETURNING *`,
      [newId(), question, context],
    );
    return this.rowToRfi(rows[0]);
  }
  async updateRfi(id: string, patch: Partial<Pick<Rfi, "status" | "answer" | "question" | "context">>): Promise<void> {
    const sets: string[] = []; const params: unknown[] = [];
    const col: Record<string, string> = { status: "status", answer: "answer", question: "question", context: "context" };
    for (const [k, v] of Object.entries(patch)) {
      const c = col[k]; if (!c) continue;
      params.push(v); sets.push(`${c} = $${params.length}`);
    }
    if (!sets.length) return;
    sets.push(`updated_at = now()`);
    params.push(id);
    await this.pool.query(`UPDATE rfis SET ${sets.join(", ")} WHERE id = $${params.length}`, params);
  }
  async deleteRfi(id: string): Promise<void> {
    await this.pool.query(`DELETE FROM rfis WHERE id = $1`, [id]);
  }

  async cveEntities(limit = 100): Promise<CveEntity[]> {
    const { rows } = await this.pool.query(
      `SELECT COALESCE(v.cve_id, v.id) AS cve,
              MAX(v.title) AS title,
              MAX(v.risk_score) AS risk,
              BOOL_OR(v.known_exploited) AS exploited,
              JSON_AGG(JSON_BUILD_OBJECT('source', v.source, 'reliability', COALESCE(s.reliability,'C'))) AS sources,
              COUNT(DISTINCT v.source) AS n
         FROM vulnerabilities v LEFT JOIN sources s ON s.id = v.source
         GROUP BY COALESCE(v.cve_id, v.id)
         ORDER BY n DESC, risk DESC
         LIMIT $1`,
      [Math.min(limit, 500)],
    );
    return rows.map((r) => ({
      cveId: r.cve as string,
      title: (r.title as string) ?? "",
      riskScore: Number(r.risk ?? 0),
      knownExploited: Boolean(r.exploited),
      sources: (r.sources as { source: string; reliability: string }[]) ?? [],
    }));
  }

  async upsertVulnerabilities(items: Vulnerability[]): Promise<number> {
    if (items.length === 0) return 0;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const v of items) {
        await client.query(
          `INSERT INTO vulnerabilities
             (id,source,cve_id,title,description,vendor,product,known_exploited,ransomware_use,
              cvss,epss,cwes,required_action,due_date,date_added,references_json,risk_score,fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
           ON CONFLICT (source,id) DO UPDATE SET
             cve_id=EXCLUDED.cve_id, title=EXCLUDED.title, description=EXCLUDED.description,
             vendor=EXCLUDED.vendor, product=EXCLUDED.product, known_exploited=EXCLUDED.known_exploited,
             ransomware_use=EXCLUDED.ransomware_use, cvss=EXCLUDED.cvss, epss=EXCLUDED.epss,
             cwes=EXCLUDED.cwes, required_action=EXCLUDED.required_action, due_date=EXCLUDED.due_date,
             date_added=EXCLUDED.date_added, references_json=EXCLUDED.references_json,
             risk_score=EXCLUDED.risk_score, fetched_at=EXCLUDED.fetched_at`,
          [
            v.id, v.source, v.cveId, v.title, v.description, v.vendor, v.product,
            v.knownExploited, v.ransomwareUse, v.cvss, v.epss, JSON.stringify(v.cwes),
            v.requiredAction, v.dueDate, v.dateAdded, JSON.stringify(v.references),
            v.riskScore, v.fetchedAt,
          ],
        );
      }
      await client.query("COMMIT");
      return items.length;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  private buildFilters(opts: ListOptions): { clause: string; params: unknown[] } {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.minRisk != null) {
      params.push(opts.minRisk);
      where.push(`risk_score >= $${params.length}`);
    }
    if (opts.source) {
      params.push(opts.source);
      where.push(`source = $${params.length}`);
    }
    if (opts.exploited) where.push(`known_exploited = TRUE`);
    if (opts.ransomware) where.push(`ransomware_use = TRUE`);
    if (opts.vendor) {
      // Match the title too: NVD CVEs often carry the vendor name only in the
      // title (the vendor column is null), so a column-only filter misses them.
      params.push(`%${opts.vendor}%`);
      where.push(`(vendor ILIKE $${params.length} OR product ILIKE $${params.length} OR title ILIKE $${params.length})`);
    }
    if (opts.terms && opts.terms.length) {
      const ors = opts.terms.map((t) => {
        params.push(`%${t}%`);
        const p = `$${params.length}`;
        return `(vendor ILIKE ${p} OR product ILIKE ${p} OR title ILIKE ${p})`;
      });
      where.push(`(${ors.join(" OR ")})`);
    }
    if (opts.q) {
      params.push(`%${opts.q}%`);
      where.push(`(title ILIKE $${params.length} OR cve_id ILIKE $${params.length} OR vendor ILIKE $${params.length})`);
    }
    return { clause: where.length ? "WHERE " + where.join(" AND ") : "", params };
  }

  private static SORT_COLS: Record<string, string> = {
    risk: "risk_score", cve: "cve_id", threat: "title",
    vendor: "vendor", cvss: "cvss", epss: "epss", reported: "date_added", source: "source",
  };

  // Whitelisted column + direction — never interpolate raw user input into SQL.
  private buildOrder(opts: ListOptions): string {
    const col = PostgresRepository.SORT_COLS[opts.sort ?? "risk"] ?? "risk_score";
    const dir = opts.dir === "asc" ? "ASC" : "DESC";
    return `ORDER BY ${col} ${dir} NULLS LAST, source, id`;
  }

  async listVulnerabilities(opts: ListOptions = {}): Promise<Vulnerability[]> {
    const { clause, params } = this.buildFilters(opts);
    params.push(opts.limit ?? 100);
    const sql = `SELECT * FROM vulnerabilities ${clause} ${this.buildOrder(opts)} LIMIT $${params.length}`;
    const { rows } = await this.pool.query(sql, params);
    return rows.map(rowToVuln);
  }

  async page(opts: ListOptions = {}): Promise<Page> {
    const { clause, params } = this.buildFilters(opts);
    const countRes = await this.pool.query(
      `SELECT COUNT(*)::int AS total FROM vulnerabilities ${clause}`,
      params,
    );
    const total = countRes.rows[0].total as number;
    const paged = [...params];
    paged.push(opts.limit ?? 50);
    const li = `$${paged.length}`;
    paged.push(opts.offset ?? 0);
    const oi = `$${paged.length}`;
    const sql = `SELECT * FROM vulnerabilities ${clause} ${this.buildOrder(opts)} LIMIT ${li} OFFSET ${oi}`;
    const { rows } = await this.pool.query(sql, paged);
    return { items: rows.map(rowToVuln), total };
  }

  async upsertIndicators(items: Indicator[]): Promise<number> {
    if (items.length === 0) return 0;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const i of items) {
        await client.query(
          `INSERT INTO indicators
             (id,source,type,value,malware,threat_type,confidence,references_json,tags,first_seen,last_seen,country,country_code,lat,lng,fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
           ON CONFLICT (source,id) DO UPDATE SET
             type=EXCLUDED.type, value=EXCLUDED.value, malware=EXCLUDED.malware,
             threat_type=EXCLUDED.threat_type, confidence=EXCLUDED.confidence,
             references_json=EXCLUDED.references_json, tags=EXCLUDED.tags,
             first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen,
             -- keep existing geo if the new row hasn't been geolocated yet
             country=COALESCE(EXCLUDED.country, indicators.country),
             country_code=COALESCE(EXCLUDED.country_code, indicators.country_code),
             lat=COALESCE(EXCLUDED.lat, indicators.lat),
             lng=COALESCE(EXCLUDED.lng, indicators.lng),
             fetched_at=EXCLUDED.fetched_at`,
          [
            i.id, i.source, i.type, i.value, i.malware, i.threatType, i.confidence,
            JSON.stringify(i.references), JSON.stringify(i.tags), i.firstSeen, i.lastSeen,
            i.country ?? null, i.countryCode ?? null, i.lat ?? null, i.lng ?? null, i.fetchedAt,
          ],
        );
      }
      await client.query("COMMIT");
      return items.length;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  private static IOC_SORT: Record<string, string> = {
    confidence: "confidence", lastseen: "last_seen", type: "type",
    malware: "malware", value: "value", source: "source",
  };

  async pageIndicators(opts: IndicatorListOptions = {}): Promise<IndicatorPage> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.type) { params.push(opts.type); where.push(`type = $${params.length}`); }
    if (opts.source) { params.push(opts.source); where.push(`source = $${params.length}`); }
    if (opts.malware) { params.push(`%${opts.malware}%`); where.push(`malware ILIKE $${params.length}`); }
    if (opts.q) {
      params.push(`%${opts.q}%`);
      where.push(`(value ILIKE $${params.length} OR malware ILIKE $${params.length} OR threat_type ILIKE $${params.length})`);
    }
    if (opts.maxAgeDays) {
      params.push(opts.maxAgeDays);
      where.push(`(last_seen IS NULL OR last_seen >= now() - ($${params.length} || ' days')::interval)`);
    }
    if (opts.minConfidence) {
      params.push(opts.minConfidence);
      where.push(`COALESCE(confidence, 0) >= $${params.length}`);
    }
    const clause = where.length ? "WHERE " + where.join(" AND ") : "";
    const countRes = await this.pool.query(`SELECT COUNT(*)::int AS total FROM indicators ${clause}`, params);
    const total = countRes.rows[0].total as number;

    const col = PostgresRepository.IOC_SORT[opts.sort ?? "lastseen"] ?? "last_seen";
    const dir = opts.dir === "asc" ? "ASC" : "DESC";
    const paged = [...params];
    paged.push(opts.limit ?? 50);
    const li = `$${paged.length}`;
    paged.push(opts.offset ?? 0);
    const oi = `$${paged.length}`;
    const sql = `SELECT * FROM indicators ${clause} ORDER BY ${col} ${dir} NULLS LAST, source, id LIMIT ${li} OFFSET ${oi}`;
    const { rows } = await this.pool.query(sql, paged);
    return { items: rows.map(rowToIndicator), total };
  }

  async upsertAdvisories(items: Advisory[]): Promise<number> {
    if (items.length === 0) return 0;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const a of items) {
        await client.query(
          `INSERT INTO advisories (id,source,title,summary,url,category,published,tags,fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
           ON CONFLICT (source,id) DO UPDATE SET
             title=EXCLUDED.title, summary=EXCLUDED.summary, url=EXCLUDED.url,
             category=EXCLUDED.category, published=EXCLUDED.published, tags=EXCLUDED.tags,
             fetched_at=EXCLUDED.fetched_at`,
          [a.id, a.source, a.title, a.summary, a.url, a.category, a.published, JSON.stringify(a.tags), a.fetchedAt],
        );
      }
      await client.query("COMMIT");
      return items.length;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async pageAdvisories(opts: AdvisoryListOptions = {}): Promise<AdvisoryPage> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.source) { params.push(opts.source); where.push(`source = $${params.length}`); }
    if (opts.q) {
      params.push(`%${opts.q}%`);
      where.push(`(title ILIKE $${params.length} OR summary ILIKE $${params.length})`);
    }
    const clause = where.length ? "WHERE " + where.join(" AND ") : "";
    const countRes = await this.pool.query(`SELECT COUNT(*)::int AS total FROM advisories ${clause}`, params);
    const total = countRes.rows[0].total as number;
    const paged = [...params];
    paged.push(opts.limit ?? 50);
    const li = `$${paged.length}`;
    paged.push(opts.offset ?? 0);
    const oi = `$${paged.length}`;
    const sql = `SELECT * FROM advisories ${clause} ORDER BY published DESC NULLS LAST, id LIMIT ${li} OFFSET ${oi}`;
    const { rows } = await this.pool.query(sql, paged);
    return { items: rows.map(rowToAdvisory), total };
  }

  async pruneStaleIndicators(days: number): Promise<number> {
    const res = await this.pool.query(
      `DELETE FROM indicators WHERE last_seen IS NOT NULL AND last_seen < now() - ($1 || ' days')::interval`,
      [days],
    );
    return res.rowCount ?? 0;
  }

  async ipsNeedingGeo(limit = 200): Promise<string[]> {
    const { rows } = await this.pool.query(
      `SELECT DISTINCT value FROM indicators WHERE type = 'ip' AND lat IS NULL LIMIT $1`,
      [limit],
    );
    return rows.map((r) => r.value as string);
  }

  async setGeo(value: string, geo: GeoPatch): Promise<void> {
    await this.pool.query(
      `UPDATE indicators SET country=$2, country_code=$3, lat=$4, lng=$5 WHERE value=$1`,
      [value, geo.country, geo.countryCode, geo.lat, geo.lng],
    );
  }

  async mapData(): Promise<MapPoint[]> {
    const { rows } = await this.pool.query(
      `SELECT COALESCE(country,'Unknown') AS country, country_code AS code,
              AVG(lat)::float8 AS lat, AVG(lng)::float8 AS lng, COUNT(*)::int AS count
         FROM indicators WHERE lat IS NOT NULL AND lng IS NOT NULL
         GROUP BY country, country_code
         ORDER BY count DESC`,
    );
    return rows.map((r) => ({ country: r.country, code: r.code, lat: r.lat, lng: r.lng, count: r.count }));
  }

  async mapIndicators(country: string, limit = 500): Promise<MapIndicator[]> {
    const { rows } = await this.pool.query(
      `SELECT value, lat, lng, malware, type, source FROM indicators
         WHERE (country_code = $1 OR country = $1) AND lat IS NOT NULL AND lng IS NOT NULL
         LIMIT $2`,
      [country, limit],
    );
    return rows.map((r) => ({
      value: r.value as string,
      lat: Number(r.lat),
      lng: Number(r.lng),
      malware: (r.malware as string) ?? null,
      type: r.type as string,
      source: r.source as string,
    }));
  }

  async cveCorrelations(limit = 50): Promise<Correlation[]> {
    // Pull indicators that mention a CVE anywhere, then extract + join in JS.
    const { rows } = await this.pool.query(
      `SELECT value, source, malware, type, threat_type, tags FROM indicators
         WHERE value ILIKE '%CVE-%' OR malware ILIKE '%CVE-%'
            OR threat_type ILIKE '%CVE-%' OR tags::text ILIKE '%CVE-%'
         LIMIT 5000`,
    );
    const byCve = new Map<string, Correlation["indicators"]>();
    for (const r of rows) {
      const tags = Array.isArray(r.tags) ? (r.tags as string[]).join(" ") : "";
      const hay = `${r.value} ${r.malware ?? ""} ${r.threat_type ?? ""} ${tags}`;
      const found = hay.match(CVE_RE);
      if (!found) continue;
      for (const raw of found) {
        const cve = raw.toUpperCase();
        const arr = byCve.get(cve) ?? [];
        if (arr.length < 25) arr.push({ value: r.value, source: r.source, malware: r.malware ?? null, type: r.type });
        byCve.set(cve, arr);
      }
    }
    if (byCve.size === 0) return [];
    const cves = [...byCve.keys()];
    const { rows: vrows } = await this.pool.query(
      `SELECT DISTINCT ON (cve_id) cve_id, title, risk_score FROM vulnerabilities
         WHERE cve_id = ANY($1) ORDER BY cve_id, risk_score DESC`,
      [cves],
    );
    const vmap = new Map(vrows.map((v) => [v.cve_id as string, { title: v.title as string, risk: v.risk_score as number }]));
    const out: Correlation[] = cves.map((cveId) => {
      const v = vmap.get(cveId);
      return { cveId, title: v?.title ?? null, riskScore: v?.risk ?? null, indicators: byCve.get(cveId)! };
    });
    out.sort((a, b) => (b.riskScore ?? -1) - (a.riskScore ?? -1) || b.indicators.length - a.indicators.length);
    return out.slice(0, limit);
  }

  async attackTechniques(limit = 60): Promise<AttackTechnique[]> {
    const hays: string[] = [];
    const adv = await this.pool.query(`SELECT title, summary, category, tags FROM advisories LIMIT 5000`);
    for (const r of adv.rows) {
      const tags = Array.isArray(r.tags) ? (r.tags as string[]).join(" ") : "";
      hays.push(`${r.title} ${r.summary ?? ""} ${r.category ?? ""} ${tags}`);
    }
    const ioc = await this.pool.query(
      `SELECT value, malware, threat_type, tags FROM indicators
         WHERE tags::text ~ 'T[0-9]{4}' OR threat_type ~ 'T[0-9]{4}' OR malware ~ 'T[0-9]{4}'
         LIMIT 5000`,
    );
    for (const r of ioc.rows) {
      const tags = Array.isArray(r.tags) ? (r.tags as string[]).join(" ") : "";
      hays.push(`${r.value} ${r.malware ?? ""} ${r.threat_type ?? ""} ${tags}`);
    }
    return tallyTechniques(hays, limit);
  }

  async actorProfiles(limit = 60): Promise<ActorProfile[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM indicators WHERE malware IS NOT NULL AND malware <> '' LIMIT 20000`,
    );
    return buildActorProfiles(rows.map(rowToIndicator)).slice(0, limit);
  }

  async actorProfile(name: string): Promise<ActorProfile | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM indicators WHERE LOWER(TRIM(malware)) = LOWER(TRIM($1)) LIMIT 20000`,
      [name],
    );
    return buildActorProfiles(rows.map(rowToIndicator))[0] ?? null;
  }

  async appendAudit(entry: Omit<AuditEntry, "id" | "at">): Promise<void> {
    await this.pool.query(
      `INSERT INTO audit_log (id, username, role, action, method, path, status)
         VALUES ($1,$2,$3,$4,$5,$6,$7)`,
      [newId(), entry.user, entry.role, entry.action, entry.method, entry.path, entry.status],
    );
  }

  async listAudit(limit = 200): Promise<AuditEntry[]> {
    const { rows } = await this.pool.query(
      `SELECT * FROM audit_log ORDER BY at DESC LIMIT $1`,
      [Math.min(limit, 1000)],
    );
    return rows.map((r) => ({
      id: r.id as string,
      at: new Date(r.at as string).toISOString(),
      user: (r.username as string) ?? null,
      role: (r.role as string) ?? null,
      action: r.action as string,
      method: r.method as string,
      path: r.path as string,
      status: r.status != null ? Number(r.status) : null,
    }));
  }

  async upsertBreaches(items: Breach[]): Promise<number> {
    for (const b of items) {
      await this.pool.query(
        `INSERT INTO breaches (id,domain,title,breach_date,added_date,pwn_count,data_classes,description,verified,fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
           ON CONFLICT (id) DO UPDATE SET
             domain=EXCLUDED.domain, title=EXCLUDED.title, breach_date=EXCLUDED.breach_date,
             added_date=EXCLUDED.added_date, pwn_count=EXCLUDED.pwn_count, data_classes=EXCLUDED.data_classes,
             description=EXCLUDED.description, verified=EXCLUDED.verified, fetched_at=EXCLUDED.fetched_at`,
        [b.id, b.domain, b.title, b.breachDate, b.addedDate, b.pwnCount, JSON.stringify(b.dataClasses), b.description, b.verified, b.fetchedAt],
      );
    }
    return items.length;
  }

  async listBreaches(limit = 200): Promise<Breach[]> {
    const { rows } = await this.pool.query(`SELECT * FROM breaches ORDER BY breach_date DESC NULLS LAST LIMIT $1`, [Math.min(limit, 500)]);
    return rows.map((r) => ({
      id: r.id as string,
      domain: r.domain as string,
      title: r.title as string,
      breachDate: r.breach_date ? new Date(r.breach_date as string).toISOString().slice(0, 10) : null,
      addedDate: r.added_date ? new Date(r.added_date as string).toISOString() : null,
      pwnCount: Number(r.pwn_count ?? 0),
      dataClasses: (r.data_classes as string[]) ?? [],
      description: (r.description as string) ?? "",
      verified: Boolean(r.verified),
      fetchedAt: new Date(r.fetched_at as string).toISOString(),
    }));
  }

  private rowToRule(r: Record<string, unknown>): Rule {
    return {
      id: r.id as string,
      name: r.name as string,
      enabled: Boolean(r.enabled),
      minRisk: Number(r.min_risk ?? 75),
      exploitedOnly: Boolean(r.exploited_only),
      stackOnly: Boolean(r.stack_only),
      action: r.action as RuleAction,
      config: (r.config as Record<string, unknown>) ?? {},
      createdAt: new Date(r.created_at as string).toISOString(),
    };
  }

  async listRules(): Promise<Rule[]> {
    const { rows } = await this.pool.query(`SELECT * FROM rules ORDER BY created_at ASC`);
    return rows.map((r) => this.rowToRule(r));
  }

  async createRule(rule: Omit<Rule, "id" | "createdAt">): Promise<Rule> {
    const id = newId();
    const { rows } = await this.pool.query(
      `INSERT INTO rules (id,name,enabled,min_risk,exploited_only,stack_only,action,config)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
      [id, rule.name, rule.enabled, rule.minRisk, rule.exploitedOnly, rule.stackOnly, rule.action, JSON.stringify(rule.config ?? {})],
    );
    return this.rowToRule(rows[0]);
  }

  async updateRule(id: string, patch: Partial<Omit<Rule, "id" | "createdAt">>): Promise<void> {
    const sets: string[] = [];
    const params: unknown[] = [];
    const col: Record<string, string> = {
      name: "name", enabled: "enabled", minRisk: "min_risk",
      exploitedOnly: "exploited_only", stackOnly: "stack_only", action: "action", config: "config",
    };
    for (const [k, v] of Object.entries(patch)) {
      const c = col[k];
      if (!c) continue;
      params.push(k === "config" ? JSON.stringify(v) : v);
      sets.push(`${c} = $${params.length}`);
    }
    if (!sets.length) return;
    params.push(id);
    await this.pool.query(`UPDATE rules SET ${sets.join(", ")} WHERE id = $${params.length}`, params);
  }

  async deleteRule(id: string): Promise<void> {
    await this.pool.query(`DELETE FROM rules WHERE id = $1`, [id]);
  }

  async pendingRuleCandidates(floorRisk: number): Promise<Vulnerability[]> {
    const { rows } = await this.pool.query(
      `SELECT v.* FROM vulnerabilities v
         WHERE (v.known_exploited = TRUE OR v.risk_score >= $1)
           AND NOT EXISTS (SELECT 1 FROM alert_log a WHERE a.id = v.source || ':' || v.id)
         ORDER BY v.risk_score DESC LIMIT 200`,
      [floorRisk],
    );
    return rows.map(rowToVuln);
  }

  async stats(): Promise<Stats> {
    const { rows } = await this.pool.query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE known_exploited)::int AS known_exploited,
              COUNT(*) FILTER (WHERE ransomware_use)::int AS ransomware,
              COUNT(*) FILTER (WHERE risk_score >= 75)::int AS critical,
              COUNT(*) FILTER (WHERE risk_score >= 50 AND risk_score < 75)::int AS high,
              (SELECT COUNT(*)::int FROM sources) AS sources,
              (SELECT COUNT(*)::int FROM indicators) AS indicators,
              (SELECT COUNT(*)::int FROM advisories) AS advisories
       FROM vulnerabilities`,
    );
    const r = rows[0];

    // "In stack" depends on the watchlist terms, so count it separately.
    const terms = await this.listWatchlist();
    let inStack = 0;
    if (terms.length) {
      const params: unknown[] = [];
      const ors = terms.map((t) => {
        params.push(`%${t}%`);
        const p = `$${params.length}`;
        return `(vendor ILIKE ${p} OR product ILIKE ${p} OR title ILIKE ${p})`;
      });
      const res = await this.pool.query(
        `SELECT COUNT(*)::int AS n FROM vulnerabilities WHERE ${ors.join(" OR ")}`,
        params,
      );
      inStack = res.rows[0].n as number;
    }

    return {
      total: r.total,
      knownExploited: r.known_exploited,
      ransomware: r.ransomware,
      critical: r.critical,
      high: r.high,
      sources: r.sources,
      indicators: r.indicators,
      advisories: r.advisories,
      inStack,
    };
  }
}

function rowToVuln(r: Record<string, unknown>): Vulnerability {
  return {
    id: r.id as string,
    source: r.source as string,
    cveId: (r.cve_id as string) ?? null,
    title: r.title as string,
    description: (r.description as string) ?? "",
    vendor: (r.vendor as string) ?? null,
    product: (r.product as string) ?? null,
    knownExploited: Boolean(r.known_exploited),
    ransomwareUse: Boolean(r.ransomware_use),
    cvss: (r.cvss as number) ?? null,
    epss: (r.epss as number) ?? null,
    cwes: (r.cwes as string[]) ?? [],
    requiredAction: (r.required_action as string) ?? null,
    dueDate: r.due_date ? String(r.due_date).slice(0, 10) : null,
    dateAdded: r.date_added ? String(r.date_added).slice(0, 10) : null,
    references: (r.references_json as string[]) ?? [],
    riskScore: r.risk_score as number,
    fetchedAt: new Date(r.fetched_at as string).toISOString(),
  };
}

function rowToAdvisory(r: Record<string, unknown>): Advisory {
  return {
    id: r.id as string,
    source: r.source as string,
    title: r.title as string,
    summary: (r.summary as string) ?? "",
    url: (r.url as string) ?? "",
    category: (r.category as string) ?? null,
    published: r.published ? new Date(r.published as string).toISOString() : null,
    tags: (r.tags as string[]) ?? [],
    fetchedAt: new Date(r.fetched_at as string).toISOString(),
  };
}

function rowToIndicator(r: Record<string, unknown>): Indicator {
  return {
    id: r.id as string,
    source: r.source as string,
    type: r.type as Indicator["type"],
    value: r.value as string,
    malware: (r.malware as string) ?? null,
    threatType: (r.threat_type as string) ?? null,
    confidence: (r.confidence as number) ?? null,
    references: (r.references_json as string[]) ?? [],
    tags: (r.tags as string[]) ?? [],
    firstSeen: r.first_seen ? new Date(r.first_seen as string).toISOString() : null,
    lastSeen: r.last_seen ? new Date(r.last_seen as string).toISOString() : null,
    country: (r.country as string) ?? null,
    countryCode: (r.country_code as string) ?? null,
    lat: r.lat != null ? Number(r.lat) : null,
    lng: r.lng != null ? Number(r.lng) : null,
    fetchedAt: new Date(r.fetched_at as string).toISOString(),
  };
}
