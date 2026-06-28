import type { Vulnerability, Indicator, Advisory, Source, NewSource, Digest, User } from "@omnisight/shared";

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

export interface IndicatorQuery {
  page?: number;
  pageSize?: number;
  type?: string;
  malware?: string;
  q?: string;
  source?: string;
  maxAgeDays?: number;
  sort?: string;
  dir?: "asc" | "desc";
}

export interface IndicatorPage {
  items: Indicator[];
  total: number;
  page: number;
  pageSize: number;
}

export interface AdvisoryQuery {
  page?: number;
  pageSize?: number;
  source?: string;
  q?: string;
}

export interface AdvisoryPage {
  items: Advisory[];
  total: number;
  page: number;
  pageSize: number;
}

export interface VulnQuery {
  page?: number;
  pageSize?: number;
  minRisk?: number;
  q?: string;
  vendor?: string;
  source?: string;
  exploited?: boolean;
  ransomware?: boolean;
  myStack?: boolean;
  sort?: string;
  dir?: "asc" | "desc";
}

export interface VulnPage {
  items: Vulnerability[];
  total: number;
  page: number;
  pageSize: number;
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
  title: string | null;
  riskScore: number | null;
  indicators: { value: string; source: string; malware: string | null; type: string }[];
}

export interface SbomResult {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
  vulns: string[];
}
export interface SbomReport {
  total: number;
  vulnerable: number;
  components: SbomResult[];
}

export interface AttackTechnique {
  id: string;
  count: number;
  framework: "attack" | "atlas";
}

export interface Note {
  id: string;
  ref: string;
  tlp: string;
  body: string;
  createdAt: string;
}

export interface ActorProfile {
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

export interface AiVulnResult {
  filters: Record<string, unknown>;
  items: Vulnerability[];
  total: number;
}

export interface IocEnrichment {
  value: string;
  type: string;
  shodan: { ports: number[]; hostnames: string[]; tags: string[]; vulns: string[]; cpes: string[] } | null;
  greynoise: { noise: boolean; riot: boolean; classification: string; name: string | null; lastSeen: string | null } | null;
  abuseipdb: { score: number; reports: number; countryCode: string | null; isp: string | null } | null;
  errors: string[];
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

// --- Auth: token storage + auth-aware fetch ---
const baseFetch = globalThis.fetch.bind(globalThis);
let token: string | null = (() => { try { return localStorage.getItem("omnisight_token"); } catch { return null; } })();

export function setToken(t: string | null): void {
  token = t;
  try { if (t) localStorage.setItem("omnisight_token", t); else localStorage.removeItem("omnisight_token"); } catch { /* ignore */ }
}
export function getToken(): string | null { return token; }
export function streamToken(): string { return token ? `?token=${encodeURIComponent(token)}` : ""; }

/** fetch with the bearer token attached when present. */
function af(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  if (token) headers.set("authorization", `Bearer ${token}`);
  return baseFetch(input, { ...init, headers });
}

function vulnQs(params: VulnQuery): string {
  const qs = new URLSearchParams();
  if (params.page != null) qs.set("page", String(params.page));
  if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
  if (params.minRisk) qs.set("minRisk", String(params.minRisk));
  if (params.q) qs.set("q", params.q);
  if (params.vendor) qs.set("vendor", params.vendor);
  if (params.source) qs.set("source", params.source);
  if (params.exploited) qs.set("exploited", "true");
  if (params.ransomware) qs.set("ransomware", "true");
  if (params.myStack) qs.set("myStack", "true");
  if (params.sort) qs.set("sort", params.sort);
  if (params.dir) qs.set("dir", params.dir);
  return qs.toString();
}

function iocQs(params: IndicatorQuery): string {
  const qs = new URLSearchParams();
  if (params.page != null) qs.set("page", String(params.page));
  if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
  if (params.type) qs.set("type", params.type);
  if (params.malware) qs.set("malware", params.malware);
  if (params.q) qs.set("q", params.q);
  if (params.source) qs.set("source", params.source);
  if (params.maxAgeDays) qs.set("maxAgeDays", String(params.maxAgeDays));
  if (params.sort) qs.set("sort", params.sort);
  if (params.dir) qs.set("dir", params.dir);
  return qs.toString();
}

export const api = {
  authConfig: () => af("/api/auth/config").then(json<{ authEnabled: boolean; sso: boolean; ssoLabel?: string }>),
  me: () => af("/api/auth/me").then(json<{ authEnabled: boolean; user: User | null }>),
  login: (username: string, password: string) =>
    af("/api/auth/login", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password }) }).then(json<{ token: string; user: User }>),
  users: () => af("/api/users").then(json<User[]>),
  createUser: (username: string, password: string, role: string) =>
    af("/api/users", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ username, password, role }) }).then(json<User>),
  setUserRole: (id: string, role: string) =>
    af(`/api/users/${id}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ role }) }).then(json<{ ok: boolean }>),
  deleteUser: (id: string) => af(`/api/users/${id}`, { method: "DELETE" }).then(json<{ ok: boolean }>),
  aiConfig: () => af("/api/ai/config").then(json<{ enabled: boolean }>),
  aiSummarize: (text: string) =>
    af("/api/ai/summarize", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ text }) }).then(json<{ summary: string }>),
  aiQuery: (q: string) =>
    af("/api/ai/query", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ q }) }).then(json<AiVulnResult>),
  actors: () => af("/api/actors").then(json<ActorProfile[]>),
  actor: (name: string) => af(`/api/actors/${encodeURIComponent(name)}`).then(json<ActorProfile>),
  audit: () => af("/api/audit").then(json<AuditEntry[]>),
  stats: () => af("/api/stats").then(json<Stats>),
  map: () => af("/api/map").then(json<MapPoint[]>),
  correlations: () => af("/api/correlations").then(json<Correlation[]>),
  attack: () => af("/api/attack").then(json<AttackTechnique[]>),
  sbom: (obj: unknown) =>
    af("/api/sbom", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(obj) }).then(json<SbomReport>),
  importStix: (obj: unknown) =>
    af("/api/import/stix", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(obj) }).then(json<{ imported: number }>),
  enrichIoc: (value: string, type: string) =>
    af(`/api/enrich/ioc?value=${encodeURIComponent(value)}&type=${encodeURIComponent(type)}`).then(json<IocEnrichment>),
  notes: (ref: string) => af(`/api/notes?ref=${encodeURIComponent(ref)}`).then(json<Note[]>),
  addNote: (ref: string, tlp: string, body: string) =>
    af("/api/notes", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ref, tlp, body }) }).then(json<Note>),
  deleteNote: (id: string) => af(`/api/notes/${encodeURIComponent(id)}`, { method: "DELETE" }).then(json<{ ok: boolean }>),
  mapIndicators: (code: string) =>
    af(`/api/map/indicators?code=${encodeURIComponent(code)}`).then(json<MapIndicator[]>),
  digest: () => af("/api/digest").then(json<Digest>),
  digestUrl: (format: "html" | "md") => `/api/digest?format=${format}`,
  vulnerabilities: (params: VulnQuery = {}) =>
    af(`/api/vulnerabilities?${vulnQs(params)}`).then(json<VulnPage>),
  exportVulnUrl: (params: VulnQuery = {}) => `/api/vulnerabilities/export?${vulnQs(params)}`,
  sources: () => af("/api/sources").then(json<Source[]>),
  addSource: (body: NewSource) =>
    af("/api/sources", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(json<Source>),
  runSource: (id: string) =>
    af(`/api/sources/${id}/run`, { method: "POST" }).then(json<{ ingested: number }>),
  indicators: (params: IndicatorQuery = {}) =>
    af(`/api/indicators?${iocQs(params)}`).then(json<IndicatorPage>),
  exportIndicatorUrl: (params: IndicatorQuery = {}, format = "csv") => {
    const qs = iocQs(params);
    return `/api/indicators/export?${qs}${qs ? "&" : ""}format=${format}`;
  },
  advisories: (params: AdvisoryQuery = {}) => {
    const qs = new URLSearchParams();
    if (params.page != null) qs.set("page", String(params.page));
    if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
    if (params.source) qs.set("source", params.source);
    if (params.q) qs.set("q", params.q);
    return af(`/api/advisories?${qs}`).then(json<AdvisoryPage>);
  },
  watchlist: () => af("/api/watchlist").then(json<string[]>),
  addWatch: (term: string) =>
    af("/api/watchlist", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ term }),
    }).then(json<string[]>),
  removeWatch: (term: string) =>
    af(`/api/watchlist/${encodeURIComponent(term)}`, { method: "DELETE" }).then(json<string[]>),
  enrich: () => af("/api/enrich", { method: "POST" }).then(json<{ enriched: number }>),
  /** Open the SSE stream. Returns the EventSource so callers can close it. */
  stream: (onUpdate: () => void, onError: () => void): EventSource => {
    const es = new EventSource(`/api/stream${streamToken()}`);
    es.onmessage = () => onUpdate();
    es.onerror = () => onError();
    return es;
  },
};
