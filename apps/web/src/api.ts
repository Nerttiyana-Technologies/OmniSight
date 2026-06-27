import type { Vulnerability, Indicator, Source, NewSource } from "@omnisight/shared";

export interface Stats {
  total: number;
  knownExploited: number;
  ransomware: number;
  critical: number;
  high: number;
  sources: number;
  indicators: number;
}

export interface IndicatorQuery {
  page?: number;
  pageSize?: number;
  type?: string;
  malware?: string;
  q?: string;
  source?: string;
  sort?: string;
  dir?: "asc" | "desc";
}

export interface IndicatorPage {
  items: Indicator[];
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

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json() as Promise<T>;
}

export const api = {
  stats: () => fetch("/api/stats").then(json<Stats>),
  vulnerabilities: (params: VulnQuery = {}) => {
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
    return fetch(`/api/vulnerabilities?${qs}`).then(json<VulnPage>);
  },
  sources: () => fetch("/api/sources").then(json<Source[]>),
  addSource: (body: NewSource) =>
    fetch("/api/sources", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }).then(json<Source>),
  runSource: (id: string) =>
    fetch(`/api/sources/${id}/run`, { method: "POST" }).then(json<{ ingested: number }>),
  indicators: (params: IndicatorQuery = {}) => {
    const qs = new URLSearchParams();
    if (params.page != null) qs.set("page", String(params.page));
    if (params.pageSize != null) qs.set("pageSize", String(params.pageSize));
    if (params.type) qs.set("type", params.type);
    if (params.malware) qs.set("malware", params.malware);
    if (params.q) qs.set("q", params.q);
    if (params.source) qs.set("source", params.source);
    if (params.sort) qs.set("sort", params.sort);
    if (params.dir) qs.set("dir", params.dir);
    return fetch(`/api/indicators?${qs}`).then(json<IndicatorPage>);
  },
  watchlist: () => fetch("/api/watchlist").then(json<string[]>),
  addWatch: (term: string) =>
    fetch("/api/watchlist", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ term }),
    }).then(json<string[]>),
  removeWatch: (term: string) =>
    fetch(`/api/watchlist/${encodeURIComponent(term)}`, { method: "DELETE" }).then(json<string[]>),
  enrich: () => fetch("/api/enrich", { method: "POST" }).then(json<{ enriched: number }>),
  /** Open the SSE stream. Returns the EventSource so callers can close it. */
  stream: (onUpdate: () => void, onError: () => void): EventSource => {
    const es = new EventSource("/api/stream");
    es.onmessage = () => onUpdate();
    es.onerror = () => onError();
    return es;
  },
};
