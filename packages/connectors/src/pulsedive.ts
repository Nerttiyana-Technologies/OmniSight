import { IndicatorSchema, type Indicator, type IndicatorType } from "@omnisight/shared";
import type { IndicatorConnector, FetchOptions } from "./types.js";

const EXPLORE_URL = "https://pulsedive.com/api/explore.php";
// Free-tier-friendly default: active, higher-risk indicators.
const DEFAULT_QUERY = "risk=high or risk=critical";

interface PdResult {
  iid?: number;
  indicator?: string;
  type?: string;
  risk?: string;
  stamp_added?: string;
  stamp_updated?: string;
  stamp_seen?: string | null;
  stamp_retired?: string | null;
  summary?: { threats?: { name?: string; category?: string }[] };
}
interface PdResponse { results?: PdResult[]; error?: string }

function pdType(t?: string): IndicatorType {
  switch ((t ?? "").toLowerCase()) {
    case "ip": case "ipv6": return "ip";
    case "domain": return "domain";
    case "url": return "url";
    case "hash": return "hash";
    default: return "other";
  }
}
// Pulsedive timestamps are "YYYY-MM-DD HH:MM:SS" in UTC.
function pdIso(s?: string | null): string | null {
  if (!s) return null;
  const d = new Date(`${s.replace(" ", "T")}Z`);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}
const RISK_CONF: Record<string, number | null> = {
  critical: 95, high: 80, medium: 55, low: 30, none: null, unknown: null, retired: null,
};

export function normalizePulsedive(data: unknown, sourceId = "pulsedive"): Indicator[] {
  const results = ((data as PdResponse)?.results ?? []) as PdResult[];
  const fetchedAt = new Date().toISOString();
  const out: Indicator[] = [];
  for (const r of results) {
    if (!r.indicator) continue;
    const threat = r.summary?.threats?.[0];
    out.push(IndicatorSchema.parse({
      id: String(r.iid ?? `${r.type}:${r.indicator}`),
      source: sourceId,
      type: pdType(r.type),
      value: r.indicator,
      malware: threat?.name ?? null,
      threatType: threat?.category ?? r.risk ?? null,
      confidence: RISK_CONF[(r.risk ?? "unknown").toLowerCase()] ?? null,
      references: r.iid ? [`https://pulsedive.com/indicator/?iid=${r.iid}`] : [],
      tags: [r.risk, threat?.name].filter(Boolean) as string[],
      firstSeen: pdIso(r.stamp_added),
      lastSeen: pdIso(r.stamp_seen ?? r.stamp_updated),
      fetchedAt,
    }));
  }
  return out;
}

/**
 * Pulsedive indicators via the free REST Explore API (`explore.php`).
 * Works on a free API key (50 results/request). The query is configurable via
 * `PULSEDIVE_QUERY`; defaults to active high/critical-risk indicators.
 * Skips gracefully (returns []) when no key is set.
 */
export const pulsediveConnector: IndicatorConnector = {
  id: "pulsedive",
  name: "Pulsedive",
  schedule: "0 */6 * * *",
  async fetchIndicators(opts: FetchOptions = {}): Promise<Indicator[]> {
    if (opts.fixture) return normalizePulsedive(opts.fixture);
    const key = opts.credentials?.pulsediveKey;
    if (!key) { console.warn("[pulsedive] PULSEDIVE_API_KEY not set — skipping"); return []; }
    const query = opts.credentials?.pulsediveQuery || DEFAULT_QUERY;
    const limit = Number(opts.credentials?.pulsediveLimit || 50);
    const url = `${EXPLORE_URL}?q=${encodeURIComponent(query)}&limit=${limit}&pretty=0&key=${encodeURIComponent(key)}`;
    const res = await fetch(url, { headers: { "user-agent": "OmniSight/0.1" } });
    if (!res.ok) {
      const body = await res.text().catch(() => "");
      throw new Error(`Pulsedive fetch failed: HTTP ${res.status}${body ? ` — ${body.slice(0, 200)}` : ""}`);
    }
    return normalizePulsedive(await res.json());
  },
};
