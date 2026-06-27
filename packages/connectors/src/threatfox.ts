import { IndicatorSchema, classifyIndicator, type Indicator } from "@omnisight/shared";
import type { IndicatorConnector, FetchOptions } from "./types.js";

const THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/";

interface TfEntry {
  id: string | number;
  ioc: string;
  ioc_type: string;
  threat_type?: string;
  threat_type_desc?: string;
  malware?: string;
  malware_printable?: string;
  confidence_level?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  reference?: string | null;
  tags?: string[] | null;
}

interface TfFeed {
  query_status: string;
  data?: TfEntry[];
}

export function normalizeThreatfox(feed: TfFeed): Indicator[] {
  const fetchedAt = new Date().toISOString();
  return (feed.data ?? []).map((e) => {
    const base = {
      id: String(e.id),
      source: "threatfox",
      type: classifyIndicator(e.ioc_type ?? ""),
      value: e.ioc,
      malware: e.malware_printable ?? e.malware ?? null,
      threatType: e.threat_type_desc ?? e.threat_type ?? null,
      confidence: typeof e.confidence_level === "number" ? e.confidence_level : null,
      references: e.reference ? [e.reference] : [],
      tags: e.tags ?? [],
      firstSeen: e.first_seen ?? null,
      lastSeen: e.last_seen ?? null,
      fetchedAt,
    };
    return IndicatorSchema.parse(base);
  });
}

/** abuse.ch ThreatFox — recent IOCs (IPs, domains, URLs, hashes) with malware context. */
export const threatfoxConnector: IndicatorConnector = {
  id: "threatfox",
  name: "abuse.ch ThreatFox",
  schedule: "0 */2 * * *",
  async fetchIndicators(opts: FetchOptions = {}): Promise<Indicator[]> {
    if (opts.fixture) return normalizeThreatfox(opts.fixture as TfFeed);

    const authKey = opts.credentials?.authKey;
    const headers: Record<string, string> = {
      "content-type": "application/json",
      "user-agent": "OmniSight/0.1",
    };
    // abuse.ch requires a free Auth-Key since 2025.
    if (authKey) headers["Auth-Key"] = authKey;

    const res = await fetch(THREATFOX_URL, {
      method: "POST",
      headers,
      body: JSON.stringify({ query: "get_iocs", days: 1 }),
    });
    if (!res.ok) throw new Error(`ThreatFox fetch failed: HTTP ${res.status}`);
    const feed = (await res.json()) as TfFeed;
    if (feed.query_status !== "ok") {
      throw new Error(`ThreatFox query_status=${feed.query_status} (missing/invalid Auth-Key?)`);
    }
    return normalizeThreatfox(feed);
  },
};
