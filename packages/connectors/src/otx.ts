import { IndicatorSchema, classifyIndicator, type Indicator } from "@omnisight/shared";
import type { IndicatorConnector, FetchOptions } from "./types.js";

const OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed";

interface OtxIndicator {
  indicator: string;
  type: string;
  created?: string;
}
interface OtxPulse {
  id: string;
  name?: string;
  tags?: string[];
  created?: string;
  modified?: string;
  references?: string[];
  indicators?: OtxIndicator[];
}
interface OtxFeed {
  results?: OtxPulse[];
}

export function normalizeOtx(feed: OtxFeed): Indicator[] {
  const fetchedAt = new Date().toISOString();
  const out: Indicator[] = [];
  for (const pulse of feed.results ?? []) {
    const malware = pulse.name ?? null;
    const threatType = pulse.tags && pulse.tags.length ? pulse.tags[0]! : null;
    for (const ind of pulse.indicators ?? []) {
      const base = {
        id: `${pulse.id}:${ind.indicator}`,
        source: "otx",
        type: classifyIndicator(ind.type ?? ""),
        value: ind.indicator,
        malware,
        threatType,
        confidence: null,
        references: pulse.references ?? [],
        tags: pulse.tags ?? [],
        firstSeen: ind.created ?? pulse.created ?? null,
        lastSeen: pulse.modified ?? null,
        fetchedAt,
      };
      out.push(IndicatorSchema.parse(base));
    }
  }
  return out;
}

/** AlienVault OTX — indicators from the API key's subscribed pulses. */
export const otxConnector: IndicatorConnector = {
  id: "otx",
  name: "AlienVault OTX",
  schedule: "0 */3 * * *",
  async fetchIndicators(opts: FetchOptions = {}): Promise<Indicator[]> {
    if (opts.fixture) return normalizeOtx(opts.fixture as OtxFeed);

    const apiKey = opts.credentials?.otxApiKey;
    const headers: Record<string, string> = { "user-agent": "OmniSight/0.1" };
    if (apiKey) headers["X-OTX-API-KEY"] = apiKey;

    const res = await fetch(`${OTX_URL}?limit=50&page=1`, { headers });
    if (!res.ok) throw new Error(`OTX fetch failed: HTTP ${res.status} (X-OTX-API-KEY set?)`);
    const feed = (await res.json()) as OtxFeed;
    return normalizeOtx(feed);
  },
};
