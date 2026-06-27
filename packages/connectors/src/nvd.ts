import {
  VulnerabilitySchema,
  computeRiskScore,
  type Vulnerability,
} from "@omnisight/shared";
import type { Connector, FetchOptions } from "./types.js";
import { cvssFromMetrics, sleep, type NvdMetrics } from "./enrichers.js";

const NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const PER_PAGE = 2000;

interface NvdItem {
  cve: {
    id: string;
    published?: string;
    descriptions?: { lang: string; value: string }[];
    metrics?: NvdMetrics;
    weaknesses?: { description: { lang: string; value: string }[] }[];
    references?: { url: string }[];
  };
}

interface NvdFeed {
  vulnerabilities?: NvdItem[];
  totalResults?: number;
  startIndex?: number;
}

export function normalizeNvd(feed: NvdFeed): Vulnerability[] {
  const fetchedAt = new Date().toISOString();
  return (feed.vulnerabilities ?? []).map((item) => {
    const c = item.cve;
    const description = c.descriptions?.find((d) => d.lang === "en")?.value ?? "";
    const cwes = (c.weaknesses ?? [])
      .flatMap((w) => w.description.filter((d) => d.lang === "en").map((d) => d.value))
      .filter((v) => /^CWE-/.test(v));
    const base = {
      id: c.id,
      cveId: c.id,
      source: "nvd",
      title: c.id,
      description,
      vendor: null,
      product: null,
      knownExploited: false, // NVD is the catalog, not an exploitation signal
      ransomwareUse: false,
      cvss: cvssFromMetrics(c.metrics),
      epss: null,
      cwes,
      requiredAction: null,
      dueDate: null,
      dateAdded: c.published ? c.published.slice(0, 10) : null,
      references: (c.references ?? []).slice(0, 5).map((r) => r.url),
      fetchedAt,
    };
    return VulnerabilitySchema.parse({ ...base, riskScore: computeRiskScore(base) });
  });
}

/** NVD CVE 2.0 — CVEs published in the last `days` (default 7). Paginates fully. */
export const nvdConnector: Connector = {
  id: "nvd",
  name: "NVD Recent CVEs",
  schedule: "0 */4 * * *",
  async fetchVulnerabilities(opts: FetchOptions = {}): Promise<Vulnerability[]> {
    if (opts.fixture) return normalizeNvd(opts.fixture as NvdFeed);

    const apiKey = opts.credentials?.nvdApiKey;
    const headers: Record<string, string> = { "user-agent": "OmniSight/0.1" };
    if (apiKey) headers["apiKey"] = apiKey;

    const end = new Date();
    const start = new Date(end.getTime() - 7 * 24 * 3600 * 1000);
    const all: Vulnerability[] = [];
    let startIndex = 0;
    for (;;) {
      const url =
        `${NVD_URL}?pubStartDate=${encodeURIComponent(start.toISOString())}` +
        `&pubEndDate=${encodeURIComponent(end.toISOString())}` +
        `&resultsPerPage=${PER_PAGE}&startIndex=${startIndex}`;
      const res = await fetch(url, { headers });
      if (!res.ok) throw new Error(`NVD fetch failed: HTTP ${res.status}`);
      const feed = (await res.json()) as NvdFeed;
      const batch = normalizeNvd(feed);
      all.push(...batch);
      const total = feed.totalResults ?? all.length;
      startIndex += PER_PAGE;
      if (startIndex >= total || batch.length === 0) break;
      await sleep(apiKey ? 700 : 6500); // respect rate limit between pages
    }
    return all;
  },
};
