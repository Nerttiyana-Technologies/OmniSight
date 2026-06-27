/**
 * Enrichers add signals to vulnerabilities we already track (keyed by CVE id),
 * rather than introducing new ones. EPSS adds exploit probability; NVD adds CVSS.
 * Both feed the composite risk score in @omnisight/shared.
 */

export interface EpssResult {
  cveId: string;
  epss: number;
}

interface EpssPayload {
  data?: { cve: string; epss: string; percentile?: string }[];
}

/**
 * FIRST EPSS — exploit-probability score (0-1) per CVE. Keyless, bulk-friendly:
 * up to 100 CVEs per request, comma-separated.
 */
export async function fetchEpss(
  cveIds: string[],
  opts: { fixture?: unknown } = {},
): Promise<EpssResult[]> {
  if (opts.fixture) return parseEpss(opts.fixture);
  if (cveIds.length === 0) return [];
  const out: EpssResult[] = [];
  for (let i = 0; i < cveIds.length; i += 100) {
    const batch = cveIds.slice(i, i + 100);
    const url = `https://api.first.org/data/v1/epss?cve=${batch.join(",")}`;
    const res = await fetch(url, { headers: { "user-agent": "OmniSight/0.1" } });
    if (!res.ok) throw new Error(`EPSS fetch failed: HTTP ${res.status}`);
    out.push(...parseEpss(await res.json()));
  }
  return out;
}

export function parseEpss(payload: unknown): EpssResult[] {
  const data = (payload as EpssPayload).data ?? [];
  return data
    .map((d) => ({ cveId: d.cve, epss: Number(d.epss) }))
    .filter((d) => d.cveId && Number.isFinite(d.epss));
}

interface NvdMetric {
  cvssData?: { baseScore?: number };
}
interface NvdPayload {
  vulnerabilities?: {
    cve?: {
      id?: string;
      metrics?: {
        cvssMetricV31?: NvdMetric[];
        cvssMetricV30?: NvdMetric[];
        cvssMetricV2?: NvdMetric[];
      };
    };
  }[];
}

/**
 * NVD CVE 2.0 — base CVSS for a single CVE. Prefers v3.1 > v3.0 > v2.
 * Rate limit: 5 req / 30s without a key, 50 with (set NVD_API_KEY).
 */
export async function fetchNvdCvss(
  cveId: string,
  opts: { apiKey?: string; fixture?: unknown } = {},
): Promise<number | null> {
  let payload: unknown;
  if (opts.fixture) {
    payload = opts.fixture;
  } else {
    const headers: Record<string, string> = { "user-agent": "OmniSight/0.1" };
    if (opts.apiKey) headers["apiKey"] = opts.apiKey;
    const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
    // NVD returns transient 429/503 under load — retry a couple of times with backoff.
    let res: Response | null = null;
    for (let attempt = 0; attempt < 3; attempt++) {
      res = await fetch(url, { headers });
      if (res.ok) break;
      // NVD returns 404 for an unknown CVE *or* an invalid API key — treat as
      // "no CVSS available" and skip rather than crash the enrichment run.
      if (res.status === 404) return null;
      if (res.status === 429 || res.status === 503) {
        await sleep(1500 * (attempt + 1));
        continue;
      }
      throw new Error(`NVD fetch failed for ${cveId}: HTTP ${res.status}`);
    }
    if (!res || !res.ok) throw new Error(`NVD fetch failed for ${cveId}: HTTP ${res?.status ?? "no response"}`);
    payload = await res.json();
  }
  return extractCvss(payload);
}

export interface NvdMetrics {
  cvssMetricV31?: NvdMetric[];
  cvssMetricV30?: NvdMetric[];
  cvssMetricV2?: NvdMetric[];
}

/** Base CVSS from an NVD metrics object, preferring v3.1 > v3.0 > v2. */
export function cvssFromMetrics(metrics: NvdMetrics | undefined): number | null {
  if (!metrics) return null;
  const set = metrics.cvssMetricV31 ?? metrics.cvssMetricV30 ?? metrics.cvssMetricV2;
  const score = set?.[0]?.cvssData?.baseScore;
  return typeof score === "number" ? score : null;
}

export function extractCvss(payload: unknown): number | null {
  const vulns = (payload as NvdPayload).vulnerabilities ?? [];
  return cvssFromMetrics(vulns[0]?.cve?.metrics);
}

/** Throttle helper so the NVD loop respects the rate limit. */
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
