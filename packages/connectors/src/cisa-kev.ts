import {
  VulnerabilitySchema,
  computeRiskScore,
  type Vulnerability,
} from "@omnisight/shared";
import type { Connector, FetchOptions } from "./types.js";

const KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

interface KevEntry {
  cveID: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes?: string;
  cwes?: string[];
}

interface KevFeed {
  title: string;
  catalogVersion: string;
  dateReleased: string;
  count: number;
  vulnerabilities: KevEntry[];
}

export function normalizeKev(feed: KevFeed): Vulnerability[] {
  const fetchedAt = new Date().toISOString();
  return feed.vulnerabilities.map((e) => {
    const base = {
      id: e.cveID,
      cveId: e.cveID,
      source: "cisa-kev",
      title: e.vulnerabilityName || e.cveID,
      description: e.shortDescription ?? "",
      vendor: e.vendorProject ?? null,
      product: e.product ?? null,
      // Every entry in the KEV catalog is, by definition, exploited in the wild.
      knownExploited: true,
      ransomwareUse: (e.knownRansomwareCampaignUse ?? "").trim().toLowerCase() === "known",
      cvss: null,
      epss: null,
      cwes: e.cwes ?? [],
      requiredAction: e.requiredAction ?? null,
      dueDate: e.dueDate ?? null,
      dateAdded: e.dateAdded ?? null,
      references: [`https://nvd.nist.gov/vuln/detail/${e.cveID}`],
      fetchedAt,
    };
    return VulnerabilitySchema.parse({
      ...base,
      riskScore: computeRiskScore(base),
    });
  });
}

export const cisaKevConnector: Connector = {
  id: "cisa-kev",
  name: "CISA Known Exploited Vulnerabilities",
  schedule: "0 */6 * * *",
  async fetchVulnerabilities(opts: FetchOptions = {}): Promise<Vulnerability[]> {
    let feed: KevFeed;
    if (opts.fixture) {
      feed = opts.fixture as KevFeed;
    } else {
      const res = await fetch(KEV_URL, {
        headers: { "user-agent": "OmniSight/0.1 (+https://github.com/Nerttiyana-Technologies/OmniSight)" },
      });
      if (!res.ok) throw new Error(`CISA KEV fetch failed: HTTP ${res.status}`);
      feed = (await res.json()) as KevFeed;
    }
    return normalizeKev(feed);
  },
};
