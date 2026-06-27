import {
  VulnerabilitySchema,
  computeRiskScore,
  type Source,
  type Vulnerability,
} from "@omnisight/shared";
import type { Connector, FetchOptions } from "./types.js";

/**
 * Generic JSON connector — lets an admin register a new feed at runtime WITHOUT
 * writing code. The Source.config provides a field mapping:
 *
 *   {
 *     "itemsPath": "vulnerabilities",   // dot-path to the array in the payload
 *     "map": { "id": "cveID", "title": "vulnerabilityName", "cveId": "cveID",
 *              "description": "shortDescription", "vendor": "vendorProject" }
 *   }
 *
 * This is the extensibility seam: built-in connectors for high-value feeds,
 * config-driven connectors for the long tail an admin adds in the UI.
 */
export function makeGenericJsonConnector(source: Source): Connector {
  const cfg = source.config as {
    itemsPath?: string;
    map?: Record<string, string>;
  };

  return {
    id: source.id,
    name: source.name,
    schedule: source.schedule,
    async fetchVulnerabilities(opts: FetchOptions = {}): Promise<Vulnerability[]> {
      let payload: unknown;
      if (opts.fixture) {
        payload = opts.fixture;
      } else {
        if (!source.url) throw new Error(`Source ${source.id} has no url`);
        const headers: Record<string, string> = { "user-agent": "OmniSight/0.1" };
        const authKey = opts.credentials?.authKey;
        if (authKey) headers["Auth-Key"] = authKey;
        const res = await fetch(source.url, { headers });
        if (!res.ok) throw new Error(`${source.id} fetch failed: HTTP ${res.status}`);
        payload = await res.json();
      }

      const items = getPath(payload, cfg.itemsPath ?? "") ?? payload;
      if (!Array.isArray(items)) {
        throw new Error(`${source.id}: itemsPath did not resolve to an array`);
      }

      const fetchedAt = new Date().toISOString();
      const map = cfg.map ?? {};
      return items.map((raw) => {
        const get = (field: string): unknown =>
          map[field] ? getPath(raw, map[field]!) : (raw as Record<string, unknown>)[field];
        const base = {
          id: String(get("id") ?? get("cveId") ?? cryptoId()),
          cveId: (get("cveId") as string) ?? null,
          source: source.id,
          title: String(get("title") ?? get("id") ?? "untitled"),
          description: String(get("description") ?? ""),
          vendor: (get("vendor") as string) ?? null,
          product: (get("product") as string) ?? null,
          knownExploited: Boolean(get("knownExploited") ?? false),
          ransomwareUse: Boolean(get("ransomwareUse") ?? false),
          cvss: numOrNull(get("cvss")),
          epss: numOrNull(get("epss")),
          cwes: [],
          requiredAction: null,
          dueDate: null,
          dateAdded: (get("dateAdded") as string) ?? null,
          references: [],
          fetchedAt,
        };
        return VulnerabilitySchema.parse({ ...base, riskScore: computeRiskScore(base) });
      });
    },
  };
}

function getPath(obj: unknown, path: string): unknown {
  if (!path) return obj;
  return path.split(".").reduce<unknown>((acc, key) => {
    if (acc && typeof acc === "object") return (acc as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

function numOrNull(v: unknown): number | null {
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function cryptoId(): string {
  return `gen-${Math.random().toString(36).slice(2, 10)}`;
}
