import { IndicatorSchema, parseStixIndicators, type Indicator, type Source } from "@omnisight/shared";
import type { IndicatorConnector, FetchOptions } from "./types.js";

/**
 * Normalize a TAXII 2.1 envelope (or a STIX 2.x bundle) into indicators.
 * A TAXII "GET objects" response is `{ more, next, objects: [...] }`; a STIX
 * bundle is `{ type: "bundle", objects: [...] }`. Both expose `.objects`, which
 * parseStixIndicators already understands.
 */
export function normalizeTaxii(envelope: unknown, sourceId: string): Indicator[] {
  const fetchedAt = new Date().toISOString();
  const out: Indicator[] = [];
  const seen = new Set<string>();
  for (const p of parseStixIndicators(envelope)) {
    const id = `${p.type}:${p.value}`;
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(IndicatorSchema.parse({
      id,
      source: sourceId,
      type: p.type,
      value: p.value,
      malware: p.name,
      threatType: null,
      confidence: null,
      references: [],
      tags: p.tags,
      firstSeen: null,
      lastSeen: null,
      fetchedAt,
    }));
  }
  return out;
}

/**
 * Build a TAXII 2.1 polling connector from an admin-registered source.
 * `source.url` must point at a collection's objects endpoint, e.g.
 * `https://server/taxii2/<api-root>/collections/<id>/objects/`.
 * Auth (optional) comes from `source.config`: `{ token }` (Bearer) or
 * `{ username, password }` (Basic).
 */
export function makeTaxiiConnector(source: Source): IndicatorConnector {
  return {
    id: source.id,
    name: source.name,
    schedule: source.schedule,
    async fetchIndicators(opts: FetchOptions = {}): Promise<Indicator[]> {
      if (opts.fixture) return normalizeTaxii(opts.fixture, source.id);
      if (!source.url) throw new Error(`TAXII source "${source.id}" has no url (collection objects endpoint)`);

      // Per-source config wins (each TAXII server has its own creds); the env
      // credentials are a convenience fallback for a single-server setup.
      const cfg = (source.config ?? {}) as Record<string, unknown>;
      const token = (cfg.token as string | undefined) ?? opts.credentials?.taxiiToken;
      const user = (cfg.username as string | undefined) ?? opts.credentials?.taxiiUser;
      const pass = (cfg.password as string | undefined) ?? opts.credentials?.taxiiPass;

      const headers: Record<string, string> = {
        // Exact TAXII 2.1 media type — strict servers reject anything else.
        accept: "application/taxii+json;version=2.1",
        "user-agent": "OmniSight/0.1",
      };
      if (token) headers.authorization = `Bearer ${token}`;
      else if (user && pass) headers.authorization = `Basic ${Buffer.from(`${user}:${pass}`).toString("base64")}`;

      const res = await fetch(source.url, { headers });
      if (!res.ok) {
        const body = await res.text().catch(() => "");
        throw new Error(`TAXII fetch failed: HTTP ${res.status}${body ? ` — ${body.slice(0, 200)}` : ""}`);
      }
      const envelope = await res.json();
      return normalizeTaxii(envelope, source.id);
    },
  };
}
