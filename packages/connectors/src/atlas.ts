import { AdvisorySchema, type Advisory } from "@omnisight/shared";
import type { AdvisoryConnector, FetchOptions } from "./types.js";

// MITRE ATLAS — the authoritative adversarial-ML threat knowledge base,
// published as a STIX 2.1 bundle. We surface its techniques as advisory items.
const ATLAS_STIX_URL =
  "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/stix-atlas.json";

interface StixRef { url?: string; external_id?: string; source_name?: string }
interface StixObject {
  type: string;
  id: string;
  name?: string;
  description?: string;
  created?: string;
  modified?: string;
  external_references?: StixRef[];
}
interface StixBundle { objects?: StixObject[] }

export function normalizeAtlas(bundle: StixBundle): Advisory[] {
  const fetchedAt = new Date().toISOString();
  const out: Advisory[] = [];
  for (const o of bundle.objects ?? []) {
    if (o.type !== "attack-pattern" || !o.name) continue;
    const refs = o.external_references ?? [];
    const urlRef = refs.find((r) => r.url);
    const idRef = refs.find((r) => r.external_id);
    out.push(
      AdvisorySchema.parse({
        id: o.id,
        source: "mitre-atlas",
        title: o.name,
        summary: (o.description ?? "").replace(/\s+/g, " ").trim().slice(0, 400),
        url: urlRef?.url ?? "https://atlas.mitre.org/",
        category: "ATLAS technique",
        published: o.modified ?? o.created ?? null,
        tags: idRef?.external_id ? [idRef.external_id] : [],
        fetchedAt,
      }),
    );
  }
  return out;
}

export const atlasConnector: AdvisoryConnector = {
  id: "mitre-atlas",
  name: "MITRE ATLAS",
  schedule: "0 6 * * *",
  async fetchAdvisories(opts: FetchOptions = {}): Promise<Advisory[]> {
    if (opts.fixture) return normalizeAtlas(opts.fixture as StixBundle);
    const res = await fetch(ATLAS_STIX_URL, { headers: { "user-agent": "OmniSight/0.1" } });
    if (!res.ok) throw new Error(`ATLAS fetch failed: HTTP ${res.status}`);
    return normalizeAtlas((await res.json()) as StixBundle);
  },
};
