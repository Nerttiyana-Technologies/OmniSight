import type { Source } from "@omnisight/shared";
import type { Connector, IndicatorConnector, AdvisoryConnector } from "./types.js";
import { cisaKevConnector } from "./cisa-kev.js";
import { nvdConnector } from "./nvd.js";
import { threatfoxConnector } from "./threatfox.js";
import { otxConnector } from "./otx.js";
import { makeRssConnector } from "./rss.js";
import { atlasConnector } from "./atlas.js";
import { makeGenericJsonConnector } from "./generic-json.js";
import { makeTaxiiConnector } from "./taxii.js";
import { pulsediveConnector } from "./pulsedive.js";

export * from "./types.js";
export { cisaKevConnector, normalizeKev } from "./cisa-kev.js";
export { nvdConnector, normalizeNvd } from "./nvd.js";
export { threatfoxConnector, normalizeThreatfox } from "./threatfox.js";
export { otxConnector, normalizeOtx } from "./otx.js";
export { makeRssConnector, parseRss } from "./rss.js";
export { atlasConnector, normalizeAtlas } from "./atlas.js";
export { makeGenericJsonConnector } from "./generic-json.js";
export { makeTaxiiConnector, normalizeTaxii } from "./taxii.js";
export { pulsediveConnector, normalizePulsedive } from "./pulsedive.js";
export {
  fetchEpss, parseEpss, fetchNvdCvss, extractCvss, cvssFromMetrics, sleep,
  fetchGeo, parseGeo, type EpssResult, type GeoResult,
} from "./enrichers.js";
export { enrichIoc, parseShodan, parseGreynoise, parseAbuse, parsePulsedive, type IocEnrichment } from "./enrich-ioc.js";
export { parseSbom, parsePurl, queryOsvBatch, type SbomComponent, type SbomResult } from "./sbom.js";
export { fetchBreaches, fetchBreachesForDomain } from "./hibp.js";

/** Built-in vulnerability connectors, keyed by source slug. */
export const builtinConnectors: Record<string, Connector> = {
  [cisaKevConnector.id]: cisaKevConnector,
  [nvdConnector.id]: nvdConnector,
};

/** Built-in indicator connectors, keyed by source slug. */
export const builtinIndicatorConnectors: Record<string, IndicatorConnector> = {
  [threatfoxConnector.id]: threatfoxConnector,
  [otxConnector.id]: otxConnector,
  [pulsediveConnector.id]: pulsediveConnector,
};

export function resolveIndicatorConnector(source: Source): IndicatorConnector {
  const c = builtinIndicatorConnectors[source.id];
  if (c) return c;
  if (source.kind === "taxii") return makeTaxiiConnector(source);
  throw new Error(`No indicator connector available for source "${source.id}"`);
}

/** Built-in advisory connectors (besides config-driven RSS). */
export const builtinAdvisoryConnectors: Record<string, AdvisoryConnector> = {
  [atlasConnector.id]: atlasConnector,
};

export function resolveAdvisoryConnector(source: Source): AdvisoryConnector {
  const builtin = builtinAdvisoryConnectors[source.id];
  if (builtin) return builtin;
  if (source.kind === "rss") return makeRssConnector(source);
  throw new Error(`No advisory connector available for source "${source.id}"`);
}

/**
 * Resolve a runnable connector for any source: a built-in if one exists,
 * otherwise build a generic connector from the admin-supplied config.
 */
export function resolveConnector(source: Source): Connector {
  const builtin = builtinConnectors[source.id];
  if (builtin) return builtin;
  if (source.kind === "json") return makeGenericJsonConnector(source);
  throw new Error(`No connector available for source "${source.id}" (kind=${source.kind})`);
}

/** Source rows seeded on first boot so the dashboard has data immediately. */
const seedSourcesRaw: Omit<Source, "reliability">[] = [
  {
    id: "cisa-kev",
    name: "CISA Known Exploited Vulnerabilities",
    kind: "builtin",
    signalType: "vulnerability",
    url: null,
    schedule: "0 */6 * * *",
    enabled: true,
    requiresAuth: false,
    config: {},
  },
  {
    id: "nvd",
    name: "NVD Recent CVEs",
    kind: "builtin",
    signalType: "vulnerability",
    url: null,
    schedule: "0 */4 * * *",
    enabled: true,
    requiresAuth: false,
    config: {},
  },
  {
    id: "threatfox",
    name: "abuse.ch ThreatFox",
    kind: "builtin",
    signalType: "indicator",
    url: null,
    schedule: "0 */2 * * *",
    enabled: true,
    requiresAuth: true,
    config: {},
  },
  {
    id: "otx",
    name: "AlienVault OTX",
    kind: "builtin",
    signalType: "indicator",
    url: null,
    schedule: "0 */3 * * *",
    enabled: true,
    requiresAuth: true,
    config: {},
  },
  {
    id: "pulsedive",
    name: "Pulsedive",
    kind: "builtin",
    signalType: "indicator",
    url: null,
    schedule: "0 */6 * * *",
    enabled: true,
    requiresAuth: true,
    config: {},
  },
  {
    id: "mitre-atlas",
    name: "MITRE ATLAS",
    kind: "builtin",
    signalType: "advisory",
    url: null,
    schedule: "0 6 * * *",
    enabled: true,
    requiresAuth: false,
    config: {},
  },
  {
    id: "securityweek-ai",
    name: "SecurityWeek — AI",
    kind: "rss",
    signalType: "advisory",
    url: "https://www.securityweek.com/category/artificial-intelligence/feed/",
    schedule: "0 */3 * * *",
    enabled: true,
    requiresAuth: false,
    config: {},
  },
  {
    id: "thehackernews",
    name: "The Hacker News",
    kind: "rss",
    signalType: "advisory",
    url: "https://feeds.feedburner.com/TheHackersNews",
    schedule: "0 */3 * * *",
    enabled: true,
    requiresAuth: false,
    config: {},
  },
  {
    id: "darkreading",
    name: "Dark Reading",
    kind: "rss",
    signalType: "advisory",
    url: "https://www.darkreading.com/rss.xml",
    schedule: "0 */3 * * *",
    enabled: true,
    requiresAuth: false,
    config: {},
  },
];

// Admiralty-style source grades: A authoritative · B usually reliable · C fairly.
const SEED_RELIABILITY: Record<string, Source["reliability"]> = {
  "cisa-kev": "A", nvd: "A", "mitre-atlas": "A",
  threatfox: "B", otx: "C", pulsedive: "B",
  "securityweek-ai": "C", thehackernews: "C", darkreading: "C",
};

export const seedSources: Source[] = seedSourcesRaw.map((s) => ({
  ...s,
  reliability: SEED_RELIABILITY[s.id] ?? "C",
}));
