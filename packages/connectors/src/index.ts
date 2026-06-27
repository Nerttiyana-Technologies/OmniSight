import type { Source } from "@omnisight/shared";
import type { Connector, IndicatorConnector } from "./types.js";
import { cisaKevConnector } from "./cisa-kev.js";
import { nvdConnector } from "./nvd.js";
import { threatfoxConnector } from "./threatfox.js";
import { otxConnector } from "./otx.js";
import { makeGenericJsonConnector } from "./generic-json.js";

export * from "./types.js";
export { cisaKevConnector, normalizeKev } from "./cisa-kev.js";
export { nvdConnector, normalizeNvd } from "./nvd.js";
export { threatfoxConnector, normalizeThreatfox } from "./threatfox.js";
export { otxConnector, normalizeOtx } from "./otx.js";
export { makeGenericJsonConnector } from "./generic-json.js";
export {
  fetchEpss, parseEpss, fetchNvdCvss, extractCvss, cvssFromMetrics, sleep, type EpssResult,
} from "./enrichers.js";

/** Built-in vulnerability connectors, keyed by source slug. */
export const builtinConnectors: Record<string, Connector> = {
  [cisaKevConnector.id]: cisaKevConnector,
  [nvdConnector.id]: nvdConnector,
};

/** Built-in indicator connectors, keyed by source slug. */
export const builtinIndicatorConnectors: Record<string, IndicatorConnector> = {
  [threatfoxConnector.id]: threatfoxConnector,
  [otxConnector.id]: otxConnector,
};

export function resolveIndicatorConnector(source: Source): IndicatorConnector {
  const c = builtinIndicatorConnectors[source.id];
  if (!c) throw new Error(`No indicator connector available for source "${source.id}"`);
  return c;
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
export const seedSources: Source[] = [
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
];
