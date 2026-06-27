import type { Source, Vulnerability, Indicator, Advisory } from "@omnisight/shared";

export interface FetchOptions {
  /** When provided, the connector parses this instead of hitting the network (used for tests/dry-runs). */
  fixture?: unknown;
  /** Secrets/keys resolved from env or the source config. */
  credentials?: Record<string, string | undefined>;
}

/**
 * A connector turns one external feed into normalized OmniSight records.
 * Built-in connectors implement this directly; admin-added feeds are handled
 * by the generic RSS/JSON connectors driven by a Source config.
 */
export interface Connector {
  id: string;
  name: string;
  schedule: string; // cron
  fetchVulnerabilities(opts?: FetchOptions): Promise<Vulnerability[]>;
}

export interface ConnectorFactory {
  /** Build a connector instance from an admin-registered Source row. */
  fromSource(source: Source): Connector;
}

/** A connector that produces indicators of compromise instead of vulnerabilities. */
export interface IndicatorConnector {
  id: string;
  name: string;
  schedule: string;
  fetchIndicators(opts?: FetchOptions): Promise<Indicator[]>;
}

/** A connector that produces news/advisory items. */
export interface AdvisoryConnector {
  id: string;
  name: string;
  schedule: string;
  fetchAdvisories(opts?: FetchOptions): Promise<Advisory[]>;
}
