import { z } from "zod";

/**
 * OmniSight shared domain model.
 * Every connector normalizes its source-specific payload into these shapes,
 * so the API, worker, and web app all speak one language.
 */

export const SIGNAL_TYPES = ["vulnerability", "indicator", "actor", "advisory"] as const;
export type SignalType = (typeof SIGNAL_TYPES)[number];

/** A feed/source the platform ingests from. Admin-manageable at runtime. */
export const SourceSchema = z.object({
  id: z.string(), // slug, e.g. "cisa-kev"
  name: z.string(),
  kind: z.enum(["builtin", "rss", "json", "taxii"]),
  signalType: z.enum(SIGNAL_TYPES),
  url: z.string().url().nullable().default(null),
  schedule: z.string().default("0 */6 * * *"), // cron
  enabled: z.boolean().default(true),
  requiresAuth: z.boolean().default(false),
  config: z.record(z.unknown()).default({}),
});
export type Source = z.infer<typeof SourceSchema>;

/** Input shape an admin submits to register a new feed (no code required). */
export const NewSourceSchema = SourceSchema.omit({ id: true }).extend({
  id: z.string().regex(/^[a-z0-9-]+$/, "lowercase slug").optional(),
});
export type NewSource = z.infer<typeof NewSourceSchema>;

/** A normalized vulnerability record. */
export const VulnerabilitySchema = z.object({
  id: z.string(), // canonical id (CVE id when available)
  cveId: z.string().nullable().default(null),
  source: z.string(), // source slug it came from
  title: z.string(),
  description: z.string().default(""),
  vendor: z.string().nullable().default(null),
  product: z.string().nullable().default(null),
  knownExploited: z.boolean().default(false),
  ransomwareUse: z.boolean().default(false),
  cvss: z.number().min(0).max(10).nullable().default(null),
  epss: z.number().min(0).max(1).nullable().default(null),
  cwes: z.array(z.string()).default([]),
  requiredAction: z.string().nullable().default(null),
  dueDate: z.string().nullable().default(null),
  dateAdded: z.string().nullable().default(null),
  references: z.array(z.string()).default([]),
  riskScore: z.number().min(0).max(100).default(0),
  fetchedAt: z.string(),
});
export type Vulnerability = z.infer<typeof VulnerabilitySchema>;

export const INDICATOR_TYPES = ["ip", "domain", "url", "hash", "other"] as const;
export type IndicatorType = (typeof INDICATOR_TYPES)[number];

/** A normalized indicator of compromise (IOC). */
export const IndicatorSchema = z.object({
  id: z.string(),
  source: z.string(),
  type: z.enum(INDICATOR_TYPES),
  value: z.string(),
  malware: z.string().nullable().default(null),
  threatType: z.string().nullable().default(null),
  confidence: z.number().min(0).max(100).nullable().default(null),
  references: z.array(z.string()).default([]),
  tags: z.array(z.string()).default([]),
  firstSeen: z.string().nullable().default(null),
  lastSeen: z.string().nullable().default(null),
  fetchedAt: z.string(),
});
export type Indicator = z.infer<typeof IndicatorSchema>;

/** Coarse IOC type from a source-specific type string (e.g. ThreatFox ioc_type). */
export function classifyIndicator(raw: string): IndicatorType {
  const s = raw.toLowerCase();
  if (s.includes("ip")) return "ip";
  if (s.includes("domain") || s.includes("host")) return "domain";
  if (s.includes("url")) return "url";
  if (s.includes("hash") || s.includes("md5") || s.includes("sha")) return "hash";
  return "other";
}

/**
 * Composite "what to worry about now" score (0-100).
 * Active exploitation dominates, then ransomware association, then CVSS/EPSS.
 * This is the seed of OmniSight's correlation moat — extend as more signals land.
 */
export function computeRiskScore(v: {
  knownExploited: boolean;
  ransomwareUse: boolean;
  cvss: number | null;
  epss: number | null;
}): number {
  let score = 0;
  if (v.knownExploited) score += 50;
  if (v.ransomwareUse) score += 15;
  if (v.cvss != null) score += (v.cvss / 10) * 25;
  if (v.epss != null) score += v.epss * 10;
  return Math.round(Math.min(100, score));
}

export function riskBand(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 75) return "critical";
  if (score >= 50) return "high";
  if (score >= 25) return "medium";
  return "low";
}
