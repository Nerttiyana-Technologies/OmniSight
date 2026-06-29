// noinspection HtmlDeprecatedAttribute,CssInvalidPropertyValue
// ^ The digest email template (digestHtml) intentionally uses table-layout
//   attributes (cellpadding/cellspacing/align/valign/width) required by email
//   clients, and its inline styles contain ${...} interpolation that WebStorm
//   mis-parses as static CSS. Both are correct for email; suppress the noise.
import { z } from "zod";

/**
 * OmniSight shared domain model.
 * Every connector normalizes its source-specific payload into these shapes,
 * so the API, worker, and web app all speak one language.
 */

export const SIGNAL_TYPES = ["vulnerability", "indicator", "actor", "advisory"] as const;
export type SignalType = (typeof SIGNAL_TYPES)[number];

export const ROLES = ["viewer", "analyst", "admin"] as const;
export type Role = (typeof ROLES)[number];
const ROLE_RANK: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 };

/** True if `role` is at least the `min` role in the hierarchy viewer<analyst<admin. */
export function roleAtLeast(role: string, min: Role): boolean {
  return (ROLE_RANK[role as Role] ?? 0) >= ROLE_RANK[min];
}

export interface User {
  id: string;
  username: string;
  role: Role;
  createdAt: string;
}

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
  reliability: z.enum(["A", "B", "C", "D", "F"]).default("C"), // admiralty-style source grade
  sector: z.string().nullable().optional(), // relevance tag, e.g. "finance", "healthcare"
  config: z.record(z.unknown()).default({}),
  createdAt: z.string().nullable().optional(), // set by the store
  lastRunAt: z.string().nullable().optional(),
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
  country: z.string().nullable().default(null),
  countryCode: z.string().nullable().default(null),
  lat: z.number().nullable().default(null),
  lng: z.number().nullable().default(null),
  fetchedAt: z.string(),
});
export type Indicator = z.infer<typeof IndicatorSchema>;

/** A normalized news/advisory item (RSS articles, MITRE ATLAS entries, etc.). */
export const AdvisorySchema = z.object({
  id: z.string(),
  source: z.string(),
  title: z.string(),
  summary: z.string().default(""),
  url: z.string().default(""),
  category: z.string().nullable().default(null),
  published: z.string().nullable().default(null),
  tags: z.array(z.string()).default([]),
  fetchedAt: z.string(),
});
export type Advisory = z.infer<typeof AdvisorySchema>;

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

// --- Exporters (interop: push to SIEM / firewall / OpenCTI / MISP) ---------

function csvCell(v: unknown): string {
  const s = v == null ? "" : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv(headers: string[], rows: unknown[][]): string {
  return [headers.join(","), ...rows.map((r) => r.map(csvCell).join(","))].join("\n");
}

export function vulnerabilitiesToCsv(items: Vulnerability[]): string {
  return toCsv(
    ["id", "cveId", "source", "title", "vendor", "product", "cvss", "epss", "riskScore", "knownExploited", "ransomwareUse", "dateAdded"],
    items.map((v) => [
      v.id, v.cveId, v.source, v.title, v.vendor, v.product, v.cvss, v.epss,
      v.riskScore, v.knownExploited, v.ransomwareUse, v.dateAdded,
    ]),
  );
}

export function indicatorsToCsv(items: Indicator[]): string {
  return toCsv(
    ["id", "source", "type", "value", "malware", "threatType", "confidence", "firstSeen", "lastSeen"],
    items.map((i) => [
      i.id, i.source, i.type, i.value, i.malware, i.threatType, i.confidence, i.firstSeen, i.lastSeen,
    ]),
  );
}

function uuid(): string {
  const c = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  return c?.randomUUID ? c.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function safeIso(s: string | null, fallback: string): string {
  if (!s) return fallback;
  const d = new Date(s);
  return Number.isNaN(d.getTime()) ? fallback : d.toISOString();
}

function ipOnly(value: string): string {
  return value.split(":")[0] ?? value;
}

function stixPattern(i: Indicator): string | null {
  const v = i.value.replace(/'/g, "\\'");
  switch (i.type) {
    case "ip": return `[ipv4-addr:value = '${ipOnly(v)}']`;
    case "domain": return `[domain-name:value = '${v}']`;
    case "url": return `[url:value = '${v}']`;
    case "hash": {
      const algo = v.length === 32 ? "MD5" : v.length === 40 ? "SHA-1" : "SHA-256";
      return `[file:hashes.'${algo}' = '${v}']`;
    }
    default: return null;
  }
}

/** STIX 2.1 bundle of indicator SDOs — importable into OpenCTI, MISP, etc. */
export function indicatorsToStix(items: Indicator[]): string {
  const now = new Date().toISOString();
  const objects = items
    .map((i) => {
      const pattern = stixPattern(i);
      if (!pattern) return null;
      return {
        type: "indicator",
        spec_version: "2.1",
        id: `indicator--${uuid()}`,
        created: safeIso(i.firstSeen, now),
        modified: safeIso(i.lastSeen, now),
        name: i.malware ? `${i.malware} (${i.type})` : `${i.type} indicator`,
        description: i.threatType ?? undefined,
        indicator_types: ["malicious-activity"],
        pattern,
        pattern_type: "stix",
        valid_from: now,
        labels: i.tags && i.tags.length ? i.tags : undefined,
      };
    })
    .filter((o) => o !== null);
  return JSON.stringify({ type: "bundle", id: `bundle--${uuid()}`, objects }, null, 2);
}

/** Plain newline-delimited blocklist (IPs/domains/URLs/hashes) for firewalls/IDS. */
export function indicatorsToBlocklist(items: Indicator[]): string {
  const lines = [`# OmniSight indicator blocklist`, `# generated ${new Date().toISOString()}`];
  for (const i of items) {
    if (i.type === "ip") lines.push(ipOnly(i.value));
    else if (i.type === "domain" || i.type === "url" || i.type === "hash") lines.push(i.value);
  }
  return lines.join("\n");
}

// --- IOC extractor / parser ------------------------------------------------

export interface ExtractedIocs {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
  cves: string[];
}

/** Undo common defanging: 1[.]2 -> 1.2, hxxp -> http, [@] -> @, etc. */
export function refang(text: string): string {
  return text
    .replace(/\[\s*\.\s*]|\(\s*\.\s*\)|{\s*\.\s*}|\[dot]/gi, ".")
    .replace(/\[\s*:\s*]/g, ":")
    .replace(/\[\s*\/\s*]/g, "/")
    .replace(/\[\s*@\s*]|\(at\)|\[at]/gi, "@")
    .replace(/h\s*x\s*x\s*p(s?)\s*(?::|\[:])\/\//gi, "http$1://")
    .replace(/\bfxp\b/gi, "ftp");
}

/** Defang for safe display/sharing: 1.2.3.4 -> 1[.]2[.]3[.]4, http -> hxxp. */
export function defang(value: string): string {
  return value.replace(/^https?/i, (m) => `hxxp${m.slice(4)}`).replace(/\./g, "[.]");
}

const FILE_TLDS = new Set([
  "exe", "dll", "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "zip", "rar", "html",
  "htm", "txt", "png", "jpg", "jpeg", "gif", "json", "xml", "csv", "js", "py", "sh", "bin", "dat", "log",
]);

function validOctet(s: string): boolean {
  const n = Number(s);
  return n >= 0 && n <= 255;
}

function uniqSorted(arr: string[]): string[] {
  return [...new Set(arr)].sort();
}

export function extractIocs(text: string): ExtractedIocs {
  const t = refang(text);
  const cves = uniqSorted((t.match(/CVE-\d{4}-\d{4,}/gi) ?? []).map((s) => s.toUpperCase()));
  const urls = uniqSorted(t.match(/\bhttps?:\/\/[^\s"'<>()\][]+/gi) ?? []);
  const hashes = uniqSorted(
    [
      ...(t.match(/\b[A-Fa-f0-9]{64}\b/g) ?? []),
      ...(t.match(/\b[A-Fa-f0-9]{40}\b/g) ?? []),
      ...(t.match(/\b[A-Fa-f0-9]{32}\b/g) ?? []),
    ].map((s) => s.toLowerCase()),
  );
  const ips = uniqSorted(
    (t.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? []).filter((ip) => ip.split(".").every(validOctet)),
  );
  const ipSet = new Set(ips);
  const noUrls = t.replace(/\bhttps?:\/\/[^\s"'<>()\][]+/gi, " ");
  const domains = uniqSorted(
    (noUrls.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}\b/gi) ?? [])
      .map((s) => s.toLowerCase())
      .filter((d) => {
        if (ipSet.has(d)) return false;
        const tld = d.split(".").pop() ?? "";
        return !FILE_TLDS.has(tld);
      }),
  );
  return { ips, domains, urls, hashes, cves };
}

function yamlStr(v: string): string {
  return `'${v.replace(/'/g, "''")}'`;
}

/** Sigma detection rules (multi-doc YAML) grouped by IOC type, for SIEM detection. */
export function indicatorsToSigma(items: Indicator[]): string {
  const ips: string[] = [];
  const domains: string[] = [];
  const urls: string[] = [];
  const hashes: string[] = [];
  for (const i of items) {
    if (i.type === "ip") ips.push(ipOnly(i.value));
    else if (i.type === "domain") domains.push(i.value);
    else if (i.type === "url") urls.push(i.value);
    else if (i.type === "hash") hashes.push(i.value);
  }
  const today = new Date().toISOString().slice(0, 10);
  const docs: string[] = [];
  const rule = (title: string, logsource: string, field: string, values: string[], desc: string) => {
    if (values.length === 0) return;
    const uniq = [...new Set(values)].slice(0, 1000);
    docs.push([
      `title: ${title}`,
      `id: ${uuid()}`,
      `status: experimental`,
      `description: ${desc}`,
      `author: OmniSight`,
      `date: ${today}`,
      `logsource:`,
      `  ${logsource}`,
      `detection:`,
      `  selection:`,
      `    ${field}:`,
      ...uniq.map((v) => `      - ${yamlStr(v)}`),
      `  condition: selection`,
      `level: high`,
      `tags:`,
      `  - attack.command_and_control`,
    ].join("\n"));
  };
  rule("OmniSight - Malicious Destination IPs", "category: firewall", "dst_ip", ips, "IPs flagged by OmniSight threat intelligence");
  rule("OmniSight - Malicious DNS Queries", "category: dns", "query", domains, "Domains flagged by OmniSight threat intelligence");
  rule("OmniSight - Malicious URLs", "category: proxy", "c-uri", urls, "URLs flagged by OmniSight threat intelligence");
  rule("OmniSight - Known Malicious File Hashes", "category: file_event", "Hashes", hashes, "File hashes flagged by OmniSight threat intelligence");
  return docs.join("\n---\n") + "\n";
}

/** YARA rules: one network-IOC string rule + one file-hash rule. */
export function indicatorsToYara(items: Indicator[]): string {
  const net: string[] = [];
  const hashes: string[] = [];
  for (const i of items) {
    if (i.type === "ip") net.push(ipOnly(i.value));
    else if (i.type === "domain" || i.type === "url") net.push(i.value);
    else if (i.type === "hash") hashes.push(i.value.toLowerCase());
  }
  const uniqNet = [...new Set(net)].slice(0, 5000);
  const uniqHash = [...new Set(hashes)].slice(0, 5000);
  const blocks: string[] = [];
  if (uniqNet.length) {
    const strings = uniqNet.map((v, idx) => `        $n${idx} = ${JSON.stringify(v)} ascii wide nocase`).join("\n");
    blocks.push(`rule OmniSight_Network_IOCs\n{\n    meta:\n        description = "Network IOCs flagged by OmniSight"\n    strings:\n${strings}\n    condition:\n        any of them\n}`);
  }
  if (uniqHash.length) {
    const conds = uniqHash.map((h) => {
      const fn = h.length === 32 ? "md5" : h.length === 40 ? "sha1" : "sha256";
      return `        hash.${fn}(0, filesize) == "${h}"`;
    }).join(" or\n");
    blocks.push(`rule OmniSight_File_Hashes\n{\n    meta:\n        description = "Malicious file hashes flagged by OmniSight"\n    condition:\n${conds}\n}`);
  }
  const header = uniqHash.length ? `import "hash"\n\n` : "";
  return header + blocks.join("\n\n") + "\n";
}

function snortContent(s: string): string {
  return s.replace(/[";\\]/g, "");
}

/** Suricata/Snort alert rules for network IOCs (sids from 1000001). */
export function indicatorsToSnort(items: Indicator[]): string {
  let sid = 1000001;
  const lines = ["# OmniSight Suricata/Snort ruleset", `# generated ${new Date().toISOString()}`];
  for (const i of items) {
    if (sid > 1010000) break; // cap
    if (i.type === "ip") {
      const ip = ipOnly(i.value);
      lines.push(`alert ip any any -> ${ip} any (msg:"OmniSight malicious IP ${ip}"; sid:${sid++}; rev:1;)`);
    } else if (i.type === "domain") {
      lines.push(`alert dns any any -> any any (msg:"OmniSight malicious domain"; dns.query; content:"${snortContent(i.value)}"; nocase; sid:${sid++}; rev:1;)`);
    } else if (i.type === "url") {
      try {
        const u = new URL(i.value);
        const path = snortContent(u.pathname + u.search) || "/";
        lines.push(`alert http any any -> any any (msg:"OmniSight malicious URL ${snortContent(u.hostname)}"; http.host; content:"${snortContent(u.hostname)}"; nocase; http.uri; content:"${path}"; sid:${sid++}; rev:1;)`);
      } catch { /* skip malformed URL */ }
    }
  }
  return lines.join("\n") + "\n";
}

/** Parse a STIX 2.1 bundle's indicator patterns back into IOC value+type pairs. */
export function parseStixIndicators(bundle: unknown): { value: string; type: IndicatorType; name: string | null; tags: string[] }[] {
  const objects = ((bundle as { objects?: unknown[] }).objects ?? []) as {
    type?: string; pattern?: string; name?: string; labels?: string[];
  }[];
  const out: { value: string; type: IndicatorType; name: string | null; tags: string[] }[] = [];
  for (const o of objects) {
    if (o.type !== "indicator" || !o.pattern) continue;
    const p = o.pattern;
    let m: RegExpMatchArray | null;
    let value: string | null = null;
    let type: IndicatorType | null = null;
    if ((m = p.match(/ipv4-addr:value\s*=\s*'([^']+)'/))) { value = m[1]!; type = "ip"; }
    else if ((m = p.match(/domain-name:value\s*=\s*'([^']+)'/))) { value = m[1]!; type = "domain"; }
    else if ((m = p.match(/url:value\s*=\s*'([^']+)'/))) { value = m[1]!; type = "url"; }
    else if ((m = p.match(/file:hashes\.[^=]*=\s*'([^']+)'/))) { value = m[1]!; type = "hash"; }
    if (value && type) out.push({ value, type, name: o.name ?? null, tags: o.labels ?? [] });
  }
  return out;
}

// --- Breach / leaked-credential exposure (Have I Been Pwned) ----------------

export interface Breach {
  /** HIBP breach Name (unique slug). */
  id: string;
  domain: string;
  title: string;
  breachDate: string | null;
  addedDate: string | null;
  pwnCount: number;
  dataClasses: string[];
  description: string;
  verified: boolean;
  fetchedAt: string;
}

interface HibpBreachRaw {
  Name?: string; Title?: string; Domain?: string; BreachDate?: string;
  AddedDate?: string; PwnCount?: number; DataClasses?: string[];
  Description?: string; IsVerified?: boolean;
}

/** Normalize HIBP `/breaches?Domain=` results into OmniSight Breach records. */
export function normalizeHibpBreaches(raw: unknown, domain: string): Breach[] {
  const arr = Array.isArray(raw) ? (raw as HibpBreachRaw[]) : [];
  const fetchedAt = new Date().toISOString();
  return arr
    .filter((b) => b.Name)
    .map((b) => ({
      id: b.Name!,
      domain: (b.Domain || domain).toLowerCase(),
      title: b.Title ?? b.Name!,
      breachDate: b.BreachDate ?? null,
      addedDate: b.AddedDate ?? null,
      pwnCount: typeof b.PwnCount === "number" ? b.PwnCount : 0,
      dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses : [],
      description: (b.Description ?? "").replace(/<[^>]+>/g, ""), // strip HTML
      verified: Boolean(b.IsVerified),
      fetchedAt,
    }));
}

// --- Source reliability weighting -------------------------------------------

/** Multiplier for blending source admiralty grade into risk ranking. */
export function reliabilityWeight(grade: string | null | undefined): number {
  switch ((grade ?? "C").toUpperCase()) {
    case "A": return 1.0;
    case "B": return 0.9;
    case "C": return 0.8;
    case "D": return 0.65;
    case "F": return 0.5;
    default: return 0.8;
  }
}

// --- ATT&CK matrix (tactic grouping) ----------------------------------------

/** Enterprise ATT&CK tactics in kill-chain order, plus buckets for ATLAS/other. */
export const ATTACK_TACTICS: { id: string; name: string }[] = [
  { id: "reconnaissance", name: "Reconnaissance" },
  { id: "resource-development", name: "Resource Development" },
  { id: "initial-access", name: "Initial Access" },
  { id: "execution", name: "Execution" },
  { id: "persistence", name: "Persistence" },
  { id: "privilege-escalation", name: "Privilege Escalation" },
  { id: "defense-evasion", name: "Defense Evasion" },
  { id: "credential-access", name: "Credential Access" },
  { id: "discovery", name: "Discovery" },
  { id: "lateral-movement", name: "Lateral Movement" },
  { id: "collection", name: "Collection" },
  { id: "command-and-control", name: "Command & Control" },
  { id: "exfiltration", name: "Exfiltration" },
  { id: "impact", name: "Impact" },
  { id: "atlas", name: "ATLAS (AI/ML)" },
  { id: "other", name: "Other / Uncategorized" },
];

// Compact technique→primary-tactic map for the most common techniques. Not
// exhaustive (full ATT&CK has ~600); unmapped IDs fall into "other".
const TECHNIQUE_TACTIC: Record<string, string> = {
  T1595: "reconnaissance", T1592: "reconnaissance", T1589: "reconnaissance", T1590: "reconnaissance", T1598: "reconnaissance", T1597: "reconnaissance",
  T1583: "resource-development", T1584: "resource-development", T1587: "resource-development", T1588: "resource-development", T1608: "resource-development", T1585: "resource-development", T1586: "resource-development",
  T1190: "initial-access", T1133: "initial-access", T1566: "initial-access", T1078: "initial-access", T1195: "initial-access", T1199: "initial-access", T1200: "initial-access", T1189: "initial-access", T1091: "initial-access",
  T1059: "execution", T1203: "execution", T1204: "execution", T1106: "execution", T1053: "execution", T1129: "execution", T1569: "execution", T1047: "execution", T1072: "execution",
  T1547: "persistence", T1543: "persistence", T1136: "persistence", T1505: "persistence", T1098: "persistence", T1197: "persistence", T1574: "persistence", T1037: "persistence", T1546: "persistence",
  T1548: "privilege-escalation", T1055: "privilege-escalation", T1068: "privilege-escalation", T1484: "privilege-escalation", T1611: "privilege-escalation",
  T1562: "defense-evasion", T1070: "defense-evasion", T1027: "defense-evasion", T1140: "defense-evasion", T1112: "defense-evasion", T1218: "defense-evasion", T1036: "defense-evasion", T1497: "defense-evasion", T1620: "defense-evasion", T1564: "defense-evasion", T1222: "defense-evasion",
  T1110: "credential-access", T1003: "credential-access", T1555: "credential-access", T1056: "credential-access", T1552: "credential-access", T1558: "credential-access", T1212: "credential-access", T1187: "credential-access", T1539: "credential-access",
  T1087: "discovery", T1083: "discovery", T1046: "discovery", T1057: "discovery", T1018: "discovery", T1082: "discovery", T1016: "discovery", T1033: "discovery", T1049: "discovery", T1518: "discovery", T1069: "discovery", T1007: "discovery",
  T1021: "lateral-movement", T1210: "lateral-movement", T1570: "lateral-movement", T1080: "lateral-movement", T1550: "lateral-movement",
  T1560: "collection", T1005: "collection", T1114: "collection", T1213: "collection", T1119: "collection", T1115: "collection", T1123: "collection",
  T1071: "command-and-control", T1105: "command-and-control", T1572: "command-and-control", T1090: "command-and-control", T1573: "command-and-control", T1219: "command-and-control", T1568: "command-and-control", T1095: "command-and-control", T1102: "command-and-control",
  T1041: "exfiltration", T1048: "exfiltration", T1567: "exfiltration", T1029: "exfiltration", T1011: "exfiltration",
  T1486: "impact", T1490: "impact", T1489: "impact", T1498: "impact", T1499: "impact", T1485: "impact", T1491: "impact", T1561: "impact", T1496: "impact", T1531: "impact", T1565: "impact",
};

/** Map a technique ID to its primary tactic id. */
export function tacticForTechnique(id: string): string {
  const up = id.toUpperCase();
  if (up.startsWith("AML")) return "atlas";
  const base = up.split(".")[0]!; // strip sub-technique
  return TECHNIQUE_TACTIC[base] ?? "other";
}

// --- Typosquat / look-alike domain generation -------------------------------

const HOMOGLYPHS: Record<string, string> = { o: "0", l: "1", i: "1", e: "3", a: "4", s: "5", g: "9", b: "6", t: "7" };
const ALT_TLDS = ["com", "net", "org", "co", "io", "info", "xyz", "online", "app", "site", "live"];

/**
 * Generate common typosquat / look-alike permutations of a domain
 * (omission, transposition, repetition, homoglyph, hyphenation, TLD swap).
 * Pure and deterministic — used to seed brand-abuse monitoring.
 */
export function typosquatVariants(domain: string): string[] {
  const d = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  const dot = d.indexOf(".");
  if (dot <= 0) return [];
  const name = d.slice(0, dot);
  const tld = d.slice(dot + 1);
  const out = new Set<string>();
  const add = (n: string, t = tld) => { if (n && n.length > 1) out.add(`${n}.${t}`); };

  for (let i = 0; i < name.length; i++) add(name.slice(0, i) + name.slice(i + 1));            // omission
  for (let i = 0; i < name.length - 1; i++) {                                                  // transposition
    const a = name.split(""); const t = a[i]!; a[i] = a[i + 1]!; a[i + 1] = t; add(a.join(""));
  }
  for (let i = 0; i < name.length; i++) add(name.slice(0, i + 1) + name[i] + name.slice(i + 1)); // repetition
  for (let i = 0; i < name.length; i++) {                                                       // homoglyph
    const h = HOMOGLYPHS[name[i]!]; if (h) add(name.slice(0, i) + h + name.slice(i + 1));
  }
  for (let i = 1; i < name.length; i++) add(name.slice(0, i) + "-" + name.slice(i));            // hyphenation
  for (const t of ALT_TLDS) if (t !== tld) add(name, t);                                        // TLD swap

  out.delete(d);
  return [...out];
}

// --- Daily brief / digest --------------------------------------------------

export type DigestTone = "critical" | "high" | "medium" | "low" | "info";
export interface DigestItem {
  primary: string;
  secondary?: string;
  badge?: string;
  tone?: DigestTone;
}
export interface DigestSection {
  title: string;
  items: DigestItem[];
  empty?: string;
}
export interface DigestStats {
  total: number;
  knownExploited: number;
  ransomware: number;
  critical: number;
  high: number;
  indicators: number;
  inStack: number;
}
export interface DigestInput {
  stats: DigestStats;
  terms: string[];
  topVulns: Vulnerability[];
  recentKev: Vulnerability[];
  stackVulns: Vulnerability[];
  topIocs: Indicator[];
}
export interface Digest {
  generatedAt: string;
  date: string;
  headline: string;
  sections: DigestSection[];
  markdown: string;
  html: string;
}

export interface ThreatLevel {
  level: number; // 1 (most severe) .. 5 (lowest)
  label: string;
  tone: DigestTone;
  note: string;
}

/** A DEFCON-style overall posture derived from current signal volume. */
export function threatLevel(s: DigestStats): ThreatLevel {
  const index = s.critical + s.inStack * 3 + Math.round(s.knownExploited * 0.02);
  const note = `${s.critical} critical · ${s.knownExploited} known-exploited` +
    (s.inStack ? ` · ${s.inStack} in your stack` : "");
  if (index >= 80) return { level: 1, label: "SEVERE", tone: "critical", note };
  if (index >= 40) return { level: 2, label: "HIGH", tone: "high", note };
  if (index >= 15) return { level: 3, label: "ELEVATED", tone: "medium", note };
  if (index >= 1) return { level: 4, label: "GUARDED", tone: "low", note };
  return { level: 5, label: "LOW", tone: "info", note };
}

const WEEKDAYS = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
const FULL_MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
const SHORT_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

function briefDate(s: string | null): string {
  if (!s) return "—";
  const d = new Date(s.length <= 10 ? `${s}T00:00:00` : s);
  if (Number.isNaN(d.getTime())) return s;
  return `${SHORT_MONTHS[d.getMonth()]}/${String(d.getDate()).padStart(2, "0")}/${d.getFullYear()}`;
}

function vendorProduct(v: Vulnerability): string {
  return [v.vendor, v.product].filter(Boolean).join(" / ");
}

export function buildDigest(input: DigestInput): Digest {
  const now = new Date();
  const date = `${WEEKDAYS[now.getDay()]}, ${FULL_MONTHS[now.getMonth()]} ${now.getDate()}, ${now.getFullYear()}`;
  const { stats } = input;

  const headline =
    `${stats.critical} critical · ${stats.knownExploited} known-exploited · ` +
    `${stats.total.toLocaleString()} CVEs · ${stats.indicators.toLocaleString()} indicators` +
    (input.terms.length ? ` · ${stats.inStack} affecting your stack` : "");

  const vulnItem = (v: Vulnerability): DigestItem => {
    const flags = [v.knownExploited ? "exploited" : "", v.ransomwareUse ? "ransomware" : ""].filter(Boolean).join(", ");
    const vp = vendorProduct(v);
    return {
      primary: `${v.cveId ?? v.id} — ${v.title}`,
      secondary: [vp, flags].filter(Boolean).join(" · ") || undefined,
      badge: String(v.riskScore),
      tone: riskBand(v.riskScore),
    };
  };

  const sections: DigestSection[] = [
    {
      title: "Top Risks",
      items: input.topVulns.map(vulnItem),
      empty: "No vulnerabilities tracked yet.",
    },
    {
      title: "Newly Added to CISA KEV",
      items: input.recentKev.map((v) => ({
        primary: `${v.cveId ?? v.id} — ${v.title}`,
        secondary: [vendorProduct(v), `added ${briefDate(v.dateAdded)}`].filter(Boolean).join(" · "),
        badge: "KEV",
        tone: "high" as DigestTone,
      })),
      empty: "No recent KEV additions.",
    },
    {
      title: input.terms.length ? `Affecting Your Stack (${input.terms.join(", ")})` : "My Stack",
      items: input.stackVulns.map(vulnItem),
      empty: input.terms.length ? "Nothing in your stack is currently flagged." : "No stack defined — add software in My Stack.",
    },
    {
      title: "Top Indicators",
      items: input.topIocs.map((i) => ({
        primary: i.value,
        secondary: [i.malware, i.threatType].filter(Boolean).join(" · ") || undefined,
        badge: i.type,
        tone: "info" as DigestTone,
      })),
      empty: "No indicators ingested yet.",
    },
  ];

  return {
    generatedAt: now.toISOString(),
    date,
    headline,
    sections,
    markdown: digestMarkdown(date, headline, sections),
    html: digestHtml(date, headline, sections),
  };
}

function digestMarkdown(date: string, headline: string, sections: DigestSection[]): string {
  const out = [`# OmniSight Daily Threat Brief`, `**${date}**`, "", `> ${headline}`, ""];
  for (const s of sections) {
    out.push(`## ${s.title}`);
    if (s.items.length === 0) out.push(`_${s.empty ?? "Nothing to report."}_`);
    else for (const it of s.items) {
      const badge = it.badge ? `[${it.badge}] ` : "";
      out.push(`- ${badge}${it.primary}${it.secondary ? ` — ${it.secondary}` : ""}`);
    }
    out.push("");
  }
  return out.join("\n");
}

const TONE_COLOR: Record<DigestTone, string> = {
  critical: "#c5343a", high: "#b9701f", medium: "#9a8a1f", low: "#2f7d57", info: "#5d6b80",
};

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** Executive, email-client-safe HTML (table layout, inline styles). */
function digestHtml(date: string, headline: string, sections: DigestSection[]): string {
  const accent = "#9a7b15";
  const ink = "#11151c";
  const muted = "#5d6b80";
  const border = "#e3e8f0";

  const sectionHtml = sections.map((s) => {
    const rows = s.items.length === 0
      ? `<tr><td style="padding:10px 0;color:${muted};font-style:italic;font-size:14px;">${esc(s.empty ?? "Nothing to report.")}</td></tr>`
      : s.items.map((it) => {
        const tone = it.tone ?? "info";
        const badge = it.badge
          ? `<span style="display:inline-block;min-width:34px;text-align:center;padding:2px 8px;border-radius:999px;background:${TONE_COLOR[tone]}1a;color:${TONE_COLOR[tone]};font-size:11px;font-weight:700;margin-right:10px;">${esc(it.badge)}</span>`
          : "";
        const sub = it.secondary ? `<div style="color:${muted};font-size:12px;margin-top:2px;">${esc(it.secondary)}</div>` : "";
        return `<tr><td style="padding:9px 0;border-bottom:1px solid ${border};">
          <table role="presentation" cellpadding="0" cellspacing="0" width="100%"><tr>
            <td width="48" valign="top" style="vertical-align:top;">${badge}</td>
            <td valign="top" style="vertical-align:top;color:${ink};font-size:14px;line-height:1.35;">${esc(it.primary)}${sub}</td>
          </tr></table>
        </td></tr>`;
      }).join("");
    return `<tr><td style="padding:22px 28px 4px;">
        <div style="font-size:12px;letter-spacing:0.08em;text-transform:uppercase;color:${accent};font-weight:700;margin-bottom:6px;">${esc(s.title)}</div>
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%">${rows}</table>
      </td></tr>`;
  }).join("");

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f6fa;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
  <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="background:#f4f6fa;padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" cellpadding="0" cellspacing="0" width="640" style="width:640px;max-width:92%;background:#ffffff;border:1px solid ${border};border-radius:14px;overflow:hidden;box-shadow:0 8px 24px rgba(16,24,40,0.08);">
        <tr><td style="background:${ink};padding:22px 28px;">
          <div style="color:#ffffff;font-size:20px;font-weight:700;letter-spacing:0.02em;">Omni<span style="color:${accent};">Sight</span></div>
          <div style="color:#9aa6b8;font-size:12px;letter-spacing:0.14em;text-transform:uppercase;margin-top:2px;">Daily Threat Brief</div>
        </td></tr>
        <tr><td style="padding:20px 28px 0;color:${muted};font-size:13px;">${esc(date)}</td></tr>
        <tr><td style="padding:10px 28px 6px;">
          <div style="background:${accent}14;border-left:3px solid ${accent};border-radius:8px;padding:12px 14px;color:${ink};font-size:14px;font-weight:600;">${esc(headline)}</div>
        </td></tr>
        ${sectionHtml}
        <tr><td style="padding:18px 28px 26px;color:${muted};font-size:11px;border-top:1px solid ${border};">
          Generated by OmniSight · open-source cyber situational awareness
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

// ===========================================================================
// Phase 2 — Defensive monitoring: asset inventory
// ===========================================================================

export const ASSET_KINDS = ["host", "service", "software", "cloud", "network", "other"] as const;
export type AssetKind = (typeof ASSET_KINDS)[number];

export const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
export type Criticality = (typeof CRITICALITIES)[number];

export const ASSET_ORIGINS = ["manual", "csv", "sbom", "scan"] as const;
export type AssetOrigin = (typeof ASSET_ORIGINS)[number];

/**
 * A tracked asset in the defender's environment. Incoming threat intel is
 * matched against these to answer "does this CVE affect something we run?".
 * "My Stack" (a flat list of terms) is the lightweight view over this inventory.
 */
export const AssetSchema = z.object({
  id: z.string(),
  name: z.string(),
  kind: z.enum(ASSET_KINDS).default("software"),
  vendor: z.string().nullable().default(null),
  product: z.string().nullable().default(null),
  version: z.string().nullable().default(null),
  cpe: z.string().nullable().default(null), // CPE 2.3 (or 2.2 URI) when known
  ip: z.string().nullable().default(null),
  hostname: z.string().nullable().default(null),
  owner: z.string().nullable().default(null),
  criticality: z.enum(CRITICALITIES).default("medium"),
  tags: z.array(z.string()).default([]),
  origin: z.enum(ASSET_ORIGINS).default("manual"),
  createdAt: z.string().nullable().optional(),
  updatedAt: z.string().nullable().optional(),
});
export type Asset = z.infer<typeof AssetSchema>;

/** Input shape for creating/importing an asset (id + timestamps are assigned by the store). */
export const NewAssetSchema = AssetSchema.omit({ id: true, createdAt: true, updatedAt: true }).extend({
  id: z.string().optional(),
});
export type NewAsset = z.infer<typeof NewAssetSchema>;

export interface ParsedCpe {
  part: string; // a (application) | o (os) | h (hardware) | *
  vendor: string;
  product: string;
  version: string;
}

/** Parse a CPE 2.3 formatted string or a 2.2 URI into its key fields. */
export function parseCpe(cpe: string | null | undefined): ParsedCpe | null {
  if (!cpe) return null;
  const s = cpe.trim().toLowerCase();
  const field = (v: string | undefined) => (v && v !== "*" && v !== "-" ? v.replace(/\\/g, "") : "*");
  if (s.startsWith("cpe:2.3:")) {
    const p = s.slice(8).split(":");
    if (p.length < 4) return null;
    return { part: field(p[0]), vendor: field(p[1]), product: field(p[2]), version: field(p[3]) };
  }
  if (s.startsWith("cpe:/")) {
    const p = s.slice(5).split(":");
    return { part: field(p[0]), vendor: field(p[1]), product: field(p[2]), version: field(p[3]) };
  }
  return null;
}

export type AssetMatchType = "cpe" | "vendor-product" | "term";

export interface AssetMatchResult {
  match: boolean;
  type: AssetMatchType | null;
  reason: string;
}

function vulnHaystack(v: { vendor: string | null; product: string | null; title: string }): string {
  return `${v.vendor ?? ""} ${v.product ?? ""} ${v.title}`.toLowerCase();
}

/**
 * Decide whether a vulnerability affects an asset, and how confidently.
 * Precedence: CPE vendor+product (strongest) → asset vendor+product → single term.
 * Version is informational (CVE feeds rarely carry reliable affected-version ranges).
 */
export function assetMatchesVuln(
  asset: Pick<Asset, "vendor" | "product" | "version" | "cpe" | "name">,
  v: { vendor: string | null; product: string | null; title: string },
): AssetMatchResult {
  const hay = vulnHaystack(v);
  const has = (t: string | null | undefined) => Boolean(t && t.trim() && hay.includes(t.trim().toLowerCase()));
  const cpe = parseCpe(asset.cpe);
  if (cpe && cpe.vendor !== "*" && cpe.product !== "*" && has(cpe.vendor) && has(cpe.product)) {
    const ver = asset.version ? ` (running ${asset.version})` : "";
    return { match: true, type: "cpe", reason: `CPE ${cpe.vendor}:${cpe.product}${ver}` };
  }
  if (has(asset.vendor) && has(asset.product)) {
    return { match: true, type: "vendor-product", reason: `vendor/product ${asset.vendor}/${asset.product}` };
  }
  for (const term of [asset.product, asset.name, asset.vendor]) {
    if (has(term)) return { match: true, type: "term", reason: `matched "${(term ?? "").trim()}"` };
  }
  return { match: false, type: null, reason: "" };
}

/** Lower-cased candidate match terms an asset contributes to "My Stack" matching. */
export function assetSearchTerms(asset: Pick<Asset, "vendor" | "product" | "name" | "cpe">): string[] {
  const out = new Set<string>();
  const add = (t: string | null | undefined) => { const s = (t ?? "").trim().toLowerCase(); if (s.length > 2) out.add(s); };
  add(asset.vendor); add(asset.product); add(asset.name);
  const cpe = parseCpe(asset.cpe);
  if (cpe) { if (cpe.vendor !== "*") add(cpe.vendor); if (cpe.product !== "*") add(cpe.product); }
  return [...out];
}

const ASSET_CSV_COLS = ["name", "kind", "vendor", "product", "version", "cpe", "ip", "hostname", "owner", "criticality", "tags"] as const;

export function assetsToCsv(items: Asset[]): string {
  return toCsv(
    [...ASSET_CSV_COLS],
    items.map((a) => [
      a.name, a.kind, a.vendor, a.product, a.version, a.cpe, a.ip, a.hostname,
      a.owner, a.criticality, a.tags.join("|"),
    ]),
  );
}

/** Split a single CSV line honoring double-quoted fields. */
function splitCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = "";
  let inQ = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i]!;
    if (inQ) {
      if (c === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else inQ = false; }
      else cur += c;
    } else if (c === '"') inQ = true;
    else if (c === ",") { out.push(cur); cur = ""; }
    else cur += c;
  }
  out.push(cur);
  return out;
}

/**
 * Parse an asset CSV (header row required, any subset/order of the known
 * columns; `tags` is pipe- or semicolon-delimited). Rows without a name are skipped.
 */
export function parseAssetsCsv(text: string): NewAsset[] {
  const lines = text.replace(/\r/g, "").split("\n").filter((l) => l.trim());
  if (lines.length < 2) return [];
  const header = splitCsvLine(lines[0]!).map((h) => h.trim().toLowerCase());
  const idx = (name: string) => header.indexOf(name);
  const out: NewAsset[] = [];
  for (const line of lines.slice(1)) {
    const cells = splitCsvLine(line);
    const get = (name: string) => { const i = idx(name); return i >= 0 ? (cells[i] ?? "").trim() : ""; };
    const name = get("name") || get("product") || get("hostname");
    if (!name) continue;
    const kind = (ASSET_KINDS as readonly string[]).includes(get("kind")) ? (get("kind") as AssetKind) : "software";
    const crit = (CRITICALITIES as readonly string[]).includes(get("criticality")) ? (get("criticality") as Criticality) : "medium";
    const tags = get("tags").split(/[|;]/).map((t) => t.trim()).filter(Boolean);
    out.push({
      name, kind, criticality: crit, tags, origin: "csv",
      vendor: get("vendor") || null, product: get("product") || null, version: get("version") || null,
      cpe: get("cpe") || null, ip: get("ip") || null, hostname: get("hostname") || null, owner: get("owner") || null,
    });
  }
  return out;
}

// ===========================================================================
// Phase 2 — Defensive monitoring: environment events (log/IOC matching)
// ===========================================================================

export const EVENT_KINDS = ["ip", "domain", "url", "hash"] as const;
export type EventKind = (typeof EVENT_KINDS)[number];

export const EVENT_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type EventSeverity = (typeof EVENT_SEVERITIES)[number];

/** A single observable seen in the defender's environment (from a log/sensor/push). */
export interface MonitorEvent {
  id: string;
  sensor: string;             // log source / sensor name
  kind: EventKind;
  value: string;              // normalized observable
  host: string | null;        // affected host/asset, when known
  observedAt: string | null;
  raw: string | null;         // short raw snippet for context
  matched: boolean;           // true when it hit a tracked indicator
  matchedSource: string | null;
  malware: string | null;
  severity: EventSeverity;
  createdAt: string;
}

/** A parsed observable plus its event context, before IOC matching. */
export interface ParsedObservable {
  sensor: string;
  host: string | null;
  observedAt: string | null;
  kind: EventKind;
  value: string;
  raw: string | null;
}

/** Canonicalize an observable for comparison against indicators. */
export function normalizeObservable(kind: EventKind, value: string): string {
  const v = value.trim();
  switch (kind) {
    case "ip": return ipOnly(v).toLowerCase();
    case "domain": return v.toLowerCase().replace(/\.$/, "");
    case "url": return v.replace(/^hxxp/i, "http").trim();
    case "hash": return v.toLowerCase();
    default: return v;
  }
}

const OBS_FIELDS: Record<EventKind, string[]> = {
  ip: ["ip", "src_ip", "source_ip", "dst_ip", "dest_ip", "destination_ip", "remote_ip", "client_ip", "ipv4"],
  domain: ["domain", "host", "hostname", "dns_query", "query", "fqdn"],
  url: ["url", "uri", "request_url", "http_url"],
  hash: ["hash", "md5", "sha1", "sha256", "filehash", "file_hash"],
};

function eventMeta(o: Record<string, unknown>): { sensor: string; host: string | null; observedAt: string | null } {
  const str = (k: string) => (typeof o[k] === "string" ? (o[k] as string) : undefined);
  const sensor = str("sensor") || str("source") || str("logsource") || str("product") || "push";
  const host = str("host") || str("hostname") || str("device") || str("computer") || null;
  const observedAt = str("timestamp") || str("time") || str("@timestamp") || str("observedAt") || str("date") || null;
  return { sensor, host, observedAt };
}

/** Pull observables out of one structured event object (typed fields first, then free-text fields). */
function observablesFromObject(o: Record<string, unknown>): ParsedObservable[] {
  const meta = eventMeta(o);
  const found = new Map<string, ParsedObservable>();
  const push = (kind: EventKind, raw: string, context: string | null) => {
    const value = normalizeObservable(kind, raw);
    if (!value) return;
    const key = `${kind}:${value}`;
    if (!found.has(key)) found.set(key, { ...meta, kind, value, raw: context });
  };
  for (const kind of EVENT_KINDS) {
    for (const f of OBS_FIELDS[kind]) {
      const val = o[f];
      if (typeof val === "string" && val.trim()) push(kind, val, val);
    }
  }
  // Free-text fields: extract anything embedded.
  for (const f of ["message", "msg", "raw", "log", "text", "description"]) {
    const val = o[f];
    if (typeof val === "string" && val.trim()) {
      const ex = extractIocs(val);
      const snippet = val.slice(0, 300);
      ex.ips.forEach((v) => push("ip", v, snippet));
      ex.domains.forEach((v) => push("domain", v, snippet));
      ex.urls.forEach((v) => push("url", v, snippet));
      ex.hashes.forEach((v) => push("hash", v, snippet));
    }
  }
  return [...found.values()];
}

/**
 * Parse arbitrary event input into observables. Accepts a JSON object, an array
 * of objects, NDJSON, CSV-ish, or free-form log text (one entry per line).
 */
export function parseEvents(input: unknown): ParsedObservable[] {
  if (input == null) return [];
  if (Array.isArray(input)) return input.flatMap((e) => parseEvents(e));
  if (typeof input === "object") return observablesFromObject(input as Record<string, unknown>);
  if (typeof input !== "string") return [];
  const text = input.trim();
  if (!text) return [];
  // Try whole-body JSON first.
  if (text.startsWith("{") || text.startsWith("[")) {
    try { return parseEvents(JSON.parse(text)); } catch { /* fall through to line mode */ }
  }
  const out: ParsedObservable[] = [];
  for (const line of text.split("\n")) {
    const l = line.trim();
    if (!l) continue;
    if (l.startsWith("{")) {
      try { out.push(...parseEvents(JSON.parse(l))); continue; } catch { /* not JSON, treat as text */ }
    }
    const ex = extractIocs(l);
    const snippet = l.slice(0, 300);
    ex.ips.forEach((v) => out.push({ sensor: "log", host: null, observedAt: null, kind: "ip", value: normalizeObservable("ip", v), raw: snippet }));
    ex.domains.forEach((v) => out.push({ sensor: "log", host: null, observedAt: null, kind: "domain", value: normalizeObservable("domain", v), raw: snippet }));
    ex.urls.forEach((v) => out.push({ sensor: "log", host: null, observedAt: null, kind: "url", value: normalizeObservable("url", v), raw: snippet }));
    ex.hashes.forEach((v) => out.push({ sensor: "log", host: null, observedAt: null, kind: "hash", value: normalizeObservable("hash", v), raw: snippet }));
  }
  return out;
}

// ===========================================================================
// Phase 3 — Vulnerability scanning
// ===========================================================================

export const SCAN_SEVERITIES = ["info", "low", "medium", "high", "critical"] as const;
export type ScanSeverity = (typeof SCAN_SEVERITIES)[number];

export const SCAN_TARGET_KINDS = ["host", "url"] as const;
export type ScanTargetKind = (typeof SCAN_TARGET_KINDS)[number];

export const SCAN_STATUSES = ["queued", "running", "done", "error"] as const;
export type ScanStatus = (typeof SCAN_STATUSES)[number];

/** A host or URL the scanner is configured to assess. */
export const ScanTargetSchema = z.object({
  id: z.string(),
  name: z.string(),
  target: z.string(), // host / ip / url
  kind: z.enum(SCAN_TARGET_KINDS).default("host"),
  adapter: z.string().default("builtin"),
  enabled: z.boolean().default(true),
  schedule: z.string().nullable().default(null), // cron; null = manual only
  createdAt: z.string().nullable().optional(),
  lastScanAt: z.string().nullable().optional(),
});
export type ScanTarget = z.infer<typeof ScanTargetSchema>;

export const NewScanTargetSchema = ScanTargetSchema.omit({ id: true, createdAt: true, lastScanAt: true }).extend({
  id: z.string().optional(),
});
export type NewScanTarget = z.infer<typeof NewScanTargetSchema>;

/** A single scan run against one target. */
export interface Scan {
  id: string;
  targetId: string | null;
  target: string;
  adapter: string;
  status: ScanStatus;
  startedAt: string | null;
  finishedAt: string | null;
  findingCount: number;
  openPorts: number;
  cveCount: number;
  error: string | null;
  createdAt: string;
}

/** A single finding produced by a scan. */
export interface ScanFinding {
  id: string;
  scanId: string;
  target: string;
  host: string | null;
  port: number | null;
  service: string | null;
  product: string | null;
  version: string | null;
  cpe: string | null;
  cve: string | null;
  severity: ScanSeverity;
  title: string;
  description: string;
  evidence: string | null;
  createdAt: string;
}

/** A raw finding emitted by a scan adapter, before persistence assigns ids. */
export type RawScanFinding = Omit<ScanFinding, "id" | "scanId" | "createdAt">;

const SEV_RANK: Record<ScanSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
/** Compare scan severities (higher = more severe), e.g. for sorting findings. */
export function severityRank(s: ScanSeverity): number { return SEV_RANK[s] ?? 0; }
