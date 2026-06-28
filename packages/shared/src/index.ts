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
    .replace(/\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]/gi, ".")
    .replace(/\[\s*:\s*\]/g, ":")
    .replace(/\[\s*\/\s*\]/g, "/")
    .replace(/\[\s*@\s*\]|\(at\)|\[at\]/gi, "@")
    .replace(/h\s*x\s*x\s*p(s?)\s*(?::|\[:\])\/\//gi, "http$1://")
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
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
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
