// Static "demo mode" — no backend required.
//
// When VITE_DEMO=true (or the app is served from *.github.io), the API client
// routes every /api/* call through demoFetch(), which returns curated sample
// data from the in-file dataset below. This lets the dashboard run as a fully
// static site on GitHub Pages: read-only, no API, no database, no keys.
import {
  computeRiskScore, buildDigest, tacticForTechnique, ATTACK_TACTICS,
  type Vulnerability, type Indicator, type Advisory,
} from "@omnisight/shared";

/**
 * True when running the static demo. Driven solely by the build-time flag
 * (the Pages workflow and `pnpm build:demo` set VITE_DEMO=true) — deliberately
 * not inferred from the hostname, which is unsafe to match by substring.
 */
export const DEMO: boolean =
  (import.meta as unknown as { env?: Record<string, string> }).env?.VITE_DEMO === "true";

const NOW = new Date().toISOString();
const daysAgo = (n: number) => new Date(Date.now() - n * 86400000).toISOString().slice(0, 10);

// --- vulnerabilities -------------------------------------------------------
function V(
  cveId: string, title: string, vendor: string, product: string,
  cvss: number, epss: number, kev: boolean, ransom: boolean, addedDaysAgo: number,
): Vulnerability {
  const v: Vulnerability = {
    id: cveId, cveId, source: kev ? "cisa-kev" : "nvd", title, description: `${title}. Tracked by OmniSight in demo mode.`,
    vendor, product, knownExploited: kev, ransomwareUse: ransom, cvss, epss, cwes: [],
    requiredAction: kev ? "Apply vendor updates per the CISA KEV catalog." : null,
    dueDate: kev ? daysAgo(-14) : null, dateAdded: daysAgo(addedDaysAgo), references: [],
    riskScore: 0, fetchedAt: NOW,
  };
  v.riskScore = computeRiskScore({ knownExploited: kev, ransomwareUse: ransom, cvss, epss });
  return v;
}

const VULNS: Vulnerability[] = [
  V("CVE-2024-21762", "Fortinet FortiOS out-of-bound write in SSL VPN", "Fortinet", "FortiOS", 9.8, 0.94, true, true, 3),
  V("CVE-2023-34362", "Progress MOVEit Transfer SQL injection", "Progress", "MOVEit Transfer", 9.8, 0.97, true, true, 9),
  V("CVE-2023-4966", "Citrix NetScaler ADC sensitive information disclosure (CitrixBleed)", "Citrix", "NetScaler ADC", 9.4, 0.96, true, true, 12),
  V("CVE-2021-44228", "Apache Log4j2 remote code execution (Log4Shell)", "Apache", "Log4j", 10.0, 0.97, true, true, 21),
  V("CVE-2024-3400", "Palo Alto Networks PAN-OS command injection in GlobalProtect", "Palo Alto Networks", "PAN-OS", 10.0, 0.93, true, false, 5),
  V("CVE-2023-22515", "Atlassian Confluence broken access control", "Atlassian", "Confluence Data Center", 9.8, 0.9, true, false, 14),
  V("CVE-2024-1709", "ConnectWise ScreenConnect authentication bypass", "ConnectWise", "ScreenConnect", 10.0, 0.95, true, true, 7),
  V("CVE-2023-20198", "Cisco IOS XE web UI privilege escalation", "Cisco", "IOS XE", 10.0, 0.92, true, false, 16),
  V("CVE-2022-30190", "Microsoft Windows MSDT remote code execution (Follina)", "Microsoft", "Windows", 7.8, 0.89, true, false, 28),
  V("CVE-2023-27350", "PaperCut MF/NG improper access control", "PaperCut", "MF/NG", 9.8, 0.88, true, true, 19),
  V("CVE-2024-23897", "Jenkins arbitrary file read via CLI", "Jenkins", "Jenkins", 9.8, 0.7, true, false, 6),
  V("CVE-2023-3519", "Citrix NetScaler ADC code injection", "Citrix", "NetScaler ADC", 9.8, 0.94, true, false, 22),
  V("CVE-2024-21887", "Ivanti Connect Secure command injection", "Ivanti", "Connect Secure", 9.1, 0.93, true, true, 4),
  V("CVE-2023-46604", "Apache ActiveMQ remote code execution", "Apache", "ActiveMQ", 10.0, 0.91, true, true, 18),
  V("CVE-2024-27198", "JetBrains TeamCity authentication bypass", "JetBrains", "TeamCity", 9.8, 0.85, true, false, 8),
  V("CVE-2023-36884", "Microsoft Office and Windows HTML remote code execution", "Microsoft", "Office", 8.8, 0.6, true, false, 26),
  V("CVE-2024-4577", "PHP-CGI argument injection on Windows", "PHP", "PHP-CGI", 9.8, 0.8, true, false, 2),
  V("CVE-2023-42793", "JetBrains TeamCity authentication bypass (RCE)", "JetBrains", "TeamCity", 9.8, 0.82, true, false, 24),
  V("CVE-2024-20253", "Cisco Unified Communications remote code execution", "Cisco", "Unified Communications", 9.9, 0.4, false, false, 10),
  V("CVE-2024-0204", "Fortra GoAnywhere MFT authentication bypass", "Fortra", "GoAnywhere MFT", 9.8, 0.86, true, true, 11),
  V("CVE-2023-48788", "Fortinet FortiClientEMS SQL injection", "Fortinet", "FortiClientEMS", 9.3, 0.55, true, false, 13),
  V("CVE-2024-1086", "Linux kernel netfilter use-after-free privilege escalation", "Linux", "Kernel", 7.8, 0.3, true, false, 15),
  V("CVE-2023-7028", "GitLab account takeover via password reset", "GitLab", "GitLab", 10.0, 0.5, false, false, 20),
  V("CVE-2024-21413", "Microsoft Outlook remote code execution (MonikerLink)", "Microsoft", "Outlook", 9.8, 0.45, false, false, 17),
];

// --- indicators ------------------------------------------------------------
type IOCT = Indicator["type"];
function I(
  type: IOCT, value: string, malware: string | null, threat: string | null, conf: number,
  country: string | null, cc: string | null, lat: number | null, lng: number | null, tags: string[],
): Indicator {
  return {
    id: value, source: ["threatfox", "otx", "pulsedive"][value.length % 3]!, type, value, malware,
    threatType: threat, confidence: conf, references: [], tags, firstSeen: NOW, lastSeen: NOW,
    country, countryCode: cc, lat, lng, fetchedAt: NOW,
  };
}
const INDICATORS: Indicator[] = [
  I("ip", "45.66.230.10", "Cobalt Strike", "botnet_cc", 92, "Russia", "RU", 55.75, 37.62, ["CVE-2024-21762", "T1071"]),
  I("ip", "185.220.101.4", "QakBot", "payload_delivery", 80, "Germany", "DE", 51.16, 10.45, ["T1105"]),
  I("ip", "104.21.5.88", "LockBit", "ransomware", 88, "United States", "US", 37.75, -97.82, ["T1486"]),
  I("domain", "secure-update-portal.com", "DarkGate", "phishing", 75, null, null, null, null, ["T1566"]),
  I("domain", "cdn-fortinet-patch.net", "Cobalt Strike", "c2", 84, null, null, null, null, ["CVE-2024-21762"]),
  I("url", "http://malicious-mfa-reset.io/login", "AsyncRAT", "phishing", 70, null, null, null, null, ["T1078"]),
  I("hash", "44d88612fea8a8f36de82e1278abb02f", "Emotet", "loader", 90, null, null, null, null, ["T1059"]),
  I("ip", "193.143.1.55", "BianLian", "ransomware", 85, "Netherlands", "NL", 52.13, 5.29, ["T1486"]),
  I("ip", "212.18.104.12", "QakBot", "botnet_cc", 78, "France", "FR", 46.23, 2.21, ["T1071"]),
  I("domain", "login-citrix-gateway.com", "CitrixBleed", "credential_theft", 82, null, null, null, null, ["CVE-2023-4966"]),
  I("ip", "159.65.20.7", "Mirai", "ddos", 65, "India", "IN", 20.59, 78.96, ["T1498"]),
  I("hash", "5f4dcc3b5aa765d61d8327deb882cf99e1", "RedLine Stealer", "infostealer", 87, null, null, null, null, ["T1555"]),
  I("ip", "91.219.236.18", "BlackBasta", "ransomware", 86, "United Kingdom", "GB", 55.37, -3.43, ["T1486"]),
  I("domain", "update-screenconnect.net", "ScreenConnect abuse", "c2", 79, null, null, null, null, ["CVE-2024-1709"]),
  I("ip", "203.0.113.42", "Cobalt Strike", "c2", 81, "Singapore", "SG", 1.35, 103.81, ["T1071"]),
  I("ip", "198.51.100.23", "Pikabot", "loader", 74, "Brazil", "BR", -14.23, -51.92, ["T1105"]),
  I("url", "http://invoice-share-doc.com/view", "DarkGate", "phishing", 72, null, null, null, null, ["T1566"]),
  I("ip", "77.91.124.20", "LockBit", "ransomware", 89, "Russia", "RU", 55.75, 37.62, ["T1486"]),
];

// --- advisories / news -----------------------------------------------------
const ADV: Advisory[] = [
  { id: "a1", source: "arstechnica-security", title: "Self-propagating malware targets cloud credentials, researchers warn", summary: "A new worm-like campaign abuses misconfigured cloud metadata services to steal and reuse credentials.", url: "https://arstechnica.com/security/", category: "news", published: NOW, tags: ["cloud", "worm"], fetchedAt: NOW },
  { id: "a2", source: "thehackernews", title: "Critical Fortinet SSL VPN flaw exploited in the wild", summary: "Attackers chain CVE-2024-21762 for pre-auth code execution on exposed FortiGate devices.", url: "https://thehackernews.com/", category: "news", published: daysAgo(1) + "T08:00:00Z", tags: ["Fortinet", "KEV"], fetchedAt: NOW },
  { id: "a3", source: "bleepingcomputer", title: "Ransomware gang leaks data after MOVEit mass-exploitation", summary: "Hundreds of organizations affected by the MOVEit Transfer SQL injection campaign.", url: "https://www.bleepingcomputer.com/", category: "news", published: daysAgo(2) + "T12:00:00Z", tags: ["ransomware", "MOVEit"], fetchedAt: NOW },
  { id: "a4", source: "darkreading", title: "Detection engineering: closing ATT&CK coverage gaps", summary: "How teams map intel to Sigma/YARA and find techniques no rule covers.", url: "https://www.darkreading.com/", category: "analysis", published: daysAgo(3) + "T09:30:00Z", tags: ["ATT&CK", "detection"], fetchedAt: NOW },
  { id: "a5", source: "securityweek-ai", title: "Adversarial ML: poisoning attacks move from theory to practice", summary: "MITRE ATLAS techniques observed against production model pipelines.", url: "https://www.securityweek.com/category/artificial-intelligence/", category: "ai", published: daysAgo(4) + "T10:00:00Z", tags: ["AML", "ATLAS"], fetchedAt: NOW },
  { id: "a6", source: "thehackernews", title: "Citrix Bleed exploitation continues against unpatched appliances", summary: "Session-token theft via CVE-2023-4966 enables MFA bypass.", url: "https://thehackernews.com/", category: "news", published: daysAgo(5) + "T07:45:00Z", tags: ["Citrix", "KEV"], fetchedAt: NOW },
  { id: "a7", source: "bleepingcomputer", title: "PAN-OS GlobalProtect command injection under active attack", summary: "CVE-2024-3400 enables unauthenticated RCE on firewalls.", url: "https://www.bleepingcomputer.com/", category: "news", published: daysAgo(6) + "T15:20:00Z", tags: ["Palo Alto", "KEV"], fetchedAt: NOW },
  { id: "a8", source: "arstechnica-security", title: "Inside a ScreenConnect supply-chain compromise", summary: "Authentication bypass CVE-2024-1709 used to drop ransomware via RMM tooling.", url: "https://arstechnica.com/security/", category: "news", published: daysAgo(7) + "T11:10:00Z", tags: ["RMM", "ransomware"], fetchedAt: NOW },
  { id: "a9", source: "darkreading", title: "EPSS vs CVSS: prioritizing what actually gets exploited", summary: "Why exploit-probability scoring reshapes patch queues.", url: "https://www.darkreading.com/", category: "analysis", published: daysAgo(8) + "T13:00:00Z", tags: ["EPSS", "prioritization"], fetchedAt: NOW },
  { id: "a10", source: "securityweek-ai", title: "ATLAS adds techniques for LLM prompt-injection chains", summary: "New adversarial-ML knowledge-base entries map real incidents.", url: "https://www.securityweek.com/category/artificial-intelligence/", category: "ai", published: daysAgo(9) + "T09:00:00Z", tags: ["ATLAS", "LLM"], fetchedAt: NOW },
];

// --- assets (Phase 2) ------------------------------------------------------
const ASSETS = [
  { id: "as1", name: "edge-fw-01", kind: "host", vendor: "Fortinet", product: "FortiOS", version: "7.2.4", cpe: "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", ip: "10.0.0.1", hostname: "edge-fw-01", owner: "Network", criticality: "critical", tags: ["perimeter"], origin: "manual", createdAt: NOW, updatedAt: NOW },
  { id: "as2", name: "vpn-gw", kind: "host", vendor: "Citrix", product: "NetScaler ADC", version: "13.1", cpe: null, ip: "10.0.0.5", hostname: "vpn-gw", owner: "Network", criticality: "critical", tags: ["remote-access"], origin: "manual", createdAt: NOW, updatedAt: NOW },
  { id: "as3", name: "log4j-app", kind: "software", vendor: "Apache", product: "Log4j", version: "2.14.1", cpe: null, ip: null, hostname: "app-07", owner: "Platform", criticality: "high", tags: ["java"], origin: "sbom", createdAt: NOW, updatedAt: NOW },
  { id: "as4", name: "ci-server", kind: "service", vendor: "Jenkins", product: "Jenkins", version: "2.426", cpe: null, ip: "10.0.2.10", hostname: "ci-server", owner: "DevOps", criticality: "high", tags: ["build"], origin: "scan", createdAt: NOW, updatedAt: NOW },
  { id: "as5", name: "exchange-01", kind: "host", vendor: "Microsoft", product: "Exchange Server", version: "2019", cpe: null, ip: "10.0.1.20", hostname: "exchange-01", owner: "IT", criticality: "high", tags: ["email"], origin: "manual", createdAt: NOW, updatedAt: NOW },
  { id: "as6", name: "wiki", kind: "service", vendor: "Atlassian", product: "Confluence", version: "8.5.1", cpe: null, ip: "10.0.2.30", hostname: "wiki", owner: "Platform", criticality: "medium", tags: ["docs"], origin: "manual", createdAt: NOW, updatedAt: NOW },
  { id: "as7", name: "rmm", kind: "service", vendor: "ConnectWise", product: "ScreenConnect", version: "23.9.7", cpe: null, ip: null, hostname: "rmm", owner: "IT", criticality: "high", tags: ["rmm"], origin: "manual", createdAt: NOW, updatedAt: NOW },
  { id: "as8", name: "scanned-host", kind: "host", vendor: null, product: "nginx", version: "1.18.0", cpe: "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*", ip: null, hostname: "demo.local", owner: null, criticality: "medium", tags: ["scanned"], origin: "scan", createdAt: NOW, updatedAt: NOW },
];
const CRIT_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const ASSET_MATCHES = [
  { assetId: "as1", assetName: "edge-fw-01", criticality: "critical", cve: "CVE-2024-21762", title: "Fortinet FortiOS out-of-bound write in SSL VPN", riskScore: 96, knownExploited: true, matchType: "cpe", reason: "CPE fortinet:fortios (running 7.2.4)" },
  { assetId: "as2", assetName: "vpn-gw", criticality: "critical", cve: "CVE-2023-4966", title: "Citrix NetScaler ADC sensitive information disclosure (CitrixBleed)", riskScore: 94, knownExploited: true, matchType: "vendor-product", reason: "vendor/product Citrix/NetScaler ADC" },
  { assetId: "as3", assetName: "log4j-app", criticality: "high", cve: "CVE-2021-44228", title: "Apache Log4j2 remote code execution (Log4Shell)", riskScore: 100, knownExploited: true, matchType: "vendor-product", reason: "vendor/product Apache/Log4j" },
  { assetId: "as4", assetName: "ci-server", criticality: "high", cve: "CVE-2024-23897", title: "Jenkins arbitrary file read via CLI", riskScore: 78, knownExploited: true, matchType: "vendor-product", reason: "vendor/product Jenkins/Jenkins" },
  { assetId: "as6", assetName: "wiki", criticality: "medium", cve: "CVE-2023-22515", title: "Atlassian Confluence broken access control", riskScore: 90, knownExploited: true, matchType: "term", reason: 'matched "confluence"' },
  { assetId: "as7", assetName: "rmm", criticality: "high", cve: "CVE-2024-1709", title: "ConnectWise ScreenConnect authentication bypass", riskScore: 95, knownExploited: true, matchType: "vendor-product", reason: "vendor/product ConnectWise/ScreenConnect" },
];

// --- environment events (Phase 2) ------------------------------------------
const EV_NOW = Date.now();
type DemoEvent = {
  id: string; sensor: string; kind: string; value: string; host: string | null;
  observedAt: string | null; raw: string | null; matched: boolean;
  matchedSource: string | null; malware: string | null; severity: string; createdAt: string;
};
const EVENTS: DemoEvent[] = [
  ...INDICATORS.filter((i) => i.type === "ip").slice(0, 9).map((i, n): DemoEvent => ({
    id: `ev${n}`, sensor: ["firewall", "syslog", "edr", "dns"][n % 4]!, kind: i.type, value: i.value,
    host: ["web-01", "edge-fw-01", "ws-204", "app-07"][n % 4]!, observedAt: new Date(EV_NOW - n * 1800000).toISOString(),
    raw: `connection to ${i.value} flagged`, matched: true, matchedSource: i.source, malware: i.malware,
    severity: (i.confidence ?? 0) >= 85 ? "high" : "medium", createdAt: new Date(EV_NOW - n * 1800000).toISOString(),
  })),
  { id: "evx1", sensor: "dns", kind: "domain", value: "internal-update.local", host: "ws-118", observedAt: NOW, raw: "benign lookup", matched: false, matchedSource: null, malware: null, severity: "info", createdAt: NOW },
  { id: "evx2", sensor: "proxy", kind: "url", value: "http://intranet/login", host: "ws-330", observedAt: NOW, raw: "internal", matched: false, matchedSource: null, malware: null, severity: "info", createdAt: NOW },
];

// --- scans (Phase 3) -------------------------------------------------------
const SCAN_TARGETS = [
  { id: "st1", name: "Perimeter firewall", target: "10.0.0.1", kind: "host", adapter: "builtin", enabled: true, schedule: "0 3 * * *", createdAt: NOW, lastScanAt: NOW },
  { id: "st2", name: "Public web app", target: "https://demo.local", kind: "url", adapter: "builtin", enabled: true, schedule: null, createdAt: NOW, lastScanAt: NOW },
  { id: "st3", name: "CI server", target: "10.0.2.10", kind: "host", adapter: "builtin", enabled: false, schedule: null, createdAt: NOW, lastScanAt: null },
];
const FINDINGS = [
  { id: "f1", scanId: "sc1", target: "10.0.0.1", host: "10.0.0.1", port: 443, service: "https", product: "fortios", version: null, cpe: null, cve: null, severity: "info", title: "Open port 443/https", description: "HTTPS management interface reachable.", evidence: "tcp/443 open", createdAt: NOW },
  { id: "f2", scanId: "sc1", target: "10.0.0.1", host: "10.0.0.1", port: 22, service: "ssh", product: null, version: null, cpe: null, cve: null, severity: "info", title: "Open port 22/ssh", description: "SSH reachable.", evidence: "tcp/22 open", createdAt: NOW },
  { id: "f3", scanId: "sc1", target: "10.0.0.1", host: "10.0.0.1", port: 443, service: "https", product: "fortinet", version: "7.2.4", cpe: "cpe:2.3:o:fortinet:fortios:7.2.4", cve: "CVE-2024-21762", severity: "critical", title: "Known CVE for fortios: CVE-2024-21762", description: "Detected FortiOS 7.2.4 — affected by the SSL VPN out-of-bound write (KEV).", evidence: "Server: fortios", createdAt: NOW },
  { id: "f4", scanId: "sc2", target: "https://demo.local", host: "demo.local", port: 443, service: "https", product: "nginx", version: "1.18.0", cpe: "cpe:2.3:a:nginx:nginx:1.18.0", cve: null, severity: "info", title: "Web server banner: nginx/1.18.0", description: "Server advertises nginx/1.18.0 — version disclosed.", evidence: "Server: nginx/1.18.0", createdAt: NOW },
  { id: "f5", scanId: "sc2", target: "https://demo.local", host: "demo.local", port: 443, service: "https", product: null, version: null, cpe: null, cve: null, severity: "low", title: "Missing security header: Strict-Transport-Security (HSTS)", description: "Response lacks HSTS.", evidence: "strict-transport-security: <absent>", createdAt: NOW },
];
const SCANS = [
  { id: "sc1", targetId: "st1", target: "10.0.0.1", adapter: "builtin", status: "done", startedAt: NOW, finishedAt: NOW, findingCount: 3, openPorts: 2, cveCount: 1, error: null, createdAt: NOW },
  { id: "sc2", targetId: "st2", target: "https://demo.local", adapter: "builtin", status: "done", startedAt: NOW, finishedAt: NOW, findingCount: 2, openPorts: 0, cveCount: 0, error: null, createdAt: daysAgo(1) + "T03:00:00Z" },
];

const BREACHES = [
  { id: "b1", domain: "example.com", title: "ExampleCorp Breach", breachDate: daysAgo(120), addedDate: NOW, pwnCount: 2400000, dataClasses: ["Email addresses", "Passwords", "Names"], description: "Demo breach record.", verified: true, fetchedAt: NOW },
  { id: "b2", domain: "example.com", title: "Forum Leak", breachDate: daysAgo(400), addedDate: NOW, pwnCount: 350000, dataClasses: ["Email addresses", "Usernames"], description: "Demo breach record.", verified: true, fetchedAt: NOW },
];
const DET_RULES = [
  { id: "dr1", name: "Cobalt Strike default C2 beacon", format: "sigma", content: "", techniques: ["T1071"], enabled: true, createdAt: NOW },
  { id: "dr2", name: "Suspicious MSDT child process (Follina)", format: "sigma", content: "", techniques: ["T1059", "T1203"], enabled: true, createdAt: NOW },
  { id: "dr3", name: "Known ransomware file hashes", format: "yara", content: "", techniques: ["T1486"], enabled: true, createdAt: NOW },
];

const WATCHLIST = ["fortinet", "citrix", "log4j", "microsoft", "confluence"];

// ATT&CK technique frequency (from indicator/advisory tags) + matrix.
const ATTACK = [
  { id: "T1486", count: 6, framework: "attack" }, { id: "T1071", count: 5, framework: "attack" },
  { id: "T1566", count: 4, framework: "attack" }, { id: "T1105", count: 3, framework: "attack" },
  { id: "T1078", count: 3, framework: "attack" }, { id: "T1059", count: 2, framework: "attack" },
  { id: "T1498", count: 2, framework: "attack" }, { id: "T1555", count: 1, framework: "attack" },
  { id: "AML.T0043", count: 2, framework: "atlas" }, { id: "AML.T0051", count: 1, framework: "atlas" },
];
function buildMatrix() {
  const byTactic = new Map<string, { id: string; count: number }[]>();
  for (const t of ATTACK) {
    const tac = tacticForTechnique(t.id);
    const arr = byTactic.get(tac) ?? [];
    arr.push({ id: t.id, count: t.count });
    byTactic.set(tac, arr);
  }
  return ATTACK_TACTICS.map((tac) => ({ tactic: tac.id, name: tac.name, techniques: byTactic.get(tac.id) ?? [] }));
}

const CORRELATIONS = VULNS.filter((v) => INDICATORS.some((i) => i.tags.includes(v.cveId!))).slice(0, 6).map((v) => ({
  cveId: v.cveId!, title: v.title, riskScore: v.riskScore,
  indicators: INDICATORS.filter((i) => i.tags.includes(v.cveId!)).map((i) => ({ value: i.value, source: i.source, malware: i.malware, type: i.type })),
}));

const ENTITIES = VULNS.slice(0, 8).map((v) => ({
  cveId: v.cveId!, title: v.title, riskScore: v.riskScore, knownExploited: v.knownExploited,
  sources: v.source === "cisa-kev" ? [{ source: "cisa-kev", reliability: "A" }, { source: "nvd", reliability: "A" }] : [{ source: "nvd", reliability: "A" }],
}));

const ACTORS = ["Cobalt Strike", "LockBit", "QakBot", "DarkGate", "BlackBasta"].map((name) => {
  const rows = INDICATORS.filter((i) => i.malware === name);
  const types: Record<string, number> = {};
  for (const i of rows) types[i.type] = (types[i.type] ?? 0) + 1;
  return {
    name, indicatorCount: rows.length || 1, types, sources: [...new Set(rows.map((i) => i.source))],
    firstSeen: NOW, lastSeen: NOW,
    cves: [...new Set(rows.flatMap((i) => i.tags.filter((t) => t.startsWith("CVE"))))],
    techniques: [...new Set(rows.flatMap((i) => i.tags.filter((t) => /^T\d{4}/.test(t))))],
    sampleIocs: rows.slice(0, 6).map((i) => ({ value: i.value, type: i.type })),
  };
});

const MAP = (() => {
  const by = new Map<string, { country: string; code: string; lat: number; lng: number; count: number }>();
  for (const i of INDICATORS) {
    if (i.lat == null || i.lng == null || !i.countryCode) continue;
    const cur = by.get(i.countryCode);
    if (cur) cur.count++;
    else by.set(i.countryCode, { country: i.country!, code: i.countryCode, lat: i.lat, lng: i.lng, count: 1 });
  }
  return [...by.values()].sort((a, b) => b.count - a.count);
})();

function stats() {
  const terms = WATCHLIST;
  const inStack = VULNS.filter((v) => terms.some((t) => `${v.vendor} ${v.product} ${v.title}`.toLowerCase().includes(t))).length;
  return {
    total: VULNS.length, knownExploited: VULNS.filter((v) => v.knownExploited).length,
    ransomware: VULNS.filter((v) => v.ransomwareUse).length,
    critical: VULNS.filter((v) => v.riskScore >= 75).length,
    high: VULNS.filter((v) => v.riskScore >= 50 && v.riskScore < 75).length,
    sources: 11, indicators: INDICATORS.length, advisories: ADV.length, inStack,
    assets: ASSETS.length, eventsMatched: EVENTS.filter((e) => e.matched).length, findings: FINDINGS.length,
  };
}

function digest() {
  const top = [...VULNS].sort((a, b) => b.riskScore - a.riskScore).slice(0, 10);
  return buildDigest({
    stats: { total: VULNS.length, knownExploited: stats().knownExploited, ransomware: stats().ransomware, critical: stats().critical, high: stats().high, indicators: INDICATORS.length, inStack: stats().inStack },
    terms: WATCHLIST, topVulns: top, recentKev: VULNS.filter((v) => v.knownExploited).slice(0, 10),
    stackVulns: top.filter((v) => WATCHLIST.some((t) => `${v.vendor} ${v.product}`.toLowerCase().includes(t))).slice(0, 10),
    topIocs: INDICATORS.slice(0, 10),
  });
}

// --- pagination / filtering ------------------------------------------------
function num(q: URLSearchParams, k: string, d: number) { const v = q.get(k); return v ? Number(v) : d; }
function paged<T>(items: T[], q: URLSearchParams, defSize = 50) {
  const page = Math.max(1, num(q, "page", 1));
  const pageSize = Math.max(1, num(q, "pageSize", defSize));
  const start = (page - 1) * pageSize;
  return { items: items.slice(start, start + pageSize), total: items.length, page, pageSize };
}
function sortBy<T>(items: T[], field: string, dir: string, val: (x: T) => string | number | null): T[] {
  const d = dir === "asc" ? 1 : -1;
  return [...items].sort((a, b) => {
    const av = val(a), bv = val(b);
    if (av == null && bv == null) return 0; if (av == null) return 1; if (bv == null) return -1;
    if (typeof av === "number" && typeof bv === "number") return (av - bv) * d;
    return String(av).localeCompare(String(bv)) * d;
  });
}

function filterVulns(q: URLSearchParams): Vulnerability[] {
  let rows = VULNS;
  const minRisk = num(q, "minRisk", 0); if (minRisk) rows = rows.filter((v) => v.riskScore >= minRisk);
  if (q.get("exploited") === "true") rows = rows.filter((v) => v.knownExploited);
  if (q.get("ransomware") === "true") rows = rows.filter((v) => v.ransomwareUse);
  if (q.get("source")) rows = rows.filter((v) => v.source === q.get("source"));
  const ven = q.get("vendor")?.toLowerCase(); if (ven) rows = rows.filter((v) => `${v.vendor} ${v.product} ${v.title}`.toLowerCase().includes(ven));
  const term = q.get("q")?.toLowerCase(); if (term) rows = rows.filter((v) => `${v.title} ${v.cveId} ${v.vendor}`.toLowerCase().includes(term));
  if (q.get("myStack") === "true") rows = rows.filter((v) => WATCHLIST.some((t) => `${v.vendor} ${v.product} ${v.title}`.toLowerCase().includes(t)));
  const f = q.get("sort") ?? "risk";
  return sortBy(rows, f, q.get("dir") ?? "desc", (v) => f === "cve" ? v.cveId : f === "cvss" ? v.cvss : f === "epss" ? v.epss : f === "vendor" ? v.vendor : f === "reported" ? v.dateAdded : f === "threat" ? v.title : v.riskScore);
}
function filterIocs(q: URLSearchParams): Indicator[] {
  let rows = INDICATORS;
  if (q.get("type")) rows = rows.filter((i) => i.type === q.get("type"));
  if (q.get("source")) rows = rows.filter((i) => i.source === q.get("source"));
  const mal = q.get("malware")?.toLowerCase(); if (mal) rows = rows.filter((i) => (i.malware ?? "").toLowerCase().includes(mal));
  const term = q.get("q")?.toLowerCase(); if (term) rows = rows.filter((i) => `${i.value} ${i.malware} ${i.threatType}`.toLowerCase().includes(term));
  const minConf = num(q, "minConfidence", 0); if (minConf) rows = rows.filter((i) => (i.confidence ?? 0) >= minConf);
  const f = q.get("sort") ?? "lastseen";
  return sortBy(rows, f, q.get("dir") ?? "desc", (i) => f === "confidence" ? i.confidence : f === "type" ? i.type : f === "malware" ? i.malware : f === "value" ? i.value : f === "source" ? i.source : i.lastSeen);
}

// --- router ----------------------------------------------------------------
function route(path: string, q: URLSearchParams, method: string, body: unknown): unknown {
  // Mutating endpoints: keep the demo read-only but responsive.
  if (method !== "GET" && method !== "HEAD") {
    if (path === "/api/watchlist" && method === "POST") { const t = (body as { term?: string })?.term?.trim().toLowerCase(); if (t && !WATCHLIST.includes(t)) WATCHLIST.push(t); return WATCHLIST; }
    if (path.startsWith("/api/watchlist/") && method === "DELETE") { const t = decodeURIComponent(path.split("/").pop()!); const i = WATCHLIST.indexOf(t); if (i >= 0) WATCHLIST.splice(i, 1); return WATCHLIST; }
    return { ok: true, demo: true, ...(body && typeof body === "object" ? body : {}), id: `demo-${Date.now()}` };
  }
  switch (true) {
    case path === "/api/auth/config": return { authEnabled: false, sso: false };
    case path === "/api/auth/me": return { authEnabled: false, user: null };
    case path === "/api/ai/config": return { enabled: false };
    case path === "/api/stats": return stats();
    case path === "/api/digest": return digest();
    case path === "/api/vulnerabilities": return paged(filterVulns(q), q);
    case path === "/api/indicators": return paged(filterIocs(q), q);
    case path === "/api/advisories": return paged(ADV, q, 30);
    case path === "/api/actors": return ACTORS;
    case path.startsWith("/api/actors/"): { const n = decodeURIComponent(path.split("/").pop()!); return ACTORS.find((a) => a.name === n) ?? ACTORS[0]; }
    case path === "/api/map": return MAP;
    case path === "/api/map/indicators": return [];
    case path === "/api/correlations": return CORRELATIONS;
    case path === "/api/attack": return ATTACK;
    case path === "/api/attack/matrix": return buildMatrix();
    case path === "/api/entities": return ENTITIES;
    case path === "/api/assets": return paged(ASSETS, q);
    case path === "/api/asset-matches": return ASSET_MATCHES;
    case path === "/api/events": return paged(q.get("matchedOnly") === "true" ? EVENTS.filter((e) => e.matched) : EVENTS, q, 100);
    case path === "/api/events/stats": { const matched = EVENTS.filter((e) => e.matched).length; return { total: EVENTS.length, matched, last24h: EVENTS.length }; }
    case path === "/api/scan/config": return { adapters: [{ id: "builtin", name: "Built-in (port + HTTP)" }] };
    case path === "/api/scan/targets": return SCAN_TARGETS;
    case path === "/api/scans": return SCANS;
    case path.startsWith("/api/scans/"): { const id = path.split("/").pop()!; return { scan: SCANS.find((s) => s.id === id) ?? SCANS[0], findings: FINDINGS.filter((f) => f.scanId === id) }; }
    case path === "/api/findings": return paged(q.get("withCveOnly") === "true" ? FINDINGS.filter((f) => f.cve) : FINDINGS, q, 100);
    case path === "/api/findings/stats": return { total: FINDINGS.length, withCve: FINDINGS.filter((f) => f.cve).length, critical: FINDINGS.filter((f) => f.severity === "critical").length, high: FINDINGS.filter((f) => f.severity === "high").length };
    case path === "/api/watchlist": return WATCHLIST;
    case path === "/api/breaches": return BREACHES;
    case path === "/api/typosquat": return [];
    case path === "/api/mentions": return [];
    case path === "/api/detection-rules": return DET_RULES;
    case path === "/api/detection-gaps": return { covered: DET_RULES.flatMap((r) => r.techniques), gaps: ATTACK.filter((t) => !DET_RULES.flatMap((r) => r.techniques).includes(t.id)), ruleCount: DET_RULES.length };
    case path === "/api/rfis": return [];
    case path === "/api/rules": return [];
    case path === "/api/searches": return [];
    case path === "/api/feedback": return {};
    case path === "/api/notes": return [];
    case path === "/api/audit": return [];
    default: return [];
  }
}

/** Resolve an /api/* request from the static demo dataset. */
export function demoFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const url = new URL(input, typeof location !== "undefined" ? location.origin : "http://localhost");
  let body: unknown;
  try { body = init.body ? JSON.parse(init.body as string) : undefined; } catch { body = undefined; }
  const data = route(url.pathname, url.searchParams, (init.method ?? "GET").toUpperCase(), body);
  const res = {
    ok: true, status: 200, headers: new Headers({ "content-type": "application/json" }),
    json: async () => data, text: async () => JSON.stringify(data),
    clone() { return this as unknown as Response; },
  };
  return Promise.resolve(res as unknown as Response);
}
