import net from "node:net";
import type { RawScanFinding, ScanSeverity } from "@omnisight/shared";
import type { ScanAdapter, ScanContext, ScanInput } from "./types.js";

/** Common ports probed on a host scan, mapped to a service label. */
const PORT_SERVICE: Record<number, string> = {
  21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
  110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
  161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 587: "submission",
  993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs",
  3306: "mysql", 3389: "rdp", 5432: "postgresql", 5601: "kibana", 5900: "vnc",
  6379: "redis", 8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch",
  11211: "memcached", 27017: "mongodb",
};

const DEFAULT_PORTS = Object.keys(PORT_SERVICE).map(Number);

/** Exposure severity for an open service (the value of finding it reachable). */
const SERVICE_SEVERITY: Record<string, ScanSeverity> = {
  telnet: "high", smb: "high", rdp: "high", vnc: "high", redis: "high",
  elasticsearch: "high", mongodb: "high", memcached: "high", "netbios-ssn": "high",
  ftp: "medium", snmp: "medium", mysql: "medium", postgresql: "medium",
  mssql: "medium", oracle: "medium", ldap: "medium", rpcbind: "medium", nfs: "medium",
  smtp: "low", pop3: "low", imap: "low", dns: "info", ssh: "info",
  http: "info", https: "info", "http-alt": "info", "https-alt": "info",
};

/** Plain-language note for why a reachable service matters. */
const SERVICE_NOTE: Record<string, string> = {
  telnet: "Telnet transmits credentials in cleartext — replace with SSH.",
  ftp: "FTP is often unencrypted — prefer SFTP/FTPS.",
  smb: "SMB exposed to the network is a common ransomware entry point.",
  rdp: "RDP exposed to the internet is heavily targeted (brute force, BlueKeep-class bugs).",
  vnc: "VNC is frequently unauthenticated or weakly authenticated.",
  redis: "Redis defaults to no authentication — exposure can mean full data/RCE.",
  elasticsearch: "Elasticsearch has no auth by default — exposure can leak all indexed data.",
  mongodb: "MongoDB has historically shipped without auth — a top cause of data leaks.",
  memcached: "Open memcached is abused for large UDP amplification DDoS.",
  snmp: "SNMP with default community strings leaks device configuration.",
};

function timeoutMs(ctx?: ScanContext): number { return ctx?.timeoutMs ?? 1500; }

/**
 * SSRF posture: this scanner intentionally connects to operator-supplied targets
 * (scanning your own hosts is the whole point), it is gated behind an authorized
 * analyst action, and httpGrab uses redirect:"manual" so it can't be bounced to
 * an internal resource. As defense-in-depth we always refuse cloud-metadata /
 * link-local addresses (never a legitimate scan target and the classic SSRF
 * pivot), and can refuse all private ranges when SCANNER_BLOCK_PRIVATE=true.
 */
function isBlockedTarget(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (h === "metadata.google.internal" || h === "169.254.169.254" || /^169\.254\./.test(h) || h === "fd00:ec2::254") return true;
  if (process.env.SCANNER_BLOCK_PRIVATE === "true") {
    if (h === "localhost" || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) ||
        /^172\.(1[6-9]|2\d|3[01])\./.test(h) || h === "::1" || /^fe80:/.test(h) || /^f[cd]/.test(h)) return true;
  }
  return false;
}

/** Resolve a TCP open/closed result for one port. */
function probePort(host: string, port: number, ms: number): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const done = (open: boolean) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(ms);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

/** Run probes with a simple concurrency cap. */
async function probeAll(host: string, ports: number[], ms: number, concurrency: number): Promise<number[]> {
  const open: number[] = [];
  let i = 0;
  async function worker() {
    while (i < ports.length) {
      const port = ports[i++]!;
      if (await probePort(host, port, ms)) open.push(port);
    }
  }
  await Promise.all(Array.from({ length: Math.min(concurrency, ports.length) }, worker));
  return open.sort((a, b) => a - b);
}

const SECURITY_HEADERS: { header: string; title: string }[] = [
  { header: "strict-transport-security", title: "Strict-Transport-Security (HSTS)" },
  { header: "content-security-policy", title: "Content-Security-Policy" },
  { header: "x-content-type-options", title: "X-Content-Type-Options" },
  { header: "x-frame-options", title: "X-Frame-Options" },
];

/** Parse a Server/x-powered-by banner like "nginx/1.18.0" into product + CPE. */
function bannerToProduct(banner: string): { product: string; version: string | null; cpe: string | null } | null {
  const m = /^([A-Za-z][\w.-]*?)(?:\/([0-9][\w.+-]*))?(?:\s|$)/.exec(banner.trim());
  if (!m) return null;
  const product = m[1]!.toLowerCase();
  const version = m[2] ?? null;
  const cpe = `cpe:2.3:a:${product}:${product}:${version ?? "*"}:*:*:*:*:*:*:*`;
  return { product, version, cpe };
}

async function httpGrab(url: string, host: string, port: number, ms: number): Promise<RawScanFinding[]> {
  const out: RawScanFinding[] = [];
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms * 3);
  try {
    const res = await fetch(url, { redirect: "manual", signal: controller.signal, headers: { "user-agent": "OmniSight-Scanner/0.1" } });
    const server = res.headers.get("server") ?? res.headers.get("x-powered-by") ?? "";
    const secure = url.startsWith("https");
    if (server) {
      const prod = bannerToProduct(server);
      out.push({
        target: url, host, port, service: secure ? "https" : "http",
        product: prod?.product ?? null, version: prod?.version ?? null, cpe: prod?.cpe ?? null,
        cve: null, severity: "info",
        title: `Web server banner: ${server}`,
        description: `HTTP ${res.status} on ${url}. Server advertises "${server}".` +
          (prod?.version ? ` Version ${prod.version} disclosed — consider suppressing the banner.` : ""),
        evidence: `Server: ${server}`,
      });
    }
    // Missing security headers (only meaningful on HTTPS for HSTS).
    for (const h of SECURITY_HEADERS) {
      if (h.header === "strict-transport-security" && !secure) continue;
      if (!res.headers.get(h.header)) {
        out.push({
          target: url, host, port, service: secure ? "https" : "http",
          product: null, version: null, cpe: null, cve: null, severity: "low",
          title: `Missing security header: ${h.title}`,
          description: `${url} does not return the ${h.title} header, weakening browser-side protections.`,
          evidence: `${h.header}: <absent>`,
        });
      }
    }
  } catch {
    /* host not serving HTTP on this port, or aborted — skip */
  } finally {
    clearTimeout(timer);
  }
  return out;
}

function hostFromTarget(input: ScanInput): { host: string; httpUrls: { url: string; port: number }[] } {
  if (input.kind === "url") {
    try {
      const u = new URL(input.target);
      const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
      return { host: u.hostname, httpUrls: [{ url: input.target, port }] };
    } catch {
      return { host: input.target, httpUrls: [] };
    }
  }
  return { host: input.target.replace(/^https?:\/\//, "").replace(/\/.*$/, ""), httpUrls: [] };
}

/**
 * Built-in keyless scanner: TCP port sweep + HTTP banner/header inspection.
 * No external tools required — works out of the box for the zero-dependency demo.
 */
export const builtinScanner: ScanAdapter = {
  id: "builtin",
  name: "Built-in (port + HTTP)",
  available: () => true,
  async scan(input: ScanInput, ctx?: ScanContext): Promise<RawScanFinding[]> {
    const ms = timeoutMs(ctx);
    const concurrency = ctx?.concurrency ?? 40;
    const findings: RawScanFinding[] = [];
    const { host, httpUrls } = hostFromTarget(input);

    if (isBlockedTarget(host)) {
      return [{
        target: input.target, host, port: null, service: null, product: null, version: null,
        cpe: null, cve: null, severity: "info", title: "Scan target blocked by SSRF guard",
        description: `${host} is a cloud-metadata/link-local address (or a private address while SCANNER_BLOCK_PRIVATE=true) and was not scanned.`,
        evidence: null,
      }];
    }

    if (input.kind === "url") {
      for (const u of httpUrls) findings.push(...(await httpGrab(u.url, host, u.port, ms)));
      return findings;
    }

    const ports = ctx?.ports ?? DEFAULT_PORTS;
    const open = await probeAll(host, ports, ms, concurrency);
    for (const port of open) {
      const service = PORT_SERVICE[port] ?? "unknown";
      const severity = SERVICE_SEVERITY[service] ?? "info";
      const note = SERVICE_NOTE[service];
      findings.push({
        target: input.target, host, port, service,
        product: null, version: null, cpe: null, cve: null, severity,
        title: `Open port ${port}/${service}`,
        description: `Port ${port} (${service}) is reachable on ${host}.` + (note ? ` ${note}` : ""),
        evidence: `tcp/${port} open`,
      });
    }
    // HTTP inspection on any open web port.
    for (const port of open) {
      const service = PORT_SERVICE[port];
      if (service === "http" || service === "http-alt") findings.push(...(await httpGrab(`http://${host}:${port === 80 ? "" : port}`.replace(/:$/, ""), host, port, ms)));
      else if (service === "https" || service === "https-alt") findings.push(...(await httpGrab(`https://${host}${port === 443 ? "" : ":" + port}`, host, port, ms)));
    }
    return findings;
  },
};
