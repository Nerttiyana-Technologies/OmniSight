// On-demand IOC enrichment / pivoting. Shodan InternetDB is keyless; GreyNoise
// and AbuseIPDB are used only when their keys are provided.

export interface IocEnrichment {
  value: string;
  type: string;
  shodan: { ports: number[]; hostnames: string[]; tags: string[]; vulns: string[]; cpes: string[] } | null;
  greynoise: { noise: boolean; riot: boolean; classification: string; name: string | null; lastSeen: string | null } | null;
  abuseipdb: { score: number; reports: number; countryCode: string | null; isp: string | null } | null;
  errors: string[];
}

export function parseShodan(p: unknown): IocEnrichment["shodan"] {
  const d = (p ?? {}) as Record<string, unknown>;
  return {
    ports: (d.ports as number[]) ?? [],
    hostnames: (d.hostnames as string[]) ?? [],
    tags: (d.tags as string[]) ?? [],
    vulns: (d.vulns as string[]) ?? [],
    cpes: (d.cpes as string[]) ?? [],
  };
}

export function parseGreynoise(p: unknown): IocEnrichment["greynoise"] {
  const d = (p ?? {}) as Record<string, unknown>;
  return {
    noise: Boolean(d.noise),
    riot: Boolean(d.riot),
    classification: (d.classification as string) ?? "unknown",
    name: (d.name as string) ?? null,
    lastSeen: (d.last_seen as string) ?? null,
  };
}

export function parseAbuse(p: unknown): IocEnrichment["abuseipdb"] {
  const d = ((p as { data?: unknown })?.data ?? p ?? {}) as Record<string, unknown>;
  return {
    score: (d.abuseConfidenceScore as number) ?? 0,
    reports: (d.totalReports as number) ?? 0,
    countryCode: (d.countryCode as string) ?? null,
    isp: (d.isp as string) ?? null,
  };
}

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export async function enrichIoc(
  value: string,
  type: string,
  opts: { greynoiseKey?: string; abuseKey?: string } = {},
): Promise<IocEnrichment> {
  const out: IocEnrichment = { value, type, shodan: null, greynoise: null, abuseipdb: null, errors: [] };
  const ip = value.split(":")[0] ?? value;
  if (type !== "ip" && !IPV4.test(ip)) {
    out.errors.push("Live enrichment currently supports IP indicators.");
    return out;
  }
  const ua = { "user-agent": "OmniSight/0.1" };

  try {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { headers: ua });
    if (r.ok) out.shodan = parseShodan(await r.json());
    else if (r.status !== 404) out.errors.push(`shodan: HTTP ${r.status}`);
  } catch (e) {
    out.errors.push(`shodan: ${(e as Error).message}`);
  }

  if (opts.greynoiseKey) {
    try {
      const r = await fetch(`https://api.greynoise.io/v3/community/${ip}`, { headers: { ...ua, key: opts.greynoiseKey } });
      if (r.ok) out.greynoise = parseGreynoise(await r.json());
      else if (r.status !== 404) out.errors.push(`greynoise: HTTP ${r.status}`);
    } catch (e) {
      out.errors.push(`greynoise: ${(e as Error).message}`);
    }
  }

  if (opts.abuseKey) {
    try {
      const r = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`, {
        headers: { ...ua, Key: opts.abuseKey, Accept: "application/json" },
      });
      if (r.ok) out.abuseipdb = parseAbuse(await r.json());
      else out.errors.push(`abuseipdb: HTTP ${r.status}`);
    } catch (e) {
      out.errors.push(`abuseipdb: ${(e as Error).message}`);
    }
  }

  return out;
}
