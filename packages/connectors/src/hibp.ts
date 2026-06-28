import { normalizeHibpBreaches, type Breach } from "@omnisight/shared";
import type { FetchOptions } from "./types.js";

const HIBP_BASE = "https://haveibeenpwned.com/api/v3";

/**
 * Fetch the FULL breaches collection. `GET /api/v3/breaches` is unauthenticated
 * (the public dataset behind the website) — it just needs a User-Agent — so this
 * works WITHOUT an API key. We filter by domain locally rather than calling the
 * paid domain-search endpoint. An optional key only raises rate limits.
 */
export async function fetchAllBreaches(opts: FetchOptions = {}): Promise<unknown[]> {
  if (opts.fixture) return Array.isArray(opts.fixture) ? opts.fixture : [];
  const headers: Record<string, string> = { "user-agent": "OmniSight/0.1" };
  const key = opts.credentials?.hibpApiKey;
  if (key) headers["hibp-api-key"] = key;
  const res = await fetch(`${HIBP_BASE}/breaches`, { headers });
  if (!res.ok) throw new Error(`HIBP fetch failed: HTTP ${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : [];
}

/** Breaches at a single domain (filtered locally from the free full list). */
export async function fetchBreachesForDomain(domain: string, opts: FetchOptions = {}): Promise<Breach[]> {
  return fetchBreaches([domain], opts);
}

/** Fetch breaches affecting the given domains, de-duplicated by breach id. */
export async function fetchBreaches(domains: string[], opts: FetchOptions = {}): Promise<Breach[]> {
  const wanted = new Set(domains.map((d) => d.trim().toLowerCase()).filter(Boolean));
  if (wanted.size === 0) return [];
  const all = await fetchAllBreaches(opts);
  // Keep only breaches whose Domain matches one of the monitored domains.
  const matched = (all as { Domain?: string }[]).filter((b) => b.Domain && wanted.has(b.Domain.toLowerCase()));
  return normalizeHibpBreaches(matched, "")
    .sort((a, b) => (b.breachDate ?? "").localeCompare(a.breachDate ?? ""));
}
