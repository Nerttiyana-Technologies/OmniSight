// Parse a CycloneDX or SPDX SBOM and check components against OSV.

export interface SbomComponent {
  name: string;
  version: string;
  ecosystem: string;
  purl: string;
}
export interface SbomResult extends SbomComponent {
  vulns: string[];
}

const PURL_ECOSYSTEM: Record<string, string> = {
  npm: "npm", pypi: "PyPI", maven: "Maven", golang: "Go", go: "Go",
  cargo: "crates.io", gem: "RubyGems", nuget: "NuGet", composer: "Packagist",
  deb: "Debian", apk: "Alpine", hex: "Hex", pub: "Pub", conan: "ConanCenter",
};

export function parsePurl(purl: string): SbomComponent | null {
  const m = /^pkg:([^/]+)\/(.+?)(?:@([^?#]+))?(?:[?#].*)?$/.exec(purl.trim());
  if (!m) return null;
  const type = m[1]!.toLowerCase();
  const nameWithNs = decodeURIComponent(m[2]!);
  const version = m[3] ? decodeURIComponent(m[3]) : "";
  const ecosystem = PURL_ECOSYSTEM[type] ?? type;
  // Maven OSV name is "group:artifact"; purl encodes it as "group/artifact".
  const name = type === "maven" ? nameWithNs.replace("/", ":") : nameWithNs;
  return { name, version, ecosystem, purl };
}

interface CycloneComponent { purl?: string }
interface SpdxRef { referenceType?: string; referenceLocator?: string }
interface SpdxPackage { externalRefs?: SpdxRef[] }

export function parseSbom(obj: unknown): SbomComponent[] {
  const o = (obj ?? {}) as { components?: CycloneComponent[]; packages?: SpdxPackage[] };
  const comps: SbomComponent[] = [];
  if (Array.isArray(o.components)) {
    for (const c of o.components) {
      if (c.purl) { const p = parsePurl(c.purl); if (p) comps.push(p); }
    }
  } else if (Array.isArray(o.packages)) {
    for (const pkg of o.packages) {
      const ref = (pkg.externalRefs ?? []).find(
        (r) => r.referenceType === "purl" || r.referenceLocator?.startsWith("pkg:"),
      );
      if (ref?.referenceLocator) { const p = parsePurl(ref.referenceLocator); if (p) comps.push(p); }
    }
  }
  const seen = new Set<string>();
  return comps.filter((c) => (seen.has(c.purl) ? false : (seen.add(c.purl), true)));
}

interface OsvBatchResponse { results?: { vulns?: { id: string }[] }[] }

/** Query OSV's batch API for components that have a version. Keyless. */
export async function queryOsvBatch(components: SbomComponent[]): Promise<SbomResult[]> {
  const valid = components.filter((c) => c.version);
  const out: SbomResult[] = [];
  for (let i = 0; i < valid.length; i += 500) {
    const chunk = valid.slice(i, i + 500);
    const res = await fetch("https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": "OmniSight/0.1" },
      body: JSON.stringify({ queries: chunk.map((c) => ({ package: { name: c.name, ecosystem: c.ecosystem }, version: c.version })) }),
    });
    if (!res.ok) throw new Error(`OSV batch failed: HTTP ${res.status}`);
    const data = (await res.json()) as OsvBatchResponse;
    const results = data.results ?? [];
    chunk.forEach((c, idx) => {
      out.push({ ...c, vulns: (results[idx]?.vulns ?? []).map((v) => v.id) });
    });
  }
  return out;
}
