import {
  riskBand,
  type RawScanFinding, type Scan, type Vulnerability, type NewAsset, type ScanTargetKind,
} from "@omnisight/shared";
import { runScan } from "./index.js";
import type { ScanContext } from "./types.js";

/**
 * The slice of the repository the scan runner needs. The full @omnisight/db
 * Repository satisfies this structurally, so both the API (run-now) and the
 * worker (scheduled) share one orchestration path without db↔scanner coupling.
 */
export interface ScanStore {
  createScan(s: Pick<Scan, "targetId" | "target" | "adapter" | "status">): Promise<Scan>;
  updateScan(id: string, patch: Partial<Omit<Scan, "id" | "createdAt">>): Promise<void>;
  insertFindings(scanId: string, findings: RawScanFinding[]): Promise<number>;
  setTargetScanned(id: string): Promise<void>;
  upsertAssets(items: NewAsset[]): Promise<number>;
  page(opts: { vendor?: string; sort?: string; dir?: "asc" | "desc"; limit?: number }): Promise<{ items: Vulnerability[] }>;
  signalChange(payload?: string): Promise<void>;
}

export interface ScanRequest {
  targetId: string | null;
  target: string;
  kind: ScanTargetKind;
  adapter?: string;
}

/**
 * Run a scan and persist everything: the scan row, raw findings, CVE-correlated
 * findings (discovered product → tracked vulnerabilities), and a discovered
 * asset. Always resolves with the final scan row (status done|error).
 */
export async function runAndStoreScan(store: ScanStore, req: ScanRequest, ctx?: ScanContext): Promise<Scan> {
  const adapter = req.adapter ?? "builtin";
  const scan = await store.createScan({ targetId: req.targetId, target: req.target, adapter, status: "running" });
  try {
    const raw = await runScan({ target: req.target, kind: req.kind }, adapter, ctx);

    // CVE correlation: map each discovered product to tracked vulnerabilities.
    const extra: RawScanFinding[] = [];
    const seen = new Set<string>();
    for (const f of raw) {
      if (!f.product) continue;
      const key = `${f.product}@${f.version ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const { items } = await store.page({ vendor: f.product, sort: "risk", dir: "desc", limit: 5 });
      for (const v of items) {
        const cve = v.cveId ?? v.id;
        extra.push({
          target: f.target, host: f.host, port: f.port, service: f.service,
          product: f.product, version: f.version, cpe: f.cpe, cve,
          severity: riskBand(v.riskScore),
          title: `Known CVE for ${f.product}${f.version ? " " + f.version : ""}: ${cve}`,
          description: `${f.product} detected on ${f.host ?? req.target}. Tracked vulnerability ${cve} (risk ${v.riskScore})` +
            ` affects this product — verify the running version is impacted. ${v.title}`,
          evidence: f.evidence,
        });
      }
    }

    const findings = [...raw, ...extra];
    await store.insertFindings(scan.id, findings);

    // Asset discovery: register the scanned host/service so future intel matches it.
    const host = raw.find((f) => f.host)?.host ?? req.target;
    const products = [...new Set(raw.map((f) => f.product).filter(Boolean))] as string[];
    await store.upsertAssets([{
      name: host,
      kind: req.kind === "url" ? "service" : "host",
      vendor: null,
      product: products[0] ?? null,
      version: raw.find((f) => f.version)?.version ?? null,
      cpe: raw.find((f) => f.cpe)?.cpe ?? null,
      ip: null,
      hostname: host,
      owner: null,
      criticality: "medium",
      tags: ["scanned"],
      origin: "scan",
    }]);

    const openPorts = raw.filter((f) => f.title.startsWith("Open port")).length;
    const cveCount = new Set(findings.filter((f) => f.cve).map((f) => f.cve)).size;
    await store.updateScan(scan.id, {
      status: "done", finishedAt: new Date().toISOString(),
      findingCount: findings.length, openPorts, cveCount,
    });
    if (req.targetId) await store.setTargetScanned(req.targetId);
    await store.signalChange("scan");
    return { ...scan, status: "done", findingCount: findings.length, openPorts, cveCount };
  } catch (e) {
    const error = (e as Error).message;
    await store.updateScan(scan.id, { status: "error", finishedAt: new Date().toISOString(), error });
    await store.signalChange("scan");
    return { ...scan, status: "error", error };
  }
}
