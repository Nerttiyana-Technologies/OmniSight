import { spawn } from "node:child_process";
import type { RawScanFinding, ScanSeverity } from "@omnisight/shared";
import type { ScanAdapter, ScanContext, ScanInput } from "./types.js";

/** Resolve whether a binary is on PATH (used to gate the external adapters). */
function binaryAvailable(bin: string): Promise<boolean> {
  return new Promise((resolve) => {
    const probe = spawn(process.platform === "win32" ? "where" : "which", [bin]);
    probe.on("error", () => resolve(false));
    probe.on("close", (code) => resolve(code === 0));
  });
}

function normSeverity(s: string | undefined): ScanSeverity {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "critical";
    case "high": return "high";
    case "medium": return "medium";
    case "low": return "low";
    default: return "info";
  }
}

interface NucleiJsonl {
  "template-id"?: string;
  info?: { name?: string; severity?: string; description?: string; reference?: string[]; classification?: { "cve-id"?: string[] } };
  host?: string;
  "matched-at"?: string;
  type?: string;
}

function mapNucleiLine(line: string, target: string): RawScanFinding | null {
  let o: NucleiJsonl;
  try { o = JSON.parse(line) as NucleiJsonl; } catch { return null; }
  if (!o.info) return null;
  const cve = o.info.classification?.["cve-id"]?.[0]?.toUpperCase() ?? null;
  return {
    target, host: o.host ?? null, port: null, service: o.type ?? null,
    product: null, version: null, cpe: null, cve, severity: normSeverity(o.info.severity),
    title: o.info.name ?? o["template-id"] ?? "nuclei finding",
    description: (o.info.description ?? "").slice(0, 600) || `nuclei template ${o["template-id"] ?? ""} matched at ${o["matched-at"] ?? o.host ?? target}.`,
    evidence: o["matched-at"] ?? null,
  };
}

/**
 * Optional nuclei adapter. Only runs when SCANNER_NUCLEI=true AND the `nuclei`
 * binary is on PATH; otherwise it reports unavailable and is skipped. Findings
 * (including CVE classifications) flow into the same correlation engine.
 */
export const nucleiAdapter: ScanAdapter = {
  id: "nuclei",
  name: "ProjectDiscovery nuclei",
  available: async () => process.env.SCANNER_NUCLEI === "true" && (await binaryAvailable("nuclei")),
  scan(input: ScanInput, ctx?: ScanContext): Promise<RawScanFinding[]> {
    const url = input.kind === "url" ? input.target : `http://${input.target}`;
    return new Promise((resolve) => {
      const findings: RawScanFinding[] = [];
      let buf = "";
      const child = spawn("nuclei", ["-u", url, "-jsonl", "-silent", "-timeout", String(Math.ceil((ctx?.timeoutMs ?? 5000) / 1000))]);
      child.stdout.on("data", (d: Buffer) => {
        buf += d.toString();
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const l of lines) { const f = mapNucleiLine(l, input.target); if (f) findings.push(f); }
      });
      child.on("error", () => resolve(findings));
      child.on("close", () => {
        const f = mapNucleiLine(buf, input.target);
        if (f) findings.push(f);
        resolve(findings);
      });
    });
  },
};
