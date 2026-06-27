import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { riskBand } from "@omnisight/shared";
import { cisaKevConnector } from "./cisa-kev.js";

/**
 * Verifies the ingest pipeline end-to-end without a database.
 *   pnpm connector:dry-run            -> live fetch from CISA
 *   pnpm connector:dry-run --fixture  -> offline, uses the bundled sample
 */
const useFixture = process.argv.includes("--fixture");
const here = dirname(fileURLToPath(import.meta.url));

const fixture = useFixture
  ? JSON.parse(readFileSync(join(here, "../fixtures/cisa-kev.sample.json"), "utf8"))
  : undefined;

console.log(`[dry-run] source=${cisaKevConnector.id} mode=${useFixture ? "fixture" : "live"}`);

const vulns = await cisaKevConnector.fetchVulnerabilities({ fixture });
vulns.sort((a, b) => b.riskScore - a.riskScore);

console.log(`[dry-run] normalized ${vulns.length} vulnerabilities\n`);
console.log("  RISK  BAND      CVE              VENDOR / PRODUCT            RANSOMWARE");
console.log("  ----  --------  ---------------  --------------------------  ----------");
for (const v of vulns.slice(0, 10)) {
  const band = riskBand(v.riskScore).padEnd(8);
  const cve = (v.cveId ?? v.id).padEnd(15);
  const vp = `${v.vendor ?? "?"} / ${v.product ?? "?"}`.slice(0, 26).padEnd(26);
  console.log(`  ${String(v.riskScore).padStart(4)}  ${band}  ${cve}  ${vp}  ${v.ransomwareUse ? "yes" : "no"}`);
}
console.log("\n[dry-run] OK");
