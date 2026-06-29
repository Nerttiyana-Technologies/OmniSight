import type { RawScanFinding, ScanTargetKind } from "@omnisight/shared";

export interface ScanInput {
  target: string; // host / ip / url
  kind: ScanTargetKind;
}

export interface ScanContext {
  /** Per-connection timeout in ms (default 1500). */
  timeoutMs?: number;
  /** Override the default port set for host scans. */
  ports?: number[];
  /** Max simultaneous probes (default 40). */
  concurrency?: number;
}

/**
 * A scan adapter turns a target into raw findings. The built-in adapter is
 * keyless and always available; external engines (nuclei/OpenVAS) implement the
 * same contract and only run when present + explicitly enabled.
 */
export interface ScanAdapter {
  id: string;
  name: string;
  /** True when this adapter can run in the current environment. */
  available(): Promise<boolean> | boolean;
  scan(input: ScanInput, ctx?: ScanContext): Promise<RawScanFinding[]>;
}
