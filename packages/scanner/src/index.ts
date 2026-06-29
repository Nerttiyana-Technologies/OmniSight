import type { RawScanFinding } from "@omnisight/shared";
import type { ScanAdapter, ScanContext, ScanInput } from "./types.js";
import { builtinScanner } from "./builtin.js";
import { nucleiAdapter } from "./nuclei.js";

export * from "./types.js";
export { builtinScanner } from "./builtin.js";
export { nucleiAdapter } from "./nuclei.js";
export { runAndStoreScan, type ScanStore, type ScanRequest } from "./runner.js";

/** All known scan adapters, keyed by id. The built-in is always available. */
export const scanAdapters: Record<string, ScanAdapter> = {
  [builtinScanner.id]: builtinScanner,
  [nucleiAdapter.id]: nucleiAdapter,
};

/** Resolve an adapter by id, falling back to the built-in scanner. */
export function resolveScanAdapter(id?: string): ScanAdapter {
  return (id && scanAdapters[id]) || builtinScanner;
}

/** Adapters that can actually run right now (built-in + any present externals). */
export async function availableAdapters(): Promise<{ id: string; name: string }[]> {
  const out: { id: string; name: string }[] = [];
  for (const a of Object.values(scanAdapters)) {
    try { if (await a.available()) out.push({ id: a.id, name: a.name }); } catch { /* skip */ }
  }
  return out;
}

/**
 * Run a scan with the chosen adapter (or built-in). Always resolves — adapter
 * failures degrade to whatever findings were produced, so a scan never throws
 * the caller out of its bookkeeping.
 */
export async function runScan(input: ScanInput, adapterId?: string, ctx?: ScanContext): Promise<RawScanFinding[]> {
  const adapter = resolveScanAdapter(adapterId);
  try {
    if (!(await adapter.available())) {
      if (adapter.id !== builtinScanner.id) return builtinScanner.scan(input, ctx);
    }
    return await adapter.scan(input, ctx);
  } catch {
    return [];
  }
}
