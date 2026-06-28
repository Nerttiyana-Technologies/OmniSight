// Configurable LLM client — works with any OpenAI-compatible endpoint,
// including Ollama (LLM_BASE_URL=http://localhost:11434/v1, no key needed).

// Read config lazily (at call time), NOT at module load — the API loads its
// .env file during startup, which happens after this module is first imported.
function llmConfig() {
  return {
    base: process.env.LLM_BASE_URL?.trim().replace(/\/$/, "") || "",
    key: process.env.LLM_API_KEY?.trim() || "",
    model: process.env.LLM_MODEL?.trim() || "llama3.1",
  };
}

export function llmConfigured(): boolean {
  return Boolean(llmConfig().base);
}

interface ChatChoice { message?: { content?: string } }
interface ChatResponse { choices?: ChatChoice[] }

export async function llmChat(system: string, user: string, opts: { json?: boolean } = {}): Promise<string> {
  const { base, key, model } = llmConfig();
  if (!base) throw new Error("LLM not configured (set LLM_BASE_URL)");
  const res = await fetch(`${base}/chat/completions`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(key ? { authorization: `Bearer ${key}` } : {}),
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
      temperature: 0.2,
      ...(opts.json ? { response_format: { type: "json_object" } } : {}),
    }),
  });
  if (!res.ok) throw new Error(`LLM HTTP ${res.status}`);
  const data = (await res.json()) as ChatResponse;
  return data.choices?.[0]?.message?.content ?? "";
}

export interface VulnAiFilters {
  minRisk?: number;
  q?: string;
  vendor?: string;
  exploited?: boolean;
  ransomware?: boolean;
  sort?: string;
  dir?: "asc" | "desc";
}

/** Defensively coerce LLM JSON into our vulnerability filter shape. */
export function coerceVulnFilters(raw: unknown): VulnAiFilters {
  const o = (raw ?? {}) as Record<string, unknown>;
  const out: VulnAiFilters = {};
  if (typeof o.minRisk === "number") out.minRisk = Math.max(0, Math.min(100, o.minRisk));
  if (typeof o.q === "string" && o.q.trim()) out.q = o.q.trim();
  if (typeof o.vendor === "string" && o.vendor.trim()) out.vendor = o.vendor.trim();
  if (typeof o.exploited === "boolean") out.exploited = o.exploited;
  if (typeof o.ransomware === "boolean") out.ransomware = o.ransomware;
  if (["risk", "cvss", "epss", "reported", "cve", "vendor"].includes(String(o.sort))) out.sort = String(o.sort);
  if (o.dir === "asc" || o.dir === "desc") out.dir = o.dir;
  return out;
}
