import { AdvisorySchema, type Advisory, type Source } from "@omnisight/shared";
import type { AdvisoryConnector, FetchOptions } from "./types.js";

// Dependency-free RSS 2.0 / Atom parser. Good enough for mainstream security
// feeds (SecurityWeek, The Hacker News, Dark Reading).

function decodeEntities(s: string): string {
  return s
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/&lt;/g, "<").replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&");
}

function stripHtml(s: string): string {
  return decodeEntities(s).replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
}

function tag(block: string, name: string): string | null {
  const m = block.match(new RegExp(`<${name}\\b[^>]*>([\\s\\S]*?)</${name}>`, "i"));
  return m ? decodeEntities(m[1]!).trim() : null;
}

function atomLink(block: string): string | null {
  const m = block.match(/<link\b[^>]*href=["']([^"']+)["'][^>]*\/?>/i);
  return m ? m[1]! : null;
}

export function parseRss(xml: string, source: string): Advisory[] {
  const fetchedAt = new Date().toISOString();
  const blocks = xml.match(/<(item|entry)\b[\s\S]*?<\/\1>/gi) ?? [];
  const out: Advisory[] = [];
  for (const block of blocks) {
    const title = tag(block, "title");
    if (!title) continue;
    const link = tag(block, "link") || atomLink(block) || "";
    const rawSummary = tag(block, "description") || tag(block, "summary") || tag(block, "content") || "";
    const published = tag(block, "pubDate") || tag(block, "published") || tag(block, "updated");
    const cats = [...block.matchAll(/<category\b[^>]*>([\s\S]*?)<\/category>/gi)].map((m) => decodeEntities(m[1]!).trim());
    const id = tag(block, "guid") || link || title;
    out.push(
      AdvisorySchema.parse({
        id,
        source,
        title: stripHtml(title),
        summary: stripHtml(rawSummary).slice(0, 400),
        url: link,
        category: cats[0] ?? null,
        published: published ? new Date(published).toISOString() : null,
        tags: cats.slice(0, 6),
        fetchedAt,
      }),
    );
  }
  return out;
}

export function makeRssConnector(source: Source): AdvisoryConnector {
  return {
    id: source.id,
    name: source.name,
    schedule: source.schedule,
    async fetchAdvisories(opts: FetchOptions = {}): Promise<Advisory[]> {
      if (opts.fixture) return parseRss(opts.fixture as string, source.id);
      if (!source.url) throw new Error(`RSS source ${source.id} has no url`);
      const res = await fetch(source.url, { headers: { "user-agent": "OmniSight/0.1", accept: "application/rss+xml, application/xml, text/xml" } });
      if (!res.ok) throw new Error(`${source.id} RSS fetch failed: HTTP ${res.status}`);
      return parseRss(await res.text(), source.id);
    },
  };
}
