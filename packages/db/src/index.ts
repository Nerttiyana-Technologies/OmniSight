import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { EventEmitter } from "node:events";
import pg from "pg";
import { computeRiskScore, type Source, type Vulnerability, type Indicator } from "@omnisight/shared";

export interface ListOptions {
  limit?: number;
  offset?: number;
  minRisk?: number;
  q?: string;
  vendor?: string;
  source?: string;
  exploited?: boolean;
  ransomware?: boolean;
  terms?: string[]; // "My Stack" — match vendor/product/title against any term
  sort?: string; // risk | cve | threat | vendor | cvss | epss | source
  dir?: "asc" | "desc";
}

export interface Page {
  items: Vulnerability[];
  total: number;
}

export interface Stats {
  total: number;
  knownExploited: number;
  ransomware: number;
  critical: number;
  high: number;
  sources: number;
  indicators: number;
  inStack: number;
}

export interface IndicatorListOptions {
  limit?: number;
  offset?: number;
  type?: string;
  malware?: string;
  q?: string;
  source?: string;
  sort?: string; // confidence | lastseen | type | malware | value | source
  dir?: "asc" | "desc";
}

export interface IndicatorPage {
  items: Indicator[];
  total: number;
}

/** Patch applied to every row matching a CVE id (used by enrichers). */
export interface EnrichPatch {
  cveId: string;
  cvss?: number | null;
  epss?: number | null;
}

/** Storage contract. Two implementations: Postgres (prod) and in-memory (demo/tests). */
export interface Repository {
  init(): Promise<void>;
  upsertVulnerabilities(items: Vulnerability[]): Promise<number>;
  listVulnerabilities(opts?: ListOptions): Promise<Vulnerability[]>;
  /** Filtered + paginated query returning items and the total match count. */
  page(opts?: ListOptions): Promise<Page>;
  upsertIndicators(items: Indicator[]): Promise<number>;
  pageIndicators(opts?: IndicatorListOptions): Promise<IndicatorPage>;
  listWatchlist(): Promise<string[]>;
  addWatchTerm(term: string): Promise<void>;
  removeWatchTerm(term: string): Promise<void>;
  upsertSource(source: Source): Promise<void>;
  listSources(): Promise<Source[]>;
  stats(): Promise<Stats>;
  /** Distinct CVE ids, optionally only those missing a given enrichment field. */
  distinctCveIds(missing?: "cvss" | "epss", limit?: number): Promise<string[]>;
  /** Apply enrichment to all rows of a CVE and recompute their risk score. */
  enrich(patches: EnrichPatch[]): Promise<number>;
  /** Emit a change signal (Postgres NOTIFY / in-memory event). */
  signalChange(payload?: string): Promise<void>;
  /** Subscribe to change signals (Postgres LISTEN / in-memory event). */
  subscribeChanges(cb: (payload: string) => void): Promise<void>;
}

/** Picks Postgres when DATABASE_URL is set, otherwise an in-memory store. */
export function createRepository(databaseUrl = process.env.DATABASE_URL): Repository {
  return databaseUrl
    ? new PostgresRepository(databaseUrl)
    : new InMemoryRepository();
}

// ---------------------------------------------------------------------------

/** True if a vulnerability matches any "My Stack" term (vendor/product/title). */
export function matchesTerms(v: Vulnerability, terms: string[]): boolean {
  if (terms.length === 0) return false;
  const hay = `${v.vendor ?? ""} ${v.product ?? ""} ${v.title}`.toLowerCase();
  return terms.some((t) => hay.includes(t.toLowerCase()));
}

export class InMemoryRepository implements Repository {
  private vulns = new Map<string, Vulnerability>();
  private indicators = new Map<string, Indicator>();
  private sources = new Map<string, Source>();
  private watch = new Set<string>();
  private bus = new EventEmitter();

  async init(): Promise<void> {}

  async listWatchlist(): Promise<string[]> {
    return [...this.watch];
  }
  async addWatchTerm(term: string): Promise<void> {
    const t = term.trim().toLowerCase();
    if (t) this.watch.add(t);
  }
  async removeWatchTerm(term: string): Promise<void> {
    this.watch.delete(term.trim().toLowerCase());
  }

  async upsertIndicators(items: Indicator[]): Promise<number> {
    for (const i of items) this.indicators.set(`${i.source}:${i.id}`, i);
    return items.length;
  }

  async pageIndicators(opts: IndicatorListOptions = {}): Promise<IndicatorPage> {
    let rows = [...this.indicators.values()];
    if (opts.type) rows = rows.filter((i) => i.type === opts.type);
    if (opts.source) rows = rows.filter((i) => i.source === opts.source);
    if (opts.malware) {
      const m = opts.malware.toLowerCase();
      rows = rows.filter((i) => (i.malware ?? "").toLowerCase().includes(m));
    }
    if (opts.q) {
      const q = opts.q.toLowerCase();
      rows = rows.filter(
        (i) =>
          i.value.toLowerCase().includes(q) ||
          (i.malware ?? "").toLowerCase().includes(q) ||
          (i.threatType ?? "").toLowerCase().includes(q),
      );
    }
    const dir = opts.dir === "asc" ? 1 : -1;
    const val = (i: Indicator): string | number | null => {
      switch (opts.sort) {
        case "confidence": return i.confidence;
        case "type": return i.type;
        case "malware": return i.malware ?? "";
        case "value": return i.value;
        case "source": return i.source;
        default: return i.lastSeen ?? "";
      }
    };
    rows.sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1;
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 50;
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }

  async signalChange(payload = ""): Promise<void> {
    this.bus.emit("change", payload);
  }

  async subscribeChanges(cb: (payload: string) => void): Promise<void> {
    this.bus.setMaxListeners(0);
    this.bus.on("change", cb);
  }

  async distinctCveIds(missing?: "cvss" | "epss", limit = 1000): Promise<string[]> {
    const ids = new Set<string>();
    for (const v of this.vulns.values()) {
      if (!v.cveId) continue;
      if (missing === "cvss" && v.cvss != null) continue;
      if (missing === "epss" && v.epss != null) continue;
      ids.add(v.cveId);
      if (ids.size >= limit) break;
    }
    return [...ids];
  }

  async enrich(patches: EnrichPatch[]): Promise<number> {
    let n = 0;
    const byCve = new Map(patches.map((p) => [p.cveId, p]));
    for (const v of this.vulns.values()) {
      if (!v.cveId) continue;
      const p = byCve.get(v.cveId);
      if (!p) continue;
      if (p.cvss !== undefined) v.cvss = p.cvss;
      if (p.epss !== undefined) v.epss = p.epss;
      v.riskScore = computeRiskScore(v);
      n++;
    }
    return n;
  }

  async upsertVulnerabilities(items: Vulnerability[]): Promise<number> {
    for (const v of items) this.vulns.set(`${v.source}:${v.id}`, v);
    return items.length;
  }

  private filtered(opts: ListOptions): Vulnerability[] {
    let rows = [...this.vulns.values()];
    if (opts.minRisk != null) rows = rows.filter((v) => v.riskScore >= opts.minRisk!);
    if (opts.source) rows = rows.filter((v) => v.source === opts.source);
    if (opts.exploited) rows = rows.filter((v) => v.knownExploited);
    if (opts.ransomware) rows = rows.filter((v) => v.ransomwareUse);
    if (opts.terms && opts.terms.length) rows = rows.filter((v) => matchesTerms(v, opts.terms!));
    if (opts.vendor) {
      const vq = opts.vendor.toLowerCase();
      rows = rows.filter(
        (v) => (v.vendor ?? "").toLowerCase().includes(vq) || (v.product ?? "").toLowerCase().includes(vq),
      );
    }
    if (opts.q) {
      const q = opts.q.toLowerCase();
      rows = rows.filter(
        (v) =>
          v.title.toLowerCase().includes(q) ||
          v.description.toLowerCase().includes(q) ||
          (v.cveId ?? "").toLowerCase().includes(q) ||
          (v.vendor ?? "").toLowerCase().includes(q),
      );
    }
    return rows;
  }

  private sorted(rows: Vulnerability[], opts: ListOptions): Vulnerability[] {
    const dir = opts.dir === "asc" ? 1 : -1;
    const val = (v: Vulnerability): string | number | null => {
      switch (opts.sort) {
        case "cve": return v.cveId ?? "";
        case "threat": return v.title;
        case "vendor": return v.vendor ?? "";
        case "cvss": return v.cvss;
        case "epss": return v.epss;
        case "reported": return v.dateAdded ?? "";
        case "source": return v.source;
        default: return v.riskScore;
      }
    };
    return [...rows].sort((a, b) => {
      const av = val(a);
      const bv = val(b);
      if (av == null && bv == null) return 0;
      if (av == null) return 1; // nulls last regardless of direction
      if (bv == null) return -1;
      if (typeof av === "number" && typeof bv === "number") return (av - bv) * dir;
      return String(av).localeCompare(String(bv)) * dir;
    });
  }

  async listVulnerabilities(opts: ListOptions = {}): Promise<Vulnerability[]> {
    return this.sorted(this.filtered(opts), opts).slice(0, opts.limit ?? 100);
  }

  async page(opts: ListOptions = {}): Promise<Page> {
    const rows = this.sorted(this.filtered(opts), opts);
    const offset = opts.offset ?? 0;
    const limit = opts.limit ?? 50;
    return { items: rows.slice(offset, offset + limit), total: rows.length };
  }

  async upsertSource(source: Source): Promise<void> {
    this.sources.set(source.id, source);
  }

  async listSources(): Promise<Source[]> {
    return [...this.sources.values()];
  }

  async stats(): Promise<Stats> {
    const rows = [...this.vulns.values()];
    const terms = [...this.watch];
    return {
      total: rows.length,
      knownExploited: rows.filter((v) => v.knownExploited).length,
      ransomware: rows.filter((v) => v.ransomwareUse).length,
      critical: rows.filter((v) => v.riskScore >= 75).length,
      high: rows.filter((v) => v.riskScore >= 50 && v.riskScore < 75).length,
      sources: this.sources.size,
      indicators: this.indicators.size,
      inStack: terms.length ? rows.filter((v) => matchesTerms(v, terms)).length : 0,
    };
  }
}

// ---------------------------------------------------------------------------

export class PostgresRepository implements Repository {
  private pool: pg.Pool;
  private connectionString: string;
  private static CHANNEL = "omnisight_ingest";

  constructor(connectionString: string) {
    this.connectionString = connectionString;
    this.pool = new pg.Pool({ connectionString });
  }

  async signalChange(payload = ""): Promise<void> {
    await this.pool.query("SELECT pg_notify($1, $2)", [PostgresRepository.CHANNEL, payload]);
  }

  async subscribeChanges(cb: (payload: string) => void): Promise<void> {
    // Dedicated long-lived client (LISTEN can't share a pooled connection).
    const client = new pg.Client({ connectionString: this.connectionString });
    await client.connect();
    client.on("notification", (msg) => cb(msg.payload ?? ""));
    client.on("error", (err) => console.error("[db] listen error:", err.message));
    await client.query(`LISTEN ${PostgresRepository.CHANNEL}`);
  }

  async distinctCveIds(missing?: "cvss" | "epss", limit = 1000): Promise<string[]> {
    const cond =
      missing === "cvss" ? "AND cvss IS NULL" : missing === "epss" ? "AND epss IS NULL" : "";
    const { rows } = await this.pool.query(
      `SELECT DISTINCT cve_id FROM vulnerabilities WHERE cve_id IS NOT NULL ${cond} LIMIT $1`,
      [limit],
    );
    return rows.map((r) => r.cve_id as string);
  }

  async enrich(patches: EnrichPatch[]): Promise<number> {
    if (patches.length === 0) return 0;
    const client = await this.pool.connect();
    let n = 0;
    try {
      await client.query("BEGIN");
      for (const p of patches) {
        // Fetch affected rows, recompute risk in JS (keeps scoring logic in one place).
        const { rows } = await client.query(
          `SELECT source, id, known_exploited, ransomware_use, cvss, epss
             FROM vulnerabilities WHERE cve_id = $1`,
          [p.cveId],
        );
        for (const r of rows) {
          const cvss = p.cvss !== undefined ? p.cvss : r.cvss;
          const epss = p.epss !== undefined ? p.epss : r.epss;
          const risk = computeRiskScore({
            knownExploited: r.known_exploited,
            ransomwareUse: r.ransomware_use,
            cvss,
            epss,
          });
          await client.query(
            `UPDATE vulnerabilities SET cvss=$1, epss=$2, risk_score=$3 WHERE source=$4 AND id=$5`,
            [cvss, epss, risk, r.source, r.id],
          );
          n++;
        }
      }
      await client.query("COMMIT");
      return n;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  async init(): Promise<void> {
    const here = dirname(fileURLToPath(import.meta.url));
    const sql = readFileSync(join(here, "schema.sql"), "utf8");
    await this.pool.query(sql);
  }

  async listWatchlist(): Promise<string[]> {
    const { rows } = await this.pool.query(`SELECT term FROM watchlist ORDER BY term`);
    return rows.map((r) => r.term as string);
  }
  async addWatchTerm(term: string): Promise<void> {
    const t = term.trim().toLowerCase();
    if (!t) return;
    await this.pool.query(`INSERT INTO watchlist (term) VALUES ($1) ON CONFLICT DO NOTHING`, [t]);
  }
  async removeWatchTerm(term: string): Promise<void> {
    await this.pool.query(`DELETE FROM watchlist WHERE term = $1`, [term.trim().toLowerCase()]);
  }

  async upsertSource(s: Source): Promise<void> {
    await this.pool.query(
      `INSERT INTO sources (id,name,kind,signal_type,url,schedule,enabled,requires_auth,config)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (id) DO UPDATE SET
         name=EXCLUDED.name, kind=EXCLUDED.kind, signal_type=EXCLUDED.signal_type,
         url=EXCLUDED.url, schedule=EXCLUDED.schedule, enabled=EXCLUDED.enabled,
         requires_auth=EXCLUDED.requires_auth, config=EXCLUDED.config`,
      [s.id, s.name, s.kind, s.signalType, s.url, s.schedule, s.enabled, s.requiresAuth, s.config],
    );
  }

  async listSources(): Promise<Source[]> {
    const { rows } = await this.pool.query(`SELECT * FROM sources ORDER BY name`);
    return rows.map((r) => ({
      id: r.id,
      name: r.name,
      kind: r.kind,
      signalType: r.signal_type,
      url: r.url,
      schedule: r.schedule,
      enabled: r.enabled,
      requiresAuth: r.requires_auth,
      config: r.config,
    }));
  }

  async upsertVulnerabilities(items: Vulnerability[]): Promise<number> {
    if (items.length === 0) return 0;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const v of items) {
        await client.query(
          `INSERT INTO vulnerabilities
             (id,source,cve_id,title,description,vendor,product,known_exploited,ransomware_use,
              cvss,epss,cwes,required_action,due_date,date_added,references_json,risk_score,fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
           ON CONFLICT (source,id) DO UPDATE SET
             cve_id=EXCLUDED.cve_id, title=EXCLUDED.title, description=EXCLUDED.description,
             vendor=EXCLUDED.vendor, product=EXCLUDED.product, known_exploited=EXCLUDED.known_exploited,
             ransomware_use=EXCLUDED.ransomware_use, cvss=EXCLUDED.cvss, epss=EXCLUDED.epss,
             cwes=EXCLUDED.cwes, required_action=EXCLUDED.required_action, due_date=EXCLUDED.due_date,
             date_added=EXCLUDED.date_added, references_json=EXCLUDED.references_json,
             risk_score=EXCLUDED.risk_score, fetched_at=EXCLUDED.fetched_at`,
          [
            v.id, v.source, v.cveId, v.title, v.description, v.vendor, v.product,
            v.knownExploited, v.ransomwareUse, v.cvss, v.epss, JSON.stringify(v.cwes),
            v.requiredAction, v.dueDate, v.dateAdded, JSON.stringify(v.references),
            v.riskScore, v.fetchedAt,
          ],
        );
      }
      await client.query("COMMIT");
      return items.length;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  private buildFilters(opts: ListOptions): { clause: string; params: unknown[] } {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.minRisk != null) {
      params.push(opts.minRisk);
      where.push(`risk_score >= $${params.length}`);
    }
    if (opts.source) {
      params.push(opts.source);
      where.push(`source = $${params.length}`);
    }
    if (opts.exploited) where.push(`known_exploited = TRUE`);
    if (opts.ransomware) where.push(`ransomware_use = TRUE`);
    if (opts.vendor) {
      params.push(`%${opts.vendor}%`);
      where.push(`(vendor ILIKE $${params.length} OR product ILIKE $${params.length})`);
    }
    if (opts.terms && opts.terms.length) {
      const ors = opts.terms.map((t) => {
        params.push(`%${t}%`);
        const p = `$${params.length}`;
        return `(vendor ILIKE ${p} OR product ILIKE ${p} OR title ILIKE ${p})`;
      });
      where.push(`(${ors.join(" OR ")})`);
    }
    if (opts.q) {
      params.push(`%${opts.q}%`);
      where.push(`(title ILIKE $${params.length} OR cve_id ILIKE $${params.length} OR vendor ILIKE $${params.length})`);
    }
    return { clause: where.length ? "WHERE " + where.join(" AND ") : "", params };
  }

  private static SORT_COLS: Record<string, string> = {
    risk: "risk_score", cve: "cve_id", threat: "title",
    vendor: "vendor", cvss: "cvss", epss: "epss", reported: "date_added", source: "source",
  };

  // Whitelisted column + direction — never interpolate raw user input into SQL.
  private buildOrder(opts: ListOptions): string {
    const col = PostgresRepository.SORT_COLS[opts.sort ?? "risk"] ?? "risk_score";
    const dir = opts.dir === "asc" ? "ASC" : "DESC";
    return `ORDER BY ${col} ${dir} NULLS LAST, source, id`;
  }

  async listVulnerabilities(opts: ListOptions = {}): Promise<Vulnerability[]> {
    const { clause, params } = this.buildFilters(opts);
    params.push(opts.limit ?? 100);
    const sql = `SELECT * FROM vulnerabilities ${clause} ${this.buildOrder(opts)} LIMIT $${params.length}`;
    const { rows } = await this.pool.query(sql, params);
    return rows.map(rowToVuln);
  }

  async page(opts: ListOptions = {}): Promise<Page> {
    const { clause, params } = this.buildFilters(opts);
    const countRes = await this.pool.query(
      `SELECT COUNT(*)::int AS total FROM vulnerabilities ${clause}`,
      params,
    );
    const total = countRes.rows[0].total as number;
    const paged = [...params];
    paged.push(opts.limit ?? 50);
    const li = `$${paged.length}`;
    paged.push(opts.offset ?? 0);
    const oi = `$${paged.length}`;
    const sql = `SELECT * FROM vulnerabilities ${clause} ${this.buildOrder(opts)} LIMIT ${li} OFFSET ${oi}`;
    const { rows } = await this.pool.query(sql, paged);
    return { items: rows.map(rowToVuln), total };
  }

  async upsertIndicators(items: Indicator[]): Promise<number> {
    if (items.length === 0) return 0;
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      for (const i of items) {
        await client.query(
          `INSERT INTO indicators
             (id,source,type,value,malware,threat_type,confidence,references_json,tags,first_seen,last_seen,fetched_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (source,id) DO UPDATE SET
             type=EXCLUDED.type, value=EXCLUDED.value, malware=EXCLUDED.malware,
             threat_type=EXCLUDED.threat_type, confidence=EXCLUDED.confidence,
             references_json=EXCLUDED.references_json, tags=EXCLUDED.tags,
             first_seen=EXCLUDED.first_seen, last_seen=EXCLUDED.last_seen, fetched_at=EXCLUDED.fetched_at`,
          [
            i.id, i.source, i.type, i.value, i.malware, i.threatType, i.confidence,
            JSON.stringify(i.references), JSON.stringify(i.tags), i.firstSeen, i.lastSeen, i.fetchedAt,
          ],
        );
      }
      await client.query("COMMIT");
      return items.length;
    } catch (err) {
      await client.query("ROLLBACK");
      throw err;
    } finally {
      client.release();
    }
  }

  private static IOC_SORT: Record<string, string> = {
    confidence: "confidence", lastseen: "last_seen", type: "type",
    malware: "malware", value: "value", source: "source",
  };

  async pageIndicators(opts: IndicatorListOptions = {}): Promise<IndicatorPage> {
    const where: string[] = [];
    const params: unknown[] = [];
    if (opts.type) { params.push(opts.type); where.push(`type = $${params.length}`); }
    if (opts.source) { params.push(opts.source); where.push(`source = $${params.length}`); }
    if (opts.malware) { params.push(`%${opts.malware}%`); where.push(`malware ILIKE $${params.length}`); }
    if (opts.q) {
      params.push(`%${opts.q}%`);
      where.push(`(value ILIKE $${params.length} OR malware ILIKE $${params.length} OR threat_type ILIKE $${params.length})`);
    }
    const clause = where.length ? "WHERE " + where.join(" AND ") : "";
    const countRes = await this.pool.query(`SELECT COUNT(*)::int AS total FROM indicators ${clause}`, params);
    const total = countRes.rows[0].total as number;

    const col = PostgresRepository.IOC_SORT[opts.sort ?? "lastseen"] ?? "last_seen";
    const dir = opts.dir === "asc" ? "ASC" : "DESC";
    const paged = [...params];
    paged.push(opts.limit ?? 50);
    const li = `$${paged.length}`;
    paged.push(opts.offset ?? 0);
    const oi = `$${paged.length}`;
    const sql = `SELECT * FROM indicators ${clause} ORDER BY ${col} ${dir} NULLS LAST, source, id LIMIT ${li} OFFSET ${oi}`;
    const { rows } = await this.pool.query(sql, paged);
    return { items: rows.map(rowToIndicator), total };
  }

  async stats(): Promise<Stats> {
    const { rows } = await this.pool.query(
      `SELECT COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE known_exploited)::int AS known_exploited,
              COUNT(*) FILTER (WHERE ransomware_use)::int AS ransomware,
              COUNT(*) FILTER (WHERE risk_score >= 75)::int AS critical,
              COUNT(*) FILTER (WHERE risk_score >= 50 AND risk_score < 75)::int AS high,
              (SELECT COUNT(*)::int FROM sources) AS sources,
              (SELECT COUNT(*)::int FROM indicators) AS indicators
       FROM vulnerabilities`,
    );
    const r = rows[0];

    // "In stack" depends on the watchlist terms, so count it separately.
    const terms = await this.listWatchlist();
    let inStack = 0;
    if (terms.length) {
      const params: unknown[] = [];
      const ors = terms.map((t) => {
        params.push(`%${t}%`);
        const p = `$${params.length}`;
        return `(vendor ILIKE ${p} OR product ILIKE ${p} OR title ILIKE ${p})`;
      });
      const res = await this.pool.query(
        `SELECT COUNT(*)::int AS n FROM vulnerabilities WHERE ${ors.join(" OR ")}`,
        params,
      );
      inStack = res.rows[0].n as number;
    }

    return {
      total: r.total,
      knownExploited: r.known_exploited,
      ransomware: r.ransomware,
      critical: r.critical,
      high: r.high,
      sources: r.sources,
      indicators: r.indicators,
      inStack,
    };
  }
}

function rowToVuln(r: Record<string, unknown>): Vulnerability {
  return {
    id: r.id as string,
    source: r.source as string,
    cveId: (r.cve_id as string) ?? null,
    title: r.title as string,
    description: (r.description as string) ?? "",
    vendor: (r.vendor as string) ?? null,
    product: (r.product as string) ?? null,
    knownExploited: Boolean(r.known_exploited),
    ransomwareUse: Boolean(r.ransomware_use),
    cvss: (r.cvss as number) ?? null,
    epss: (r.epss as number) ?? null,
    cwes: (r.cwes as string[]) ?? [],
    requiredAction: (r.required_action as string) ?? null,
    dueDate: r.due_date ? String(r.due_date).slice(0, 10) : null,
    dateAdded: r.date_added ? String(r.date_added).slice(0, 10) : null,
    references: (r.references_json as string[]) ?? [],
    riskScore: r.risk_score as number,
    fetchedAt: new Date(r.fetched_at as string).toISOString(),
  };
}

function rowToIndicator(r: Record<string, unknown>): Indicator {
  return {
    id: r.id as string,
    source: r.source as string,
    type: r.type as Indicator["type"],
    value: r.value as string,
    malware: (r.malware as string) ?? null,
    threatType: (r.threat_type as string) ?? null,
    confidence: (r.confidence as number) ?? null,
    references: (r.references_json as string[]) ?? [],
    tags: (r.tags as string[]) ?? [],
    firstSeen: r.first_seen ? new Date(r.first_seen as string).toISOString() : null,
    lastSeen: r.last_seen ? new Date(r.last_seen as string).toISOString() : null,
    fetchedAt: new Date(r.fetched_at as string).toISOString(),
  };
}
