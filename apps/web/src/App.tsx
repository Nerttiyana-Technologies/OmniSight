import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  Radar, Moon, Sun, RefreshCw, Plus, ShieldAlert, Skull, Flame, Database, TrendingUp, Rss,
  Activity, Gauge, ChevronLeft, ChevronRight, Crosshair, Server, X,
} from "lucide-react";
import {
  riskBand, type Vulnerability, type Indicator, type NewSource, type Source,
} from "@omnisight/shared";
import {
  api, type Stats, type VulnQuery, type IndicatorQuery,
} from "./api.ts";

type Theme = "dark" | "light";
type Tab = "vulns" | "iocs";

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** mmm/dd/yyyy, e.g. Jun/25/2026. */
function formatDate(s: string | null): string {
  if (!s) return "—";
  const d = new Date(s.length <= 10 ? `${s}T00:00:00` : s);
  if (Number.isNaN(d.getTime())) return s;
  return `${MONTHS[d.getMonth()]}/${String(d.getDate()).padStart(2, "0")}/${d.getFullYear()}`;
}

/** Client-side "in my stack" check (mirrors the server's matching). */
function inStack(v: Vulnerability, terms: string[]): boolean {
  if (!terms.length) return false;
  const hay = `${v.vendor ?? ""} ${v.product ?? ""} ${v.title}`.toLowerCase();
  return terms.some((t) => hay.includes(t.toLowerCase()));
}

export function App() {
  const [theme, setTheme] = useState<Theme>("dark");
  const [stats, setStats] = useState<Stats | null>(null);
  const [tab, setTab] = useState<Tab>("vulns");
  const [sources, setSources] = useState<Source[]>([]);
  const [terms, setTerms] = useState<string[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [showStack, setShowStack] = useState(false);
  const [live, setLive] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  const REFRESH_MS = 15000;
  const bump = useCallback(() => setReloadKey((k) => k + 1), []);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
  }, [theme]);

  useEffect(() => {
    api.sources().then(setSources).catch(() => {});
  }, []);

  // Stats + watchlist follow every reload (manual, SSE push, or poll).
  useEffect(() => {
    api.stats().then((s) => { setStats(s); setUpdatedAt(new Date()); }).catch(() => {});
    api.watchlist().then(setTerms).catch(() => {});
  }, [reloadKey]);

  // Real-time: SSE push bumps reloadKey; fall back to polling if the stream drops.
  useEffect(() => {
    if (!live) return;
    let es: EventSource | null = null;
    let poll: ReturnType<typeof setInterval> | null = null;
    const startPolling = () => {
      if (poll) return;
      poll = setInterval(() => { if (!document.hidden) bump(); }, REFRESH_MS);
    };
    try {
      es = api.stream(() => bump(), () => { es?.close(); es = null; startPolling(); });
    } catch {
      startPolling();
    }
    return () => { es?.close(); if (poll) clearInterval(poll); };
  }, [live, bump]);

  return (
    <>
      <header className="topbar">
        <div className="brand">
          <Radar size={22} className="mark" />
          <div>
            OmniSight <br />
            <small>Cyber Situational Awareness</small>
          </div>
        </div>
        <div className="spacer" />
        <div className="live-status" title={live ? "Auto-refreshing" : "Auto-refresh paused"}>
          <span className={`live-dot ${live ? "on" : "off"}`} />
          <span className="live-text">
            {live ? "Live" : "Paused"}
            {updatedAt && <span className="muted"> · {updatedAt.toLocaleTimeString()}</span>}
          </span>
        </div>
        <button
          className="icon-btn"
          data-tooltip={live ? "Pause auto-refresh" : "Resume auto-refresh"}
          aria-label="Toggle auto-refresh"
          onClick={() => setLive((v) => !v)}
        >
          <Activity size={18} className={live ? "pulse" : ""} />
        </button>
        <button
          className="icon-btn"
          data-tooltip="Fetch EPSS scores"
          aria-label="Enrich with EPSS"
          onClick={async () => { try { await api.enrich(); bump(); } catch { /* offline */ } }}
        >
          <Gauge size={18} />
        </button>
        <button
          className="icon-btn"
          data-tooltip="My Stack"
          aria-label="My Stack"
          onClick={() => setShowStack((v) => !v)}
        >
          <Server size={18} />
        </button>
        <button
          className="icon-btn"
          data-tooltip="Add feed (admin)"
          aria-label="Add feed"
          onClick={() => setShowAdd((v) => !v)}
        >
          <Plus size={18} />
        </button>
        <button className="icon-btn" data-tooltip="Refresh" aria-label="Refresh" onClick={bump}>
          <RefreshCw size={18} />
        </button>
        <button
          className="icon-btn"
          data-tooltip={theme === "dark" ? "Light theme" : "Dark theme"}
          aria-label="Toggle theme"
          onClick={() => setTheme((t) => (t === "dark" ? "light" : "dark"))}
        >
          {theme === "dark" ? <Sun size={18} /> : <Moon size={18} />}
        </button>
      </header>

      <main>
        <section className="stat-grid">
          <StatCard icon={<Database size={16} />} label="Tracked" value={stats?.total} />
          <StatCard icon={<ShieldAlert size={16} />} label="Known Exploited" value={stats?.knownExploited} accent />
          <StatCard icon={<Skull size={16} />} label="Ransomware-linked" value={stats?.ransomware} />
          <StatCard icon={<Flame size={16} />} label="Critical (75+)" value={stats?.critical} crit />
          <StatCard icon={<TrendingUp size={16} />} label="High (50–74)" value={stats?.high} />
          <StatCard icon={<Crosshair size={16} />} label="Indicators" value={stats?.indicators} />
          <StatCard icon={<Server size={16} />} label="My Stack" value={stats?.inStack} accent />
          <StatCard icon={<Rss size={16} />} label="Active Sources" value={stats?.sources} />
        </section>

        {showStack && <StackPanel terms={terms} onChange={bump} />}
        {showAdd && <AddFeed onAdded={bump} />}

        <div className="tabs">
          <button className={`tab ${tab === "vulns" ? "active" : ""}`} onClick={() => setTab("vulns")}>
            Vulnerabilities {stats && <span className="muted">({stats.total.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "iocs" ? "active" : ""}`} onClick={() => setTab("iocs")}>
            Indicators {stats && <span className="muted">({stats.indicators.toLocaleString()})</span>}
          </button>
        </div>

        {tab === "vulns"
          ? <VulnGrid reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "vulnerability")} terms={terms} />
          : <IndicatorGrid reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "indicator")} />}
      </main>
    </>
  );
}

// ---------------------------------------------------------------------------
// Vulnerabilities grid

interface VulnFilters {
  q: string;
  vendor: string;
  source: string;
  minRisk: number;
  flag: "" | "exploited" | "ransomware";
  myStack: boolean;
}
const EMPTY_VULN_FILTERS: VulnFilters = { q: "", vendor: "", source: "", minRisk: 0, flag: "", myStack: false };

function VulnGrid({ reloadKey, sources, terms }: { reloadKey: number; sources: Source[]; terms: string[] }) {
  const [items, setItems] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [filters, setFilters] = useState<VulnFilters>(EMPTY_VULN_FILTERS);
  const [sort, setSort] = useState<{ field: string; dir: "asc" | "desc" }>({ field: "risk", dir: "desc" });
  const [loading, setLoading] = useState(false);
  const pages = Math.max(1, Math.ceil(total / pageSize));

  const ref = useRef({ page, pageSize, filters, sort });
  ref.current = { page, pageSize, filters, sort };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { page, pageSize, filters, sort } = ref.current;
      const q: VulnQuery = { page, pageSize, sort: sort.field, dir: sort.dir };
      if (filters.q) q.q = filters.q;
      if (filters.vendor) q.vendor = filters.vendor;
      if (filters.source) q.source = filters.source;
      if (filters.minRisk) q.minRisk = filters.minRisk;
      if (filters.flag === "exploited") q.exploited = true;
      if (filters.flag === "ransomware") q.ransomware = true;
      if (filters.myStack) q.myStack = true;
      const p = await api.vulnerabilities(q);
      setItems(p.items); setTotal(p.total);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  }, [reloadKey, page, pageSize, filters, sort, load]);

  function setFilter<K extends keyof VulnFilters>(k: K, v: VulnFilters[K]) {
    setFilters((f) => ({ ...f, [k]: v }));
    setPage(1);
  }
  function toggleSort(field: string) {
    setSort((s) => (s.field === field ? { field, dir: s.dir === "asc" ? "desc" : "asc" } : { field, dir: "desc" }));
    setPage(1);
  }
  const arrow = (f: string) => (sort.field === f ? (sort.dir === "asc" ? " ▲" : " ▼") : "");

  return (
    <div className="panel">
      <div className="grid-toolbar">
        <button
          className={`chip ${filters.myStack ? "on" : ""}`}
          onClick={() => setFilter("myStack", !filters.myStack)}
          disabled={terms.length === 0}
          title={terms.length === 0 ? "Add software to My Stack first" : "Show only CVEs affecting your stack"}
        >
          <Server size={14} /> My Stack only
          {terms.length > 0 && <span className="muted"> ({terms.length})</span>}
        </button>
        {terms.length === 0 && <span className="muted">Add software via the My Stack panel to filter by what you run.</span>}
      </div>
      <table>
        <thead>
          <tr>
            <th className="sortable" onClick={() => toggleSort("risk")}>Risk{arrow("risk")}</th>
            <th className="sortable" onClick={() => toggleSort("cve")}>CVE{arrow("cve")}</th>
            <th className="sortable" onClick={() => toggleSort("threat")}>Threat{arrow("threat")}</th>
            <th className="sortable" onClick={() => toggleSort("vendor")}>Vendor / Product{arrow("vendor")}</th>
            <th className="sortable" onClick={() => toggleSort("cvss")}>CVSS{arrow("cvss")}</th>
            <th className="sortable" onClick={() => toggleSort("epss")}>EPSS{arrow("epss")}</th>
            <th className="sortable" onClick={() => toggleSort("reported")}>Reported{arrow("reported")}</th>
            <th>Flags</th>
            <th className="sortable" onClick={() => toggleSort("source")}>Source{arrow("source")}</th>
          </tr>
          <tr className="filter-row">
            <th>
              <select value={filters.minRisk} onChange={(e) => setFilter("minRisk", Number(e.target.value))}>
                <option value={0}>All</option>
                <option value={75}>Critical</option>
                <option value={50}>High+</option>
                <option value={25}>Medium+</option>
              </select>
            </th>
            <th colSpan={2}>
              <input placeholder="Search CVE or threat…" value={filters.q} onChange={(e) => setFilter("q", e.target.value)} />
            </th>
            <th>
              <input placeholder="Vendor / product" value={filters.vendor} onChange={(e) => setFilter("vendor", e.target.value)} />
            </th>
            <th /><th /><th />
            <th>
              <select value={filters.flag} onChange={(e) => setFilter("flag", e.target.value as VulnFilters["flag"])}>
                <option value="">All</option>
                <option value="exploited">Exploited</option>
                <option value="ransomware">Ransomware</option>
              </select>
            </th>
            <th>
              <select value={filters.source} onChange={(e) => setFilter("source", e.target.value)}>
                <option value="">All</option>
                {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.length === 0 && (
            <tr><td colSpan={9} className="muted" style={{ padding: 28, textAlign: "center" }}>
              {total === 0 ? "No vulnerabilities yet. Start the API and worker to ingest data." : "No matches — try clearing filters."}
            </td></tr>
          )}
          {items.map((v) => {
            const band = riskBand(v.riskScore);
            const mine = inStack(v, terms);
            return (
              <tr key={`${v.source}:${v.id}`} className={mine ? "in-stack" : ""}>
                <td>
                  <div className="risk-cell">
                    <span className={`badge ${band}`}>{v.riskScore}</span>
                    <div className="risk-bar"><span style={{ width: `${v.riskScore}%`, background: `var(--${band})` }} /></div>
                  </div>
                </td>
                <td className="cve">
                  {mine && <span className="stack-dot" title="In your stack" />}
                  {v.cveId ?? v.id}
                </td>
                <td>{v.title}</td>
                <td className="muted">{[v.vendor, v.product].filter(Boolean).join(" / ") || "—"}</td>
                <td className="muted">{v.cvss != null ? v.cvss.toFixed(1) : "—"}</td>
                <td className="muted">{v.epss != null ? `${(v.epss * 100).toFixed(0)}%` : "—"}</td>
                <td className="muted">{formatDate(v.dateAdded)}</td>
                <td>
                  {v.knownExploited && <span className="flag">EXPLOITED</span>}
                  {v.ransomwareUse && <span className="flag"> · RANSOMWARE</span>}
                </td>
                <td className="muted">{v.source}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
      <Pager total={total} page={page} pages={pages} pageSize={pageSize} loading={loading}
        onPage={setPage} onPageSize={(n) => { setPageSize(n); setPage(1); }} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Indicators grid

interface IocFilters { q: string; type: string; source: string }
const EMPTY_IOC_FILTERS: IocFilters = { q: "", type: "", source: "" };

function IndicatorGrid({ reloadKey, sources }: { reloadKey: number; sources: Source[] }) {
  const [items, setItems] = useState<Indicator[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [filters, setFilters] = useState<IocFilters>(EMPTY_IOC_FILTERS);
  const [sort, setSort] = useState<{ field: string; dir: "asc" | "desc" }>({ field: "lastseen", dir: "desc" });
  const [loading, setLoading] = useState(false);
  const pages = Math.max(1, Math.ceil(total / pageSize));

  const ref = useRef({ page, pageSize, filters, sort });
  ref.current = { page, pageSize, filters, sort };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { page, pageSize, filters, sort } = ref.current;
      const q: IndicatorQuery = { page, pageSize, sort: sort.field, dir: sort.dir };
      if (filters.q) q.q = filters.q;
      if (filters.type) q.type = filters.type;
      if (filters.source) q.source = filters.source;
      const p = await api.indicators(q);
      setItems(p.items); setTotal(p.total);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  }, [reloadKey, page, pageSize, filters, sort, load]);

  function setFilter<K extends keyof IocFilters>(k: K, v: IocFilters[K]) {
    setFilters((f) => ({ ...f, [k]: v }));
    setPage(1);
  }
  function toggleSort(field: string) {
    setSort((s) => (s.field === field ? { field, dir: s.dir === "asc" ? "desc" : "asc" } : { field, dir: "desc" }));
    setPage(1);
  }
  const arrow = (f: string) => (sort.field === f ? (sort.dir === "asc" ? " ▲" : " ▼") : "");

  return (
    <div className="panel">
      <table>
        <thead>
          <tr>
            <th className="sortable" onClick={() => toggleSort("type")}>Type{arrow("type")}</th>
            <th className="sortable" onClick={() => toggleSort("value")}>Indicator{arrow("value")}</th>
            <th className="sortable" onClick={() => toggleSort("malware")}>Malware{arrow("malware")}</th>
            <th>Threat</th>
            <th className="sortable" onClick={() => toggleSort("confidence")}>Confidence{arrow("confidence")}</th>
            <th className="sortable" onClick={() => toggleSort("lastseen")}>Last Seen{arrow("lastseen")}</th>
            <th className="sortable" onClick={() => toggleSort("source")}>Source{arrow("source")}</th>
          </tr>
          <tr className="filter-row">
            <th>
              <select value={filters.type} onChange={(e) => setFilter("type", e.target.value)}>
                <option value="">All</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">Hash</option>
                <option value="other">Other</option>
              </select>
            </th>
            <th colSpan={3}>
              <input placeholder="Search indicator, malware or threat…" value={filters.q} onChange={(e) => setFilter("q", e.target.value)} />
            </th>
            <th /><th />
            <th>
              <select value={filters.source} onChange={(e) => setFilter("source", e.target.value)}>
                <option value="">All</option>
                {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
              </select>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.length === 0 && (
            <tr><td colSpan={7} className="muted" style={{ padding: 28, textAlign: "center" }}>
              {total === 0 ? "No indicators yet. Ensure ABUSECH_AUTH_KEY is set and the worker is running." : "No matches — try clearing filters."}
            </td></tr>
          )}
          {items.map((i) => (
            <tr key={`${i.source}:${i.id}`}>
              <td><span className={`badge ioc-${i.type}`}>{i.type}</span></td>
              <td className="ioc-value">{i.value}</td>
              <td>{i.malware ?? "—"}</td>
              <td className="muted">{i.threatType ?? "—"}</td>
              <td className="muted">{i.confidence != null ? `${i.confidence}%` : "—"}</td>
              <td className="muted">{formatDate(i.lastSeen)}</td>
              <td className="muted">{i.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <Pager total={total} page={page} pages={pages} pageSize={pageSize} loading={loading}
        onPage={setPage} onPageSize={(n) => { setPageSize(n); setPage(1); }} />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Shared bits

function Pager(props: {
  total: number; page: number; pages: number; pageSize: number; loading: boolean;
  onPage: (updater: (p: number) => number) => void; onPageSize: (n: number) => void;
}) {
  const { total, page, pages, pageSize, loading, onPage, onPageSize } = props;
  return (
    <div className="pager">
      <div className="pager-left">
        <span className="muted">{total.toLocaleString()} result{total === 1 ? "" : "s"}{loading ? " · loading…" : ""}</span>
        <select className="page-size" value={pageSize} onChange={(e) => onPageSize(Number(e.target.value))} aria-label="Rows per page">
          <option value={25}>25 / page</option>
          <option value={50}>50 / page</option>
          <option value={100}>100 / page</option>
        </select>
      </div>
      <div className="pager-controls">
        <button className="icon-btn" data-tooltip="Previous page" aria-label="Previous page"
          disabled={page <= 1} onClick={() => onPage((p) => Math.max(1, p - 1))}>
          <ChevronLeft size={16} />
        </button>
        <span className="muted">Page {page} of {pages}</span>
        <button className="icon-btn" data-tooltip="Next page" aria-label="Next page"
          disabled={page >= pages} onClick={() => onPage((p) => Math.min(pages, p + 1))}>
          <ChevronRight size={16} />
        </button>
      </div>
    </div>
  );
}

function StatCard(props: { icon: React.ReactNode; label: string; value?: number; accent?: boolean; crit?: boolean }) {
  return (
    <div className={`stat-card ${props.accent ? "accent" : ""} ${props.crit ? "crit" : ""}`}>
      <div className="label" style={{ display: "flex", alignItems: "center", gap: 6 }}>
        {props.icon} {props.label}
      </div>
      <div className="value">{props.value ?? "—"}</div>
    </div>
  );
}

function StackPanel({ terms, onChange }: { terms: string[]; onChange: () => void }) {
  const [term, setTerm] = useState("");

  async function add(e: FormEvent) {
    e.preventDefault();
    if (!term.trim()) return;
    try { await api.addWatch(term.trim()); setTerm(""); onChange(); } catch { /* offline */ }
  }
  async function remove(t: string) {
    try { await api.removeWatch(t); onChange(); } catch { /* offline */ }
  }

  return (
    <div className="panel drawer">
      <div className="section-head"><h2>My Stack</h2></div>
      <div className="hint" style={{ marginTop: 0, marginBottom: 12 }}>
        Add the vendors and products you run. CVEs matching these are flagged in the grid and filterable with “My Stack only”.
      </div>
      <div className="chips">
        {terms.length === 0 && (
          <span className="muted">No software yet — try “fortinet”, “log4j”, “windows”, “cisco”.</span>
        )}
        {terms.map((t) => (
          <span key={t} className="chip removable">
            {t}
            <button onClick={() => remove(t)} aria-label={`Remove ${t}`}><X size={12} /></button>
          </span>
        ))}
      </div>
      <form onSubmit={add} className="stack-add">
        <input value={term} onChange={(e) => setTerm(e.target.value)} placeholder="e.g. fortinet" />
        <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
      </form>
    </div>
  );
}

function AddFeed({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [itemsPath, setItemsPath] = useState("");
  const [msg, setMsg] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setMsg("");
    const body: NewSource = {
      name, kind: "json", signalType: "vulnerability", url,
      schedule: "0 */6 * * *", enabled: true, requiresAuth: false,
      config: { itemsPath, map: {} },
    };
    try {
      const created = await api.addSource(body);
      await api.runSource(created.id);
      setMsg(`Added "${created.name}" and triggered first fetch.`);
      setName(""); setUrl(""); setItemsPath("");
      onAdded();
    } catch (err) {
      setMsg(`Error: ${(err as Error).message}`);
    }
  }

  return (
    <div className="panel drawer">
      <div className="section-head"><h2>Add Feed</h2></div>
      <form onSubmit={submit}>
        <div className="field">
          <label>Feed name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="My CVE feed" required />
        </div>
        <div className="field">
          <label>JSON URL</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com/feed.json" required />
        </div>
        <div className="field">
          <label>Items path</label>
          <input value={itemsPath} onChange={(e) => setItemsPath(e.target.value)} placeholder="vulnerabilities" />
        </div>
        <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
      </form>
      <div className="hint">
        Generic JSON connector — point it at any feed, set the array path, and OmniSight ingests it. No code required.
        {msg && <span style={{ display: "block", marginTop: 6 }}>{msg}</span>}
      </div>
    </div>
  );
}
