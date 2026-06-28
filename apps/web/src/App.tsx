import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  Radar, Moon, Sun, RefreshCw, Plus, ShieldAlert, Skull, Flame, Database, TrendingUp, Rss,
  Activity, Gauge, ChevronLeft, ChevronRight, Crosshair, Server, X, Download, FileText, Newspaper, ExternalLink,
  ScanSearch, Copy, Package, LogOut, Users as UsersIcon, Lock, Trash2, Sparkles, ScrollText, Bug, KeyRound,
  Workflow, Link2, ShieldOff,
} from "lucide-react";
import {
  riskBand, threatLevel, extractIocs, defang, roleAtLeast, type Vulnerability, type Indicator, type Advisory, type NewSource, type Source,
  type Digest, type DigestTone, type ExtractedIocs, type User,
} from "@omnisight/shared";
import {
  api, setToken, type Stats, type VulnQuery, type IndicatorQuery, type AdvisoryQuery, type MapPoint, type MapIndicator,
  type Correlation, type AttackTechnique, type ActorProfile, type AuditEntry, type Breach, type Rule, type AiLink,
} from "./api.ts";
import { makeProjector, topologyToGeometries, geomToPath, type Geom } from "./geo.ts";

type Theme = "dark" | "light";
type Tab = "overview" | "vulns" | "iocs" | "actors" | "exposure" | "news" | "map";

function toneBadgeClass(tone?: DigestTone): string {
  return tone && tone !== "info" ? tone : "info";
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** mmm/dd/yyyy, e.g. Jun/25/2026. */
function formatDate(s: string | null): string {
  if (!s) return "—";
  const d = new Date(s.length <= 10 ? `${s}T00:00:00` : s);
  if (Number.isNaN(d.getTime())) return s;
  return `${MONTHS[d.getMonth()]}/${String(d.getDate()).padStart(2, "0")}/${d.getFullYear()}`;
}

/** Trigger a browser download for an export URL (server sets attachment headers). */
function download(url: string) {
  const a = document.createElement("a");
  a.href = url;
  a.rel = "noopener";
  document.body.appendChild(a);
  a.click();
  a.remove();
}

/** Download in-memory content as a file (no navigation). */
function downloadBlob(filename: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function reliabilityOf(sources: Source[], id: string): string | null {
  return sources.find((s) => s.id === id)?.reliability ?? null;
}
function isStale(lastSeen: string | null, days = 90): boolean {
  if (!lastSeen) return false;
  return Date.now() - new Date(lastSeen).getTime() > days * 86400000;
}
function SourceCell({ source, reliability }: { source: string; reliability: string | null }) {
  return (
    <span>
      {source}{reliability && <span className={`badge rel-${reliability}`} title={`Source reliability: ${reliability}`} style={{ marginLeft: 6 }}>{reliability}</span>}
    </span>
  );
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
  const [tab, setTab] = useState<Tab>("overview");
  const [sources, setSources] = useState<Source[]>([]);
  const [terms, setTerms] = useState<string[]>([]);
  const [showAdd, setShowAdd] = useState(false);
  const [showStack, setShowStack] = useState(false);
  const [showExtract, setShowExtract] = useState(false);
  const [showSbom, setShowSbom] = useState(false);
  const [enrichTarget, setEnrichTarget] = useState<{ value: string; type: string } | null>(null);
  const onEnrich = useCallback((value: string, type: string) => setEnrichTarget({ value, type }), []);
  const [detailTarget, setDetailTarget] = useState<Vulnerability | null>(null);
  const onDetail = useCallback((v: Vulnerability) => setDetailTarget(v), []);
  const [live, setLive] = useState(true);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const [reloadKey, setReloadKey] = useState(0);

  // Auth
  const [authEnabled, setAuthEnabled] = useState(false);
  const [me, setMe] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(false);
  const [showUsers, setShowUsers] = useState(false);
  const [showAudit, setShowAudit] = useState(false);

  // AI
  const [aiEnabled, setAiEnabled] = useState(false);
  const [showAsk, setShowAsk] = useState(false);
  const [showCorrelate, setShowCorrelate] = useState(false);

  // Automation rules (admin)
  const [showRules, setShowRules] = useState(false);

  const REFRESH_MS = 15000;
  const bump = useCallback(() => setReloadKey((k) => k + 1), []);

  const canWrite = !authEnabled || (me != null && roleAtLeast(me.role, "analyst"));
  const isAdmin = !authEnabled || me?.role === "admin";

  useEffect(() => {
    api.aiConfig().then((c) => setAiEnabled(c.enabled)).catch(() => {});
    // Capture an SSO token handed back in the URL fragment (#sso_token=...).
    const hash = window.location.hash;
    if (hash.includes("sso_token=")) {
      const t = new URLSearchParams(hash.slice(1)).get("sso_token");
      if (t) setToken(t);
      history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    api.authConfig().then((cfg) => {
      setAuthEnabled(cfg.authEnabled);
      if (!cfg.authEnabled) { setAuthReady(true); return; }
      api.me().then((r) => { setMe(r.user); setAuthReady(true); }).catch(() => { setMe(null); setAuthReady(true); });
    }).catch(() => setAuthReady(true));
  }, []);

  function logout() {
    setToken(null);
    setMe(null);
  }

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
  }, [live, bump, me]);

  if (authReady && authEnabled && !me) {
    return <Login onLogin={(u) => { setMe(u); bump(); }} theme={theme} />;
  }

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
        {authEnabled && me && (
          <div className="user-chip" title={`Signed in as ${me.username}`}>
            <span className="user-name">{me.username}</span>
            <span className={`badge rel-${me.role === "admin" ? "A" : me.role === "analyst" ? "B" : "C"}`}>{me.role}</span>
          </div>
        )}
        {aiEnabled && (
          <button className="icon-btn" data-tooltip="Ask AI" aria-label="Ask AI" onClick={() => setShowAsk(true)}>
            <Sparkles size={18} />
          </button>
        )}
        {aiEnabled && (
          <button className="icon-btn" data-tooltip="AI correlation suggestions" aria-label="AI correlations" onClick={() => setShowCorrelate(true)}>
            <Link2 size={18} />
          </button>
        )}
        {isAdmin && (
          <button className="icon-btn" data-tooltip="Automation rules" aria-label="Automation rules" onClick={() => setShowRules(true)}>
            <Workflow size={18} />
          </button>
        )}
        {isAdmin && authEnabled && (
          <button className="icon-btn" data-tooltip="Audit log" aria-label="Audit log" onClick={() => setShowAudit(true)}>
            <ScrollText size={18} />
          </button>
        )}
        {isAdmin && authEnabled && (
          <button className="icon-btn" data-tooltip="Users" aria-label="Users" onClick={() => setShowUsers(true)}>
            <UsersIcon size={18} />
          </button>
        )}
        {authEnabled && me && (
          <button className="icon-btn" data-tooltip="Sign out" aria-label="Sign out" onClick={logout}>
            <LogOut size={18} />
          </button>
        )}
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
        {canWrite && (
          <button
            className="icon-btn"
            data-tooltip="Fetch EPSS scores"
            aria-label="Enrich with EPSS"
            onClick={async () => { try { await api.enrich(); bump(); } catch { /* offline */ } }}
          >
            <Gauge size={18} />
          </button>
        )}
        <button
          className="icon-btn"
          data-tooltip="Extract IOCs from text"
          aria-label="Extract IOCs"
          onClick={() => setShowExtract(true)}
        >
          <ScanSearch size={18} />
        </button>
        {canWrite && (
          <button
            className="icon-btn"
            data-tooltip="Scan an SBOM (CycloneDX/SPDX)"
            aria-label="Scan SBOM"
            onClick={() => setShowSbom(true)}
          >
            <Package size={18} />
          </button>
        )}
        {canWrite && (
          <button
            className="icon-btn"
            data-tooltip="My Stack"
            aria-label="My Stack"
            onClick={() => setShowStack((v) => !v)}
          >
            <Server size={18} />
          </button>
        )}
        {isAdmin && (
          <button
            className="icon-btn"
            data-tooltip="Add feed (admin)"
            aria-label="Add feed"
            onClick={() => setShowAdd((v) => !v)}
          >
            <Plus size={18} />
          </button>
        )}
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
          <StatCard icon={<Skull size={16} />} label="Ransomware" value={stats?.ransomware} />
          <StatCard icon={<Flame size={16} />} label="Critical (75+)" value={stats?.critical} crit />
          <StatCard icon={<TrendingUp size={16} />} label="High (50–74)" value={stats?.high} />
          <StatCard icon={<Crosshair size={16} />} label="Indicators" value={stats?.indicators} />
          <StatCard icon={<Newspaper size={16} />} label="News" value={stats?.advisories} />
          <StatCard icon={<Server size={16} />} label="My Stack" value={stats?.inStack} accent />
          <StatCard icon={<Rss size={16} />} label="Active Sources" value={stats?.sources} />
        </section>

        {showStack && <StackPanel terms={terms} onChange={bump} />}
        {showAdd && <AddFeed onAdded={bump} />}

        <div className="tabs">
          <button className={`tab ${tab === "overview" ? "active" : ""}`} onClick={() => setTab("overview")}>
            Overview
          </button>
          <button className={`tab ${tab === "vulns" ? "active" : ""}`} onClick={() => setTab("vulns")}>
            Vulnerabilities {stats && <span className="muted">({stats.total.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "iocs" ? "active" : ""}`} onClick={() => setTab("iocs")}>
            Indicators {stats && <span className="muted">({stats.indicators.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "actors" ? "active" : ""}`} onClick={() => setTab("actors")}>
            Actors
          </button>
          <button className={`tab ${tab === "exposure" ? "active" : ""}`} onClick={() => setTab("exposure")}>
            Exposure
          </button>
          <button className={`tab ${tab === "news" ? "active" : ""}`} onClick={() => setTab("news")}>
            News {stats && <span className="muted">({stats.advisories.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "map" ? "active" : ""}`} onClick={() => setTab("map")}>
            Map
          </button>
        </div>

        {tab === "overview" && <Overview reloadKey={reloadKey} stats={stats} />}
        {tab === "vulns" && <VulnGrid reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "vulnerability")} terms={terms} onDetail={onDetail} />}
        {tab === "iocs" && <IndicatorGrid reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "indicator")} onEnrich={onEnrich} canWrite={canWrite} />}
        {tab === "actors" && <ActorsView reloadKey={reloadKey} onEnrich={onEnrich} />}
        {tab === "exposure" && <ExposureView reloadKey={reloadKey} canWrite={canWrite} />}
        {tab === "news" && <NewsView reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "advisory")} />}
        {tab === "map" && <MapView reloadKey={reloadKey} onEnrich={onEnrich} />}
        {enrichTarget && <EnrichModal target={enrichTarget} onClose={() => setEnrichTarget(null)} canWrite={canWrite} />}
        {detailTarget && <VulnDetailModal v={detailTarget} onClose={() => setDetailTarget(null)} canWrite={canWrite} aiEnabled={aiEnabled} />}
        {showUsers && <UsersPanel onClose={() => setShowUsers(false)} meId={me?.id ?? null} />}
        {showAudit && <AuditPanel onClose={() => setShowAudit(false)} />}
        {showRules && <RulesPanel onClose={() => setShowRules(false)} />}
        {showAsk && <AskAiModal onClose={() => setShowAsk(false)} onDetail={onDetail} />}
        {showCorrelate && <CorrelateModal onClose={() => setShowCorrelate(false)} />}
        {showExtract && <ExtractModal onClose={() => setShowExtract(false)} onEnrich={onEnrich} />}
        {showSbom && <SbomModal onClose={() => setShowSbom(false)} />}
      </main>
    </>
  );
}

// ---------------------------------------------------------------------------
// News / advisories

function NewsView({ reloadKey, sources }: { reloadKey: number; sources: Source[] }) {
  const [items, setItems] = useState<Advisory[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pageSize] = useState(30);
  const [filters, setFilters] = useState<{ q: string; source: string }>({ q: "", source: "" });
  const [loading, setLoading] = useState(false);
  const pages = Math.max(1, Math.ceil(total / pageSize));

  const ref = useRef({ page, filters });
  ref.current = { page, filters };

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const { page, filters } = ref.current;
      const q: AdvisoryQuery = { page, pageSize: 30 };
      if (filters.q) q.q = filters.q;
      if (filters.source) q.source = filters.source;
      const p = await api.advisories(q);
      setItems(p.items); setTotal(p.total);
    } catch { /* offline */ } finally { setLoading(false); }
  }, []);

  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  }, [reloadKey, page, filters, load]);

  function setFilter<K extends "q" | "source">(k: K, v: string) {
    setFilters((f) => ({ ...f, [k]: v }));
    setPage(1);
  }

  return (
    <div>
      <div className="news-toolbar">
        <input className="news-search" placeholder="Search news & advisories…" value={filters.q} onChange={(e) => setFilter("q", e.target.value)} />
        <select className="page-size" value={filters.source} onChange={(e) => setFilter("source", e.target.value)} aria-label="Source">
          <option value="">All sources</option>
          {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
        </select>
      </div>
      {items.length === 0 && (
        <div className="panel" style={{ padding: 28, textAlign: "center" }}>
          <span className="muted">{total === 0 ? "No news yet — ensure the worker is running to pull feeds." : "No matches."}</span>
        </div>
      )}
      <div className="news-list">
        {items.map((a) => (
          <a className="panel news-card" key={`${a.source}:${a.id}`} href={a.url || "#"} target="_blank" rel="noopener noreferrer">
            <div className="news-meta">
              <span className="news-source">{a.source}</span>
              {a.category && <span className="news-cat">{a.category}</span>}
              <span className="muted">{formatDate(a.published)}</span>
              <ExternalLink size={13} className="news-ext" />
            </div>
            <div className="news-title">{a.title}</div>
            {a.summary && <div className="news-summary muted">{a.summary}</div>}
          </a>
        ))}
      </div>
      <div className="pager" style={{ borderTop: "none" }}>
        <span className="muted">{total.toLocaleString()} item{total === 1 ? "" : "s"}{loading ? " · loading…" : ""}</span>
        <div className="pager-controls">
          <button className="icon-btn" data-tooltip="Previous page" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}><ChevronLeft size={16} /></button>
          <span className="muted">Page {page} of {pages}</span>
          <button className="icon-btn" data-tooltip="Next page" disabled={page >= pages} onClick={() => setPage((p) => Math.min(pages, p + 1))}><ChevronRight size={16} /></button>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// World map (geolocated attack origins)

const WORLD_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json";
let worldCache: Geom[] | null = null;
async function loadWorld(): Promise<Geom[]> {
  if (worldCache) return worldCache;
  const res = await fetch(WORLD_URL);
  const topo = await res.json();
  worldCache = topologyToGeometries(topo, "countries");
  return worldCache;
}

const MAP_W = 1000;
const MAP_H = 500;
const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v));

function MapView({ reloadKey, onEnrich }: { reloadKey: number; onEnrich: (value: string, type: string) => void }) {
  const [points, setPoints] = useState<MapPoint[]>([]);
  const [land, setLand] = useState<Geom[]>([]);
  const [selected, setSelected] = useState<MapPoint | null>(null);
  const [ips, setIps] = useState<MapIndicator[]>([]);
  const [view, setView] = useState({ x: 0, y: 0, w: MAP_W, h: MAP_H });

  const proj = makeProjector(MAP_W, MAP_H);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const animRef = useRef<number | undefined>(undefined);
  const panRef = useRef<{ px: number; py: number; vx: number; vy: number } | null>(null);
  const viewRef = useRef(view);
  viewRef.current = view;

  // Smoothly tween the viewBox to a target frame.
  const animateTo = useCallback((target: { x: number; y: number; w: number; h: number }) => {
    if (animRef.current) cancelAnimationFrame(animRef.current);
    const start = { ...viewRef.current };
    const t0 = performance.now();
    const dur = 550;
    const ease = (t: number) => (t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2);
    const step = (now: number) => {
      const t = Math.min(1, (now - t0) / dur);
      const k = ease(t);
      setView({
        x: start.x + (target.x - start.x) * k,
        y: start.y + (target.y - start.y) * k,
        w: start.w + (target.w - start.w) * k,
        h: start.h + (target.h - start.h) * k,
      });
      if (t < 1) animRef.current = requestAnimationFrame(step);
    };
    animRef.current = requestAnimationFrame(step);
  }, []);

  // Wheel zoom centered on the cursor (native listener so preventDefault works).
  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      if (animRef.current) cancelAnimationFrame(animRef.current);
      const rect = svg.getBoundingClientRect();
      const v = viewRef.current;
      const mx = v.x + ((e.clientX - rect.left) / rect.width) * v.w;
      const my = v.y + ((e.clientY - rect.top) / rect.height) * v.h;
      const factor = e.deltaY > 0 ? 1.15 : 1 / 1.15;
      const w = clamp(v.w * factor, 30, MAP_W);
      const h = w * (MAP_H / MAP_W);
      const x = clamp(mx - ((mx - v.x) / v.w) * w, 0, MAP_W - w);
      const y = clamp(my - ((my - v.y) / v.h) * h, 0, MAP_H - h);
      setView({ x, y, w, h });
    };
    svg.addEventListener("wheel", onWheel, { passive: false });
    return () => svg.removeEventListener("wheel", onWheel);
  }, []);

  function onPointerDown(e: React.PointerEvent) {
    panRef.current = { px: e.clientX, py: e.clientY, vx: viewRef.current.x, vy: viewRef.current.y };
  }
  function onPointerMove(e: React.PointerEvent) {
    const pan = panRef.current;
    const svg = svgRef.current;
    if (!pan || !svg) return;
    const rect = svg.getBoundingClientRect();
    const v = viewRef.current;
    const dx = (e.clientX - pan.px) * (v.w / rect.width);
    const dy = (e.clientY - pan.py) * (v.h / rect.height);
    setView({ ...v, x: clamp(pan.vx - dx, 0, MAP_W - v.w), y: clamp(pan.vy - dy, 0, MAP_H - v.h) });
  }
  function endPan() { panRef.current = null; }

  useEffect(() => {
    api.map().then(setPoints).catch(() => {});
  }, [reloadKey]);

  useEffect(() => {
    loadWorld().then(setLand).catch(() => {}); // graceful: graticule-only if CDN blocked
  }, []);

  // When a country is selected, fetch its IPs and zoom to fit them.
  useEffect(() => {
    if (!selected) { setIps([]); return; }
    const code = selected.code ?? selected.country;
    api.mapIndicators(code).then((list) => {
      setIps(list);
      if (list.length) {
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        for (const i of list) {
          const [x, y] = proj(i.lng, i.lat);
          minX = Math.min(minX, x); maxX = Math.max(maxX, x);
          minY = Math.min(minY, y); maxY = Math.max(maxY, y);
        }
        const padX = Math.max(50, (maxX - minX) * 0.4);
        const padY = Math.max(35, (maxY - minY) * 0.4);
        let x = minX - padX, y = minY - padY;
        let w = (maxX - minX) + padX * 2, h = (maxY - minY) + padY * 2;
        // keep the 2:1 aspect ratio
        if (w / h < MAP_W / MAP_H) { const nw = h * (MAP_W / MAP_H); x -= (nw - w) / 2; w = nw; }
        else { const nh = w * (MAP_H / MAP_W); y -= (nh - h) / 2; h = nh; }
        w = Math.min(w, MAP_W); h = Math.min(h, MAP_H);
        animateTo({ x: clamp(x, 0, MAP_W - w), y: clamp(y, 0, MAP_H - h), w, h });
      } else {
        const [cx, cy] = proj(selected.lng, selected.lat);
        const w = 220, h = w * (MAP_H / MAP_W);
        animateTo({ x: clamp(cx - w / 2, 0, MAP_W - w), y: clamp(cy - h / 2, 0, MAP_H - h), w, h });
      }
    }).catch(() => setIps([]));
  }, [selected]);

  function reset() {
    setSelected(null);
    animateTo({ x: 0, y: 0, w: MAP_W, h: MAP_H });
  }

  const scale = view.w / MAP_W; // shrink markers as we zoom so on-screen size stays steady
  const max = points.reduce((m, p) => Math.max(m, p.count), 1);
  const radius = (c: number) => (4 + Math.sqrt(c / max) * 22) * scale;

  // Spread co-located IPs (city-level geo stacks many on one point) into a ring.
  const sizeByKey = new Map<string, number>();
  for (const ip of ips) {
    const k = `${ip.lat.toFixed(2)},${ip.lng.toFixed(2)}`;
    sizeByKey.set(k, (sizeByKey.get(k) ?? 0) + 1);
  }
  const seenByKey = new Map<string, number>();
  const placedIps = ips.map((ip) => {
    const k = `${ip.lat.toFixed(2)},${ip.lng.toFixed(2)}`;
    const idx = seenByKey.get(k) ?? 0;
    seenByKey.set(k, idx + 1);
    const size = sizeByKey.get(k)!;
    let [x, y] = proj(ip.lng, ip.lat);
    if (size > 1) {
      const ang = (2 * Math.PI * idx) / size;
      const spread = 7 * scale * Math.min(2.6, 0.8 + size * 0.1);
      x += Math.cos(ang) * spread;
      y += Math.sin(ang) * spread;
    }
    return { ip, x, y };
  });

  const graticule: React.ReactNode[] = [];
  for (let lng = -150; lng <= 150; lng += 30) {
    const [x] = proj(lng, 0);
    graticule.push(<line key={`v${lng}`} x1={x} y1={0} x2={x} y2={MAP_H} />);
  }
  for (let lat = -60; lat <= 60; lat += 30) {
    const [, y] = proj(0, lat);
    graticule.push(<line key={`h${lat}`} x1={0} y1={y} x2={MAP_W} y2={y} />);
  }

  return (
    <div className="map-layout">
      <div className="panel map-wrap">
        <svg
          ref={svgRef}
          viewBox={`${view.x} ${view.y} ${view.w} ${view.h}`}
          className="worldmap"
          preserveAspectRatio="xMidYMid meet"
          onPointerDown={onPointerDown}
          onPointerMove={onPointerMove}
          onPointerUp={endPan}
          onPointerLeave={endPan}
          onDoubleClick={() => {
            const v = viewRef.current;
            const w = clamp(v.w / 1.8, 30, MAP_W);
            const h = w * (MAP_H / MAP_W);
            animateTo({ x: clamp(v.x + (v.w - w) / 2, 0, MAP_W - w), y: clamp(v.y + (v.h - h) / 2, 0, MAP_H - h), w, h });
          }}
        >
          <rect x={0} y={0} width={MAP_W} height={MAP_H} className="map-bg" />
          <g className="graticule">{graticule}</g>
          <g className="map-land-group">
            {land.map((g, i) => <path key={i} className="map-land" d={geomToPath(g, proj)} style={{ strokeWidth: 0.5 * scale }} />)}
          </g>

          {/* Aggregate country points (clickable) when nothing is selected */}
          {!selected && points.map((p, i) => {
            const [x, y] = proj(p.lng, p.lat);
            return (
              <g key={i} className="map-point" onClick={() => setSelected(p)}>
                <circle cx={x} cy={y} r={radius(p.count)} className="map-glow" />
                <circle cx={x} cy={y} r={Math.max(2.5 * scale, radius(p.count) * 0.34)} className="map-core" />
                <title>{p.country}: {p.count} — click to zoom</title>
              </g>
            );
          })}

          {/* Individual IP markers for the selected country (co-located ones spread into a ring) */}
          {selected && placedIps.map(({ ip, x, y }, i) => (
            <g key={i}>
              <circle cx={x} cy={y} r={5 * scale} className="map-glow" />
              <circle cx={x} cy={y} r={2.2 * scale} className="map-core" />
              <title>{ip.value}{ip.malware ? ` — ${ip.malware}` : ""}</title>
            </g>
          ))}
        </svg>
        {points.length === 0 && (
          <div className="map-empty muted">
            No geolocated indicators yet — the worker geolocates IP indicators on each enrichment cycle.
          </div>
        )}
        {selected && (
          <button className="chip map-reset" onClick={reset}><ChevronLeft size={14} /> All origins</button>
        )}
      </div>

      <div className="panel map-side">
        {!selected ? (
          <>
            <div className="ov-card-title">Top Origins</div>
            {points.length === 0 && <div className="muted ov-empty">Awaiting geo data…</div>}
            {points.slice(0, 20).map((p, i) => (
              <div className="ov-row map-origin" key={i} onClick={() => setSelected(p)} title="Click to zoom">
                <span className="badge info">{p.count}</span>
                <div className="ov-row-text">
                  <div className="ov-primary">{p.country}{p.code ? ` (${p.code})` : ""}</div>
                </div>
              </div>
            ))}
          </>
        ) : (
          <>
            <div className="ov-card-title">
              {selected.country} · {ips.length} indicator{ips.length === 1 ? "" : "s"}
            </div>
            {ips.length === 0 && <div className="muted ov-empty">No located indicators.</div>}
            {ips.map((ip, i) => (
              <div className="ov-row map-origin" key={i} onClick={() => onEnrich(ip.value, ip.type)} title="Enrich / pivot">
                <span className={`badge ioc-${ip.type}`}>{ip.type}</span>
                <div className="ov-row-text">
                  <div className="ov-primary ioc-value" style={{ maxWidth: "100%" }}>{ip.value}</div>
                  {ip.malware && <div className="muted ov-secondary">{ip.malware}</div>}
                </div>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Overview (command center)

function Overview({ reloadKey, stats }: { reloadKey: number; stats: Stats | null }) {
  const [digest, setDigest] = useState<Digest | null>(null);
  const [correlations, setCorrelations] = useState<Correlation[]>([]);
  const [attack, setAttack] = useState<AttackTechnique[]>([]);
  const [preview, setPreview] = useState<null | "html" | "md">(null);

  useEffect(() => {
    api.digest().then(setDigest).catch(() => {});
    api.correlations().then(setCorrelations).catch(() => {});
    api.attack().then(setAttack).catch(() => {});
  }, [reloadKey]);

  // While the preview modal is open: Esc closes it and the background is locked.
  useEffect(() => {
    if (!preview) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setPreview(null); };
    window.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [preview]);

  const tl = stats ? threatLevel(stats) : null;

  return (
    <>
      {tl && (
        <div className={`threat-banner tone-${tl.tone}`}>
          <div className="tl-badge">
            <span className="tl-num">{tl.level}</span>
          </div>
          <div className="tl-main">
            <div className="tl-label">Threat level: {tl.label}</div>
            <div className="tl-note">{digest?.headline ?? tl.note}</div>
          </div>
        </div>
      )}

      <div className="brief-head">
        <div className="section-head" style={{ margin: 0 }}>
          <h2>Daily Brief{digest && <span className="muted"> · {digest.date}</span>}</h2>
        </div>
        <div className="spacer" />
        <button className="chip" onClick={() => setPreview("html")} title="Preview the HTML email brief" disabled={!digest}>
          <FileText size={14} /> Email preview
        </button>
        <button className="chip" onClick={() => setPreview("md")} title="View the Markdown brief" disabled={!digest}>
          <FileText size={14} /> Markdown
        </button>
      </div>

      <div className="overview-grid">
        {digest?.sections.map((s) => (
          <div className="panel ov-card" key={s.title}>
            <div className="ov-card-title">{s.title}</div>
            {s.items.length === 0 ? (
              <div className="muted ov-empty">{s.empty}</div>
            ) : (
              s.items.map((it, idx) => (
                <div className="ov-row" key={idx}>
                  {it.badge && <span className={`badge ${toneBadgeClass(it.tone)}`}>{it.badge}</span>}
                  <div className="ov-row-text">
                    <div className="ov-primary">{it.primary}</div>
                    {it.secondary && <div className="muted ov-secondary">{it.secondary}</div>}
                  </div>
                </div>
              ))
            )}
          </div>
        ))}
        {!digest && <div className="muted" style={{ padding: 20 }}>Loading brief… (start the API to populate)</div>}
      </div>

      <div className="section-head" style={{ marginTop: 24 }}>
        <h2>Cross-Source Correlations</h2>
      </div>
      <div className="panel" style={{ padding: 16 }}>
        {correlations.length === 0 ? (
          <div className="muted ov-empty">
            No CVE references found in current indicators yet. IOC feeds only sometimes cite CVEs — links appear here when they do.
          </div>
        ) : (
          correlations.map((c) => (
            <div className="ov-row" key={c.cveId}>
              <span className={`badge ${c.riskScore != null ? riskBand(c.riskScore) : "info"}`}>
                {c.riskScore != null ? c.riskScore : "—"}
              </span>
              <div className="ov-row-text">
                <div className="ov-primary">
                  <span className="cve">{c.cveId}</span>
                  {c.title ? ` — ${c.title}` : <span className="muted"> (not in tracked CVEs)</span>}
                </div>
                <div className="muted ov-secondary">
                  {c.indicators.length} related indicator{c.indicators.length === 1 ? "" : "s"}
                  {c.indicators[0] && ` · e.g. ${c.indicators[0].value}${c.indicators[0].malware ? ` (${c.indicators[0].malware})` : ""}`}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="section-head" style={{ marginTop: 24 }}>
        <h2>ATT&amp;CK Techniques in Intel</h2>
      </div>
      <div className="panel" style={{ padding: 16 }}>
        {attack.length === 0 ? (
          <div className="muted ov-empty">No ATT&amp;CK / ATLAS technique IDs found in current intel yet — they appear as feeds reference them.</div>
        ) : (
          <div className="attack-grid">
            {attack.map((t) => (
              <a
                className="attack-chip"
                key={t.id}
                href={t.framework === "atlas"
                  ? `https://atlas.mitre.org/techniques/${t.id}`
                  : `https://attack.mitre.org/techniques/${t.id.replace(".", "/")}`}
                target="_blank"
                rel="noopener noreferrer"
              >
                <span className={`badge ${t.framework === "atlas" ? "ioc-domain" : "info"}`}>{t.framework === "atlas" ? "ATLAS" : "ATT&CK"}</span>
                <span className="attack-id">{t.id}</span>
                <span className="muted">×{t.count}</span>
              </a>
            ))}
          </div>
        )}
      </div>

      {preview && digest && (
        <div className="modal-backdrop" onClick={() => setPreview(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="modal-head">
              <div className="modal-title">Daily Brief · {digest.date}</div>
              <div className="spacer" />
              <button
                className="chip"
                onClick={() =>
                  preview === "html"
                    ? downloadBlob("omnisight-brief.html", digest.html, "text/html")
                    : downloadBlob("omnisight-brief.md", digest.markdown, "text/markdown")
                }
              >
                <Download size={14} /> Download
              </button>
              <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={() => setPreview(null)}>
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              {preview === "html"
                ? <iframe className="brief-frame" srcDoc={digest.html} title="Daily brief email" />
                : <pre className="brief-md">{digest.markdown}</pre>}
            </div>
          </div>
        </div>
      )}
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

function VulnGrid({ reloadKey, sources, terms, onDetail }: { reloadKey: number; sources: Source[]; terms: string[]; onDetail: (v: Vulnerability) => void }) {
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

  function exportParams(): VulnQuery {
    const q: VulnQuery = { sort: sort.field, dir: sort.dir };
    if (filters.q) q.q = filters.q;
    if (filters.vendor) q.vendor = filters.vendor;
    if (filters.source) q.source = filters.source;
    if (filters.minRisk) q.minRisk = filters.minRisk;
    if (filters.flag === "exploited") q.exploited = true;
    if (filters.flag === "ransomware") q.ransomware = true;
    if (filters.myStack) q.myStack = true;
    return q;
  }

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
        <div className="spacer" />
        <button className="chip" onClick={() => download(api.exportVulnUrl(exportParams()))} title="Download current view as CSV">
          <Download size={14} /> Export CSV
        </button>
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
                  <span className="pivot" onClick={() => onDetail(v)} title="View full details">
                    {v.cveId ?? v.id}
                  </span>
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
                <td className="muted"><SourceCell source={v.source} reliability={reliabilityOf(sources, v.source)} /></td>
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

interface IocFilters { q: string; type: string; source: string; fresh: boolean }
const EMPTY_IOC_FILTERS: IocFilters = { q: "", type: "", source: "", fresh: false };

function IndicatorGrid({ reloadKey, sources, onEnrich, canWrite }: { reloadKey: number; sources: Source[]; onEnrich: (value: string, type: string) => void; canWrite: boolean }) {
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
      if (filters.fresh) q.maxAgeDays = 90;
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

  function exportParams(): IndicatorQuery {
    const q: IndicatorQuery = { sort: sort.field, dir: sort.dir };
    if (filters.q) q.q = filters.q;
    if (filters.type) q.type = filters.type;
    if (filters.source) q.source = filters.source;
    return q;
  }

  return (
    <div className="panel">
      <div className="grid-toolbar">
        <button
          className={`chip ${filters.fresh ? "on" : ""}`}
          onClick={() => setFilter("fresh", !filters.fresh)}
          title="Show only indicators seen in the last 90 days"
        >
          <Activity size={14} /> Fresh (90d)
        </button>
        <div className="spacer" />
        <span className="muted">Export:</span>
        <button className="chip" onClick={() => download(api.exportIndicatorUrl(exportParams(), "csv"))} title="Download as CSV">
          <Download size={14} /> CSV
        </button>
        <button className="chip" onClick={() => download(api.exportIndicatorUrl(exportParams(), "stix"))} title="STIX 2.1 bundle (OpenCTI/MISP)">
          STIX
        </button>
        <button className="chip" onClick={() => download(api.exportIndicatorUrl(exportParams(), "blocklist"))} title="Plain blocklist for firewalls/IDS">
          Blocklist
        </button>
        <button className="chip" onClick={() => download(api.exportIndicatorUrl(exportParams(), "sigma"))} title="Sigma detection rules (SIEM)">
          Sigma
        </button>
        <button className="chip" onClick={() => download(api.exportIndicatorUrl(exportParams(), "yara"))} title="YARA rules">
          YARA
        </button>
        <button className="chip" onClick={() => download(api.exportIndicatorUrl(exportParams(), "snort"))} title="Suricata/Snort rules">
          Snort
        </button>
        {canWrite && (
          <label className="chip" style={{ cursor: "pointer" }} title="Import a STIX 2.1 bundle">
            Import STIX
            <input
              type="file"
              accept=".json,application/json"
              style={{ display: "none" }}
              onChange={async (e) => {
                const file = e.target.files?.[0];
                if (!file) return;
                try { await api.importStix(JSON.parse(await file.text())); load(); } catch { /* invalid */ }
                e.target.value = "";
              }}
            />
          </label>
        )}
      </div>
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
              <td className="ioc-value pivot" onClick={() => onEnrich(i.value, i.type)} title="Enrich / pivot">{i.value}</td>
              <td>{i.malware ?? "—"}</td>
              <td className="muted">{i.threatType ?? "—"}</td>
              <td className="muted">{i.confidence != null ? `${i.confidence}%` : "—"}</td>
              <td className="muted">
                {formatDate(i.lastSeen)}
                {isStale(i.lastSeen) && <span className="badge stale" title="Last seen over 90 days ago">stale</span>}
              </td>
              <td className="muted"><SourceCell source={i.source} reliability={reliabilityOf(sources, i.source)} /></td>
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

function SbomModal({ onClose }: { onClose: () => void }) {
  const [report, setReport] = useState<import("./api.ts").SbomReport | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [fileName, setFileName] = useState("");

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name); setError(""); setReport(null); setBusy(true);
    try {
      const obj = JSON.parse(await file.text());
      setReport(await api.sbom(obj));
    } catch (err) {
      setError(`Could not scan: ${(err as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">SBOM Scan {report && <span className="muted">· {report.vulnerable}/{report.total} components vulnerable</span>}</div>
          <div className="spacer" />
          <label className="chip" style={{ cursor: "pointer" }}>
            <Package size={14} /> Choose file
            <input type="file" accept=".json,application/json" style={{ display: "none" }} onChange={onFile} />
          </label>
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          {!report && !busy && !error && (
            <div className="muted ov-empty">Upload a CycloneDX or SPDX SBOM (JSON). Components are matched against OSV — keyless, no upload leaves your machine except component coordinates.</div>
          )}
          {busy && <div className="muted" style={{ padding: 12 }}>Scanning {fileName} against OSV…</div>}
          {error && <div className="muted ov-empty" style={{ color: "var(--critical)" }}>{error}</div>}
          {report && (
            <div className="panel" style={{ padding: 0 }}>
              <table>
                <thead><tr><th>Component</th><th>Ecosystem</th><th>Version</th><th>Vulnerabilities</th></tr></thead>
                <tbody>
                  {report.components.map((c) => (
                    <tr key={c.purl}>
                      <td className="ioc-value">{c.name}</td>
                      <td className="muted">{c.ecosystem}</td>
                      <td className="muted">{c.version}</td>
                      <td>
                        {c.vulns.length === 0 ? <span className="muted">—</span> : c.vulns.map((id) => (
                          <a key={id} className="badge critical" style={{ marginRight: 4, textDecoration: "none" }}
                            href={`https://osv.dev/vulnerability/${id}`} target="_blank" rel="noopener noreferrer">{id}</a>
                        ))}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ExtractModal({ onClose, onEnrich }: { onClose: () => void; onEnrich: (value: string, type: string) => void }) {
  const [text, setText] = useState("");
  const [fanged, setFanged] = useState(false); // defang output for safe sharing
  const iocs: ExtractedIocs | null = text.trim() ? extractIocs(text) : null;
  const fmt = (v: string) => (fanged ? defang(v) : v);
  const total = iocs ? iocs.ips.length + iocs.domains.length + iocs.urls.length + iocs.hashes.length + iocs.cves.length : 0;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  const copy = (items: string[]) => { navigator.clipboard?.writeText(items.map(fmt).join("\n")).catch(() => {}); };

  function Group({ title, items, type }: { title: string; items: string[]; type?: string }) {
    if (items.length === 0) return null;
    return (
      <div className="extract-group">
        <div className="extract-group-head">
          <span className="ov-card-title" style={{ margin: 0 }}>{title} <span className="muted">({items.length})</span></span>
          <button className="icon-btn" data-tooltip="Copy" aria-label="Copy" onClick={() => copy(items)}><Copy size={14} /></button>
        </div>
        {items.map((v) => (
          <div className="extract-row" key={v}>
            <span className="ioc-value">{fmt(v)}</span>
            {type === "ip" && <button className="chip mini" onClick={() => onEnrich(v, "ip")}>enrich</button>}
          </div>
        ))}
      </div>
    );
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">Extract IOCs {total > 0 && <span className="muted">· {total} found</span>}</div>
          <div className="spacer" />
          <label className="chip" style={{ cursor: "pointer" }}>
            <input type="checkbox" checked={fanged} onChange={(e) => setFanged(e.target.checked)} style={{ marginRight: 6 }} />
            Defang output
          </label>
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <textarea
            className="note-input"
            style={{ width: "100%", minHeight: 120 }}
            placeholder="Paste an email, report, or chat log — IOCs are extracted automatically (defanged input like 1[.]2[.]3[.]4 and hxxp:// is handled)."
            value={text}
            onChange={(e) => setText(e.target.value)}
          />
          {iocs && total === 0 && <div className="muted ov-empty">No IOCs found.</div>}
          {iocs && total > 0 && (
            <div className="extract-results">
              <Group title="IPs" items={iocs.ips} type="ip" />
              <Group title="Domains" items={iocs.domains} />
              <Group title="URLs" items={iocs.urls} />
              <Group title="Hashes" items={iocs.hashes} />
              <Group title="CVEs" items={iocs.cves} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

const TLP_LEVELS = ["clear", "green", "amber", "red"] as const;

function NotesSection({ refKey, canWrite }: { refKey: string; canWrite: boolean }) {
  const [notes, setNotes] = useState<import("./api.ts").Note[]>([]);
  const [body, setBody] = useState("");
  const [tlp, setTlp] = useState<string>("amber");
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api.notes(refKey).then(setNotes).catch(() => setNotes([])).finally(() => setLoading(false));
  }, [refKey]);
  useEffect(() => { load(); }, [load]);

  async function add(e: FormEvent) {
    e.preventDefault();
    if (!body.trim()) return;
    try { await api.addNote(refKey, tlp, body.trim()); setBody(""); load(); } catch { /* offline */ }
  }
  async function remove(id: string) {
    try { await api.deleteNote(id); load(); } catch { /* offline */ }
  }

  return (
    <div className="notes-section">
      <div className="ov-card-title">Notes</div>
      {canWrite && (
        <form onSubmit={add} className="note-form">
          <select className="page-size" value={tlp} onChange={(e) => setTlp(e.target.value)} aria-label="TLP">
            {TLP_LEVELS.map((l) => <option key={l} value={l}>TLP:{l.toUpperCase()}</option>)}
          </select>
          <textarea className="note-input" value={body} onChange={(e) => setBody(e.target.value)} placeholder="Add an investigation note…" rows={2} />
          <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
        </form>
      )}
      {loading && <div className="muted" style={{ padding: 8 }}>Loading…</div>}
      {!loading && notes.length === 0 && <div className="muted ov-empty">No notes yet.</div>}
      {notes.map((n) => (
        <div className="note" key={n.id}>
          <div className="note-meta">
            <span className={`badge tlp-${n.tlp}`}>TLP:{n.tlp.toUpperCase()}</span>
            <span className="muted">{new Date(n.createdAt).toLocaleString()}</span>
            <div className="spacer" />
            {canWrite && <button className="icon-btn note-del" data-tooltip="Delete" aria-label="Delete note" onClick={() => remove(n.id)}><X size={14} /></button>}
          </div>
          <div className="note-body">{n.body}</div>
        </div>
      ))}
    </div>
  );
}

function VulnDetailModal({ v, onClose, canWrite, aiEnabled }: { v: Vulnerability; onClose: () => void; canWrite: boolean; aiEnabled: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  const band = riskBand(v.riskScore);
  const cve = v.cveId ?? v.id;
  const [summary, setSummary] = useState("");
  const [summarizing, setSummarizing] = useState(false);
  const [aiErr, setAiErr] = useState("");
  async function summarize() {
    setSummarizing(true); setAiErr("");
    try {
      const text = `${cve}: ${v.title}\n\n${v.description}\n\nVendor: ${v.vendor ?? "?"} ${v.product ?? ""}. CVSS ${v.cvss ?? "n/a"}, EPSS ${v.epss ?? "n/a"}.${v.knownExploited ? " Known exploited." : ""}`;
      const r = await api.aiSummarize(text);
      setSummary(r.summary);
    } catch { setAiErr("Summarization failed — check the AI/Ollama connection."); }
    finally { setSummarizing(false); }
  }
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><span className="cve">{cve}</span> <span className={`badge ${band}`}>{v.riskScore}</span></div>
          <div className="spacer" />
          {v.cveId && (
            <a className="chip" href={`https://nvd.nist.gov/vuln/detail/${v.cveId}`} target="_blank" rel="noopener noreferrer"><ExternalLink size={14} /> NVD</a>
          )}
          {aiEnabled && (
            <button className="icon-btn" data-tooltip="Summarize with AI" aria-label="Summarize with AI" disabled={summarizing} onClick={summarize}>
              <Sparkles size={16} className={summarizing ? "pulse" : ""} />
            </button>
          )}
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 18 }}>
          <div className="vuln-title">{v.title}</div>
          <div className="vuln-flags">
            {v.knownExploited && <span className="flag">EXPLOITED (KEV)</span>}
            {v.ransomwareUse && <span className="flag"> · RANSOMWARE</span>}
          </div>
          {v.description && <p className="vuln-desc">{v.description}</p>}
          {(summary || aiErr) && (
            <div className="ai-summary">
              <div className="ov-card-title"><Sparkles size={13} /> AI summary</div>
              {aiErr ? <p className="login-error">{aiErr}</p> : <p className="vuln-desc">{summary}</p>}
            </div>
          )}
          <div className="vuln-facts">
            <EnrichRow label="Vendor / product" val={[v.vendor, v.product].filter(Boolean).join(" / ") || "—"} />
            <EnrichRow label="CVSS" val={v.cvss != null ? String(v.cvss) : "—"} />
            <EnrichRow label="EPSS" val={v.epss != null ? `${(v.epss * 100).toFixed(1)}%` : "—"} />
            <EnrichRow label="CWEs" val={v.cwes.length ? v.cwes.join(", ") : "—"} />
            <EnrichRow label="Reported" val={formatDate(v.dateAdded)} />
            {v.dueDate && <EnrichRow label="Remediation due" val={formatDate(v.dueDate)} />}
            <EnrichRow label="Source" val={v.source} />
          </div>
          {v.requiredAction && (
            <div className="vuln-action">
              <div className="ov-card-title">Required action</div>
              <p className="vuln-desc">{v.requiredAction}</p>
            </div>
          )}
          {v.references.length > 0 && (
            <div className="vuln-refs">
              <div className="ov-card-title">References</div>
              {v.references.map((r) => (
                <a key={r} className="vuln-ref" href={r} target="_blank" rel="noopener noreferrer">{r}</a>
              ))}
            </div>
          )}
          <NotesSection refKey={`cve:${cve}`} canWrite={canWrite} />
        </div>
      </div>
    </div>
  );
}

function EnrichRow({ label, val, crit }: { label: string; val: string; crit?: boolean }) {
  return (
    <div className="enrich-row">
      <span className="muted">{label}</span>
      <span className={crit ? "crit-text" : ""}>{val}</span>
    </div>
  );
}

function EnrichModal({ target, onClose, canWrite }: { target: { value: string; type: string }; onClose: () => void; canWrite: boolean }) {
  const [data, setData] = useState<import("./api.ts").IocEnrichment | null>(null);
  const [loading, setLoading] = useState(true);
  const ipForLinks = target.value.split(":")[0];

  useEffect(() => {
    setLoading(true);
    api.enrichIoc(target.value, target.type).then(setData).catch(() => setData(null)).finally(() => setLoading(false));
  }, [target.value, target.type]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  const hasAny = data && (data.shodan || data.greynoise || data.abuseipdb);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title ioc-value">{target.value}</div>
          <div className="spacer" />
          <a className="chip" href={`https://www.virustotal.com/gui/search/${encodeURIComponent(ipForLinks)}`} target="_blank" rel="noopener noreferrer">
            <ExternalLink size={14} /> VirusTotal
          </a>
          <a className="chip" href={`https://www.shodan.io/host/${encodeURIComponent(ipForLinks)}`} target="_blank" rel="noopener noreferrer">
            <ExternalLink size={14} /> Shodan
          </a>
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          {loading && <div className="muted" style={{ padding: 20 }}>Enriching…</div>}
          {!loading && data && (
            <div className="enrich">
              {data.shodan && (
                <div className="panel enrich-card">
                  <div className="ov-card-title">Shodan InternetDB</div>
                  <EnrichRow label="Open ports" val={data.shodan.ports.join(", ") || "—"} />
                  <EnrichRow label="Hostnames" val={data.shodan.hostnames.join(", ") || "—"} />
                  <EnrichRow label="Tags" val={data.shodan.tags.join(", ") || "—"} />
                  <EnrichRow label="Known CVEs" val={data.shodan.vulns.join(", ") || "—"} crit={data.shodan.vulns.length > 0} />
                </div>
              )}
              {data.greynoise && (
                <div className="panel enrich-card">
                  <div className="ov-card-title">GreyNoise</div>
                  <EnrichRow label="Classification" val={data.greynoise.classification} crit={data.greynoise.classification === "malicious"} />
                  <EnrichRow label="Internet scanner" val={data.greynoise.noise ? "yes" : "no"} />
                  <EnrichRow label="Benign (RIOT)" val={data.greynoise.riot ? "yes" : "no"} />
                  {data.greynoise.name && <EnrichRow label="Actor / tool" val={data.greynoise.name} />}
                </div>
              )}
              {data.abuseipdb && (
                <div className="panel enrich-card">
                  <div className="ov-card-title">AbuseIPDB</div>
                  <EnrichRow label="Abuse score" val={`${data.abuseipdb.score}%`} crit={data.abuseipdb.score >= 50} />
                  <EnrichRow label="Reports" val={String(data.abuseipdb.reports)} />
                  <EnrichRow label="Country" val={data.abuseipdb.countryCode ?? "—"} />
                  {data.abuseipdb.isp && <EnrichRow label="ISP" val={data.abuseipdb.isp} />}
                </div>
              )}
              {!hasAny && (
                <div className="muted" style={{ padding: 20 }}>{data.errors[0] ?? "No enrichment data available."}</div>
              )}
              {hasAny && data.errors.length > 0 && (
                <div className="muted enrich-errors">{data.errors.join("; ")}</div>
              )}
            </div>
          )}
          <NotesSection refKey={`ioc:${target.value}`} canWrite={canWrite} />
        </div>
      </div>
    </div>
  );
}

function Login({ onLogin, theme }: { onLogin: (u: User) => void; theme: "dark" | "light" }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState<{ enabled: boolean; label: string }>({ enabled: false, label: "SSO" });
  useEffect(() => { document.documentElement.setAttribute("data-theme", theme); }, [theme]);
  useEffect(() => {
    api.authConfig().then((c) => setSso({ enabled: Boolean(c.sso), label: c.ssoLabel || "SSO" })).catch(() => {});
  }, []);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      const r = await api.login(username, password);
      setToken(r.token);
      onLogin(r.user);
    } catch {
      setError("Invalid username or password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-wrap">
      <form className="panel login-card" onSubmit={submit}>
        <div className="brand" style={{ justifyContent: "center", marginBottom: 14 }}>
          <Radar size={26} className="mark" />
          <div>OmniSight <br /><small>Cyber Situational Awareness</small></div>
        </div>
        <div className="login-title"><Lock size={14} /> Sign in</div>
        <input className="note-input" placeholder="Username" value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
        <input className="note-input" type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} />
        {error && <div className="login-error">{error}</div>}
        <button className="btn-primary" type="submit" disabled={busy} style={{ justifyContent: "center" }}>{busy ? "Signing in…" : "Sign in"}</button>
        {sso.enabled && (
          <>
            <div className="login-or"><span>or</span></div>
            <a className="btn-secondary" href="/api/auth/sso/login" style={{ justifyContent: "center" }}>
              <KeyRound size={14} /> Sign in with {sso.label}
            </a>
          </>
        )}
      </form>
    </div>
  );
}

function UsersPanel({ onClose, meId }: { onClose: () => void; meId: string | null }) {
  const [users, setUsers] = useState<User[]>([]);
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [role, setRole] = useState("viewer");
  const [error, setError] = useState("");

  const load = useCallback(() => { api.users().then(setUsers).catch(() => {}); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  async function add(e: FormEvent) {
    e.preventDefault();
    setError("");
    try { await api.createUser(u, p, role); setU(""); setP(""); load(); }
    catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title">Users</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <form onSubmit={add} className="user-form">
            <input className="note-input" placeholder="username" value={u} onChange={(e) => setU(e.target.value)} />
            <input className="note-input" type="password" placeholder="password" value={p} onChange={(e) => setP(e.target.value)} />
            <select className="page-size" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="viewer">viewer</option>
              <option value="analyst">analyst</option>
              <option value="admin">admin</option>
            </select>
            <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
          </form>
          {error && <div className="login-error">{error}</div>}
          {users.map((usr) => (
            <div className="ov-row" key={usr.id}>
              <div className="ov-row-text"><div className="ov-primary">{usr.username}{usr.id === meId && <span className="muted"> (you)</span>}</div></div>
              <div className="spacer" />
              <select className="page-size" value={usr.role} onChange={(e) => { api.setUserRole(usr.id, e.target.value).then(load).catch(() => {}); }}>
                <option value="viewer">viewer</option>
                <option value="analyst">analyst</option>
                <option value="admin">admin</option>
              </select>
              {usr.id !== meId && (
                <button className="icon-btn note-del" data-tooltip="Delete" aria-label="Delete user" onClick={() => api.deleteUser(usr.id).then(load).catch(() => {})}><Trash2 size={14} /></button>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function techniqueUrl(id: string): string {
  return id.startsWith("AML")
    ? `https://atlas.mitre.org/techniques/${id}`
    : `https://attack.mitre.org/techniques/${id.replace(".", "/")}`;
}

// ---------------------------------------------------------------------------
// Actor / campaign profiles

function ActorsView({ reloadKey, onEnrich }: { reloadKey: number; onEnrich: (value: string, type: string) => void }) {
  const [actors, setActors] = useState<ActorProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    api.actors().then(setActors).catch(() => setActors([])).finally(() => setLoading(false));
  }, [reloadKey]);

  const filtered = actors.filter((a) => a.name.toLowerCase().includes(q.toLowerCase()));

  return (
    <section className="panel">
      <div className="grid-toolbar">
        <div className="toolbar-title"><Bug size={16} /> Actor &amp; campaign profiles <span className="muted">({actors.length})</span></div>
        <div className="spacer" />
        <input className="note-input" style={{ maxWidth: 220 }} placeholder="Filter by malware/campaign…" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {loading && <div className="empty">Loading…</div>}
      {!loading && filtered.length === 0 && <div className="empty">No actor profiles yet — they build up as malware-tagged indicators are ingested.</div>}
      <div className="actor-grid">
        {filtered.map((a) => {
          const isOpen = open === a.name;
          return (
            <div className={`actor-card ${isOpen ? "open" : ""}`} key={a.name}>
              <button className="actor-head" onClick={() => setOpen(isOpen ? null : a.name)}>
                <div className="actor-name">{a.name}</div>
                <span className="badge rel-A">{a.indicatorCount} IOC{a.indicatorCount === 1 ? "" : "s"}</span>
              </button>
              <div className="actor-types">
                {Object.entries(a.types).map(([t, n]) => <span className="chip" key={t}>{t} · {n}</span>)}
              </div>
              <div className="actor-meta muted">
                {a.sources.length} source{a.sources.length === 1 ? "" : "s"} · last seen {formatDate(a.lastSeen)}
              </div>
              {isOpen && (
                <div className="actor-detail">
                  {a.cves.length > 0 && (
                    <div className="actor-block">
                      <div className="ov-card-title">Related CVEs</div>
                      <div className="actor-chips">
                        {a.cves.map((c) => <a className="chip" key={c} href={`https://nvd.nist.gov/vuln/detail/${c}`} target="_blank" rel="noopener noreferrer">{c}</a>)}
                      </div>
                    </div>
                  )}
                  {a.techniques.length > 0 && (
                    <div className="actor-block">
                      <div className="ov-card-title">Techniques</div>
                      <div className="actor-chips">
                        {a.techniques.map((t) => <a className="chip" key={t} href={techniqueUrl(t)} target="_blank" rel="noopener noreferrer">{t}</a>)}
                      </div>
                    </div>
                  )}
                  <div className="actor-block">
                    <div className="ov-card-title">Sample indicators</div>
                    <div className="actor-chips">
                      {a.sampleIocs.map((s) => (
                        s.type === "ip"
                          ? <button className="chip mono" key={s.value} onClick={() => onEnrich(s.value, s.type)} data-tooltip="Enrich">{defang(s.value)}</button>
                          : <span className="chip mono" key={s.value}>{defang(s.value)}</span>
                      ))}
                    </div>
                  </div>
                  <div className="actor-block muted">Sources: {a.sources.join(", ")}</div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

// ---------------------------------------------------------------------------
// Ask AI — natural-language vulnerability query

function AskAiModal({ onClose, onDetail }: { onClose: () => void; onDetail: (v: Vulnerability) => void }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [filters, setFilters] = useState<Record<string, unknown> | null>(null);
  const [items, setItems] = useState<Vulnerability[]>([]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  async function run(e: FormEvent) {
    e.preventDefault();
    if (!q.trim()) return;
    setBusy(true); setErr(""); setFilters(null); setItems([]);
    try {
      const r = await api.aiQuery(q.trim());
      setFilters(r.filters); setItems(r.items);
    } catch { setErr("Query failed — check the AI/Ollama connection."); }
    finally { setBusy(false); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Sparkles size={16} /> Ask AI</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <form onSubmit={run} className="ask-form">
            <input className="note-input" autoFocus placeholder='e.g. "exploited Cisco bugs, highest risk first"' value={q} onChange={(e) => setQ(e.target.value)} />
            <button className="btn-primary" type="submit" disabled={busy}><Sparkles size={16} /> {busy ? "Thinking…" : "Ask"}</button>
          </form>
          <div className="muted" style={{ fontSize: 12, margin: "6px 0 10px" }}>The model translates your question into filters, then OmniSight runs them against the live data.</div>
          {err && <div className="login-error">{err}</div>}
          {filters && (
            <div className="actor-chips" style={{ marginBottom: 10 }}>
              {Object.entries(filters).map(([k, v]) => <span className="chip" key={k}>{k}: {String(v)}</span>)}
              {Object.keys(filters).length === 0 && <span className="muted">No filters inferred — showing top results.</span>}
            </div>
          )}
          {items.map((v) => (
            <div className="ov-row" key={`${v.source}:${v.id}`} onClick={() => { onDetail(v); onClose(); }} style={{ cursor: "pointer" }}>
              <span className={`badge ${riskBand(v.riskScore)}`}>{v.riskScore}</span>
              <div className="ov-row-text">
                <div className="ov-primary">{v.cveId ?? v.id}{v.knownExploited && <span className="flag"> EXPLOITED</span>}</div>
                <div className="ov-secondary muted">{v.title}</div>
              </div>
            </div>
          ))}
          {filters && items.length === 0 && !err && <div className="empty">No matches.</div>}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Audit log (admin)

function AuditPanel({ onClose }: { onClose: () => void }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    setLoading(true);
    api.audit().then(setEntries).catch(() => setEntries([])).finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><ScrollText size={16} /> Audit log</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          {loading && <div className="empty">Loading…</div>}
          {!loading && entries.length === 0 && <div className="empty">No audit entries yet.</div>}
          {entries.map((a) => (
            <div className="ov-row audit-row" key={a.id}>
              <span className={`badge ${a.status && a.status >= 400 ? "crit" : "rel-B"}`}>{a.status ?? "—"}</span>
              <div className="ov-row-text">
                <div className="ov-primary mono">{a.action}</div>
                <div className="ov-secondary muted">{a.user ?? "anon"}{a.role ? ` (${a.role})` : ""} · {new Date(a.at).toLocaleString()}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Breach exposure (Have I Been Pwned)

function ExposureView({ reloadKey, canWrite }: { reloadKey: number; canWrite: boolean }) {
  const [breaches, setBreaches] = useState<Breach[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api.breaches().then(setBreaches).catch(() => setBreaches([])).finally(() => setLoading(false));
  }, []);
  useEffect(() => { load(); }, [load, reloadKey]);

  async function run() {
    setRunning(true);
    try { await api.runBreaches(); load(); } catch { /* not configured */ }
    finally { setRunning(false); }
  }

  return (
    <section className="panel">
      <div className="grid-toolbar">
        <div className="toolbar-title"><ShieldOff size={16} /> Breach exposure <span className="muted">({breaches.length})</span></div>
        <div className="spacer" />
        {canWrite && (
          <button className="icon-btn" data-tooltip="Check now (HIBP)" aria-label="Check breaches" disabled={running} onClick={run}>
            <RefreshCw size={18} className={running ? "spin" : ""} />
          </button>
        )}
      </div>
      {loading && <div className="empty">Loading…</div>}
      {!loading && breaches.length === 0 && (
        <div className="empty">No breach data. Set <code>HIBP_DOMAINS</code> (comma-separated) in <code>.env</code>, then check now — OmniSight lists known breaches at your domains via Have I Been Pwned.</div>
      )}
      {breaches.map((b) => (
        <div className="ov-row breach-row" key={b.id}>
          <span className={`badge ${b.verified ? "crit" : "rel-C"}`}>{b.pwnCount ? `${(b.pwnCount / 1e6).toFixed(b.pwnCount >= 1e6 ? 1 : 3)}M` : "—"}</span>
          <div className="ov-row-text">
            <div className="ov-primary">{b.title} <span className="muted">· {b.domain}</span> {b.breachDate && <span className="muted">· {b.breachDate}</span>}</div>
            <div className="ov-secondary muted">{b.dataClasses.slice(0, 6).join(", ")}{b.dataClasses.length > 6 ? "…" : ""}</div>
          </div>
        </div>
      ))}
    </section>
  );
}

// ---------------------------------------------------------------------------
// AI auto-correlation suggestions

function CorrelateModal({ onClose }: { onClose: () => void }) {
  const [links, setLinks] = useState<AiLink[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  async function run() {
    setBusy(true); setErr(""); setLinks(null);
    try { const r = await api.aiCorrelate(); setLinks(r.links); }
    catch { setErr("Correlation failed — check the AI/Ollama connection."); }
    finally { setBusy(false); }
  }
  useEffect(() => { run(); }, []);

  const conf = (c: string) => (c === "high" ? "crit" : c === "medium" ? "rel-B" : "rel-C");

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Link2 size={16} /> AI correlation suggestions</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Re-run" aria-label="Re-run" disabled={busy} onClick={run}><RefreshCw size={16} className={busy ? "spin" : ""} /></button>
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>The model proposes likely CVE↔IOC / campaign links from current top vulnerabilities and indicators. Suggestions only — verify before acting.</div>
          {busy && <div className="empty">Analyzing…</div>}
          {err && <div className="login-error">{err}</div>}
          {links && links.length === 0 && !busy && <div className="empty">No well-supported links proposed.</div>}
          {links?.map((l, i) => (
            <div className="ov-row" key={i}>
              <span className={`badge ${conf(l.confidence)}`}>{l.confidence}</span>
              <div className="ov-row-text">
                <div className="ov-primary mono">{l.cve} ↔ {defang(l.ioc)}{l.malware && <span className="muted"> · {l.malware}</span>}</div>
                <div className="ov-secondary muted">{l.rationale}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Automation rules (admin)

function RulesPanel({ onClose }: { onClose: () => void }) {
  const [rules, setRules] = useState<Rule[]>([]);
  const [name, setName] = useState("");
  const [minRisk, setMinRisk] = useState(75);
  const [exploitedOnly, setExploitedOnly] = useState(false);
  const [stackOnly, setStackOnly] = useState(true);
  const [action, setAction] = useState<"webhook" | "email" | "jira">("webhook");
  const [target, setTarget] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(() => { api.rules().then(setRules).catch(() => {}); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  async function add(e: FormEvent) {
    e.preventDefault();
    setError("");
    if (!name.trim()) { setError("Name required."); return; }
    const config: Record<string, unknown> = action === "webhook" ? { url: target } : action === "email" ? { to: target } : {};
    try { await api.createRule({ name: name.trim(), enabled: true, minRisk, exploitedOnly, stackOnly, action, config }); setName(""); setTarget(""); load(); }
    catch (err) { setError((err as Error).message); }
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Workflow size={16} /> Automation rules</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>When a vulnerability matches the trigger, run the action. With no rules, OmniSight uses the <code>.env</code> stack-alert defaults.</div>
          <form onSubmit={add} className="rule-form">
            <input className="note-input" placeholder="Rule name" value={name} onChange={(e) => setName(e.target.value)} />
            <label className="rule-field">Min risk <input className="note-input rule-num" type="number" min={0} max={100} value={minRisk} onChange={(e) => setMinRisk(Number(e.target.value))} /></label>
            <label className="rule-check"><input type="checkbox" checked={exploitedOnly} onChange={(e) => setExploitedOnly(e.target.checked)} /> Exploited only</label>
            <label className="rule-check"><input type="checkbox" checked={stackOnly} onChange={(e) => setStackOnly(e.target.checked)} /> My Stack only</label>
            <select className="page-size" value={action} onChange={(e) => setAction(e.target.value as "webhook" | "email" | "jira")}>
              <option value="webhook">webhook</option>
              <option value="email">email</option>
              <option value="jira">jira</option>
            </select>
            {action !== "jira" && (
              <input className="note-input" placeholder={action === "webhook" ? "https://hooks.slack.com/…" : "alerts@example.com"} value={target} onChange={(e) => setTarget(e.target.value)} />
            )}
            <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
          </form>
          {error && <div className="login-error">{error}</div>}
          {rules.length === 0 && <div className="empty">No rules yet.</div>}
          {rules.map((r) => (
            <div className="ov-row" key={r.id}>
              <button className="icon-btn" data-tooltip={r.enabled ? "Disable" : "Enable"} aria-label="Toggle" onClick={() => api.updateRule(r.id, { enabled: !r.enabled }).then(load).catch(() => {})}>
                {r.enabled ? <Workflow size={16} /> : <ShieldOff size={16} />}
              </button>
              <div className="ov-row-text">
                <div className="ov-primary">{r.name} {!r.enabled && <span className="muted">(disabled)</span>}</div>
                <div className="ov-secondary muted">
                  risk ≥ {r.minRisk}{r.exploitedOnly ? " · exploited" : ""}{r.stackOnly ? " · my-stack" : ""} → {r.action}
                  {typeof r.config.url === "string" ? ` (${r.config.url.slice(0, 32)}…)` : typeof r.config.to === "string" ? ` (${r.config.to})` : ""}
                </div>
              </div>
              <button className="icon-btn note-del" data-tooltip="Delete" aria-label="Delete rule" onClick={() => api.deleteRule(r.id).then(load).catch(() => {})}><Trash2 size={14} /></button>
            </div>
          ))}
        </div>
      </div>
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
  const [feedKind, setFeedKind] = useState<"json" | "taxii">("json");
  const [taxiiUser, setTaxiiUser] = useState("");
  const [taxiiSecret, setTaxiiSecret] = useState("");
  const [msg, setMsg] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setMsg("");
    // Basic auth when a username is given (e.g. Pulsedive: taxii2 / <api key>);
    // otherwise treat the secret as a Bearer token.
    const taxiiConfig: Record<string, string> = taxiiUser
      ? { username: taxiiUser, password: taxiiSecret }
      : taxiiSecret ? { token: taxiiSecret } : {};
    const body: NewSource = feedKind === "taxii"
      ? {
          name, kind: "taxii", signalType: "indicator", url,
          schedule: "0 */6 * * *", enabled: true, requiresAuth: Boolean(taxiiSecret),
          config: taxiiConfig,
        }
      : {
          name, kind: "json", signalType: "vulnerability", url,
          schedule: "0 */6 * * *", enabled: true, requiresAuth: false,
          config: { itemsPath, map: {} },
        };
    try {
      const created = await api.addSource(body);
      await api.runSource(created.id);
      setMsg(`Added "${created.name}" and triggered first fetch.`);
      setName(""); setUrl(""); setItemsPath(""); setTaxiiUser(""); setTaxiiSecret("");
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
          <label>Feed type</label>
          <select className="page-size" value={feedKind} onChange={(e) => setFeedKind(e.target.value as "json" | "taxii")}>
            <option value="json">Generic JSON (vulnerabilities)</option>
            <option value="taxii">TAXII 2.1 (indicators)</option>
          </select>
        </div>
        <div className="field">
          <label>Feed name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={feedKind === "taxii" ? "My TAXII collection" : "My CVE feed"} required />
        </div>
        <div className="field">
          <label>{feedKind === "taxii" ? "Collection objects URL" : "JSON URL"}</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={feedKind === "taxii" ? "https://server/taxii2/<root>/collections/<id>/objects/" : "https://example.com/feed.json"} required />
        </div>
        {feedKind === "json" && (
          <div className="field">
            <label>Items path</label>
            <input value={itemsPath} onChange={(e) => setItemsPath(e.target.value)} placeholder="vulnerabilities" />
          </div>
        )}
        {feedKind === "taxii" && (
          <>
            <div className="field">
              <label>Username (optional)</label>
              <input value={taxiiUser} onChange={(e) => setTaxiiUser(e.target.value)} placeholder="e.g. taxii2 (Pulsedive)" />
            </div>
            <div className="field">
              <label>Password / API key / token</label>
              <input value={taxiiSecret} onChange={(e) => setTaxiiSecret(e.target.value)} placeholder="Basic password with a username, else Bearer token" />
            </div>
          </>
        )}
        <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
      </form>
      <div className="hint">
        {feedKind === "taxii"
          ? "Polls a TAXII 2.1 collection's objects endpoint and ingests STIX indicators on schedule."
          : "Generic JSON connector — point it at any feed, set the array path, and OmniSight ingests it. No code required."}
        {msg && <span style={{ display: "block", marginTop: 6 }}>{msg}</span>}
      </div>
    </div>
  );
}
