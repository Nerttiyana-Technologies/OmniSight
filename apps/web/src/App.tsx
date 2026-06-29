import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  Radar, Moon, Sun, RefreshCw, Plus, ShieldAlert, Skull, Flame, Database, TrendingUp, Rss,
  Activity, Gauge, ChevronLeft, ChevronRight, Crosshair, Server, X, Download, FileText, Newspaper, ExternalLink,
  ScanSearch, Copy, Package, LogOut, Users as UsersIcon, Lock, Trash2, Sparkles, ScrollText, Bug, KeyRound,
  Workflow, Link2, ShieldOff, Bookmark, ThumbsUp, ThumbsDown, Globe, Power, Play,
  ShieldCheck, Grid3x3, Layers, HelpCircle, HardDrive, Radio, Target, Upload,
} from "lucide-react";
import {
  riskBand, threatLevel, extractIocs, defang, roleAtLeast, reliabilityWeight, type Vulnerability, type Indicator, type Advisory, type NewSource, type Source,
  type Digest, type DigestTone, type ExtractedIocs, type User,
} from "@omnisight/shared";
import {
  api, setToken, type Stats, type VulnQuery, type IndicatorQuery, type AdvisoryQuery, type MapPoint, type MapIndicator,
  type Correlation, type AttackTechnique, type ActorProfile, type AuditEntry, type Breach, type Rule, type AiLink,
  type SavedSearch, type Verdict, type TyposquatGroup,
  type AssetMatch, type MonitorEvent, type ScanTarget, type Scan, type ScanFinding,
  type EventStats, type ScanAdapterInfo, type AssetPage, type EventPage,
} from "./api.ts";
import { makeProjector, topologyToGeometries, geomToPath, type Geom } from "./geo.ts";

type Theme = "dark" | "light";
type Tab = "overview" | "vulns" | "iocs" | "assets" | "monitoring" | "scanning" | "actors" | "exposure" | "news" | "map";

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
  const [showSources, setShowSources] = useState(false);

  // Analyst tools
  const [showDetection, setShowDetection] = useState(false);
  const [showMatrix, setShowMatrix] = useState(false);
  const [showEntities, setShowEntities] = useState(false);
  const [showRfi, setShowRfi] = useState(false);

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
        <button className="icon-btn" data-tooltip="ATT&CK matrix" aria-label="ATT&CK matrix" onClick={() => setShowMatrix(true)}>
          <Grid3x3 size={18} />
        </button>
        <button className="icon-btn" data-tooltip="Entity resolution (CVE across sources)" aria-label="Entities" onClick={() => setShowEntities(true)}>
          <Layers size={18} />
        </button>
        <button className="icon-btn" data-tooltip="RFI tracker" aria-label="RFIs" onClick={() => setShowRfi(true)}>
          <HelpCircle size={18} />
        </button>
        {canWrite && (
          <button className="icon-btn" data-tooltip="Detection rule library" aria-label="Detection rules" onClick={() => setShowDetection(true)}>
            <ShieldCheck size={18} />
          </button>
        )}
        {isAdmin && (
          <button className="icon-btn" data-tooltip="Automation rules" aria-label="Automation rules" onClick={() => setShowRules(true)}>
            <Workflow size={18} />
          </button>
        )}
        {isAdmin && (
          <button className="icon-btn" data-tooltip="Manage feeds" aria-label="Manage feeds" onClick={() => setShowSources(true)}>
            <Database size={18} />
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
        {authEnabled && me && (
            <div className="user-chip" title={`Signed in as ${me.username}`}>
              <span className="user-name">{me.username}</span>
              <span className={`badge rel-${me.role === "admin" ? "A" : me.role === "analyst" ? "B" : "C"}`}>{me.role}</span>
            </div>
        )}
        {authEnabled && me && (
            <button className="icon-btn" data-tooltip="Sign out" aria-label="Sign out" onClick={logout}>
              <LogOut size={18} />
            </button>
        )}
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
          <StatCard icon={<HardDrive size={16} />} label="Assets" value={stats?.assets} />
          <StatCard icon={<Radio size={16} />} label="Event Hits" value={stats?.eventsMatched} accent />
          <StatCard icon={<Target size={16} />} label="Scan Findings" value={stats?.findings} />
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
          <button className={`tab ${tab === "assets" ? "active" : ""}`} onClick={() => setTab("assets")}>
            Assets {stats && <span className="muted">({stats.assets.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "monitoring" ? "active" : ""}`} onClick={() => setTab("monitoring")}>
            Monitoring {stats && stats.eventsMatched > 0 && <span className="muted">({stats.eventsMatched.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "scanning" ? "active" : ""}`} onClick={() => setTab("scanning")}>
            Scanning {stats && stats.findings > 0 && <span className="muted">({stats.findings.toLocaleString()})</span>}
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
        {tab === "assets" && <AssetsView reloadKey={reloadKey} canWrite={canWrite} />}
        {tab === "monitoring" && <MonitoringView reloadKey={reloadKey} canWrite={canWrite} onEnrich={onEnrich} />}
        {tab === "scanning" && <ScanningView reloadKey={reloadKey} canWrite={canWrite} />}
        {tab === "actors" && <ActorsView reloadKey={reloadKey} onEnrich={onEnrich} />}
        {tab === "exposure" && <ExposureView reloadKey={reloadKey} canWrite={canWrite} />}
        {tab === "news" && <NewsView reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "advisory")} />}
        {tab === "map" && <MapView reloadKey={reloadKey} onEnrich={onEnrich} />}
        {enrichTarget && <EnrichModal target={enrichTarget} onClose={() => setEnrichTarget(null)} canWrite={canWrite} />}
        {detailTarget && <VulnDetailModal v={detailTarget} onClose={() => setDetailTarget(null)} canWrite={canWrite} aiEnabled={aiEnabled} />}
        {showUsers && <UsersPanel onClose={() => setShowUsers(false)} meId={me?.id ?? null} />}
        {showAudit && <AuditPanel onClose={() => setShowAudit(false)} />}
        {showRules && <RulesPanel onClose={() => setShowRules(false)} />}
        {showSources && <SourcesPanel onClose={() => setShowSources(false)} onChange={bump} />}
        {showDetection && <DetectionPanel onClose={() => setShowDetection(false)} canWrite={canWrite} />}
        {showMatrix && <MatrixModal onClose={() => setShowMatrix(false)} />}
        {showEntities && <EntitiesModal onClose={() => setShowEntities(false)} />}
        {showRfi && <RfiPanel onClose={() => setShowRfi(false)} canWrite={canWrite} />}
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
  const [feedback, setFeedback] = useState<Record<string, Verdict>>({});
  const [hideFp, setHideFp] = useState(false);
  const [weighted, setWeighted] = useState(false);
  const pages = Math.max(1, Math.ceil(total / pageSize));
  useEffect(() => { api.feedback().then(setFeedback).catch(() => {}); }, [reloadKey]);

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

  // Apply client-side feedback hiding + reliability weighting to the loaded page.
  let view = items;
  if (hideFp) view = view.filter((x) => feedback[`cve:${x.cveId ?? x.id}`] !== "false_positive");
  if (weighted) {
    view = [...view].sort((a, b) =>
      b.riskScore * reliabilityWeight(reliabilityOf(sources, b.source)) -
      a.riskScore * reliabilityWeight(reliabilityOf(sources, a.source)),
    );
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
        <button className={`chip ${weighted ? "on" : ""}`} onClick={() => setWeighted((v) => !v)} title="Re-rank the current view by source reliability grade">
          <ShieldAlert size={14} /> Weight by grade
        </button>
        <button className={`chip ${hideFp ? "on" : ""}`} onClick={() => setHideFp((v) => !v)} title="Hide indicators marked false-positive">
          <ThumbsDown size={14} /> Hide FPs
        </button>
        <div className="spacer" />
        <SavedSearchBar
          kind="vuln"
          current={{ filters, sort }}
          onApply={(p) => {
            const pp = p as { filters?: Partial<VulnFilters>; sort?: { field: string; dir: "asc" | "desc" } };
            if (pp.filters) setFilters({ ...EMPTY_VULN_FILTERS, ...pp.filters });
            if (pp.sort) setSort(pp.sort);
            setPage(1);
          }}
        />
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
          {view.length === 0 && (
            <tr><td colSpan={9} className="muted" style={{ padding: 28, textAlign: "center" }}>
              {total === 0 ? "No vulnerabilities yet. Start the API and worker to ingest data." : "No matches — try clearing filters."}
            </td></tr>
          )}
          {view.map((v) => {
            const verdict = feedback[`cve:${v.cveId ?? v.id}`];
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
                  {verdict && <span className={`fb-badge ${verdict}`} title={verdict === "confirmed" ? "Confirmed" : "False positive"}>{verdict === "confirmed" ? "✓" : "FP"}</span>}
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

interface IocFilters { q: string; type: string; source: string; fresh: boolean; minConf: number }
const EMPTY_IOC_FILTERS: IocFilters = { q: "", type: "", source: "", fresh: false, minConf: 0 };

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
      if (filters.minConf) q.minConfidence = filters.minConf;
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
        <select className="page-size" value={filters.minConf} onChange={(e) => setFilter("minConf", Number(e.target.value))} title="Suppress low-confidence noise" aria-label="Min confidence">
          <option value={0}>Any confidence</option>
          <option value={25}>Conf ≥ 25</option>
          <option value={50}>Conf ≥ 50</option>
          <option value={75}>Conf ≥ 75</option>
        </select>
        <SavedSearchBar
          kind="ioc"
          current={{ filters, sort }}
          onApply={(p) => {
            const pp = p as { filters?: Partial<IocFilters>; sort?: { field: string; dir: "asc" | "desc" } };
            if (pp.filters) setFilters({ ...EMPTY_IOC_FILTERS, ...pp.filters });
            if (pp.sort) setSort(pp.sort);
            setPage(1);
          }}
        />
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
          <FeedbackButtons refKey={`cve:${cve}`} canWrite={canWrite} />
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

  const hasAny = data && (data.shodan || data.greynoise || data.abuseipdb || data.pulsedive);
  const isIp = target.type === "ip" || /^\d{1,3}(\.\d{1,3}){3}$/.test(ipForLinks);

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title ioc-value">{target.value}</div>
          <div className="spacer" />
          <a className="chip" href={`https://www.virustotal.com/gui/search/${encodeURIComponent(target.value)}`} target="_blank" rel="noopener noreferrer">
            <ExternalLink size={14} /> VirusTotal
          </a>
          {isIp && (
            <a className="chip" href={`https://www.shodan.io/host/${encodeURIComponent(ipForLinks)}`} target="_blank" rel="noopener noreferrer">
              <ExternalLink size={14} /> Shodan
            </a>
          )}
          <FeedbackButtons refKey={`ioc:${target.value}`} canWrite={canWrite} />
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
              {data.pulsedive && (
                <div className="panel enrich-card">
                  <div className="ov-card-title">Pulsedive {data.pulsedive.iid && <a className="chip" href={`https://pulsedive.com/indicator/?iid=${data.pulsedive.iid}`} target="_blank" rel="noopener noreferrer"><ExternalLink size={12} /></a>}</div>
                  <EnrichRow label="Risk" val={data.pulsedive.risk} crit={["high", "critical"].includes(data.pulsedive.risk)} />
                  <EnrichRow label="Threats" val={data.pulsedive.threats.map((t) => t.name).join(", ") || "—"} />
                  <EnrichRow label="Feeds" val={data.pulsedive.feeds.slice(0, 5).join(", ") || "—"} />
                  <EnrichRow label="Last seen" val={data.pulsedive.lastSeen ?? "—"} />
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
  const [typo, setTypo] = useState<TyposquatGroup[]>([]);
  const [mentions, setMentions] = useState<import("./api.ts").MentionGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const load = useCallback(() => {
    setLoading(true);
    api.breaches().then(setBreaches).catch(() => setBreaches([])).finally(() => setLoading(false));
    api.typosquat().then(setTypo).catch(() => setTypo([]));
    api.mentions().then(setMentions).catch(() => setMentions([]));
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

      <div className="grid-toolbar" style={{ marginTop: 18 }}>
        <div className="toolbar-title"><Globe size={16} /> Look-alike domains</div>
      </div>
      {typo.length === 0 && <div className="empty">Add domain-style terms (e.g. <code>yourbrand.com</code>) to My Stack to monitor for typosquats.</div>}
      {typo.map((g) => (
        <div className="typo-group" key={g.brand}>
          <div className="ov-card-title">{g.brand}</div>
          {g.seen.length > 0 && (
            <div className="typo-block">
              <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>Seen in your intel ({g.seen.length}):</div>
              <div className="actor-chips">
                {g.seen.map((s) => <span className="chip mono" key={s.value} title={`${s.source}${s.malware ? " · " + s.malware : ""}`}>{defang(s.value)}</span>)}
              </div>
            </div>
          )}
          <div className="typo-block">
            <div className="muted" style={{ fontSize: 12, margin: "6px 0 4px" }}>Permutations to watch:</div>
            <div className="actor-chips">
              {g.candidates.slice(0, 24).map((c) => <span className="chip mono dim" key={c}>{c}</span>)}
            </div>
          </div>
        </div>
      ))}

      <div className="grid-toolbar" style={{ marginTop: 18 }}>
        <div className="toolbar-title"><ScanSearch size={16} /> Brand mentions <span className="muted">(in your intel)</span></div>
      </div>
      {mentions.length === 0 && <div className="empty">No mentions of your My Stack terms in ingested advisories or indicators.</div>}
      {mentions.map((m) => (
        <div className="typo-group" key={m.term}>
          <div className="ov-card-title">{m.term} <span className="muted">· {m.advisories.length} advisory · {m.indicators.length} IOC</span></div>
          {m.advisories.slice(0, 5).map((a) => (
            <div className="ov-secondary" key={a.url || a.title}>
              <a href={a.url} target="_blank" rel="noopener noreferrer">{a.title}</a> <span className="muted">· {a.source}{a.published ? ` · ${formatDate(a.published)}` : ""}</span>
            </div>
          ))}
          {m.indicators.length > 0 && (
            <div className="actor-chips" style={{ marginTop: 4 }}>
              {m.indicators.slice(0, 12).map((i) => <span className="chip mono" key={i.value} title={i.source}>{defang(i.value)}</span>)}
            </div>
          )}
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

// Saved-search control for a grid toolbar: apply / save / delete named views.
function SavedSearchBar({ kind, current, onApply }: { kind: "vuln" | "ioc"; current: Record<string, unknown>; onApply: (params: Record<string, unknown>) => void }) {
  const [list, setList] = useState<SavedSearch[]>([]);
  const [sel, setSel] = useState("");
  const load = useCallback(() => { api.searches().then((s) => setList(s.filter((x) => x.kind === kind))).catch(() => {}); }, [kind]);
  useEffect(() => { load(); }, [load]);
  async function save() {
    const name = window.prompt("Name this saved search:");
    if (!name?.trim()) return;
    try { await api.createSearch(name.trim(), kind, current); load(); } catch { /* ignore */ }
  }
  function apply(id: string) {
    setSel(id);
    const s = list.find((x) => x.id === id);
    if (s) onApply(s.params);
  }
  async function del() {
    if (!sel) return;
    try { await api.deleteSearch(sel); setSel(""); load(); } catch { /* ignore */ }
  }
  return (
    <>
      <select className="page-size" value={sel} onChange={(e) => apply(e.target.value)} aria-label="Saved searches" title="Apply a saved search">
        <option value="">Saved…</option>
        {list.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
      </select>
      <button className="icon-btn" data-tooltip="Save current view" aria-label="Save search" onClick={save}><Bookmark size={16} /></button>
      {sel && <button className="icon-btn note-del" data-tooltip="Delete saved search" aria-label="Delete saved search" onClick={del}><Trash2 size={14} /></button>}
    </>
  );
}

// Analyst verdict (confirmed / false-positive) for a CVE or IOC ref.
function FeedbackButtons({ refKey, canWrite }: { refKey: string; canWrite: boolean }) {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  useEffect(() => {
    api.feedback().then((m) => setVerdict(m[refKey] ?? null)).catch(() => {});
  }, [refKey]);
  async function set(v: Verdict) {
    const next = verdict === v ? null : v;
    setVerdict(next);
    try { await api.setFeedback(refKey, next); } catch { /* ignore */ }
  }
  if (!canWrite) {
    return verdict ? <span className={`badge ${verdict === "confirmed" ? "crit" : "rel-C"}`}>{verdict === "confirmed" ? "confirmed" : "false positive"}</span> : null;
  }
  return (
    <>
      <button className={`icon-btn ${verdict === "confirmed" ? "fb-on" : ""}`} data-tooltip="Confirmed threat" aria-label="Mark confirmed" onClick={() => set("confirmed")}><ThumbsUp size={16} /></button>
      <button className={`icon-btn ${verdict === "false_positive" ? "fb-off" : ""}`} data-tooltip="False positive" aria-label="Mark false positive" onClick={() => set("false_positive")}><ThumbsDown size={16} /></button>
    </>
  );
}

// Admin: manage feeds — enable/disable, run now, delete.
function SourcesPanel({ onClose, onChange }: { onClose: () => void; onChange: () => void }) {
  const [sources, setSources] = useState<Source[]>([]);
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const load = useCallback(() => { api.sources().then(setSources).catch(() => {}); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);

  async function toggle(s: Source) {
    setErr("");
    try { await api.setSourceEnabled(s.id, !s.enabled); } catch (e) { setErr(`Toggle failed: ${(e as Error).message}`); }
    load();
  }
  async function run(s: Source) {
    setBusy(s.id); setErr("");
    try { await api.runSource(s.id); onChange(); } catch (e) { setErr(`Run failed: ${(e as Error).message}`); } finally { setBusy(""); }
  }
  async function remove(s: Source) {
    if (!window.confirm(`Delete "${s.name}" and all its ingested data? This cannot be undone.`)) return;
    setErr("");
    try { await api.deleteSource(s.id); } catch (e) { setErr(`Delete failed: ${(e as Error).message}`); }
    load(); onChange();
  }

  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Database size={16} /> Manage feeds <span className="muted">({sources.length})</span></div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>Enable/disable, run, or delete feeds. Schedule changes apply on the worker's next cycle; deleting a feed removes its ingested rows.</div>
          {err && <div className="login-error">{err}</div>}
          {sources.map((s) => (
            <div className="ov-row src-row" key={s.id}>
              <button className={`icon-btn ${s.enabled ? "fb-on" : ""}`} data-tooltip={s.enabled ? "Disable" : "Enable"} aria-label="Toggle" onClick={() => toggle(s)}>
                <Power size={16} />
              </button>
              <div className="ov-row-text">
                <div className="ov-primary">{s.name} {!s.enabled && <span className="muted">(disabled)</span>}</div>
                <div className="ov-secondary muted">{s.signalType} · {s.kind} · <span className={`badge rel-${s.reliability}`}>{s.reliability}</span></div>
              </div>
              <div className="spacer" />
              <input
                className="note-input src-sector"
                placeholder="sector…"
                defaultValue={s.sector ?? ""}
                title="Relevance sector tag"
                onBlur={(e) => { const v = e.target.value.trim(); if (v !== (s.sector ?? "")) api.setSourceSector(s.id, v || null).then(load).catch(() => {}); }}
              />
              <div className="src-dates">
                <div className="src-date muted">{s.createdAt ? `added ${formatDate(s.createdAt)}` : ""}</div>
                {s.lastRunAt && <div className="src-date muted">last run {formatDate(s.lastRunAt)}</div>}
              </div>
              <button className="icon-btn" data-tooltip="Run now" aria-label="Run now" disabled={busy === s.id} onClick={() => run(s)}><Play size={16} className={busy === s.id ? "spin" : ""} /></button>
              <button className="icon-btn danger" data-tooltip="Delete feed" aria-label="Delete feed" onClick={() => remove(s)}><Trash2 size={16} /></button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// ATT&CK coverage matrix

function MatrixModal({ onClose }: { onClose: () => void }) {
  const [cols, setCols] = useState<import("./api.ts").AttackMatrixColumn[]>([]);
  const [loading, setLoading] = useState(true);
  useEffect(() => { api.attackMatrix().then(setCols).catch(() => setCols([])).finally(() => setLoading(false)); }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow; document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  const shown = cols.filter((c) => c.techniques.length > 0);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal modal-wide" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Grid3x3 size={16} /> ATT&amp;CK coverage matrix</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>Techniques referenced across your ingested intel, grouped by tactic. Chip number = times referenced.</div>
          {loading && <div className="empty">Loading…</div>}
          {!loading && shown.length === 0 && <div className="empty">No ATT&CK/ATLAS techniques referenced in current intel.</div>}
          <div className="matrix">
            {shown.map((c) => (
              <div className="matrix-col" key={c.tactic}>
                <div className="matrix-head">{c.name} <span className="muted">({c.techniques.length})</span></div>
                {c.techniques.map((t) => (
                  <a className="matrix-tech" key={t.id} href={techniqueUrl(t.id)} target="_blank" rel="noopener noreferrer">
                    {t.id} <span className="muted">×{t.count}</span>
                  </a>
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Entity resolution: same CVE across sources

function EntitiesModal({ onClose }: { onClose: () => void }) {
  const [items, setItems] = useState<import("./api.ts").CveEntity[]>([]);
  const [loading, setLoading] = useState(true);
  const [multiOnly, setMultiOnly] = useState(false);
  useEffect(() => { api.entities().then(setItems).catch(() => setItems([])).finally(() => setLoading(false)); }, []);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow; document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  const view = multiOnly ? items.filter((e) => e.sources.length > 1) : items;
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Layers size={16} /> Entity resolution</div>
          <div className="spacer" />
          <button className={`chip ${multiOnly ? "on" : ""}`} onClick={() => setMultiOnly((v) => !v)}>Multi-source only</button>
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>The same CVE reported by multiple feeds, merged — with each source and its reliability grade.</div>
          {loading && <div className="empty">Loading…</div>}
          {!loading && view.length === 0 && <div className="empty">No entities.</div>}
          {view.map((e) => (
            <div className="ov-row" key={e.cveId}>
              <span className={`badge ${riskBand(e.riskScore)}`}>{e.riskScore}</span>
              <div className="ov-row-text">
                <div className="ov-primary">
                  <a href={`https://nvd.nist.gov/vuln/detail/${e.cveId}`} target="_blank" rel="noopener noreferrer">{e.cveId}</a>
                  {e.knownExploited && <span className="flag"> EXPLOITED</span>}
                  <span className="badge rel-A" style={{ marginLeft: 6 }}>{e.sources.length} source{e.sources.length === 1 ? "" : "s"}</span>
                </div>
                <div className="ov-secondary muted">{e.title}</div>
                <div className="actor-chips" style={{ marginTop: 4 }}>
                  {e.sources.map((s) => <span className="chip" key={s.source}>{s.source} <span className={`badge rel-${s.reliability}`}>{s.reliability}</span></span>)}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detection-rule library + gap analysis

function DetectionPanel({ onClose, canWrite }: { onClose: () => void; canWrite: boolean }) {
  const [rules, setRules] = useState<import("./api.ts").DetectionRule[]>([]);
  const [gaps, setGaps] = useState<import("./api.ts").DetectionGaps | null>(null);
  const [name, setName] = useState("");
  const [format, setFormat] = useState<"sigma" | "yara" | "snort" | "other">("sigma");
  const [techniques, setTechniques] = useState("");
  const [content, setContent] = useState("");
  const load = useCallback(() => {
    api.detectionRules().then(setRules).catch(() => {});
    api.detectionGaps().then(setGaps).catch(() => setGaps(null));
  }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow; document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  async function add(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    const techs = techniques.split(/[,\s]+/).map((t) => t.trim().toUpperCase()).filter(Boolean);
    try { await api.createDetectionRule({ name: name.trim(), format, techniques: techs, content, enabled: true }); setName(""); setTechniques(""); setContent(""); load(); } catch { /* ignore */ }
  }
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><ShieldCheck size={16} /> Detection rule library</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          {gaps && (
            <div className="ai-summary" style={{ marginTop: 0 }}>
              <div className="ov-card-title">Coverage gaps</div>
              <div className="muted" style={{ fontSize: 12 }}>{gaps.ruleCount} rule(s) · {gaps.gaps.length} technique(s) in intel with no covering rule:</div>
              <div className="actor-chips" style={{ marginTop: 6 }}>
                {gaps.gaps.slice(0, 30).map((t) => <a className="chip" key={t.id} href={techniqueUrl(t.id)} target="_blank" rel="noopener noreferrer">{t.id} ×{t.count}</a>)}
                {gaps.gaps.length === 0 && <span className="muted">No gaps — every referenced technique is covered.</span>}
              </div>
            </div>
          )}
          {canWrite && (
            <form onSubmit={add} className="rule-form" style={{ marginTop: 12 }}>
              <input className="note-input" placeholder="Rule name" value={name} onChange={(e) => setName(e.target.value)} />
              <select className="page-size" value={format} onChange={(e) => setFormat(e.target.value as typeof format)}>
                <option value="sigma">sigma</option><option value="yara">yara</option><option value="snort">snort</option><option value="other">other</option>
              </select>
              <input className="note-input" placeholder="ATT&CK IDs (T1059, T1486…)" value={techniques} onChange={(e) => setTechniques(e.target.value)} />
              <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
            </form>
          )}
          {canWrite && <textarea className="note-input" placeholder="Rule content (optional)" rows={2} value={content} onChange={(e) => setContent(e.target.value)} style={{ width: "100%", marginBottom: 10 }} />}
          {rules.length === 0 && <div className="empty">No rules yet.</div>}
          {rules.map((r) => (
            <div className="ov-row" key={r.id}>
              <span className="badge rel-B">{r.format}</span>
              <div className="ov-row-text">
                <div className="ov-primary">{r.name}</div>
                <div className="actor-chips" style={{ marginTop: 2 }}>{r.techniques.map((t) => <span className="chip" key={t}>{t}</span>)}</div>
              </div>
              <div className="spacer" />
              {canWrite && <button className="icon-btn danger" data-tooltip="Delete" aria-label="Delete rule" onClick={() => api.deleteDetectionRule(r.id).then(load).catch(() => {})}><Trash2 size={16} /></button>}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// RFI tracker

function RfiPanel({ onClose, canWrite }: { onClose: () => void; canWrite: boolean }) {
  const [rfis, setRfis] = useState<import("./api.ts").Rfi[]>([]);
  const [question, setQuestion] = useState("");
  const [context, setContext] = useState("");
  const load = useCallback(() => { api.rfis().then(setRfis).catch(() => {}); }, []);
  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow; document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  async function add(e: FormEvent) {
    e.preventDefault();
    if (!question.trim()) return;
    try { await api.createRfi(question.trim(), context.trim()); setQuestion(""); setContext(""); load(); } catch { /* ignore */ }
  }
  async function answer(r: import("./api.ts").Rfi) {
    const a = window.prompt("Answer:", r.answer);
    if (a == null) return;
    try { await api.updateRfi(r.id, { answer: a, status: a.trim() ? "answered" : r.status }); load(); } catch { /* ignore */ }
  }
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><HelpCircle size={16} /> RFI tracker <span className="muted">({rfis.length})</span></div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          {canWrite && (
            <form onSubmit={add} className="ask-form" style={{ flexWrap: "wrap" }}>
              <input className="note-input" placeholder="Request / question…" value={question} onChange={(e) => setQuestion(e.target.value)} />
              <input className="note-input" placeholder="Context (optional)" value={context} onChange={(e) => setContext(e.target.value)} />
              <button className="btn-primary" type="submit"><Plus size={16} /> Raise</button>
            </form>
          )}
          {rfis.length === 0 && <div className="empty">No RFIs yet.</div>}
          {rfis.map((r) => (
            <div className="ov-row" key={r.id}>
              <span className={`badge ${r.status === "open" ? "crit" : r.status === "answered" ? "rel-B" : "rel-C"}`}>{r.status}</span>
              <div className="ov-row-text">
                <div className="ov-primary">{r.question}</div>
                {r.context && <div className="ov-secondary muted">{r.context}</div>}
                {r.answer && <div className="ov-secondary">↳ {r.answer}</div>}
              </div>
              <div className="spacer" />
              {canWrite && <button className="icon-btn" data-tooltip="Answer" aria-label="Answer" onClick={() => answer(r)}><FileText size={15} /></button>}
              {canWrite && r.status !== "closed" && <button className="icon-btn" data-tooltip="Close RFI" aria-label="Close RFI" onClick={() => api.updateRfi(r.id, { status: "closed" }).then(load).catch(() => {})}><X size={15} /></button>}
              {canWrite && <button className="icon-btn danger" data-tooltip="Delete" aria-label="Delete RFI" onClick={() => api.deleteRfi(r.id).then(load).catch(() => {})}><Trash2 size={15} /></button>}
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
  const [feedKind, setFeedKind] = useState<"json" | "taxii" | "rss">("json");
  const [taxiiUser, setTaxiiUser] = useState("");
  const [taxiiSecret, setTaxiiSecret] = useState("");
  const [sector, setSector] = useState("");
  const [msg, setMsg] = useState("");

  async function submit(e: FormEvent) {
    e.preventDefault();
    setMsg("");
    // Basic auth when a username is given (e.g. Pulsedive: taxii2 / <api key>);
    // otherwise treat the secret as a Bearer token.
    const taxiiConfig: Record<string, string> = taxiiUser
      ? { username: taxiiUser, password: taxiiSecret }
      : taxiiSecret ? { token: taxiiSecret } : {};
    const sec = sector.trim() || null;
    const body: NewSource = feedKind === "taxii"
      ? {
          name, kind: "taxii", signalType: "indicator", url,
          schedule: "0 */6 * * *", enabled: true, requiresAuth: Boolean(taxiiSecret),
          reliability: "C", sector: sec, config: taxiiConfig,
        }
      : feedKind === "rss"
      ? {
          name, kind: "rss", signalType: "advisory", url,
          schedule: "0 */3 * * *", enabled: true, requiresAuth: false,
          reliability: "C", sector: sec, config: {},
        }
      : {
          name, kind: "json", signalType: "vulnerability", url,
          schedule: "0 */6 * * *", enabled: true, requiresAuth: false,
          reliability: "C", sector: sec, config: { itemsPath, map: {} },
        };
    try {
      const created = await api.addSource(body);
      await api.runSource(created.id);
      setMsg(`Added "${created.name}" and triggered first fetch.`);
      setName(""); setUrl(""); setItemsPath(""); setTaxiiUser(""); setTaxiiSecret(""); setSector("");
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
          <select className="page-size" value={feedKind} onChange={(e) => setFeedKind(e.target.value as "json" | "taxii" | "rss")}>
            <option value="json">Generic JSON (vulnerabilities)</option>
            <option value="rss">RSS / Atom (news &amp; advisories)</option>
            <option value="taxii">TAXII 2.1 (indicators)</option>
          </select>
        </div>
        <div className="field">
          <label>Feed name</label>
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={feedKind === "taxii" ? "My TAXII collection" : "My CVE feed"} required />
        </div>
        <div className="field">
          <label>Sector (optional)</label>
          <input value={sector} onChange={(e) => setSector(e.target.value)} placeholder="e.g. finance, healthcare" />
        </div>
        <div className="field">
          <label>{feedKind === "taxii" ? "Collection objects URL" : feedKind === "rss" ? "RSS / Atom feed URL" : "JSON URL"}</label>
          <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder={feedKind === "taxii" ? "https://server/taxii2/<root>/collections/<id>/objects/" : feedKind === "rss" ? "https://feeds.arstechnica.com/arstechnica/security" : "https://example.com/feed.json"} required />
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
          : feedKind === "rss"
          ? "RSS/Atom news feed — articles appear in the News tab. Try Ars Technica, BleepingComputer, KrebsOnSecurity, or any vendor advisory feed. No code required."
          : "Generic JSON connector — point it at any feed, set the array path, and OmniSight ingests it. No code required."}
        {msg && <span style={{ display: "block", marginTop: 6 }}>{msg}</span>}
      </div>
    </div>
  );
}

// ===========================================================================
// Phase 2 — Asset inventory
// ===========================================================================

const CRITICALITIES = ["low", "medium", "high", "critical"] as const;
const ASSET_KINDS = ["software", "host", "service", "cloud", "network", "other"] as const;

function AssetForm({ onAdded }: { onAdded: () => void }) {
  const [name, setName] = useState("");
  const [vendor, setVendor] = useState("");
  const [product, setProduct] = useState("");
  const [version, setVersion] = useState("");
  const [cpe, setCpe] = useState("");
  const [hostname, setHostname] = useState("");
  const [criticality, setCriticality] = useState<(typeof CRITICALITIES)[number]>("medium");
  const [kind, setKind] = useState<(typeof ASSET_KINDS)[number]>("software");
  const [err, setErr] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) { setErr("Name required."); return; }
    try {
      await api.createAsset({
        name: name.trim(), vendor: vendor.trim() || null, product: product.trim() || null,
        version: version.trim() || null, cpe: cpe.trim() || null, hostname: hostname.trim() || null,
        criticality, kind, origin: "manual", tags: [],
      });
      setName(""); setVendor(""); setProduct(""); setVersion(""); setCpe(""); setHostname("");
      onAdded();
    } catch (er) { setErr((er as Error).message); }
  }
  return (
    <form onSubmit={submit} className="rule-form" style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
      <input className="note-input" placeholder="Name *" value={name} onChange={(e) => setName(e.target.value)} />
      <input className="note-input" placeholder="Vendor" value={vendor} onChange={(e) => setVendor(e.target.value)} />
      <input className="note-input" placeholder="Product" value={product} onChange={(e) => setProduct(e.target.value)} />
      <input className="note-input rule-num" placeholder="Version" value={version} onChange={(e) => setVersion(e.target.value)} />
      <input className="note-input" placeholder="CPE (cpe:2.3:a:vendor:product:…)" value={cpe} onChange={(e) => setCpe(e.target.value)} />
      <input className="note-input" placeholder="Host / IP" value={hostname} onChange={(e) => setHostname(e.target.value)} />
      <select className="page-size" value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}>
        {ASSET_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
      </select>
      <select className="page-size" value={criticality} onChange={(e) => setCriticality(e.target.value as typeof criticality)}>
        {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
      </select>
      <button className="btn-primary" type="submit"><Plus size={16} /> Add</button>
      {err && <span className="login-error">{err}</span>}
    </form>
  );
}

function AssetsView({ reloadKey, canWrite }: { reloadKey: number; canWrite: boolean }) {
  const [data, setData] = useState<AssetPage | null>(null);
  const [matches, setMatches] = useState<AssetMatch[]>([]);
  const [q, setQ] = useState("");
  const [crit, setCrit] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [msg, setMsg] = useState("");
  const csvRef = useRef<HTMLInputElement>(null);
  const sbomRef = useRef<HTMLInputElement>(null);

  const load = useCallback(() => {
    api.assets({ q: q || undefined, criticality: crit || undefined, pageSize: 200 }).then(setData).catch(() => setData(null));
    api.assetMatches().then(setMatches).catch(() => setMatches([]));
  }, [q, crit]);
  useEffect(() => { load(); }, [load, reloadKey]);

  async function importCsv(file: File) {
    try { const r = await api.importAssetsCsv(await file.text()); setMsg(`Imported ${r.imported} asset(s) from CSV.`); load(); }
    catch (e) { setMsg(`CSV import failed: ${(e as Error).message}`); }
  }
  async function importSbom(file: File) {
    try { const obj = JSON.parse(await file.text()); const r = await api.importAssetsSbom(obj); setMsg(`Imported ${r.imported} asset(s) from ${r.components} SBOM component(s).`); load(); }
    catch (e) { setMsg(`SBOM import failed: ${(e as Error).message}`); }
  }

  const matchBadge = (t: AssetMatch["matchType"]) => (t === "cpe" ? "rel-A" : t === "vendor-product" ? "rel-B" : "rel-C");

  return (
    <section className="panel">
      <div className="grid-toolbar">
        <div className="toolbar-title"><HardDrive size={16} /> Asset inventory <span className="muted">({data?.total ?? 0})</span></div>
        <input className="note-input" style={{ maxWidth: 200 }} placeholder="Search assets…" value={q} onChange={(e) => setQ(e.target.value)} />
        <select className="page-size" value={crit} onChange={(e) => setCrit(e.target.value)}>
          <option value="">All criticality</option>
          {CRITICALITIES.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <div className="spacer" />
        {canWrite && <button className="icon-btn" data-tooltip="Add asset" aria-label="Add asset" onClick={() => setShowForm((v) => !v)}><Plus size={18} /></button>}
        {canWrite && <button className="icon-btn" data-tooltip="Import CSV" aria-label="Import CSV" onClick={() => csvRef.current?.click()}><Upload size={18} /></button>}
        {canWrite && <button className="icon-btn" data-tooltip="Import SBOM (CycloneDX/SPDX)" aria-label="Import SBOM" onClick={() => sbomRef.current?.click()}><Package size={18} /></button>}
        <button className="icon-btn" data-tooltip="Export CSV" aria-label="Export CSV" onClick={() => download(api.exportAssetsUrl())}><Download size={18} /></button>
        <button className="icon-btn" data-tooltip="Refresh" aria-label="Refresh" onClick={load}><RefreshCw size={18} /></button>
        <input ref={csvRef} type="file" accept=".csv,text/csv" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) importCsv(f); e.target.value = ""; }} />
        <input ref={sbomRef} type="file" accept=".json" hidden onChange={(e) => { const f = e.target.files?.[0]; if (f) importSbom(f); e.target.value = ""; }} />
      </div>
      {msg && <div className="hint" style={{ padding: "8px 16px" }}>{msg}</div>}
      {showForm && canWrite && <AssetForm onAdded={() => { setShowForm(false); load(); }} />}
      <div className="ov-list" style={{ padding: "4px 16px" }}>
        {(!data || data.items.length === 0) && <div className="empty">No assets yet. Add one, import a CSV, or scan an SBOM — then incoming CVEs that affect them are flagged below and drive "My Stack".</div>}
        {data?.items.map((a) => (
          <div className="ov-row" key={a.id}>
            <span className={`badge ${a.criticality}`}>{a.criticality}</span>
            <div className="ov-row-text">
              <div className="ov-primary">{a.name} {a.version && <span className="muted">· v{a.version}</span>} <span className="badge info" style={{ marginLeft: 6 }}>{a.origin}</span></div>
              <div className="ov-secondary muted">
                {[a.vendor, a.product].filter(Boolean).join(" / ") || "—"}
                {a.cpe && <span className="mono"> · {a.cpe}</span>}
                {(a.hostname || a.ip) && <span> · {a.hostname || a.ip}</span>}
                {a.tags.length > 0 && <span> · {a.tags.join(", ")}</span>}
              </div>
            </div>
            <div className="spacer" />
            {canWrite && <button className="icon-btn danger" data-tooltip="Delete" aria-label="Delete asset" onClick={() => api.deleteAsset(a.id).then(load).catch(() => {})}><Trash2 size={16} /></button>}
          </div>
        ))}
      </div>

      <div className="grid-toolbar" style={{ marginTop: 10 }}>
        <div className="toolbar-title"><ShieldAlert size={16} /> Vulnerabilities affecting your assets <span className="muted">({matches.length})</span></div>
      </div>
      <div style={{ padding: "4px 16px 12px" }}>
        {matches.length === 0 && <div className="empty">No tracked CVEs currently match your assets.</div>}
        {matches.map((m, i) => (
          <div className="ov-row" key={i}>
            <span className={`badge ${riskBand(m.riskScore)}`}>{m.riskScore}</span>
            <div className="ov-row-text">
              <div className="ov-primary">
                <a href={`https://nvd.nist.gov/vuln/detail/${m.cve}`} target="_blank" rel="noopener noreferrer">{m.cve}</a>
                {m.knownExploited && <span className="flag"> EXPLOITED</span>}
                <span className="muted"> → {m.assetName}</span>
              </div>
              <div className="ov-secondary muted">{m.title}</div>
              <div className="ov-secondary"><span className={`badge ${matchBadge(m.matchType)}`}>{m.matchType}</span> <span className="muted">{m.reason} · {m.criticality} asset</span></div>
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

// ===========================================================================
// Phase 2 — Environment monitoring (events / IOC matching)
// ===========================================================================

function MonitoringView({ reloadKey, canWrite, onEnrich }: { reloadKey: number; canWrite: boolean; onEnrich: (value: string, type: string) => void }) {
  const [data, setData] = useState<EventPage | null>(null);
  const [stats, setStats] = useState<EventStats | null>(null);
  const [matchedOnly, setMatchedOnly] = useState(false);
  const [kind, setKind] = useState("");
  const [q, setQ] = useState("");
  const [text, setText] = useState("");
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    api.events({ matchedOnly, kind: kind || undefined, q: q || undefined, pageSize: 200 }).then(setData).catch(() => setData(null));
    api.eventStats().then(setStats).catch(() => setStats(null));
  }, [matchedOnly, kind, q]);
  useEffect(() => { load(); }, [load, reloadKey]);

  async function submit() {
    if (!text.trim()) return;
    setBusy(true); setMsg("");
    try { const r = await api.ingestEventsText(text); setMsg(`Ingested ${r.inserted} observable(s) — ${r.matched} matched a tracked indicator.`); setText(""); load(); }
    catch (e) { setMsg(`Ingest failed: ${(e as Error).message}`); }
    finally { setBusy(false); }
  }

  return (
    <section className="panel">
      <div className="grid-toolbar">
        <div className="toolbar-title"><Radio size={16} /> Environment monitoring <span className="muted">({data?.total ?? 0})</span></div>
        {stats && <span className="muted" style={{ fontSize: 12 }}>{stats.matched} matched · {stats.last24h} in 24h</span>}
        <div className="spacer" />
        <button className={`chip ${matchedOnly ? "on" : ""}`} onClick={() => setMatchedOnly((v) => !v)}>Matched only</button>
        <select className="page-size" value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="">All types</option><option value="ip">ip</option><option value="domain">domain</option><option value="url">url</option><option value="hash">hash</option>
        </select>
        <input className="note-input" style={{ maxWidth: 180 }} placeholder="Search…" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="icon-btn" data-tooltip="Refresh" aria-label="Refresh" onClick={load}><RefreshCw size={18} /></button>
      </div>
      {canWrite && (
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Paste log lines, NDJSON, or a JSON event — OmniSight extracts observables (IP/domain/URL/hash) and matches them against tracked indicators. Or POST to <code>/api/events</code> / point syslog at the worker.</div>
          <textarea className="note-input" rows={3} style={{ width: "100%" }} placeholder='e.g. {"src_ip":"45.66.230.10","host":"web-01"}  — or a raw log line' value={text} onChange={(e) => setText(e.target.value)} />
          <div style={{ marginTop: 8 }}>
            <button className="btn-primary" disabled={busy} onClick={submit}><Radio size={16} /> Ingest event</button>
            {msg && <span className="muted" style={{ marginLeft: 10 }}>{msg}</span>}
          </div>
        </div>
      )}
      <div style={{ padding: "4px 16px 12px" }}>
        {(!data || data.items.length === 0) && <div className="empty">No environment events yet. Submit logs above, POST JSON to <code>/api/events</code>, or enable the syslog listener (<code>SYSLOG_ENABLED=true</code>).</div>}
        {data?.items.map((ev: MonitorEvent) => (
          <div className="ov-row" key={ev.id}>
            <span className={`badge ${ev.matched ? ev.severity : "info"}`}>{ev.matched ? ev.severity : "no hit"}</span>
            <div className="ov-row-text">
              <div className="ov-primary mono">{defang(ev.value)} <span className="badge info" style={{ marginLeft: 6 }}>{ev.kind}</span></div>
              <div className="ov-secondary muted">
                {ev.sensor}{ev.host ? ` · ${ev.host}` : ""}
                {ev.matched ? ` · matched ${ev.matchedSource ?? ""}${ev.malware ? " · " + ev.malware : ""}` : ""}
                {` · ${formatDate(ev.observedAt ?? ev.createdAt)}`}
              </div>
            </div>
            {ev.matched && ev.kind === "ip" && <button className="chip mini" onClick={() => onEnrich(ev.value, "ip")}>enrich</button>}
          </div>
        ))}
      </div>
    </section>
  );
}

// ===========================================================================
// Phase 3 — Vulnerability scanning
// ===========================================================================

function scanStatusBadge(s: string): string {
  return s === "done" ? "rel-A" : s === "running" ? "rel-B" : s === "error" ? "critical" : "info";
}

function ScanTargetForm({ adapters, onAdded }: { adapters: ScanAdapterInfo[]; onAdded: () => void }) {
  const [name, setName] = useState("");
  const [target, setTarget] = useState("");
  const [kind, setKind] = useState<"host" | "url">("host");
  const [adapter, setAdapter] = useState("builtin");
  const [schedule, setSchedule] = useState("");
  const [err, setErr] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim() || !target.trim()) { setErr("Name and target required."); return; }
    try {
      await api.createScanTarget({ name: name.trim(), target: target.trim(), kind, adapter, schedule: schedule.trim() || null });
      setName(""); setTarget(""); setSchedule("");
      onAdded();
    } catch (er) { setErr((er as Error).message); }
  }
  return (
    <form onSubmit={submit} className="rule-form" style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
      <input className="note-input" placeholder="Target name *" value={name} onChange={(e) => setName(e.target.value)} />
      <input className="note-input" placeholder="host / IP / URL *" value={target} onChange={(e) => setTarget(e.target.value)} />
      <select className="page-size" value={kind} onChange={(e) => setKind(e.target.value as "host" | "url")}>
        <option value="host">host</option><option value="url">url</option>
      </select>
      <select className="page-size" value={adapter} onChange={(e) => setAdapter(e.target.value)}>
        {adapters.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
      </select>
      <input className="note-input rule-num" placeholder="cron (optional)" value={schedule} onChange={(e) => setSchedule(e.target.value)} />
      <button className="btn-primary" type="submit"><Plus size={16} /> Add target</button>
      {err && <span className="login-error">{err}</span>}
    </form>
  );
}

function ScanningView({ reloadKey, canWrite }: { reloadKey: number; canWrite: boolean }) {
  const [targets, setTargets] = useState<ScanTarget[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [adapters, setAdapters] = useState<ScanAdapterInfo[]>([]);
  const [adhoc, setAdhoc] = useState("");
  const [adhocKind, setAdhocKind] = useState<"host" | "url">("host");
  const [adapter, setAdapter] = useState("builtin");
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const [findingScan, setFindingScan] = useState<string | null>(null);

  const load = useCallback(() => {
    api.scanTargets().then(setTargets).catch(() => setTargets([]));
    api.scans(50).then(setScans).catch(() => setScans([]));
  }, []);
  useEffect(() => { load(); }, [load, reloadKey]);
  useEffect(() => { api.scanConfig().then((c) => setAdapters(c.adapters)).catch(() => setAdapters([{ id: "builtin", name: "Built-in" }])); }, []);

  async function runAdhoc() {
    if (!adhoc.trim()) return;
    setBusy(true); setMsg("");
    try { const s = await api.runScan({ target: adhoc.trim(), kind: adhocKind, adapter }); setMsg(`Scan ${s.status}: ${s.findingCount} finding(s), ${s.openPorts} open port(s), ${s.cveCount} CVE.`); setAdhoc(""); load(); }
    catch (e) { setMsg(`Scan failed: ${(e as Error).message}`); }
    finally { setBusy(false); }
  }
  async function runTarget(t: ScanTarget) {
    setBusy(true); setMsg("");
    try { const s = await api.runScan({ targetId: t.id }); setMsg(`Scan ${t.name}: ${s.status} — ${s.findingCount} finding(s), ${s.cveCount} CVE.`); load(); }
    catch (e) { setMsg(`Scan failed: ${(e as Error).message}`); }
    finally { setBusy(false); }
  }

  return (
    <section className="panel">
      <div className="grid-toolbar">
        <div className="toolbar-title"><Target size={16} /> Vulnerability scanning</div>
        <span className="muted" style={{ fontSize: 12 }}>adapters: {adapters.map((a) => a.name).join(", ") || "builtin"}</span>
        <div className="spacer" />
        {canWrite && <button className="icon-btn" data-tooltip="Add saved target" aria-label="Add target" onClick={() => setShowForm((v) => !v)}><Plus size={18} /></button>}
        <button className="icon-btn" data-tooltip="Refresh" aria-label="Refresh" onClick={load}><RefreshCw size={18} /></button>
      </div>
      {canWrite && (
        <div style={{ padding: "12px 16px", borderBottom: "1px solid var(--border)" }}>
          <div className="muted" style={{ fontSize: 12, marginBottom: 6 }}>Run an ad-hoc scan (TCP ports + HTTP banner/headers; discovered products are correlated to tracked CVEs and registered as assets). Only scan systems you are authorized to test.</div>
          <div className="ask-form" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <input className="note-input" placeholder="host / IP / URL" value={adhoc} onChange={(e) => setAdhoc(e.target.value)} />
            <select className="page-size" value={adhocKind} onChange={(e) => setAdhocKind(e.target.value as "host" | "url")}>
              <option value="host">host</option><option value="url">url</option>
            </select>
            <select className="page-size" value={adapter} onChange={(e) => setAdapter(e.target.value)}>
              {adapters.map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
            </select>
            <button className="btn-primary" disabled={busy} onClick={runAdhoc}><Play size={16} className={busy ? "spin" : ""} /> Scan now</button>
          </div>
          {msg && <div className="muted" style={{ marginTop: 8 }}>{msg}</div>}
        </div>
      )}
      {showForm && canWrite && <ScanTargetForm adapters={adapters} onAdded={() => { setShowForm(false); load(); }} />}

      <div className="grid-toolbar"><div className="toolbar-title">Saved targets <span className="muted">({targets.length})</span></div></div>
      <div style={{ padding: "4px 16px" }}>
        {targets.length === 0 && <div className="empty">No saved targets. Add one (with an optional cron) for scheduled scans, or run ad-hoc above.</div>}
        {targets.map((t) => (
          <div className="ov-row" key={t.id}>
            {canWrite
              ? <button className={`icon-btn ${t.enabled ? "fb-on" : ""}`} data-tooltip={t.enabled ? "Disable" : "Enable"} aria-label="Toggle" onClick={() => api.updateScanTarget(t.id, { enabled: !t.enabled }).then(load).catch(() => {})}><Power size={16} /></button>
              : <span className="badge info">{t.enabled ? "on" : "off"}</span>}
            <div className="ov-row-text">
              <div className="ov-primary">{t.name} <span className="muted mono">· {t.target}</span></div>
              <div className="ov-secondary muted">{t.kind} · {t.adapter}{t.schedule ? ` · ${t.schedule}` : " · manual"}{t.lastScanAt ? ` · last ${formatDate(t.lastScanAt)}` : ""}</div>
            </div>
            <div className="spacer" />
            {canWrite && <button className="icon-btn" data-tooltip="Scan now" aria-label="Scan now" disabled={busy} onClick={() => runTarget(t)}><Play size={16} className={busy ? "spin" : ""} /></button>}
            {canWrite && <button className="icon-btn danger" data-tooltip="Delete target" aria-label="Delete target" onClick={() => api.deleteScanTarget(t.id).then(load).catch(() => {})}><Trash2 size={16} /></button>}
          </div>
        ))}
      </div>

      <div className="grid-toolbar" style={{ marginTop: 6 }}><div className="toolbar-title">Recent scans <span className="muted">({scans.length})</span></div></div>
      <div style={{ padding: "4px 16px 12px" }}>
        {scans.length === 0 && <div className="empty">No scans yet.</div>}
        {scans.map((s) => (
          <div className="ov-row" key={s.id} style={{ cursor: "pointer" }} onClick={() => setFindingScan(s.id)}>
            <span className={`badge ${scanStatusBadge(s.status)}`}>{s.status}</span>
            <div className="ov-row-text">
              <div className="ov-primary mono">{s.target}</div>
              <div className="ov-secondary muted">{s.findingCount} finding(s) · {s.openPorts} open port(s) · {s.cveCount} CVE · {formatDate(s.finishedAt ?? s.createdAt)}{s.error ? ` · ${s.error}` : ""}</div>
            </div>
            <ChevronRight size={16} />
          </div>
        ))}
      </div>
      {findingScan && <ScanFindingsModal scanId={findingScan} onClose={() => setFindingScan(null)} />}
    </section>
  );
}

function ScanFindingsModal({ scanId, onClose }: { scanId: string; onClose: () => void }) {
  const [data, setData] = useState<{ scan: Scan; findings: ScanFinding[] } | null>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow; document.body.style.overflow = "hidden";
    return () => { window.removeEventListener("keydown", onKey); document.body.style.overflow = prev; };
  }, [onClose]);
  useEffect(() => { api.scan(scanId).then(setData).catch(() => setData(null)); }, [scanId]);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-head">
          <div className="modal-title"><Target size={16} /> Scan findings {data && <span className="muted">· {data.scan.target}</span>}</div>
          <div className="spacer" />
          <button className="icon-btn" data-tooltip="Close" aria-label="Close" onClick={onClose}><X size={16} /></button>
        </div>
        <div className="modal-body" style={{ padding: 16 }}>
          {!data && <div className="empty">Loading…</div>}
          {data && data.findings.length === 0 && <div className="empty">No findings for this scan.</div>}
          {data?.findings.map((f) => (
            <div className="ov-row" key={f.id}>
              <span className={`badge ${f.severity}`}>{f.severity}</span>
              <div className="ov-row-text">
                <div className="ov-primary">
                  {f.title}
                  {f.cve && <a style={{ marginLeft: 6 }} href={`https://nvd.nist.gov/vuln/detail/${f.cve}`} target="_blank" rel="noopener noreferrer">{f.cve}</a>}
                </div>
                <div className="ov-secondary muted">
                  {[f.host, f.port ? `:${f.port}` : "", f.service].filter(Boolean).join(" ")}
                  {f.product ? ` · ${f.product}${f.version ? " " + f.version : ""}` : ""}
                </div>
                <div className="ov-secondary">{f.description}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
