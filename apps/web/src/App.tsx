import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import {
  Radar, Moon, Sun, RefreshCw, Plus, ShieldAlert, Skull, Flame, Database, TrendingUp, Rss,
  Activity, Gauge, ChevronLeft, ChevronRight, Crosshair, Server, X, Download, FileText, Newspaper, ExternalLink,
} from "lucide-react";
import {
  riskBand, threatLevel, type Vulnerability, type Indicator, type Advisory, type NewSource, type Source,
  type Digest, type DigestTone,
} from "@omnisight/shared";
import {
  api, type Stats, type VulnQuery, type IndicatorQuery, type AdvisoryQuery, type MapPoint, type MapIndicator,
  type Correlation,
} from "./api.ts";
import { makeProjector, topologyToGeometries, geomToPath, type Geom } from "./geo.ts";

type Theme = "dark" | "light";
type Tab = "overview" | "vulns" | "iocs" | "news" | "map";

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
          <button className={`tab ${tab === "news" ? "active" : ""}`} onClick={() => setTab("news")}>
            News {stats && <span className="muted">({stats.advisories.toLocaleString()})</span>}
          </button>
          <button className={`tab ${tab === "map" ? "active" : ""}`} onClick={() => setTab("map")}>
            Map
          </button>
        </div>

        {tab === "overview" && <Overview reloadKey={reloadKey} stats={stats} />}
        {tab === "vulns" && <VulnGrid reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "vulnerability")} terms={terms} />}
        {tab === "iocs" && <IndicatorGrid reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "indicator")} />}
        {tab === "news" && <NewsView reloadKey={reloadKey} sources={sources.filter((s) => s.signalType === "advisory")} />}
        {tab === "map" && <MapView reloadKey={reloadKey} />}
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

function MapView({ reloadKey }: { reloadKey: number }) {
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
              <div className="ov-row" key={i}>
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
  const [preview, setPreview] = useState<null | "html" | "md">(null);

  useEffect(() => {
    api.digest().then(setDigest).catch(() => {});
    api.correlations().then(setCorrelations).catch(() => {});
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
        <span className="muted">Export current view:</span>
        <div className="spacer" />
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
