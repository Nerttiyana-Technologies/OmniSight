// Minimal, dependency-free TopoJSON → SVG path helpers for the world map.
// We decode world-atlas (countries-110m, TopoJSON) and project with a plain
// equirectangular projection — no d3 / topojson-client needed.

export type Coord = [number, number]; // [lng, lat]
export interface Geom {
  type: "Polygon" | "MultiPolygon";
  coordinates: Coord[][] | Coord[][][];
}

export type Projector = (lng: number, lat: number) => [number, number];

export function makeProjector(width: number, height: number): Projector {
  return (lng, lat) => [((lng + 180) / 360) * width, ((90 - lat) / 180) * height];
}

interface Topology {
  type: "Topology";
  arcs: number[][][];
  transform?: { scale: [number, number]; translate: [number, number] };
  objects: Record<string, { type: string; geometries?: TopoGeometry[] }>;
}
interface TopoGeometry {
  type: string;
  arcs?: number[][] | number[][][];
}

function decodeArcs(topo: Topology): Coord[][] {
  const t = topo.transform;
  return topo.arcs.map((arc) => {
    let x = 0;
    let y = 0;
    const out: Coord[] = [];
    for (const point of arc) {
      x += point[0]!;
      y += point[1]!;
      out.push(t ? [x * t.scale[0] + t.translate[0], y * t.scale[1] + t.translate[1]] : [x, y]);
    }
    return out;
  });
}

/** Stitch a ring from its (possibly reversed) arc indices. */
function stitch(arcs: Coord[][], indices: number[]): Coord[] {
  const pts: Coord[] = [];
  for (const idx of indices) {
    const rev = idx < 0;
    const a = arcs[rev ? ~idx : idx] ?? [];
    const seg = rev ? [...a].reverse() : a;
    for (let i = 0; i < seg.length; i++) {
      if (i === 0 && pts.length) continue; // drop duplicate join vertex
      pts.push(seg[i]!);
    }
  }
  return pts;
}

export function topologyToGeometries(topo: Topology, object: string): Geom[] {
  const obj = topo.objects[object];
  if (!obj || !obj.geometries) return [];
  const arcs = decodeArcs(topo);
  const out: Geom[] = [];
  for (const g of obj.geometries) {
    if (g.type === "Polygon") {
      out.push({ type: "Polygon", coordinates: (g.arcs as number[][]).map((r) => stitch(arcs, r)) });
    } else if (g.type === "MultiPolygon") {
      out.push({
        type: "MultiPolygon",
        coordinates: (g.arcs as number[][][]).map((poly) => poly.map((r) => stitch(arcs, r))),
      });
    }
  }
  return out;
}

export function geomToPath(g: Geom, proj: Projector): string {
  const ring = (r: Coord[]) =>
    r.map((c, i) => {
      const [x, y] = proj(c[0], c[1]);
      return `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
    }).join("") + "Z";
  if (g.type === "Polygon") return (g.coordinates as Coord[][]).map(ring).join("");
  return (g.coordinates as Coord[][][]).flatMap((poly) => poly.map(ring)).join("");
}
