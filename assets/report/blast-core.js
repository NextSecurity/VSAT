/* VSAT blast radius core: the deterministic search and fix ranking used by the report and the local
 * UI when the viewer ticks fixes. Pure functions over results.analysis.blastRadius (no DOM). It mirrors
 * Invoke-VsatGraphSearch and Get-VsatFixPlan in src/76-Graph.ps1 exactly, and tests/js/blast-parity
 * checks that both give the same paths and fix order. The build places this file first in the
 * report's and the UI's single inline script. */
var VsatBlastCore = (function () {
  'use strict';

  // Weakest-link order for a path's confidence (same ranks as $script:VsatConfidenceRank).
  const CONF_RANK = { 'observed': 4, 'operator-declared': 3, 'configuration-inferred': 2, 'correlated': 1 };
  const CRIT_WEIGHT = { high: 3, medium: 2, low: 1 };

  // Ordinal (UTF-16 code unit) comparison, the same order as [string]::CompareOrdinal.
  function ord(a, b) { return a < b ? -1 : a > b ? 1 : 0; }
  function num(v) { const n = Number(v); return isFinite(n) ? n : 0; }

  // Binary min-heap of [cost, hops, nodeId]; the pop order is (cost, hops, node id ordinal).
  function less(x, y) { return x[0] !== y[0] ? x[0] < y[0] : x[1] !== y[1] ? x[1] < y[1] : x[2] < y[2]; }
  function Heap() { this.a = []; }
  Heap.prototype.push = function (v) {
    const a = this.a; a.push(v); let i = a.length - 1;
    while (i > 0) { const p = (i - 1) >> 1; if (!less(a[i], a[p])) break; const t = a[i]; a[i] = a[p]; a[p] = t; i = p; }
  };
  Heap.prototype.pop = function () {
    const a = this.a, top = a[0], last = a.pop();
    if (a.length) {
      a[0] = last; let i = 0;
      for (;;) {
        const l = 2 * i + 1, r = l + 1; let m = i;
        if (l < a.length && less(a[l], a[m])) m = l;
        if (r < a.length && less(a[r], a[m])) m = r;
        if (m === i) break;
        const t = a[i]; a[i] = a[m]; a[m] = t; i = m;
      }
    }
    return top;
  };

  // Index the exported blast radius: nodes by id, adjacency ordered by (cost, edge id ordinal), crowns.
  // Edges are used exactly as exported; nothing is re-derived in the browser.
  function model(blast) {
    const b = blast && typeof blast === 'object' ? blast : {};
    const nodes = new Map(), out = new Map(), edgeById = new Map(), crit = new Map();
    (Array.isArray(b.nodes) ? b.nodes : []).forEach(function (n) { if (n && n.id !== undefined && n.id !== null) nodes.set(String(n.id), n); });
    (Array.isArray(b.edges) ? b.edges : []).forEach(function (e) {
      if (!e || e.id === undefined || e.source === undefined || e.target === undefined) return;
      edgeById.set(String(e.id), e);
      const s = String(e.source);
      if (!out.has(s)) out.set(s, []);
      out.get(s).push(e);
    });
    out.forEach(function (list) { list.sort(function (x, y) { return num(x.cost) - num(y.cost) || ord(String(x.id), String(y.id)); }); });
    const crowns = [];
    nodes.forEach(function (n, id) { if (n.crown === true) { crowns.push(id); if (CRIT_WEIGHT[n.criticality]) crit.set(id, n.criticality); } });
    crowns.sort(ord);
    // Older results carry criticality on paths only.
    (Array.isArray(b.paths) ? b.paths : []).forEach(function (p) { if (p && p.crown !== undefined && !crit.has(String(p.crown)) && CRIT_WEIGHT[p.criticality]) crit.set(String(p.crown), p.criticality); });
    const entries = (Array.isArray(b.entries) ? b.entries : []).map(String).filter(function (id) { return nodes.has(id); });
    const bounds = b.bounds && typeof b.bounds === 'object' ? b.bounds : {};
    const maxDepth = num(bounds.maxDepth) > 0 ? num(bounds.maxDepth) : 8;
    return { nodes: nodes, out: out, edgeById: edgeById, crowns: crowns, crownSet: new Set(crowns), entries: entries, maxDepth: maxDepth, crit: crit, edgeCount: edgeById.size };
  }

  // Dijkstra over (node, hops) states with hops <= maxDepth, exactly as Invoke-VsatGraphSearch:
  // relax only on a strict cost improvement per state; skip a state whose node was already settled
  // with no more hops; a node's label is its first settled state. Edges whose fixId is in `cut` are
  // treated as removed.
  function search(M, start, cut) {
    const sd = new Map(), prev = new Map(), minHops = new Map(), dist = new Map(), hops = new Map(), done = [];
    let pops = 0;   // non-dominated pops, counted exactly like $State.pops in the engine
    const heap = new Heap();
    const noCut = !cut || cut.size === 0;
    sd.set('0|' + start, 0);
    heap.push([0, 0, start]);
    while (heap.a.length) {
      const it = heap.pop(), h = it[1], u = it[2];
      if (minHops.has(u) && h >= minHops.get(u)) continue;
      const du = sd.get(h + '|' + u);
      minHops.set(u, h);
      if (!dist.has(u)) { dist.set(u, du); hops.set(u, h); done.push(u); }
      pops++;
      if (h >= M.maxDepth) continue;
      const adj = M.out.get(u);
      if (!adj) continue;
      const nh = h + 1;
      for (let i = 0; i < adj.length; i++) {
        const e = adj[i];
        if (!noCut && e.fixId && cut.has(String(e.fixId))) continue;
        const t = String(e.target);
        if (!M.nodes.has(t)) continue;
        if (minHops.has(t) && nh >= minHops.get(t)) continue;
        const nk = nh + '|' + t, nd = du + num(e.cost);
        if (sd.has(nk) && nd >= sd.get(nk)) continue;
        sd.set(nk, nd); prev.set(nk, e);
        heap.push([nd, nh, t]);
      }
    }
    return { dist: dist, hops: hops, prev: prev, done: done, pops: pops };
  }

  function chain(s, to) {
    const out = []; let x = to, h = s.hops.get(to) || 0;
    while (h > 0) { const e = s.prev.get(h + '|' + x); out.unshift(e); x = String(e.source); h--; }
    return out;
  }

  function weakest(edges) {
    let c = 'observed';
    edges.forEach(function (e) { const r = CONF_RANK[e.confidence]; if (r !== undefined && r < CONF_RANK[c]) c = e.confidence; });
    return c;
  }

  // Cheapest route from one entry to every crown it reaches, ordered by (cost, crown ordinal).
  function shortest(M, entry, cut) {
    const s = search(M, entry, cut);
    const hits = s.done.filter(function (id) { return M.crownSet.has(id) && id !== entry; });
    hits.sort(function (a, b) { return s.dist.get(a) - s.dist.get(b) || ord(a, b); });
    const paths = hits.map(function (c) {
      const edges = chain(s, c);
      return { entry: entry, crown: c, cost: s.dist.get(c), hops: edges.length, edges: edges, confidence: weakest(edges), criticality: M.crit.get(c) || 'high' };
    });
    return { depth: s.hops, dist: s.dist, paths: paths, byCrown: new Map(paths.map(function (p) { return [p.crown, p]; })) };
  }

  // Every (entry, crown) path, entries in export order.
  function allPaths(M, cut) {
    const out = [];
    M.entries.forEach(function (en) { shortest(M, en, cut).paths.forEach(function (p) { out.push(p); }); });
    return out;
  }

  // Greedy weighted set cover over fixIds, exactly as Get-VsatFixPlan: weight high 3, medium 2, low 1;
  // each round picks the fix breaking the most remaining weight, ties by fixId ordinal; at most 10 rounds.
  function fixPlan(paths, rounds) {
    const max = rounds === undefined ? 10 : rounds;
    let items = paths.map(function (p) {
      const fx = new Set();
      p.edges.forEach(function (e) { if (e && e.fixId) fx.add(String(e.fixId)); });
      return { path: p, weight: CRIT_WEIGHT[p.criticality] || 3, fixes: fx };
    });
    const total = items.length, plan = [];
    let cum = 0;
    while (items.length && plan.length < max) {
      const score = new Map();
      items.forEach(function (it) { it.fixes.forEach(function (f) { score.set(f, (score.get(f) || 0) + it.weight); }); });
      if (!score.size) break;
      let best = null;
      score.forEach(function (v, f) { if (best === null || v > score.get(best) || (v === score.get(best) && ord(f, best) < 0)) best = f; });
      const broken = items.filter(function (it) { return it.fixes.has(best); });
      items = items.filter(function (it) { return !it.fixes.has(best); });
      cum += broken.length;
      plan.push({ rank: plan.length + 1, fixId: best, pathsBroken: broken.length, cumulativeBroken: cum, pathsTotal: total, weightBroken: score.get(best) });
    }
    return plan;
  }

  return { model: model, search: search, shortest: shortest, allPaths: allPaths, fixPlan: fixPlan, weakest: weakest, ord: ord, CONF_RANK: CONF_RANK };
})();
if (typeof module !== 'undefined' && module.exports) module.exports = VsatBlastCore;
