/* VSAT Blast radius view, shared by the offline report and the local UI (the build concatenates it
 * after blast-core.js). It fills a static skeleton whose parts carry data-br attributes.
 * Security: all data is untrusted. DOM is built with createElement/textContent and an attribute
 * allow-list only; no innerHTML-family APIs, no dynamic code, no network, no storage. */
var VsatBlastView = (function () {
  'use strict';
  const C = VsatBlastCore;
  const NS = 'http://www.w3.org/2000/svg';
  const SAFE = /^(?:class|id|role|tabindex|title|type|value|for|scope|checked|disabled|hidden|label|aria-[a-z]+|data-[a-z-]+)$/;
  const SAFE_SVG = /^(?:x|y|x1|y1|x2|y2|cx|cy|r|rx|width|height|d|transform|viewBox|text-anchor|class|id|role|tabindex|focusable|aria-[a-z]+|data-[a-z-]+)$/;

  const KIND_VERB = { 'admin-of': 'is admin of', 'controls': 'controls', 'embodies': 'is', 'network-allow': 'can reach', 'mgmt-reach': 'can reach management of', 'credential-exposure': 'holds credentials for', 'member-of': 'is a member of' };
  const CONF_TEXT = { 'observed': 'Seen in config', 'configuration-inferred': 'Inferred from policy', 'correlated': 'Matched by IP', 'operator-declared': 'Declared by you' };
  const GAP_TEXT = { unknown: 'policy undecidable', denied: 'access denied', error: 'collection error', unsupported: 'not supported by the source', missing: 'not collected' };
  const PLAT = [['identity', 'Accounts'], ['hyperv', 'Hyper-V'], ['vmware', 'VMware'], ['nsx', 'NSX'], ['kvm', 'KVM']];
  const FIX_VERB = { 'revoke': 'remove this admin grant', 'revoke-member': 'remove this group membership', 'relocate': 'move this appliance to a dedicated management cluster', 'rule': 'tighten this firewall rule', 'segment': 'segment this network', 'isolate': 'isolate the management network', 'scope-svc': 'scope the service account', 'rotate': 'rotate these credentials' };
  const TYPE_TEXT = { 'vcenter': 'vCenter', 'nsx-manager': 'NSX Manager', 'hyperv-cluster': 'Hyper-V cluster', 'host': 'ESXi host', 'hyperv-host': 'Hyper-V host', 'kvm-host': 'KVM host', 'vm': 'VM', 'hyperv-vm': 'Hyper-V VM', 'kvm-vm': 'KVM VM', 'group': 'group', 'user': 'account' };
  const RING_MAX = 12, NODE_MAX = 300, IDLE_EDGES = 2000;
  const CX = 450, CY = 450;
  // Must match the skeleton's viewBox="-130 -10 1160 920"; label widths are estimated per character.
  const VB_LEFT = -126, VB_RIGHT = 1026, LBL_CHAR = 7.2, LBL2_CHAR = 6.2;
  function fitLabel(text, room, perChar) {
    const max = Math.max(4, Math.min(28, Math.floor(room / perChar)));
    return text.length > max ? text.slice(0, max - 1) + '…' : text;
  }

  function str(v) { return v === null || v === undefined ? '' : String(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
  function num(v) { const n = Number(v); return isFinite(n) ? n : 0; }
  function h(tag, attrs, text) {
    const el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (!SAFE.test(k)) throw new Error('Attribute not allowed: ' + k);
      el.setAttribute(k, v === true ? '' : String(v));
    });
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }
  function s(tag, attrs, parent, text) {
    const el = document.createElementNS(NS, tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (!SAFE_SVG.test(k)) throw new Error('SVG attribute not allowed: ' + k);
      el.setAttribute(k, String(v));
    });
    if (text !== undefined && text !== null) el.textContent = String(text);
    if (parent) parent.appendChild(el);
    return el;
  }
  function f1(n) { return (Math.round(n * 10) / 10).toString(); }
  function plural(n, one, many) { return n === 1 ? one : many; }

  function mount(root, data, opts) {
    const o = opts || {};
    const D = obj(data);
    const A = obj(D.analysis);
    const B = obj(A.blastRadius);
    const q = function (k) { return root.querySelector('[data-br="' + k + '"]'); };
    const M = C.model(B);
    const N = M.nodes;
    const fixPlanData = arr(B.fixPlan).filter(function (f) { return f && f.fixId; });
    const catalog = new Map();
    arr(A.workPackages).forEach(function (w) { if (w && w.id) catalog.set(str(w.id), str(w.title)); });
    arr(A.workPackageCatalog).forEach(function (w) { if (w && w.id && w.title) catalog.set(str(w.id), str(w.title)); });
    const fixTitle = new Map(fixPlanData.map(function (f) { return [str(f.fixId), str(f.title) || str(f.fixId)]; }));
    const zoneOf = typeof o.zoneOf === 'function' ? o.zoneOf : function () { return ''; };
    const nameOf = function (id) { const n = N.get(str(id)); return n ? (str(n.name) || str(n.id)) : (typeof o.nameOf === 'function' ? o.nameOf(id) : str(id)); };
    const reduceMotion = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
    const small = !!(window.matchMedia && window.matchMedia('(max-width: 640px)').matches);
    const svg = q('svg'), tip = q('tip');
    const state = { entry: M.entries[0] || null, cut: new Set(), crown: null, view: small ? 'list' : 'map', expanded: new Set(), lastBlast: null, forcedList: false, idle: 0 };

    function fixLabel(fixId) {
      const t = fixTitle.get(str(fixId));
      if (t) return t;
      const verb = str(fixId).split(':')[0];
      return FIX_VERB[verb] ? FIX_VERB[verb].charAt(0).toUpperCase() + FIX_VERB[verb].slice(1) : str(fixId);
    }
    function typeText(n) { return TYPE_TEXT[str(n.type)] || str(n.type).replace(/-/g, ' '); }
    function evidenceText(e) {
      return arr(e.evidence).slice(0, 2).map(function (x) { x = obj(x); return nameOf(x.assetId) + ' · ' + str(x.fact) + ' · ' + str(x.status); }).join('; ') || 'no evidence cited';
    }

    // ---------------------------------------------------------------- empty states
    if (!state.entry || !M.crowns.length) {
      const top = q('top'); if (top) top.hidden = true;
      const main = q('main'); if (main) main.hidden = true;
      const pathSec = q('path-wrap'); if (pathSec) pathSec.hidden = true;
      const box = q('empty');
      if (box) {
        box.hidden = false;
        box.appendChild(h('p', { class: 'br-verdict is-safe' }, !M.crowns.length ? 'No crown jewels in this assessment' : 'No starting point to analyze'));
        box.appendChild(h('p', { class: 'br-sub' }, !M.crowns.length
          ? 'Mark your critical assets in the scope file (criticalAssets) or connect a vCenter, NSX Manager or Hyper-V cluster so VSAT can trace paths to them.'
          : 'VSAT found no account with admin rights and no VM to start from in the collected evidence. Based on collected configuration; not proof of exploitability.'));
        arr(B.notes).slice(0, 6).forEach(function (n) { box.appendChild(h('p', { class: 'br-hint' }, str(n))); });
      }
      renderGaps();
      return;
    }

    // ---------------------------------------------------------------- base state
    const BASE = C.allPaths(M, new Set());
    // Open-path counts per cut set (key: the sorted fixIds), so ticking back and forth never recomputes.
    const openCache = new Map();
    function openCount(cutIds) {
      const k = cutIds.slice().sort(C.ord).join('\n');
      if (!openCache.has(k)) openCache.set(k, C.allPaths(M, new Set(cutIds)).length);
      return openCache.get(k);
    }
    const baseKey = new Map(BASE.map(function (p) { return [p.entry + '\n' + p.crown, p]; }));

    // ---------------------------------------------------------------- layout: sectors = platforms, rings = steps
    function layout(entry) {
      const sr = C.search(M, entry, null);
      const depth = sr.hops;
      const parent = function (id) { const e = sr.prev.get(depth.get(id) + '|' + id); return e ? str(e.source) : ''; };
      let ids = Array.from(depth.keys()).filter(function (id) { return id !== entry; });
      M.crowns.forEach(function (c) { if (c !== entry && !depth.has(c)) ids.push(c); });
      // Cap: keep crowns, then the nodes closest to the entry.
      let capped = false;
      if (ids.length + 1 > NODE_MAX) {
        const cr = ids.filter(function (id) { return N.get(id).crown; });
        const rest = ids.filter(function (id) { return !N.get(id).crown; }).sort(function (x, y) { return depth.get(x) - depth.get(y) || C.ord(nameOf(x), nameOf(y)) || C.ord(x, y); });
        ids = cr.concat(rest.slice(0, Math.max(0, NODE_MAX - 1 - cr.length)));
        capped = true;
      }
      // Aggregate: more than RING_MAX non-crown nodes in one (sector, ring) collapse per predecessor.
      const cell = new Map();
      ids.forEach(function (id) {
        const n = N.get(id);
        if (n.crown || !depth.has(id)) return;
        const k = str(n.platform) + '|' + depth.get(id);
        if (!cell.has(k)) cell.set(k, []);
        cell.get(k).push(id);
      });
      const aggOf = new Map(), aggs = new Map();
      cell.forEach(function (list, k) {
        if (list.length <= RING_MAX) return;
        const byParent = new Map();
        list.forEach(function (id) { const p = parent(id); if (!byParent.has(p)) byParent.set(p, []); byParent.get(p).push(id); });
        byParent.forEach(function (members, p) {
          const key = 'agg:' + k + '|' + p;
          if (members.length < 2 || state.expanded.has(key)) return;
          const t = N.get(members[0]);
          const noun = members.every(function (m) { return N.get(m).kind === 'principal'; }) ? 'accounts'
            : members.every(function (m) { return /vm$/.test(str(N.get(m).type)); }) ? 'VMs'
              : members.every(function (m) { return /host$/.test(str(N.get(m).type)); }) ? 'hosts' : 'items';
          aggs.set(key, { id: key, agg: true, members: members, platform: t.platform, depth: depth.get(members[0]), name: members.length + ' ' + noun + (p ? ' on ' + nameOf(p) : ''), kind: t.kind, type: t.type });
          members.forEach(function (m) { aggOf.set(m, key); });
        });
      });
      const show = [];
      ids.forEach(function (id) { if (!aggOf.has(id)) show.push(id); });
      aggs.forEach(function (_, key) { show.push(key); });
      const info = function (id) { return aggs.get(id) || N.get(id); };
      const dOf = function (id) { const a = aggs.get(id); return a ? a.depth : depth.get(id); };
      const reach = Array.from(depth.values());
      const maxD = Math.max(1, Math.max.apply(null, reach.length ? reach : [0]));
      const byPlat = new Map();
      show.forEach(function (id) { const p = str(info(id).platform) || 'other'; if (!byPlat.has(p)) byPlat.set(p, []); byPlat.get(p).push(id); });
      const order = PLAT.filter(function (p) { return byPlat.has(p[0]); });
      byPlat.forEach(function (_, p) { if (!PLAT.some(function (x) { return x[0] === p; })) order.push([p, p]); });
      const total = order.reduce(function (a, p) { return a + byPlat.get(p[0]).length + 0.8; }, 0) || 1;
      const pos = new Map(); pos.set(entry, { x: CX, y: CY, a: 0, r: 0 });
      const sectors = [];
      let ang = order.length ? -Math.PI / 2 - (Math.PI * 2 * (byPlat.get(order[0][0]).length + 0.8) / total) / 2 : 0;
      const unreached = M.crowns.some(function (c) { return c !== entry && !depth.has(c); });
      const R0 = 70, R = 380, step = (R - R0) / (maxD + (unreached ? 1 : 0.35));
      order.forEach(function (p) {
        const list = byPlat.get(p[0]).sort(function (x, y) { return (dOf(x) === undefined ? 99 : dOf(x)) - (dOf(y) === undefined ? 99 : dOf(y)) || C.ord(str(info(x).name), str(info(y).name)) || C.ord(x, y); });
        const span = Math.PI * 2 * (list.length + 0.8) / total;
        sectors.push({ label: p[1], a0: ang, a1: ang + span });
        list.forEach(function (id, i) {
          const a = ang + span * (i + 0.9) / (list.length + 0.8);
          const d = dOf(id);
          const r = d === undefined ? R0 + step * (maxD + 1) - 10 : R0 + step * d;
          pos.set(id, { x: CX + r * Math.cos(a), y: CY + r * Math.sin(a), a: a, r: r });
        });
        ang += span;
      });
      const at = function (id) { return pos.get(id) || (aggOf.has(id) ? pos.get(aggOf.get(id)) : null); };
      return { pos: pos, at: at, info: info, aggs: aggs, aggOf: aggOf, sectors: sectors, maxD: maxD, step: step, R0: R0, depth: depth, capped: capped, shown: show.length + 1 };
    }

    // ---------------------------------------------------------------- tooltip
    function showTip(text, ev) {
      if (!tip) return;
      tip.textContent = text;
      const c = q('canvas').getBoundingClientRect(), t = ev.currentTarget.getBoundingClientRect();
      tip.style.left = Math.max(4, Math.min(c.width - 290, t.left - c.left + t.width / 2 - 60)) + 'px';
      tip.style.top = Math.max(4, t.top - c.top - 40) + 'px';
      tip.classList.add('show');
    }
    function hideTip() { if (tip) tip.classList.remove('show'); }

    // ---------------------------------------------------------------- map
    function draw(now) {
      const entry = state.entry;
      const L = layout(entry);
      const onPath = new Set(arr(now.byCrown.get(state.crown) && now.byCrown.get(state.crown).edges).map(function (e) { return str(e.id); }));
      const reachedNow = now.depth;
      let maxNow = 0; reachedNow.forEach(function (d) { if (d > maxNow) maxNow = d; });
      while (svg.firstChild) svg.removeChild(svg.firstChild);
      s('title', { id: 'br-svg-title' }, svg, 'Blast radius map from ' + nameOf(entry));
      const g0 = s('g', null, svg);
      const blastR = maxNow ? L.R0 + L.step * maxNow : L.R0 * 0.55;
      const disc = s('circle', { cx: CX, cy: CY, r: f1(state.lastBlast === null || reduceMotion ? blastR : state.lastBlast), class: 'br-blast' }, g0);
      if (state.lastBlast !== null && state.lastBlast !== blastR && !reduceMotion) {
        void disc.getBoundingClientRect();
        window.requestAnimationFrame(function () { disc.setAttribute('r', f1(blastR)); });
      }
      state.lastBlast = blastR;
      s('circle', { cx: CX, cy: CY, r: f1(L.R0 * 0.55), class: 'br-blast-core' }, g0);
      const labA = L.sectors.length ? L.sectors[0].a0 : -Math.PI / 2;
      for (let d = 1; d <= L.maxD; d++) {
        const r = L.R0 + L.step * d;
        s('circle', { cx: CX, cy: CY, r: f1(r), class: 'br-ring' }, g0);
        s('text', { x: f1(CX + (r - 8) * Math.cos(labA)), y: f1(CY + (r - 8) * Math.sin(labA) + 4), 'text-anchor': 'middle', class: 'br-ring-num' }, g0, String(d));
      }
      L.sectors.forEach(function (sc) {
        s('line', { x1: f1(CX + L.R0 * Math.cos(sc.a0)), y1: f1(CY + L.R0 * Math.sin(sc.a0)), x2: f1(CX + 430 * Math.cos(sc.a0)), y2: f1(CY + 430 * Math.sin(sc.a0)), class: 'br-sector-line' }, g0);
        const m = (sc.a0 + sc.a1) / 2;
        s('text', { x: f1(CX + 446 * Math.cos(m)), y: f1(CY + 446 * Math.sin(m) + 4), 'text-anchor': Math.abs(Math.cos(m)) < 0.3 ? 'middle' : Math.cos(m) > 0 ? 'start' : 'end', class: 'br-sector-name' }, g0, sc.label);
      });
      // Edges reachable from the entry in the unfixed graph, drawn once per displayed pair.
      const gE = s('g', null, svg);
      const drawn = new Map();
      M.edgeById.forEach(function (e) {
        const src = str(e.source), tgt = str(e.target);
        if (!L.depth.has(src)) return;
        const a = L.at(src), b = L.at(tgt);
        if (!a || !b || a === b) return;
        const cut = !!(e.fixId && state.cut.has(str(e.fixId)));
        const on = onPath.has(str(e.id));
        const k = f1(a.x) + ',' + f1(a.y) + '>' + f1(b.x) + ',' + f1(b.y) + '|' + e.confidence;
        const prev = drawn.get(k);
        if (prev && (prev.on || !on) && (prev.cut || !cut)) return;
        if (prev) { gE.removeChild(prev.el); prev.marks.forEach(function (x) { gE.removeChild(x); }); }
        const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
        const cx = mx + (CX - mx) * 0.12, cy = my + (CY - my) * 0.12;
        const cls = ['br-edge', 'c-' + str(e.confidence), on ? 'on-path' : '', cut ? 'is-cut' : '', !on && !cut && onPath.size ? 'dim' : ''].join(' ');
        const el = s('path', { d: 'M' + f1(a.x) + ',' + f1(a.y) + ' Q' + f1(cx) + ',' + f1(cy) + ' ' + f1(b.x) + ',' + f1(b.y), class: cls }, gE);
        const marks = [];
        if (cut) {
          const qx = 0.25 * a.x + 0.5 * cx + 0.25 * b.x, qy = 0.25 * a.y + 0.5 * cy + 0.25 * b.y;
          const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1, nx = -dy / len * 9, ny = dx / len * 9;
          marks.push(s('line', { x1: f1(qx - nx), y1: f1(qy - ny), x2: f1(qx + nx), y2: f1(qy + ny), class: 'br-cut-mark' }, gE));
          marks.push(s('line', { x1: f1(qx - nx + dx / len * 5), y1: f1(qy - ny + dy / len * 5), x2: f1(qx + nx + dx / len * 5), y2: f1(qy + ny + dy / len * 5), class: 'br-cut-mark' }, gE));
        }
        drawn.set(k, { el: el, marks: marks, on: on, cut: cut });
      });
      // Nodes: crowns drawn last so they sit on top.
      const gN = s('g', null, svg);
      const ids = Array.from(L.pos.keys()).sort(function (x, y) { return (L.info(x).crown ? 1 : 0) - (L.info(y).crown ? 1 : 0); });
      ids.forEach(function (id) {
        const n = L.info(id), p = L.pos.get(id);
        const isAgg = !!n.agg;
        const reached = isAgg ? n.members.some(function (m) { return reachedNow.has(m); }) : reachedNow.has(id);
        const open = !!(n.crown && now.byCrown.has(id));
        const cls = ['br-node', n.crown ? 'crown' : '', id === entry ? 'entry' : '', reached ? 'reached' : 'unreached', n.crown && !open ? 'safe' : '', isAgg ? 'agg' : ''].join(' ');
        const label = isAgg ? n.name + ', group of ' + n.members.length + ', ' + (reached ? 'reachable' : 'not reachable now') + '. Press Enter to expand.'
          : str(n.name) + ', ' + typeText(n) + (id === entry ? ', compromised starting point' : '') + (n.crown ? ', crown jewel, ' + (open ? 'reachable in ' + now.byCrown.get(id).hops + ' steps' : 'not reachable') : reached ? ', reachable' : ', not reachable now');
        const g = s('g', { class: cls, transform: 'translate(' + f1(p.x) + ',' + f1(p.y) + ')', tabindex: 0, role: 'button', 'aria-label': label }, gN);
        s('circle', { r: 22, class: 'br-hit' }, g);
        const k = id === entry ? 1.35 : n.crown ? 1.15 : 1;
        if (n.crown) s('path', { d: 'M0,' + f1(-13 * k) + ' L' + f1(13 * k) + ',0 L0,' + f1(13 * k) + ' L' + f1(-13 * k) + ',0 Z', class: 'br-glyph' }, g);
        else if (n.kind === 'principal') s('circle', { r: f1(8 * k), class: 'br-glyph' }, g);
        else if (/host|cluster|manager|vcenter|endpoint/.test(str(n.type)) || n.kind === 'scope') s('rect', { x: f1(-8 * k), y: f1(-8 * k), width: f1(16 * k), height: f1(16 * k), rx: 1.5, class: 'br-glyph' }, g);
        else s('rect', { x: f1(-7 * k), y: f1(-7 * k), width: f1(14 * k), height: f1(14 * k), rx: 4, class: 'br-glyph' }, g);
        if (isAgg) s('text', { x: 0, y: 4, 'text-anchor': 'middle', class: 'br-agg-n' }, g, String(n.members.length));
        const out = id === entry ? { x: 0, y: 34, anchor: 'middle' } : { x: Math.cos(p.a) * 20, y: Math.sin(p.a) * 20 + 4, anchor: Math.abs(Math.cos(p.a)) < 0.35 ? 'middle' : Math.cos(p.a) > 0 ? 'start' : 'end' };
        if (id !== entry && Math.abs(Math.cos(p.a)) < 0.35) out.y += Math.sin(p.a) > 0 ? 10 : -6;
        // Keep labels inside the viewBox: truncate to the room left between the anchor and the edge
        // (the full name stays in the aria-label and the <title>).
        const room = out.anchor === 'end' ? p.x + out.x - VB_LEFT : out.anchor === 'start' ? VB_RIGHT - (p.x + out.x) : 2 * Math.min(p.x - VB_LEFT, VB_RIGHT - p.x);
        s('title', null, g, str(n.name));
        s('text', { x: f1(out.x), y: f1(out.y), 'text-anchor': out.anchor, class: 'br-lbl' }, g, fitLabel(str(n.name), room, LBL_CHAR));
        if (n.crown) s('text', { x: f1(out.x), y: f1(out.y + 14), 'text-anchor': out.anchor, class: 'br-lbl2' }, g, fitLabel(open ? 'reachable in ' + now.byCrown.get(id).hops + ' ' + plural(now.byCrown.get(id).hops, 'step', 'steps') : 'not reachable', room, LBL2_CHAR));
        const tipText = isAgg ? n.name + ' · press Enter or click to expand' : str(n.name) + ' · ' + typeText(n) + (n.crown ? ' · ' + str(n.crownReason) : '') + (zoneOf(id) ? ' · zone ' + zoneOf(id) : '');
        g.addEventListener('mouseenter', function (ev) { showTip(tipText, ev); });
        g.addEventListener('mouseleave', hideTip);
        g.addEventListener('focus', function (ev) { showTip(tipText, ev); });
        g.addEventListener('blur', hideTip);
        const pick = function () {
          if (isAgg) { state.expanded.add(id); render(); return; }
          if (n.crown && (now.byCrown.has(id) || baseKey.has(entry + '\n' + id))) { state.crown = id; render(); focusNode(id); }
        };
        g.addEventListener('click', pick);
        g.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); } });
        g.setAttribute('data-node', id);
      });
      const note = q('mapnote');
      if (note) { note.hidden = !L.capped; note.textContent = L.capped ? 'Map shows the ' + NODE_MAX + ' nodes closest to the compromised point. The List view has every path.' : ''; }
      return L;
    }
    function focusNode(id) {
      const list = svg.querySelectorAll('[data-node]');
      for (let i = 0; i < list.length; i++) if (list[i].getAttribute('data-node') === id) { list[i].focus(); break; }
    }

    // ---------------------------------------------------------------- verdict
    function tween(el, to) {
      const from = el.getAttribute('data-v') === null ? to : num(el.getAttribute('data-v'));
      el.setAttribute('data-v', String(to));
      if (reduceMotion || from === to) { el.textContent = String(to); return; }
      const t0 = performance.now();
      const stepFn = function (t) { const k = Math.min(1, (t - t0) / 320); el.textContent = String(Math.round(from + (to - from) * (1 - Math.pow(1 - k, 3)))); if (k < 1) window.requestAnimationFrame(stepFn); };
      window.requestAnimationFrame(stepFn);
    }
    // The visible count animates; screen readers get only the final sentence, written once.
    const verdictN = h('span', { class: 'n', 'aria-hidden': 'true' });
    const verdictRest = h('span', { 'aria-hidden': 'true' });
    const verdictSr = h('span', { class: 'br-sr' });
    let lastVerdict = null;
    function renderVerdict(now, base) {
      const reached = now.paths.length;
      const total = M.crowns.filter(function (c) { return c !== state.entry; }).length;
      const v = q('verdict');
      if (!verdictN.parentNode) { v.appendChild(verdictN); v.appendChild(verdictRest); v.appendChild(verdictSr); }
      v.classList.toggle('is-safe', reached === 0);
      const rest = ' of ' + total + ' crown ' + plural(total, 'jewel', 'jewels') + ' ' + plural(reached, 'is', 'are') + ' reachable';
      verdictRest.textContent = rest;
      if (lastVerdict !== reached + rest) { lastVerdict = reached + rest; verdictSr.textContent = reached + rest; }
      tween(verdictN, reached);
      const lost = base.paths.length - reached;
      const honesty = ' Based on collected configuration; not proof of exploitability.';
      let sub;
      if (reached === 0) sub = lost ? 'Your selected fixes close every path from ' + nameOf(state.entry) + '.' : 'No path from ' + nameOf(state.entry) + ' reaches a crown jewel in the collected evidence.';
      else {
        const fast = now.paths.slice().sort(function (a, b) { return a.hops - b.hops || a.cost - b.cost || C.ord(nameOf(a.crown), nameOf(b.crown)); })[0];
        sub = 'Fastest route: ' + fast.hops + ' ' + plural(fast.hops, 'step', 'steps') + ' to ' + nameOf(fast.crown) + '.' + (lost ? ' Your fixes already close ' + lost + '.' : '');
      }
      q('sub').textContent = sub + honesty;
    }
    function renderScope() {
      const el = q('scope'); if (!el) return;
      const bd = obj(B.bounds);
      const reach = bd.crownsReachable !== undefined ? num(bd.crownsReachable) : new Set(BASE.map(function (p) { return p.crown; })).size;
      const found = bd.pathsFound !== undefined ? num(bd.pathsFound) : BASE.length;
      el.textContent = 'Across all ' + M.entries.length + ' starting ' + plural(M.entries.length, 'point', 'points') + ' VSAT checked, ' + reach + ' of ' + M.crowns.length + ' crown ' + plural(M.crowns.length, 'jewel is', 'jewels are') + ' reachable through ' + found + ' attack ' + plural(found, 'path', 'paths') + '.';
      const partial = q('partial');
      if (partial) {
        const notes = arr(B.notes).map(str).filter(function (n) { return /bounds hit/i.test(n); });
        partial.hidden = !(bd.truncated && notes.length);
        while (partial.firstChild) partial.removeChild(partial.firstChild);
        if (!partial.hidden) { partial.appendChild(h('strong', null, 'Results are partial. ')); partial.appendChild(document.createTextNode(notes.join(' '))); }
      }
    }

    // ---------------------------------------------------------------- fixes
    function renderFixes() {
      const now = C.allPaths(M, state.cut);
      const pct = BASE.length ? now.length / BASE.length : 0;
      q('meter').style.width = (pct * 100).toFixed(1) + '%';
      q('meter-a').textContent = now.length + ' of ' + BASE.length + ' attack ' + plural(BASE.length, 'path', 'paths') + ' open';
      q('meter-b').textContent = state.cut.size ? (BASE.length - now.length) + ' closed' : '';
      const note = q('fixnote');
      if (note) { const fn = fixPlanData.map(function (f) { return str(f.note); }).filter(Boolean)[0]; note.hidden = !fn; note.textContent = fn || ''; }
      const box = q('fixes');
      while (box.firstChild) box.removeChild(box.firstChild);
      if (!fixPlanData.length) box.appendChild(h('p', { class: 'br-hint' }, 'No fix breaks a path: every route uses only inherent hops (a host controls its VMs).'));
      const rows = fixPlanData.map(function (f) { const id = str(f.fixId); return { f: f, id: id, on: state.cut.has(id), live: null }; });
      const draw = function () {
        rows.sort(function (a, b) { return (b.on - a.on) || ((b.live === null ? -1 : b.live) - (a.live === null ? -1 : a.live)) || C.ord(a.id, b.id); });
        while (box.firstChild) box.removeChild(box.firstChild);
        rows.forEach(function (r) {
          const wp = str(r.f.workPackage);
          const area = catalog.get(wp) || '';
          const lab = h('label', { class: 'br-fix-item' + (r.on ? ' on' : '') + (!r.on && r.live === 0 ? ' spent' : '') });
          const cb = h('input', { type: 'checkbox', 'aria-describedby': null });
          cb.checked = r.on;
          cb.addEventListener('change', function () { if (cb.checked) state.cut.add(r.id); else state.cut.delete(r.id); render(); });
          lab.appendChild(cb);
          lab.appendChild(h('span', { class: 't' }, fixLabel(r.id)));
          lab.appendChild(h('span', { class: 'k' }, r.on ? 'applied' : r.live === null ? 'counting…' : r.live ? 'closes ' + r.live : 'no effect now'));
          if (area) lab.appendChild(h('span', { class: 'd' }, area));
          box.appendChild(lab);
        });
      };
      const count = function (r) { r.live = r.on ? 0 : now.length - openCount(Array.from(state.cut).concat([r.id])); };
      if (state.idle) { (window.cancelIdleCallback || window.clearTimeout)(state.idle); state.idle = 0; }
      if (M.edgeCount > IDLE_EDGES) {
        draw();
        const queue = rows.slice();
        const idle = window.requestIdleCallback || function (fn) { return window.setTimeout(function () { fn({ timeRemaining: function () { return 8; } }); }, 16); };
        const work = function (dl) {
          while (queue.length && dl.timeRemaining() > 4) count(queue.shift());
          draw();
          state.idle = queue.length ? idle(work) : 0;
        };
        state.idle = idle(work);
      } else { rows.forEach(count); draw(); }
      // Reroute honesty: paths that survive the selected fixes by going the long way around.
      let reroutes = 0;
      now.forEach(function (p) { const b = baseKey.get(p.entry + '\n' + p.crown); if (b && (p.hops > b.hops || p.cost > b.cost)) reroutes++; });
      const rr = q('reroute');
      rr.classList.toggle('show', reroutes > 0);
      rr.textContent = reroutes ? reroutes + ' ' + plural(reroutes, 'path', 'paths') + ' found a longer way around your fixes. ' + plural(reroutes, 'It is', 'They are') + ' still counted as open.' : '';
      q('reset').hidden = state.cut.size === 0;
    }

    // ---------------------------------------------------------------- path detail
    function renderPath(now, base) {
      const pick = q('pick'), ol = q('steps');
      while (pick.firstChild) pick.removeChild(pick.firstChild);
      while (ol.firstChild) ol.removeChild(ol.firstChild);
      const crowns = base.paths.map(function (p) { return p.crown; });
      now.paths.forEach(function (p) { if (crowns.indexOf(p.crown) < 0) crowns.push(p.crown); });
      const conf = q('conf');
      if (!crowns.length) { ol.appendChild(h('li', { class: 'br-empty' }, 'No crown jewel is reachable from here.')); if (conf) conf.textContent = ''; return; }
      crowns.forEach(function (c) {
        const b = h('button', { type: 'button', class: 'br-chip', 'aria-pressed': String(c === state.crown) }, nameOf(c) + (now.byCrown.has(c) ? '' : ' (closed)'));
        b.addEventListener('click', function () { state.crown = c; render(); });
        pick.appendChild(b);
      });
      const p = now.byCrown.get(state.crown) || base.byCrown.get(state.crown);
      const edges = p ? p.edges : [];
      if (conf) conf.textContent = p ? 'Weakest link: ' + (CONF_TEXT[p.confidence] || str(p.confidence)) + '. ' + edges.length + ' ' + plural(edges.length, 'step', 'steps') + ' from ' + nameOf(state.entry) + ' to ' + nameOf(state.crown) + '.' : '';
      edges.forEach(function (e) {
        const cut = !!(e.fixId && state.cut.has(str(e.fixId)));
        const li = h('li', { class: cut ? 'cut' : null });
        li.appendChild(h('div', { class: 'how' }, nameOf(e.source) + ' ' + (KIND_VERB[e.kind] || str(e.kind)) + ' ' + nameOf(e.target)));
        if (e.explanation) li.appendChild(h('div', { class: 'why' }, str(e.explanation)));
        const m = h('div', { class: 'meta' });
        m.appendChild(h('span', { class: 'br-pill' }, CONF_TEXT[e.confidence] || str(e.confidence)));
        m.appendChild(h('span', { class: 'br-pill mono' }, evidenceText(e)));
        const at = obj(e.attack);
        if (at.technique) m.appendChild(h('span', { class: 'br-pill mono', title: str(at.name) || 'MITRE ATT&CK technique', 'aria-label': 'ATT&CK ' + str(at.technique) + (at.name ? ': ' + str(at.name) : '') }, 'ATT&CK ' + str(at.technique)));
        if (e.fixId) m.appendChild(h('span', { class: 'br-pill' + (cut ? ' fixed' : '') }, cut ? 'Fixed by your selection' : 'Fixable: ' + fixLabel(e.fixId)));
        li.appendChild(m);
        ol.appendChild(li);
      });
      if (!now.byCrown.has(state.crown)) ol.appendChild(h('li', { class: 'br-empty' }, 'This path is closed by your selected fixes.'));
    }

    // ---------------------------------------------------------------- list view
    function renderList(now) {
      const box = q('list');
      while (box.firstChild) box.removeChild(box.firstChild);
      const rows = now.paths.slice().sort(function (x, y) { return x.hops - y.hops || x.cost - y.cost || C.ord(nameOf(x.crown), nameOf(y.crown)); });
      box.appendChild(h('p', { class: 'br-hint' }, rows.length ? 'Open attack paths from ' + nameOf(state.entry) + ', fastest first.' : 'No open attack path from ' + nameOf(state.entry) + '.'));
      if (!rows.length) return;
      const t = h('table');
      const hd = h('tr');
      ['Crown jewel', 'Steps', 'How VSAT knows', 'Route'].forEach(function (c) { hd.appendChild(h('th', { scope: 'col' }, c)); });
      const th = h('thead'); th.appendChild(hd); t.appendChild(th);
      const tb = h('tbody');
      rows.forEach(function (p) {
        const tr = h('tr');
        const c1 = h('td', { 'data-l': 'Crown jewel', class: 'cj' });
        const b = h('button', { type: 'button', class: 'br-link' }, nameOf(p.crown));
        b.addEventListener('click', function () { state.crown = p.crown; render(); const sec = q('path-wrap'); if (sec && sec.scrollIntoView) sec.scrollIntoView({ block: 'start', behavior: reduceMotion ? 'auto' : 'smooth' }); });
        c1.appendChild(b);
        tr.appendChild(c1);
        tr.appendChild(h('td', { 'data-l': 'Steps' }, String(p.hops)));
        tr.appendChild(h('td', { 'data-l': 'How VSAT knows' }, CONF_TEXT[p.confidence] || str(p.confidence)));
        tr.appendChild(h('td', { 'data-l': 'Route' }, [nameOf(state.entry)].concat(p.edges.map(function (e) { return nameOf(e.target); })).join(' → ')));
        tb.appendChild(tr);
      });
      t.appendChild(tb);
      box.appendChild(t);
    }

    // ---------------------------------------------------------------- needs evidence
    function renderGaps() {
      const wrap = q('gaps-wrap'), ul = q('gaps');
      if (!wrap || !ul) return;
      const items = arr(B.needsEvidence).filter(function (x) { return x && typeof x === 'object'; });
      wrap.hidden = !items.length;
      while (ul.firstChild) ul.removeChild(ul.firstChild);
      const mine = state.entry ? items.filter(function (x) { return str(x.entry) === state.entry; }) : [];
      const rest = items.filter(function (x) { return mine.indexOf(x) < 0; });
      mine.concat(rest).slice(0, 50).forEach(function (x) {
        const g = obj(x.gap);
        const li = h('li');
        li.appendChild(h('div', { class: 'how' }, str(x.narrative)));
        li.appendChild(h('div', { class: 'why' }, str(x.explanation)));
        const m = h('div', { class: 'meta' });
        m.appendChild(h('span', { class: 'br-pill warn' }, GAP_TEXT[str(g.status)] || str(g.status) || 'not verified'));
        m.appendChild(h('span', { class: 'br-pill mono' }, nameOf(g.assetId) + ' · ' + str(g.missingFact) + ' · ' + str(g.status)));
        if (str(x.entry) === state.entry) m.appendChild(h('span', { class: 'br-pill' }, 'From the selected starting point'));
        li.appendChild(m);
        ul.appendChild(li);
      });
      if (items.length > 50) ul.appendChild(h('li', { class: 'br-empty' }, (items.length - 50) + ' more in results.json (analysis.blastRadius.needsEvidence).'));
    }

    // ---------------------------------------------------------------- render
    function setView(v) {
      state.view = v;
      root.classList.toggle('view-list', v === 'list');
      root.querySelectorAll('[data-br-view]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-br-view') === v)); });
    }
    function render() {
      const base = C.shortest(M, state.entry, null);
      const now = C.shortest(M, state.entry, state.cut);
      if (!state.crown || (!now.byCrown.has(state.crown) && !base.byCrown.has(state.crown))) state.crown = now.paths.length ? now.paths[0].crown : base.paths.length ? base.paths[0].crown : null;
      const L = draw(now);
      if (L.capped && !state.forcedList) { state.forcedList = true; setView('list'); }
      renderVerdict(now, base);
      renderFixes();
      renderPath(now, base);
      renderList(now);
      renderGaps();
    }

    // ---------------------------------------------------------------- controls
    const sel = q('entry');
    const principals = M.entries.filter(function (id) { return N.get(id).kind === 'principal'; });
    const others = M.entries.filter(function (id) { return N.get(id).kind !== 'principal'; })
      .sort(function (a, b) { return C.ord(zoneOf(a) || '￿', zoneOf(b) || '￿') || C.ord(nameOf(a), nameOf(b)) || C.ord(a, b); });
    function opt(id) {
      const n = N.get(id), z = zoneOf(id);
      return h('option', { value: id }, nameOf(id) + ' (' + (n.kind === 'principal' ? 'account' : typeText(n) + (z ? ', zone ' + z : '')) + ')');
    }
    if (principals.length) { const g = h('optgroup', { label: 'Accounts' }); principals.forEach(function (id) { g.appendChild(opt(id)); }); sel.appendChild(g); }
    const zones = [];
    others.forEach(function (id) { const z = zoneOf(id) || ''; if (zones.indexOf(z) < 0) zones.push(z); });
    zones.forEach(function (z) {
      const g = h('optgroup', { label: z ? 'VMs in zone ' + z : (zones.length > 1 ? 'Other VMs' : 'VMs') });
      others.filter(function (id) { return (zoneOf(id) || '') === z; }).forEach(function (id) { g.appendChild(opt(id)); });
      sel.appendChild(g);
    });
    sel.value = state.entry;
    sel.addEventListener('change', function () { state.entry = sel.value; state.crown = null; state.expanded.clear(); state.lastBlast = null; render(); });
    q('reset').addEventListener('click', function () { state.cut.clear(); render(); });
    root.querySelectorAll('[data-br-view]').forEach(function (b) { b.addEventListener('click', function () { setView(b.getAttribute('data-br-view')); }); });
    renderScope();
    setView(state.view);
    render();
    return { render: render, state: state };
  }

  return { mount: mount };
})();
