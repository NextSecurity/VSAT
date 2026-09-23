/* VSAT 2.0 standalone report.
 * Security model: all data from results.json is untrusted. It is rendered exclusively through
 * textContent / createElement / setAttribute on an allow-list of non-URL, non-event attributes.
 * No innerHTML-family APIs, no dynamic code, no network access, no persistent storage of data. */
(function () {
  'use strict';

  // =====================================================================
  // Safe DOM helpers
  // =====================================================================
  const SAFE_ATTR = /^(?:class|id|role|tabindex|title|type|value|name|for|colspan|rowspan|scope|placeholder|min|max|step|checked|selected|disabled|hidden|lang|dir|autocomplete|spellcheck|open|size|maxlength|aria-[a-z]+|data-[a-z-]+)$/;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const SAFE_SVG_ATTR = /^(?:x|y|x1|y1|x2|y2|cx|cy|r|rx|ry|width|height|d|points|fill|stroke|stroke-width|stroke-dasharray|stroke-linecap|stroke-linejoin|stroke-opacity|fill-opacity|opacity|transform|viewBox|font-size|font-family|font-weight|text-anchor|dominant-baseline|marker-end|marker-start|refX|refY|markerWidth|markerHeight|markerUnits|orient|preserveAspectRatio|focusable|pointer-events|vector-effect|class|id|role|tabindex|aria-[a-z]+|data-[a-z-]+|letter-spacing|paint-order)$/;

  function appendKids(el, kids) {
    for (let i = 0; i < kids.length; i++) {
      const k = kids[i];
      if (k === null || k === undefined || k === false) continue;
      if (Array.isArray(k)) appendKids(el, k);
      else if (k instanceof Node) el.appendChild(k);
      else el.appendChild(document.createTextNode(String(k)));
    }
  }
  function h(tag, attrs) {
    const el = document.createElement(tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        const v = attrs[key];
        if (v === null || v === undefined || v === false) continue;
        if (!SAFE_ATTR.test(key)) throw new Error('Attribute not allowed: ' + key);
        el.setAttribute(key, v === true ? '' : String(v));
      }
    }
    appendKids(el, Array.prototype.slice.call(arguments, 2));
    return el;
  }
  function svg(tag, attrs, text) {
    const el = document.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const key of Object.keys(attrs)) {
        const v = attrs[key];
        if (v === null || v === undefined || v === false) continue;
        if (!SAFE_SVG_ATTR.test(key)) throw new Error('SVG attribute not allowed: ' + key);
        el.setAttribute(key, String(v));
      }
    }
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }
  function on(el, ev, fn, opts) { el.addEventListener(ev, fn, opts); return el; }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function btn(label, fn, cls, attrs) {
    const b = h('button', Object.assign({ type: 'button', class: 'btn ' + (cls || '') }, attrs || {}), label);
    if (fn) on(b, 'click', fn);
    return b;
  }
  function linkBtn(label, fn, attrs) { return on(h('button', Object.assign({ type: 'button', class: 'linklike' }, attrs || {}), label), 'click', fn); }
  function str(v) { return v === null || v === undefined ? '' : String(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
  function num(v) { const n = Number(v); return isFinite(n) ? n : 0; }
  function fmtN(n) { return num(n).toLocaleString('en-US'); }
  function fmtTime(s) {
    if (!s) return '-';
    const d = new Date(String(s));
    if (isNaN(d.getTime())) return String(s);
    return d.toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
  }
  function trunc(s, n) { s = str(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function pct(a, b) { return b > 0 ? Math.round((a / b) * 100) : 0; }
  function safeFilePart(s) { return str(s).replace(/[^A-Za-z0-9._-]+/g, '_').slice(0, 60) || 'run'; }
  function announce(msg) { const l = document.getElementById('live'); if (l) { l.textContent = ''; l.textContent = msg; } }
  function debounce(fn, ms) { let t = 0; return function () { const a = arguments; clearTimeout(t); t = setTimeout(function () { fn.apply(null, a); }, ms); }; }
  function jsonText(v) { try { return JSON.stringify(v); } catch (e) { return ''; } }
  function valueText(v) {
    if (v === null || v === undefined) return '-';
    if (Array.isArray(v)) return v.map(valueText).join(', ');
    if (typeof v === 'object') return jsonText(v);
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    return String(v);
  }

  function fatal(msg) {
    const m = document.getElementById('main');
    if (!m) return;
    clear(m);
    m.appendChild(h('div', { class: 'notice notice-bad', role: 'alert' }, h('strong', null, 'Report could not be displayed'), msg));
  }

  // =====================================================================
  // Data
  // =====================================================================
  let D = null;
  try {
    const node = document.getElementById('vsat-data');
    D = JSON.parse(node ? node.textContent : '');
  } catch (e) { D = null; }
  if (!D || typeof D !== 'object' || Array.isArray(D)) { fatal('The embedded results data is missing or malformed. Re-generate the report with VSAT.'); return; }

  const SEV = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const RESULTS = ['FAIL', 'UNKNOWN', 'ERROR', 'MANUAL', 'PASS', 'NOT_APPLICABLE'];
  const RESULT_RANK = { FAIL: 5, ERROR: 4, UNKNOWN: 3, MANUAL: 2, PASS: 1, NOT_APPLICABLE: 0 };
  const RESULT_LABEL = { PASS: 'Pass', FAIL: 'Fail', MANUAL: 'Manual', UNKNOWN: 'Unknown', ERROR: 'Error', NOT_APPLICABLE: 'N/A' };
  const DOMAIN_LABEL = { vcenter: 'vCenter', esxi: 'ESXi', cluster: 'Cluster', vm: 'VM', network: 'Network', nsx: 'NSX', storage: 'Storage' };
  const TYPE_LABEL = {
    site: 'Site', vcenter: 'vCenter', datacenter: 'Datacenter', cluster: 'Cluster', host: 'Host', vm: 'VM', vss: 'Std switch', vds: 'Dist. switch',
    portgroup: 'Port group', dvportgroup: 'DV port group', pnic: 'Physical NIC', vmknic: 'VMkernel NIC', datastore: 'Datastore',
    'nsx-manager': 'NSX Manager', 'nsx-segment': 'NSX segment', 'nsx-t0': 'Tier-0 GW', 'nsx-t1': 'Tier-1 GW', 'nsx-edge-cluster': 'Edge cluster',
    'nsx-transport-node': 'Transport node', 'nsx-group': 'NSX group', 'nsx-policy': 'DFW policy', 'nsx-rule': 'DFW rule',
    'physical-neighbor': 'Phys. switch', zone: 'Zone'
  };
  const PAGE_SIZE = 200;

  // Shallow copies so display defaults never alter the embedded results used for JSON export.
  const findings = arr(D.findings).filter(function (f) { return f && typeof f === 'object'; }).map(function (f) {
    const c = Object.assign({}, f);
    return c;
  });
  const assets = arr(D.assets).filter(function (a) { return a && typeof a === 'object' && a.id !== undefined && a.id !== null; });
  const rels = arr(D.relationships).filter(function (r) { return r && typeof r === 'object'; });
  const analysis = obj(D.analysis);
  const run = obj(D.run);
  const tool = obj(D.tool);

  const ruleById = new Map();
  arr(D.rules).forEach(function (r) { if (r && typeof r === 'object' && r.id !== undefined) ruleById.set(str(r.id), r); });
  // Compact findings (typically PASS / NOT_APPLICABLE) may omit descriptive fields; fall back to the rule catalogue.
  function fx(f, field) {
    const v = f ? f[field] : undefined;
    if (v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length)) return v;
    const r = ruleById.get(str(f && f.ruleId));
    return r ? r[field] : undefined;
  }
  findings.forEach(function (f) {
    const r = ruleById.get(str(f.ruleId));
    if (!r) return;
    ['title', 'severity', 'domain'].forEach(function (k) { if (f[k] === undefined || f[k] === null || f[k] === '') f[k] = r[k]; });
  });
  function isCompact(f) { return !f.rationale && !f.mitigation && ruleById.has(str(f.ruleId)); }
  const assetById = new Map();
  assets.forEach(function (a) { assetById.set(String(a.id), a); });
  const findingById = new Map();
  const findingsByAsset = new Map();
  findings.forEach(function (f) {
    findingById.set(str(f.id), f);
    const k = str(f.assetId);
    if (!findingsByAsset.has(k)) findingsByAsset.set(k, []);
    findingsByAsset.get(k).push(f);
  });
  const relsByAsset = new Map();
  rels.forEach(function (r, i) {
    [str(r.source), str(r.target)].forEach(function (k) {
      if (!relsByAsset.has(k)) relsByAsset.set(k, []);
      relsByAsset.get(k).push(i);
    });
  });

  function sevOk(s) { return Object.prototype.hasOwnProperty.call(SEV_RANK, s) ? s : null; }
  function resOk(r) { return Object.prototype.hasOwnProperty.call(RESULT_RANK, r) ? r : null; }
  function assetName(id) { const a = assetById.get(str(id)); return a ? str(a.name) || str(a.id) : str(id); }
  function assetType(id) { const a = assetById.get(str(id)); return a ? str(a.type) : ''; }
  function typeLabel(t) { return TYPE_LABEL[t] || str(t); }
  function worstOf(list) { let w = null; list.forEach(function (f) { const s = sevOk(f.severity); if (f.result === 'FAIL' && s && (w === null || SEV_RANK[s] > SEV_RANK[w])) w = s; }); return w; }
  function assetWorst(a) { const s = sevOk(a && a.worstSeverity); return s || worstOf(findingsByAsset.get(str(a && a.id)) || []); }
  function assetFails(a) { const c = obj(a && a.findingCounts); if (c.FAIL !== undefined) return num(c.FAIL); return (findingsByAsset.get(str(a && a.id)) || []).filter(function (f) { return f.result === 'FAIL'; }).length; }

  // ---------- badges ----------
  function sevBadge(s) { const v = sevOk(s); return h('span', { class: 'badge sev-' + (v || 'none') }, v ? v : 'none'); }
  function resBadge(r) { const v = resOk(r); return h('span', { class: 'badge res-' + (v || 'NOT_APPLICABLE') }, v ? RESULT_LABEL[v] : str(r) || 'n/a'); }
  function stateClass(state) {
    switch (str(state).toUpperCase()) {
      case 'ASSESSED': return 'ok';
      case 'NOT_APPLICABLE': return 'neutral';
      case 'PARTIAL': case 'REVIEW': return 'warn';
      default: return 'bad';
    }
  }
  function stateBadge(state) { return h('span', { class: 'state state-' + stateClass(state) }, str(state).replace(/_/g, ' ') || 'UNKNOWN'); }

  // =====================================================================
  // Header, theme
  // =====================================================================
  function setText(id, v) { const e = document.getElementById(id); if (e) { e.textContent = v; e.setAttribute('title', v); } }
  setText('meta-version', (str(tool.name) || 'VSAT') + ' ' + (str(tool.version) || ''));
  setText('meta-run', str(run.id) || '-');
  setText('meta-generated', fmtTime(D.generatedUtc || run.endedUtc));
  setText('meta-profile', (str(obj(D.rulePack).profile) || '-') + ' · rules ' + (str(obj(D.rulePack).version) || '-'));

  const THEME_KEY = 'vsat-theme';
  function storedTheme() { try { const v = window.localStorage.getItem(THEME_KEY); return v === 'light' || v === 'dark' ? v : 'system'; } catch (e) { return 'system'; } }
  function applyTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.setAttribute('data-theme', t);
    else document.documentElement.removeAttribute('data-theme');
    const b = document.getElementById('theme-toggle');
    if (b) { const lbl = t === 'system' ? 'System' : t === 'dark' ? 'Dark' : 'Light'; b.textContent = 'Theme: ' + lbl; b.setAttribute('aria-label', 'Color theme: ' + lbl + '. Activate to change.'); }
  }
  function effectiveTheme() {
    const t = document.documentElement.getAttribute('data-theme');
    if (t === 'light' || t === 'dark') return t;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  let theme = storedTheme();
  applyTheme(theme);
  on(document.getElementById('theme-toggle'), 'click', function () {
    theme = theme === 'system' ? 'light' : theme === 'light' ? 'dark' : 'system';
    try { if (theme === 'system') window.localStorage.removeItem(THEME_KEY); else window.localStorage.setItem(THEME_KEY, theme); } catch (e) { /* storage unavailable */ }
    applyTheme(theme);
    onThemeChange();
  });
  if (window.matchMedia) {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    if (mq.addEventListener) mq.addEventListener('change', function () { onThemeChange(); });
  }
  function onThemeChange() { if (topo.ready) topo.render(); }

  // =====================================================================
  // Side panel
  // =====================================================================
  const panelEl = document.getElementById('panel');
  const panelTitle = document.getElementById('panel-title');
  const panelBody = document.getElementById('panel-body');
  let panelReturnFocus = null;
  function openPanel(title, content) {
    if (panelEl.hidden) panelReturnFocus = document.activeElement;
    panelTitle.textContent = title;
    clear(panelBody);
    appendKids(panelBody, [content]);
    panelEl.hidden = false;
    panelBody.scrollTop = 0;
    const c = document.getElementById('panel-close');
    if (c) c.focus();
  }
  function closePanel() {
    panelEl.hidden = true;
    if (panelReturnFocus && document.contains(panelReturnFocus) && panelReturnFocus.focus) panelReturnFocus.focus();
    panelReturnFocus = null;
  }
  on(document.getElementById('panel-close'), 'click', closePanel);
  on(document, 'keydown', function (e) { if (e.key === 'Escape' && !panelEl.hidden) { closePanel(); } });

  function section(title, content) {
    if (content === null || content === undefined || content === '' || (Array.isArray(content) && content.length === 0)) return null;
    return h('div', { class: 'section' }, h('h4', null, title), content);
  }
  function listOf(items, ordered) {
    const a = arr(items).filter(function (x) { return x !== null && x !== undefined && x !== ''; });
    if (!a.length) return null;
    return h(ordered ? 'ol' : 'ul', null, a.map(function (x) { return h('li', { class: 'break' }, valueText(x)); }));
  }
  function kv(pairs) {
    const dl = h('dl', { class: 'kv' });
    pairs.forEach(function (p) {
      if (p[1] === null || p[1] === undefined || p[1] === '') return;
      dl.appendChild(h('dt', null, p[0]));
      dl.appendChild(h('dd', null, p[1] instanceof Node ? p[1] : valueText(p[1])));
    });
    return dl;
  }

  // ---------- finding panel ----------
  function openFinding(f) {
    if (!f) return;
    const m = obj(fx(f, 'mitigation'));
    const pr = obj(f.priority);
    const ex = f.exception && typeof f.exception === 'object' ? f.exception : null;
    const rationale = fx(f, 'rationale'), limitations = fx(f, 'limitations');
    const advisories = arr(f.advisories).filter(function (x) { return x && typeof x === 'object'; });
    const content = h('div', null,
      h('div', { class: 'badges' }, resBadge(f.result), sevBadge(f.severity),
        h('span', { class: 'badge no-dot sev-info' }, 'Priority ' + num(pr.score)),
        h('span', { class: 'badge no-dot sev-info' }, 'Confidence: ' + (str(f.confidence) || 'n/a')),
        ex ? h('span', { class: 'badge no-dot ' + (ex.active ? 'sev-low' : 'sev-high') }, ex.active ? 'Exception active' : 'Exception expired') : null),
      h('h3', null, str(fx(f, 'title')) || str(f.ruleId)),
      isCompact(f) ? h('p', { class: 'small muted' }, 'Compact result: description, frameworks and mitigation shown from the rule catalogue.') : null,
      h('p', { class: 'muted small mono break' }, str(f.ruleId) + (f.ruleVersion ? ' v' + str(f.ruleVersion) : '') + ' · ' + str(f.id) + ' · ' + (DOMAIN_LABEL[f.domain] || str(f.domain))),
      kv([['Asset', h('span', null, linkBtn(str(f.assetName) || str(f.assetId), function () { openAsset(f.assetId); }), ' ', h('span', { class: 'muted small' }, '(' + typeLabel(f.assetType) + ')'))], ['Asset ID', h('span', { class: 'mono small' }, str(f.assetId))]]),
      h('div', { class: 'actions' },
        btn('Show on topology', function () { showOnTopology(f.assetId); }, 'btn-primary btn-sm'),
        m.workPackage ? btn('Open work package', function () { gotoWorkPackage(m.workPackage); }, 'btn-sm') : null),
      section('Why it matters', rationale ? h('p', { class: 'break' }, str(rationale)) : null),
      section('Observed vs expected', h('div', { class: 'obs-exp' },
        h('div', null, h('div', { class: 'lbl' }, 'Observed'), h('div', { class: 'val' }, str(f.observed) || '-')),
        h('div', null, h('div', { class: 'lbl' }, 'Expected'), h('div', { class: 'val' }, str(f.expected) || '-')))),
      section('Priority reasons', listOf(pr.reasons)),
      section('Advisories', advisories.length ? h('ul', { class: 'mini-list' }, advisories.map(function (a) {
        return h('li', null, sevBadge(a.severity), h('span', { class: 'grow' }, h('strong', { class: 'mono' }, str(a.id)),
          a.kev ? h('span', { class: 'state state-bad', title: 'Listed as known exploited' }, 'KNOWN EXPLOITED') : null,
          a.fix ? h('span', { class: 'sub small' }, 'Fix: ' + valueText(a.fix)) : null,
          arr(a.cves).length ? h('span', { class: 'sub small mono muted' }, arr(a.cves).map(str).join(', ')) : null));
      })) : null),
      section('Evidence', evidenceTable(arr(f.evidence))),
      section('Frameworks', frameworksList(arr(fx(f, 'frameworks')))),
      section('Mitigation', mitigationBlock(m)),
      section('Limitations', limitations ? h('p', { class: 'break' }, str(limitations)) : null),
      section('Exception', ex ? h('div', { class: 'notice ' + (ex.active ? 'notice-info' : 'notice-warn') },
        h('strong', null, ex.active ? 'Accepted risk (result stays FAIL)' : 'Exception expired — no longer accepted'),
        kv([['Owner', ex.owner], ['Rationale', ex.rationale], ['Expires', ex.expires]])) : null)
    );
    openPanel('Finding ' + str(f.id), content);
  }
  function evidenceTable(ev) {
    if (!ev.length) return null;
    return h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Fact'), h('th', { scope: 'col' }, 'Status'), h('th', { scope: 'col' }, 'Endpoint'), h('th', { scope: 'col' }, 'Observed'))),
      h('tbody', null, ev.map(function (e) {
        e = obj(e);
        const st = str(e.status);
        return h('tr', null, h('td', { class: 'mono break' }, str(e.fact)),
          h('td', null, h('span', { class: 'state state-' + (st === 'ok' || st === 'absent' ? 'ok' : st === 'denied' || st === 'unsupported' ? 'warn' : 'bad') }, st || 'n/a')),
          h('td', { class: 'break' }, str(e.endpoint)), h('td', { class: 'nowrap' }, fmtTime(e.observedUtc)));
      }))));
  }
  function frameworksList(fw) {
    if (!fw.length) return h('p', { class: 'muted' }, 'No framework mapping.');
    return h('ul', { class: 'fw-list' }, fw.map(function (x) {
      x = obj(x);
      const verified = x.mappingStatus === 'verified';
      return h('li', null, h('strong', null, str(x.framework)), x.edition ? ' ' + str(x.edition) : '',
        x.control ? h('span', null, ' — control ', h('span', { class: 'mono' }, str(x.control))) : null,
        h('span', { class: verified ? 'verified' : 'unverified', title: verified ? 'Mapping reviewed' : 'Mapping not verified; treat as indicative' }, verified ? 'verified' : 'unverified mapping'));
    }));
  }
  function mitigationBlock(m) {
    if (!m || !Object.keys(m).length) return null;
    return h('div', null,
      m.summary ? h('p', { class: 'break' }, str(m.summary)) : null,
      m.steps && arr(m.steps).length ? h('div', null, h('strong', { class: 'small' }, 'Steps'), listOf(m.steps, true)) : null,
      kv([['Validation', m.validation], ['Rollback', m.rollback], ['Impact', m.impact],
        ['Maintenance window', m.maintenanceWindow === undefined ? null : (m.maintenanceWindow ? 'required' : 'not required')], ['Work package', m.workPackage]]));
  }

  // ---------- asset panel ----------
  function openAsset(id) {
    const a = assetById.get(str(id));
    if (!a) { openPanel('Asset', h('p', { class: 'muted' }, 'Asset ' + str(id) + ' is not part of this report.')); return; }
    const fl = (findingsByAsset.get(str(a.id)) || []).slice().sort(findingCmp);
    const props = obj(a.props);
    const propPairs = Object.keys(props).map(function (k) {
      let v = props[k];
      if (a.type === 'nsx-rule' && (k === 'sources' || k === 'destinations' || k === 'appliedTo')) v = arr(v).map(function (x) { return assetById.has(str(x)) ? assetName(x) : x; });
      if (k === 'policy' && assetById.has(str(v))) v = assetName(v);
      return [k, valueText(v)];
    });
    const relIdx = relsByAsset.get(str(a.id)) || [];
    const relItems = relIdx.slice(0, 40).map(function (i) {
      const r = rels[i];
      const other = str(r.source) === str(a.id) ? r.target : r.source;
      const dir = str(r.source) === str(a.id) ? str(r.type) + ' →' : '← ' + str(r.type);
      return h('li', null, h('span', { class: 'via' }, dir), h('span', { class: 'grow' }, linkBtn(assetName(other), function () { openAsset(other); }), ' ', h('span', { class: 'muted small' }, typeLabel(assetType(other)))));
    });
    const mitigations = [];
    const seen = new Set();
    fl.forEach(function (f) { const m = obj(f.mitigation); if (f.result === 'FAIL' && m.summary && !seen.has(m.summary)) { seen.add(m.summary); mitigations.push(h('li', null, h('span', { class: 'grow' }, str(m.summary), m.workPackage ? h('span', { class: 'sub muted small' }, 'Work package ' + str(m.workPackage)) : null))); } });
    const content = h('div', null,
      h('div', { class: 'badges' }, h('span', { class: 'badge no-dot sev-info' }, typeLabel(a.type)), sevBadge(assetWorst(a)),
        a.criticality ? h('span', { class: 'badge no-dot sev-medium' }, 'Criticality ' + str(a.criticality) + (a.criticalitySource ? ' (' + str(a.criticalitySource) + ')' : '')) : null),
      h('h3', null, str(a.name) || str(a.id)),
      h('div', { class: 'actions' }, btn('Show on topology', function () { showOnTopology(a.id); }, 'btn-primary btn-sm'),
        fl.length ? btn('Open in Findings', function () { findingsPage.filterAsset(a.id); }, 'btn-sm') : null),
      kv([['ID', h('span', { class: 'mono small' }, str(a.id))], ['Endpoint', a.endpoint], ['Site', a.site], ['Zone', a.zone],
        ['Tags', arr(a.tags).length ? h('span', null, arr(a.tags).map(function (t) { return h('span', { class: 'tag' }, str(t)); })) : null],
        ['Version', a.version ? str(a.version) + (a.build ? ' (build ' + str(a.build) + ')' : '') : null], ['Observed', a.observedUtc ? fmtTime(a.observedUtc) : null]]),
      section('Properties', propPairs.length ? kv(propPairs) : null),
      section('Findings (' + fl.length + ')', fl.length ? h('ul', { class: 'mini-list' }, fl.slice(0, 100).map(function (f) {
        return h('li', null, resBadge(f.result), h('span', { class: 'grow' }, linkBtn(str(f.title) || str(f.ruleId), function () { openFinding(f); }), h('span', { class: 'sub muted small' }, str(f.ruleId))), f.result === 'FAIL' ? sevBadge(f.severity) : null);
      })) : h('p', { class: 'muted' }, 'No findings for this asset.')),
      section('Mitigations', mitigations.length ? h('ul', { class: 'mini-list' }, mitigations) : null),
      section('Relationships (' + relIdx.length + ')', relItems.length ? h('ul', { class: 'mini-list' }, relItems, relIdx.length > 40 ? h('li', { class: 'muted small' }, 'and ' + (relIdx.length - 40) + ' more') : null) : null)
    );
    openPanel(typeLabel(a.type) + ': ' + trunc(a.name, 60), content);
  }

  function findingCmp(a, b) {
    return (RESULT_RANK[b.result] || 0) - (RESULT_RANK[a.result] || 0) || (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || num(obj(b.priority).score) - num(obj(a.priority).score);
  }

  // =====================================================================
  // Generic paginated / sortable table
  // =====================================================================
  function DataTable(opts) {
    this.opts = opts;
    this.rows = [];
    this.page = 0;
    this.sortKey = opts.sortKey || null;
    this.sortDir = opts.sortDir || 'desc';
    this.pageSize = opts.pageSize || PAGE_SIZE;
    this.el = h('div', null);
    this.wrap = h('div', { class: 'table-wrap' });
    this.table = h('table', null);
    if (opts.caption) this.table.appendChild(h('caption', { class: 'sr-only' }, opts.caption));
    this.thead = h('thead');
    this.tbody = h('tbody');
    this.table.appendChild(this.thead);
    this.table.appendChild(this.tbody);
    this.wrap.appendChild(this.table);
    this.pager = h('div', { class: 'pager' });
    this.el.appendChild(this.wrap);
    this.el.appendChild(this.pager);
    this.renderHead();
  }
  DataTable.prototype.renderHead = function () {
    const self = this;
    clear(this.thead);
    const tr = h('tr');
    this.opts.columns.forEach(function (c) {
      const th = h('th', { scope: 'col', class: c.num ? 'num' : null });
      if (c.sort) {
        const active = self.sortKey === c.key;
        th.setAttribute('aria-sort', active ? (self.sortDir === 'asc' ? 'ascending' : 'descending') : 'none');
        th.appendChild(on(h('button', { type: 'button', title: 'Sort by ' + c.label }, c.label, h('span', { class: 'sort-ind', 'aria-hidden': 'true' }, active ? (self.sortDir === 'asc' ? '▲' : '▼') : '↕')), 'click', function () {
          if (self.sortKey === c.key) self.sortDir = self.sortDir === 'asc' ? 'desc' : 'asc';
          else { self.sortKey = c.key; self.sortDir = c.defaultDir || 'asc'; }
          self.applySort(); self.page = 0; self.renderHead(); self.renderBody();
        }));
      } else th.textContent = c.label;
      tr.appendChild(th);
    });
    this.thead.appendChild(tr);
  };
  DataTable.prototype.applySort = function () {
    const c = this.opts.columns.find(function (x) { return x.key === this.sortKey; }, this);
    if (!c || !c.sort) return;
    const dir = this.sortDir === 'asc' ? 1 : -1;
    const keyed = this.rows.map(function (r, i) { return { r: r, k: c.sort(r), i: i }; });
    keyed.sort(function (a, b) {
      const x = a.k, y = b.k;
      let d = 0;
      if (typeof x === 'number' && typeof y === 'number') d = x - y;
      else d = String(x).localeCompare(String(y), 'en', { numeric: true, sensitivity: 'base' });
      return d * dir || a.i - b.i;
    });
    this.rows = keyed.map(function (k) { return k.r; });
  };
  DataTable.prototype.setRows = function (rows, keepPage) {
    this.rows = rows.slice();
    this.applySort();
    if (!keepPage) this.page = 0;
    this.renderBody();
  };
  DataTable.prototype.renderBody = function () {
    const self = this;
    const o = this.opts;
    clear(this.tbody);
    const total = this.rows.length;
    const pages = Math.max(1, Math.ceil(total / this.pageSize));
    if (this.page >= pages) this.page = pages - 1;
    const start = this.page * this.pageSize;
    const slice = this.rows.slice(start, start + this.pageSize);
    const frag = document.createDocumentFragment();
    if (!slice.length) frag.appendChild(h('tr', null, h('td', { colspan: o.columns.length, class: 'empty' }, o.empty || 'No rows.')));
    slice.forEach(function (r) {
      const tr = h('tr', o.onRowClick ? { class: 'clickable', tabindex: '0' } : null);
      o.columns.forEach(function (c) {
        const v = c.render ? c.render(r) : str(r[c.key]);
        tr.appendChild(h('td', { class: (c.num ? 'num ' : '') + (c.cls || '') }, v));
      });
      if (o.onRowClick) {
        on(tr, 'click', function (e) { if (e.target.closest && e.target.closest('button')) return; o.onRowClick(r, tr); });
        on(tr, 'keydown', function (e) { if ((e.key === 'Enter' || e.key === ' ') && e.target === tr) { e.preventDefault(); o.onRowClick(r, tr); } });
      }
      frag.appendChild(tr);
    });
    this.tbody.appendChild(frag);
    clear(this.pager);
    this.pager.appendChild(h('span', null, total ? 'Rows ' + fmtN(start + 1) + '–' + fmtN(Math.min(total, start + this.pageSize)) + ' of ' + fmtN(total) : '0 rows'));
    if (pages > 1) {
      const prev = btn('‹ Previous', function () { self.page--; self.renderBody(); self.wrap.scrollIntoView({ block: 'nearest' }); }, 'btn-sm');
      prev.disabled = this.page === 0;
      const next = btn('Next ›', function () { self.page++; self.renderBody(); self.wrap.scrollIntoView({ block: 'nearest' }); }, 'btn-sm');
      next.disabled = this.page >= pages - 1;
      this.pager.appendChild(h('span', { class: 'btn-group' }, prev, h('span', { class: 'btn btn-sm', 'aria-live': 'polite' }, 'Page ' + (this.page + 1) + ' of ' + pages), next));
    }
  };

  // =====================================================================
  // Router
  // =====================================================================
  const PAGES = ['overview', 'findings', 'topology', 'nsx', 'changes', 'remediation', 'exports'];
  const rendered = {};
  const renderers = {};
  function ensureRendered(p) {
    if (rendered[p]) return;
    rendered[p] = true;
    const el = document.getElementById('page-' + p);
    try { renderers[p](el); } catch (e) { clear(el); el.appendChild(h('div', { class: 'notice notice-bad', role: 'alert' }, h('strong', null, 'This section could not be rendered.'), 'The results data may be incomplete or from an incompatible version.')); if (window.console) console.error(e); }
  }
  let currentPage = null;
  function route() {
    const raw = location.hash.replace(/^#/, '');
    const parts = raw.split('/');
    const page = PAGES.indexOf(parts[0]) >= 0 ? parts[0] : 'overview';
    const sub = parts[1] || '';
    ensureRendered(page);
    PAGES.forEach(function (p) { const el = document.getElementById('page-' + p); if (el) el.hidden = p !== page; });
    document.querySelectorAll('#tabs a').forEach(function (a) { if (a.getAttribute('data-page') === page) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    if (page === 'topology') topoPage.showSub(sub);
    if (currentPage !== page) { window.scrollTo(0, 0); currentPage = page; }
  }
  function go(page, sub) {
    const target = '#' + page + (sub ? '/' + sub : '');
    if (location.hash !== target) location.hash = target;
    route();
  }
  window.addEventListener('hashchange', route);
  window.addEventListener('beforeprint', function () { PAGES.forEach(ensureRendered); });

  function pageHead(id, title, subtitle, extra) {
    return h('div', { class: 'page-head' }, h('div', null, h('h1', { id: id }, title), subtitle ? h('p', null, subtitle) : null), extra || null);
  }

  // =====================================================================
  // Overview
  // =====================================================================
  renderers.overview = function (el) {
    const st = obj(D.status);
    const overall = str(st.overall).toLowerCase();
    let cls = 'st-bad', icon = '!';
    if (overall === 'complete') { cls = 'st-ok'; icon = '✓'; }
    else if (overall === 'incomplete') { cls = 'st-warn'; icon = '!'; }
    const label = str(st.label) || (overall ? overall.toUpperCase() : 'UNKNOWN: STATUS NOT REPORTED');
    const exitMap = { 0: 'clean', 1: 'findings present', 2: 'incomplete', 3: 'fatal', 4: 'canceled' };
    const rp = obj(D.rulePack), adv = obj(D.advisory);
    el.appendChild(pageHead('h-overview', 'Overview', 'Security findings, assessment coverage and evidence confidence are separate dimensions — read all three.'));
    el.appendChild(h('div', { class: 'status-banner ' + cls, role: 'status' },
      h('div', { class: 'st-icon', 'aria-hidden': 'true' }, icon),
      h('div', null,
        h('p', { class: 'st-label' }, label),
        h('p', { class: 'muted small' }, overall === 'complete' ? 'All mandatory domains were assessed.' : 'Assessment status: ' + (overall || 'unknown') + '. Missing evidence is never counted as compliant.'),
        listOf(st.reasons)),
      h('div', { class: 'st-side' },
        h('div', null, 'Exit code ', h('strong', null, str(st.exitCode === undefined ? '-' : st.exitCode)), st.exitCode !== undefined && exitMap[st.exitCode] ? ' (' + exitMap[st.exitCode] + ')' : ''),
        h('div', null, 'Run ', str(run.mode) || '-', ' · collection ', str(run.status) || '-'),
        h('div', null, fmtTime(run.startedUtc), ' → ', fmtTime(run.endedUtc)))));

    // three dimensions
    const sum = obj(D.summary);
    const sevC = obj(sum.severity), resC = obj(sum.results), confC = obj(sum.confidence);
    const failTotal = SEV.reduce(function (a, s) { return a + num(sevC[s]); }, 0);
    const resTotal = RESULTS.reduce(function (a, r) { return a + num(resC[r]); }, 0);
    const secCard = h('div', { class: 'card dim-card' },
      h('div', { class: 'dim-title' }, h('h2', null, 'Security findings'), h('span', { class: 'muted' }, 'FAIL results by severity')),
      h('div', { class: 'metric-row' }, SEV.map(function (s) {
        return h('div', { class: 'metric sev-tile sev-' + s }, h('div', { class: 'm-val' }, fmtN(sevC[s])), h('div', { class: 'm-lbl' }, s));
      })),
      resultBar(resC, resTotal),
      h('p', { class: 'small muted' }, fmtN(failTotal) + ' failing checks of ' + fmtN(resTotal) + ' evaluated.'),
      btn('Review findings →', function () { go('findings'); }, 'btn-sm'));
    const auto = obj(obj(D.coverage).automated);
    const known = num(auto.known), total = num(auto.total);
    const domains = coverageDomains();
    const assessedMand = domains.filter(function (d) { return d.mandatory; });
    const okMand = assessedMand.filter(function (d) { return stateClass(d.state) === 'ok' || stateClass(d.state) === 'neutral'; }).length;
    const covCard = h('div', { class: 'card dim-card' },
      h('div', { class: 'dim-title' }, h('h2', null, 'Assessment coverage'), h('span', { class: 'muted' }, 'how much could be decided')),
      h('div', null, h('span', { class: 'big-num' }, pct(known, total) + '%'), ' ', h('span', { class: 'muted' }, 'of checks decided automatically (' + fmtN(known) + ' / ' + fmtN(total) + ')')),
      h('div', { class: 'bar', role: 'img', 'aria-label': pct(known, total) + ' percent decided' }, sized(h('span', { class: 'b-known' }), known, total)),
      h('p', { class: 'small' }, h('strong', null, okMand + ' of ' + assessedMand.length), ' mandatory domains fully assessed.'),
      h('p', { class: 'small muted' }, 'UNKNOWN and ERROR results reduce coverage; they never count as compliant.'));
    const coll = arr(obj(D.collection).collectors);
    const collCounts = {};
    coll.forEach(function (c) { const s = str(c.status) || 'unknown'; collCounts[s] = (collCounts[s] || 0) + 1; });
    const confTotal = num(confC.observed) + num(confC.inferred);
    const confCard = h('div', { class: 'card dim-card' },
      h('div', { class: 'dim-title' }, h('h2', null, 'Evidence confidence'), h('span', { class: 'muted' }, 'how results were derived')),
      h('div', null, h('span', { class: 'big-num' }, pct(num(confC.observed), confTotal) + '%'), ' ', h('span', { class: 'muted' }, 'directly observed')),
      h('div', { class: 'bar', role: 'img', 'aria-label': 'observed ' + num(confC.observed) + ', inferred ' + num(confC.inferred) }, sized(h('span', { class: 'b-observed' }), confC.observed, confTotal), sized(h('span', { class: 'b-inferred' }), confC.inferred, confTotal)),
      h('ul', { class: 'legend-inline' }, h('li', null, swatch('b-observed'), 'Observed ' + fmtN(confC.observed)), h('li', null, swatch('b-inferred'), 'Inferred ' + fmtN(confC.inferred))),
      h('p', { class: 'small', }, 'Collectors: ', Object.keys(collCounts).length ? Object.keys(collCounts).sort().map(function (k, i) { return h('span', null, i ? ', ' : '', h('strong', null, String(collCounts[k])), ' ' + k); }) : 'not reported'));
    el.appendChild(h('div', { class: 'grid grid-3' }, secCard, covCard, confCard));

    // coverage domain cards
    el.appendChild(h('div', { class: 'section' }, h('div', { class: 'card-head' }, h('h2', null, 'Coverage by domain'), h('span', { class: 'muted small' }, 'Mandatory domains must be ASSESSED (or evidence-backed NOT APPLICABLE) for a complete status.')),
      coverageGroups(domains)));

    // top findings + side info
    const top = findings.filter(function (f) { return f.result === 'FAIL' || f.result === 'UNKNOWN' || f.result === 'ERROR'; })
      .sort(function (a, b) { return num(obj(b.priority).score) - num(obj(a.priority).score) || (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0); }).slice(0, 10);
    const topTable = h('div', { class: 'table-wrap' }, h('table', null,
      h('caption', { class: 'sr-only' }, 'Top 10 findings by priority'),
      h('thead', null, h('tr', null, h('th', { scope: 'col', class: 'num' }, 'Score'), h('th', { scope: 'col' }, 'Result'), h('th', { scope: 'col' }, 'Severity'), h('th', { scope: 'col' }, 'Finding'), h('th', { scope: 'col' }, 'Why prioritized'))),
      h('tbody', null, top.length ? top.map(function (f) {
        const tr = h('tr', { class: 'clickable', tabindex: '0' },
          h('td', { class: 'num' }, h('span', { class: 'score' }, String(num(obj(f.priority).score)))),
          h('td', null, resBadge(f.result)), h('td', null, sevBadge(f.severity)),
          h('td', { class: 'title-cell' }, linkBtn(str(f.title), function () { openFinding(f); }), h('span', { class: 'sub' }, str(f.assetName) + ' · ' + typeLabel(f.assetType) + (f.exception ? ' · exception' : ''))),
          h('td', { class: 'reasons' }, arr(obj(f.priority).reasons).map(str).join('; ')));
        on(tr, 'click', function (e) { if (!e.target.closest('button')) openFinding(f); });
        on(tr, 'keydown', function (e) { if (e.key === 'Enter' && e.target === tr) openFinding(f); });
        return tr;
      }) : h('tr', null, h('td', { colspan: '5', class: 'empty' }, 'No failing, unknown or error findings.')))));
    const ageDays = num(adv.ageDays);
    const advState = !adv.snapshotDate ? 'bad' : ageDays > 30 ? 'bad' : ageDays > 7 ? 'warn' : 'ok';
    const infoCard = h('div', { class: 'card' },
      h('h2', null, 'Rules & advisories'),
      kv([['Rule pack', str(rp.version) || '-'], ['Profile', str(rp.profile) || '-'], ['Rules', rp.ruleCount !== undefined ? fmtN(rp.ruleCount) : '-'],
        ['Advisory snapshot', h('span', null, str(adv.snapshotDate) || 'not available', ' ', h('span', { class: 'state state-' + advState }, adv.snapshotDate ? ageDays + ' days old' : 'missing'))]]),
      advState !== 'ok' ? h('p', { class: 'small muted' }, 'Patch/advisory findings are only as current as the snapshot. Update the advisory data and re-run for current results.') : null);
    const errs = coll.filter(function (c) { return str(c.status) !== 'ok'; });
    const errCard = h('div', { class: 'card' }, h('h2', null, 'Collector issues (' + errs.length + ')'),
      errs.length ? h('ul', { class: 'mini-list' }, errs.map(function (c) {
        const s = str(c.status);
        return h('li', null, h('span', { class: 'state state-' + (s === 'skipped' || s === 'unsupported' ? 'neutral' : s === 'partial' || s === 'denied' ? 'warn' : 'bad') }, s || '?'),
          h('span', { class: 'grow' }, h('strong', null, str(c.name)), h('span', { class: 'muted small' }, ' · ' + str(c.endpoint)),
            c.error ? h('span', { class: 'sub small break' }, str(c.error)) : null,
            arr(c.affects).length ? h('span', { class: 'sub muted small' }, 'Affects: ' + arr(c.affects).map(str).join(', ')) : null));
      })) : h('p', { class: 'muted' }, 'All collectors completed successfully.'));
    el.appendChild(h('div', { class: 'section' },
      h('div', { class: 'grid grid-2' },
        h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Top 10 findings by priority'), btn('All findings →', function () { go('findings'); }, 'btn-sm')), topTable),
        h('div', { class: 'stack' }, infoCard, errCard))));
  };
  function sized(span, v, total) { span.style.width = (total > 0 ? (num(v) / total) * 100 : 0) + '%'; if (!num(v)) span.style.minWidth = '0'; return span; }
  function swatch(cls) { return h('span', { class: 'sw ' + cls, 'aria-hidden': 'true' }); }
  function resultBar(resC, total) {
    const order = ['FAIL', 'ERROR', 'UNKNOWN', 'MANUAL', 'PASS', 'NOT_APPLICABLE'];
    const bar = h('div', { class: 'bar', role: 'img', 'aria-label': order.map(function (r) { return RESULT_LABEL[r] + ' ' + num(resC[r]); }).join(', ') });
    order.forEach(function (r) { bar.appendChild(sized(h('span', { class: 'b-' + r, title: RESULT_LABEL[r] + ': ' + num(resC[r]) }), resC[r], total)); });
    const legend = h('ul', { class: 'legend-inline' }, order.map(function (r) { return h('li', null, h('span', { class: 'sw b-' + r, 'aria-hidden': 'true' }), RESULT_LABEL[r] + ' ' + fmtN(resC[r])); }));
    return h('div', null, bar, legend);
  }
  function coverageDomains() {
    const doms = arr(obj(D.coverage).domains).filter(function (d) { return d && typeof d === 'object'; }).slice();
    if (!doms.some(function (d) { return d.id === 'nsx'; })) {
      const nd = obj(obj(D.nsx).discovery);
      doms.push({ id: 'nsx', name: 'NSX', mandatory: true, state: 'UNKNOWN', label: 'UNKNOWN: NSX COVERAGE NOT REPORTED', detail: 'This results file does not contain an NSX coverage entry.' + (nd.status ? ' Discovery status: ' + str(nd.status) + '.' : ''), missing: ['NSX coverage data'], checks: { total: 0 } });
    }
    doms.sort(function (a, b) { return (b.mandatory ? 1 : 0) - (a.mandatory ? 1 : 0); });
    return doms;
  }
  const PLATFORM_LABEL = { vmware: 'VMware vSphere / NSX', hyperv: 'Microsoft Hyper-V', kvm: 'KVM' };
  function coverageGroups(domains) {
    const hasPlatform = domains.some(function (d) { return d.platform; });
    if (!hasPlatform) return h('div', { class: 'grid grid-auto' }, domains.map(coverageCard));
    const groups = new Map();
    domains.forEach(function (d) { const p = str(d.platform) || 'vmware'; if (!groups.has(p)) groups.set(p, []); groups.get(p).push(d); });
    const out = [];
    groups.forEach(function (list, p) { out.push(h('h3', { class: 'platform-head' }, PLATFORM_LABEL[p] || p)); out.push(h('div', { class: 'grid grid-auto' }, list.map(coverageCard))); });
    return h('div', null, out);
  }
  function coverageCard(d) {
    const c = obj(d.checks);
    return h('div', { class: 'cov-card cov-' + stateClass(d.state) },
      h('h3', null, h('span', null, str(d.name) || DOMAIN_LABEL[d.id] || str(d.id)), stateBadge(d.state)),
      d.mandatory ? h('span', { class: 'mandatory' }, 'Mandatory') : h('span', { class: 'mandatory' }, 'Optional'),
      d.label ? h('p', { class: 'cov-label' }, str(d.label)) : null,
      d.detail ? h('p', { class: 'small muted break' }, str(d.detail)) : null,
      arr(d.missing).length ? h('div', { class: 'small' }, h('strong', null, 'Missing:'), listOf(d.missing)) : null,
      h('div', { class: 'cov-checks' }, h('span', null, h('strong', null, fmtN(c.total)), ' checks'),
        ['PASS', 'FAIL', 'UNKNOWN', 'ERROR', 'MANUAL', 'NOT_APPLICABLE'].map(function (r) { return num(c[r]) ? h('span', null, RESULT_LABEL[r] + ' ' + fmtN(c[r])) : null; })));
  }

  // =====================================================================
  // Findings page
  // =====================================================================
  const findingsPage = (function () {
    const state = { q: '', results: new Set(['FAIL', 'UNKNOWN', 'ERROR']), sev: new Set(SEV), domain: '', type: '', asset: '', wp: '' };
    let table = null, countEl = null, activeEl = null, root = null;
    const searchText = new Map();
    function textOf(f) {
      let t = searchText.get(f);
      if (t === undefined) { t = [f.id, f.title, f.ruleId, f.assetName, f.assetId, f.observed, f.domain, f.assetType].map(str).join('\u0001').toLowerCase(); searchText.set(f, t); }
      return t;
    }
    function filtered() {
      const q = state.q.trim().toLowerCase();
      return findings.filter(function (f) {
        if (!state.results.has(f.result)) return false;
        if (!state.sev.has(f.severity)) return false;
        if (state.domain && f.domain !== state.domain) return false;
        if (state.type && f.assetType !== state.type) return false;
        if (state.asset && str(f.assetId) !== state.asset) return false;
        if (state.wp && str(obj(f.mitigation).workPackage) !== state.wp) return false;
        if (q && textOf(f).indexOf(q) < 0) return false;
        return true;
      });
    }
    function refresh() {
      if (!table) return;
      const rows = filtered();
      table.setRows(rows);
      countEl.textContent = fmtN(rows.length) + ' of ' + fmtN(findings.length) + ' findings';
      clear(activeEl);
      if (state.asset) activeEl.appendChild(h('span', { class: 'active-filter' }, 'Asset: ' + trunc(assetName(state.asset), 40), btn('×', function () { state.asset = ''; refresh(); }, 'btn-ghost btn-sm', { 'aria-label': 'Remove asset filter' })));
      if (state.wp) activeEl.appendChild(h('span', { class: 'active-filter' }, 'Work package: ' + state.wp, btn('×', function () { state.wp = ''; refresh(); }, 'btn-ghost btn-sm', { 'aria-label': 'Remove work package filter' })));
    }
    function chipset(legend, values, set, labelFn) {
      const fs = h('fieldset', { class: 'chipset' }, h('legend', null, legend));
      values.forEach(function (v) {
        const input = h('input', { type: 'checkbox', value: v, checked: set.has(v) });
        on(input, 'change', function () { if (input.checked) set.add(v); else set.delete(v); refresh(); });
        fs.appendChild(h('label', { class: 'chip' }, input, h('span', null, labelFn ? labelFn(v) : v)));
      });
      return fs;
    }
    function selectOf(id, label, values, labelFn, key) {
      const sel = h('select', { id: id }, h('option', { value: '' }, 'All'), values.map(function (v) { return h('option', { value: v }, labelFn ? labelFn(v) : v); }));
      on(sel, 'change', function () { state[key] = sel.value; refresh(); });
      return h('label', { class: 'field', for: id }, h('span', null, label), sel);
    }
    function render(el) {
      root = el;
      el.appendChild(pageHead('h-findings', 'Findings', 'Default view shows FAIL, UNKNOWN and ERROR results. Exceptions remain FAIL and are labeled.'));
      const search = h('input', { type: 'search', id: 'f-search', placeholder: 'Search title, rule, asset, ID…', autocomplete: 'off', spellcheck: 'false' });
      on(search, 'input', debounce(function () { state.q = search.value; refresh(); }, 160));
      const domains = Array.from(new Set(findings.map(function (f) { return str(f.domain); }).filter(Boolean))).sort();
      const types = Array.from(new Set(findings.map(function (f) { return str(f.assetType); }).filter(Boolean))).sort();
      countEl = h('span', { class: 'muted small', 'aria-live': 'polite' });
      activeEl = h('span', { class: 'active-filters' });
      const reset = btn('Reset filters', function () {
        state.q = ''; search.value = ''; state.results = new Set(['FAIL', 'UNKNOWN', 'ERROR']); state.sev = new Set(SEV); state.domain = ''; state.type = ''; state.asset = ''; state.wp = '';
        clear(el); table = null; render(el);
      }, 'btn-sm btn-ghost');
      el.appendChild(h('div', { class: 'toolbar', role: 'search' },
        h('label', { class: 'field', for: 'f-search' }, h('span', null, 'Search'), search),
        chipset('Result', RESULTS, state.results, function (r) { return RESULT_LABEL[r]; }),
        chipset('Severity', SEV, state.sev),
        selectOf('f-domain', 'Domain', domains, function (d) { return DOMAIN_LABEL[d] || d; }, 'domain'),
        selectOf('f-type', 'Asset type', types, typeLabel, 'type'),
        h('div', { class: 'field' }, h('span', null, ' '), reset)));
      el.appendChild(h('div', { class: 'card-head' }, h('div', null, countEl, ' ', activeEl), h('span', { class: 'muted small' }, 'Select a row for details, evidence and mitigation.')));
      table = new DataTable({
        caption: 'Findings', sortKey: 'priority', sortDir: 'desc', empty: 'No findings match the current filters.',
        columns: [
          { key: 'priority', label: 'Priority', num: true, defaultDir: 'desc', sort: function (f) { return num(obj(f.priority).score); }, render: function (f) { return h('span', { class: 'score' }, String(num(obj(f.priority).score))); } },
          { key: 'result', label: 'Result', defaultDir: 'desc', sort: function (f) { return RESULT_RANK[f.result] || 0; }, render: function (f) { return resBadge(f.result); } },
          { key: 'severity', label: 'Severity', defaultDir: 'desc', sort: function (f) { return SEV_RANK[f.severity] || 0; }, render: function (f) { return sevBadge(f.severity); } },
          { key: 'title', label: 'Finding', cls: 'title-cell', sort: function (f) { return str(f.title); }, render: function (f) { return [linkBtn(str(f.title) || str(f.ruleId), function () { openFinding(f); }), h('span', { class: 'sub mono' }, str(f.ruleId) + ' · ' + str(f.id))]; } },
          { key: 'asset', label: 'Asset', sort: function (f) { return str(f.assetName); }, render: function (f) { return h('span', { class: 'break' }, str(f.assetName)); } },
          { key: 'type', label: 'Type', sort: function (f) { return str(f.assetType); }, render: function (f) { return typeLabel(f.assetType); } },
          { key: 'domain', label: 'Domain', sort: function (f) { return str(f.domain); }, render: function (f) { return DOMAIN_LABEL[f.domain] || str(f.domain); } },
          { key: 'exception', label: 'Exception', sort: function (f) { return f.exception ? (f.exception.active ? 2 : 1) : 0; }, render: function (f) { return f.exception ? h('span', { class: 'state state-' + (f.exception.active ? 'neutral' : 'warn') }, f.exception.active ? 'accepted' : 'expired') : ''; } }
        ],
        onRowClick: function (f) { openFinding(f); }
      });
      el.appendChild(table.el);
      refresh();
    }
    return {
      render: render,
      filterAsset: function (id) { state.asset = str(id); state.results = new Set(RESULTS); go('findings'); refreshUI(); },
      filterWp: function (wp) { state.wp = str(wp); state.results = new Set(RESULTS); go('findings'); refreshUI(); }
    };
    function refreshUI() { if (root && table) { clear(root); table = null; render(root); } }
  })();
  renderers.findings = findingsPage.render;

  // =====================================================================
  // Topology
  // =====================================================================
  const NODE_W = 212, NODE_H = 42, COL_W = 290, ROW_H = 54, PILL_W = 38, CHILD_PAGE = 50;
  const VIEWS = {
    infra: { label: 'Infrastructure', desc: 'site → vCenter → datacenter → cluster → host → VM; datastores', types: ['site', 'vcenter', 'datacenter', 'cluster', 'host', 'vm', 'datastore'],
      tree: [{ t: 'contains', p: 'source' }, { t: 'runs-on', p: 'target' }], overlay: ['stores'] },
    network: { label: 'Network', desc: 'switches, port groups, NSX segments and gateways, uplinks and physical neighbors', types: ['vds', 'vss', 'portgroup', 'dvportgroup', 'nsx-t0', 'nsx-t1', 'nsx-segment', 'vm', 'pnic', 'physical-neighbor'],
      tree: [{ t: 'routes', p: 'source' }, { t: 'contains', p: 'source' }, { t: 'uplink', p: 'target' }, { t: 'connects', p: 'target' }, { t: 'neighbor', p: 'source' }], overlay: ['connects', 'uplink', 'neighbor', 'routes'] },
    security: { label: 'Security', desc: 'zones, NSX groups and members, DFW policies and rules, critical assets', types: ['zone', 'nsx-group', 'nsx-policy', 'nsx-rule', 'vm'],
      tree: [{ t: 'contains', p: 'source', parentTypes: ['nsx-policy'] }, { t: 'member-of', p: 'target' }, { t: 'contains', p: 'source', parentTypes: ['zone'] }], overlay: ['member-of', 'applies-to', 'enforces', 'contains'] },
    resilience: { label: 'Resilience', desc: 'clusters, hosts, physical NICs, datastores, edge clusters and their dependents', types: ['cluster', 'host', 'vm', 'pnic', 'physical-neighbor', 'datastore', 'nsx-edge-cluster', 'nsx-t0', 'nsx-t1'],
      tree: [{ t: 'contains', p: 'source', parentTypes: ['cluster', 'host'] }, { t: 'runs-on', p: 'target' }, { t: 'depends', p: 'target', parentTypes: ['nsx-edge-cluster'] }, { t: 'neighbor', p: 'source' }], overlay: ['stores', 'depends', 'uplink', 'neighbor'] }
  };
  const VIEW_KEYS = ['infra', 'network', 'security', 'resilience'];
  const TYPE_ORDER = ['site', 'zone', 'nsx-manager', 'vcenter', 'datacenter', 'cluster', 'nsx-edge-cluster', 'nsx-t0', 'nsx-t1', 'vds', 'vss', 'nsx-policy', 'nsx-rule', 'nsx-group', 'host', 'datastore', 'portgroup', 'dvportgroup', 'nsx-segment', 'pnic', 'physical-neighbor', 'vmknic', 'vm'];
  const EDGE_STYLE = {
    contains: { label: 'contains (structure)', c: ['#9aa6b2', '#5b6878'], w: 1.3 },
    'runs-on': { label: 'runs on (placement)', c: ['#7b8794', '#7d8a99'], w: 1.4, dash: '2 3' },
    stores: { label: 'stores (datastore)', c: ['#8a5a2b', '#c49a6c'], w: 1.4, dash: '7 4' },
    connects: { label: 'connects (vNIC)', c: ['#1f6feb', '#58a6ff'], w: 1.9 },
    uplink: { label: 'uplink (physical NIC)', c: ['#0f766e', '#2dd4bf'], w: 2.8 },
    neighbor: { label: 'LLDP/CDP neighbor', c: ['#7c3aed', '#b392f0'], w: 1.7, dash: '9 3 2 3' },
    'member-of': { label: 'group membership', c: ['#15803d', '#56d47a'], w: 1.5, dash: '1.5 3' },
    'applies-to': { label: 'rule applied to', c: ['#c2410c', '#ff9a5c'], w: 1.7, dash: '5 3', arrow: true },
    enforces: { label: 'rule source/destination', c: ['#b42318', '#ff7b72'], w: 1.8, arrow: true },
    routes: { label: 'routes (L3 gateway)', c: ['#4338ca', '#8c95ff'], w: 2.6, arrow: true },
    depends: { label: 'depends on', c: ['#374151', '#aab4c0'], w: 1.7, dash: '4 2', arrow: true },
    manages: { label: 'manages', c: ['#6b7785', '#8b98a8'], w: 1.2, dash: '1 2' }
  };
  const STRUCTURAL = { contains: 1, 'runs-on': 1, stores: 1, 'member-of': 1, manages: 1 };
  const PALETTE = {
    light: { bg: '#ffffff', node: '#ffffff', nodeStroke: '#b3bdc8', text: '#16202a', text2: '#4a5663', accent: '#1d5bbf', pill: '#f0f3f7', more: '#f7f9fb',
      sev: { critical: '#a4161a', high: '#b93d0a', medium: '#8f5600', low: '#0b6a80', info: '#56616d' },
      tint: { critical: '#fde8e8', high: '#fdede3', medium: '#fcf3dc', low: '#e1f3f6', info: '#f4f5f7' }, crit: '#6a3fbf', idx: 0 },
    dark: { bg: '#151b23', node: '#1b232d', nodeStroke: '#3d4a59', text: '#e6edf3', text2: '#aeb9c5', accent: '#6ea8fe', pill: '#242e3a', more: '#1b232d',
      sev: { critical: '#ff7b7b', high: '#ff9a5c', medium: '#e8b54a', low: '#4fc3d9', info: '#a3aebb' },
      tint: { critical: '#3a1618', high: '#3a2113', medium: '#33280f', low: '#0f2f36', info: '#1b232d' }, crit: '#b99bff', idx: 1 }
  };
  const FONT = 'system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif';

  const relsByType = new Map();
  rels.forEach(function (r, i) { const t = str(r.type); if (!relsByType.has(t)) relsByType.set(t, []); relsByType.get(t).push(i); });

  const models = {};
  function model(key) {
    if (models[key]) return models[key];
    const V = VIEWS[key];
    const types = new Set(V.types);
    const inView = function (id) { const a = assetById.get(id); return a && types.has(a.type); };
    const parent = new Map(), children = new Map(), treeRel = new Map(), treeSet = new Set();
    function wouldCycle(child, par) { let p = par, guard = 0; while (p !== undefined && guard++ < 10000) { if (p === child) return true; p = parent.get(p); } return false; }
    V.tree.forEach(function (rule) {
      (relsByType.get(rule.t) || []).forEach(function (i) {
        const r = rels[i];
        const src = str(r.source), tgt = str(r.target);
        const child = rule.p === 'source' ? tgt : src;
        const par = rule.p === 'source' ? src : tgt;
        if (child === par || !inView(child) || !inView(par)) return;
        if (rule.parentTypes && rule.parentTypes.indexOf(assetType(par)) < 0) return;
        if (parent.has(child) || wouldCycle(child, par)) return;
        parent.set(child, par);
        if (!children.has(par)) children.set(par, []);
        children.get(par).push(child);
        treeRel.set(child, i);
        treeSet.add(i);
      });
    });
    const typeRank = function (id) { const i = TYPE_ORDER.indexOf(assetType(id)); return i < 0 ? 99 : i; };
    const cmp = function (a, b) { return typeRank(a) - typeRank(b) || assetName(a).localeCompare(assetName(b), 'en', { numeric: true }) || (a < b ? -1 : 1); };
    children.forEach(function (list) { list.sort(cmp); });
    const roots = [];
    const all = [];
    assets.forEach(function (a) { const id = str(a.id); if (types.has(a.type)) { all.push(id); if (!parent.has(id)) roots.push(id); } });
    roots.sort(cmp);
    // subtree aggregates (iterative post-order)
    const agg = new Map();
    const order = [];
    const stack = roots.slice();
    while (stack.length) { const n = stack.pop(); order.push(n); (children.get(n) || []).forEach(function (c) { stack.push(c); }); }
    for (let i = order.length - 1; i >= 0; i--) {
      const id = order[i];
      const a = assetById.get(id);
      let fail = assetFails(a), worst = assetWorst(a), count = 0;
      (children.get(id) || []).forEach(function (c) {
        const g = agg.get(c);
        fail += g.fail; count += 1 + g.count;
        if (g.worst && (!worst || SEV_RANK[g.worst] > SEV_RANK[worst])) worst = g.worst;
      });
      agg.set(id, { fail: fail, worst: worst, count: count });
    }
    const overlaySet = new Set(V.overlay);
    const overlay = [];
    overlaySet.forEach(function (t) { (relsByType.get(t) || []).forEach(function (i) { const r = rels[i]; if (!treeSet.has(i) && inView(str(r.source)) && inView(str(r.target))) overlay.push(i); }); });
    const m = { key: key, V: V, parent: parent, children: children, roots: roots, agg: agg, overlay: overlay, treeRel: treeRel, all: all, has: function (id) { return inView(id); } };
    models[key] = m;
    return m;
  }

  const topo = {
    ready: false, view: 'infra', expanded: {}, shown: {}, selected: null, hl: new Set(), hlEdges: new Set(), hlLabel: '',
    tx: 40, ty: 40, k: 1, sevMin: -1, site: '', table: false, layout: null, svg: null, vp: null, focusId: null, scopeEl: null, legendEl: null,
    render: function () {}
  };
  VIEW_KEYS.forEach(function (k) { topo.expanded[k] = new Set(); topo.shown[k] = new Map(); });

  function nodePasses(M, id) {
    const a = assetById.get(id);
    if (topo.site && a && a.site && str(a.site) !== topo.site) return false;
    if (topo.sevMin >= 0) { const g = M.agg.get(id); if (!g || !g.worst || SEV_RANK[g.worst] < topo.sevMin) return false; }
    return true;
  }
  function visibleKids(M, id) {
    const key = id === null ? '__root__' : id;
    const list = (id === null ? M.roots : (M.children.get(id) || [])).filter(function (c) { return nodePasses(M, c); });
    const limit = topo.shown[M.key].get(key) || CHILD_PAGE;
    return { list: list.slice(0, limit), hidden: Math.max(0, list.length - limit), total: list.length };
  }
  function computeLayout(M) {
    const pos = new Map();
    const items = [];
    const links = [];
    let row = 0;
    const exp = topo.expanded[M.key];
    function place(id, depth, parentId) {
      const kidsInfo = exp.has(id) ? visibleKids(M, id) : { list: [], hidden: 0 };
      const ys = [];
      kidsInfo.list.forEach(function (c) { ys.push(place(c, depth + 1, id)); links.push({ from: id, to: c, rel: M.treeRel.get(c) }); });
      if (kidsInfo.hidden > 0) {
        const mid = 'more:' + id;
        const y = row++ * ROW_H;
        items.push({ kind: 'more', id: mid, parent: id, x: (depth + 1) * COL_W, y: y, hidden: kidsInfo.hidden });
        links.push({ from: id, to: mid, rel: undefined });
        pos.set(mid, { x: (depth + 1) * COL_W, y: y });
        ys.push(y);
      }
      let y;
      if (!ys.length) y = row++ * ROW_H;
      else y = (ys[0] + ys[ys.length - 1]) / 2;
      pos.set(id, { x: depth * COL_W, y: y });
      items.push({ kind: 'node', id: id, parent: parentId, x: depth * COL_W, y: y });
      return y;
    }
    const r = visibleKids(M, null);
    r.list.forEach(function (id) { place(id, 0, null); row += 0.35; });
    if (r.hidden > 0) { const y = row++ * ROW_H; items.push({ kind: 'more', id: 'more:__root__', parent: '__root__', x: 0, y: y, hidden: r.hidden }); pos.set('more:__root__', { x: 0, y: y }); }
    let maxX = 0, maxY = 0;
    pos.forEach(function (p) { if (p.x > maxX) maxX = p.x; if (p.y > maxY) maxY = p.y; });
    return { pos: pos, items: items, links: links, w: maxX + NODE_W + PILL_W + 20, h: maxY + NODE_H, rootsHidden: r.hidden, rootsTotal: r.total };
  }

  function edgeColor(type, pal) { const s = EDGE_STYLE[type] || EDGE_STYLE.contains; return s.c[pal.idx]; }
  function addMarkers(defs, pal, prefix) {
    Object.keys(EDGE_STYLE).forEach(function (t) {
      if (!EDGE_STYLE[t].arrow) return;
      const mk = svg('marker', { id: prefix + 'arr-' + t, viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '7', markerHeight: '7', orient: 'auto', markerUnits: 'userSpaceOnUse' });
      mk.appendChild(svg('path', { d: 'M0,0 L10,5 L0,10 z', fill: edgeColor(t, pal) }));
      defs.appendChild(mk);
    });
    const hm = svg('marker', { id: prefix + 'arr-hl', viewBox: '0 0 10 10', refX: '9', refY: '5', markerWidth: '8', markerHeight: '8', orient: 'auto', markerUnits: 'userSpaceOnUse' });
    hm.appendChild(svg('path', { d: 'M0,0 L10,5 L0,10 z', fill: pal.accent }));
    defs.appendChild(hm);
  }

  // Draw graph into group g (shared by on-screen rendering and export).
  function drawGraph(g, M, L, pal, interactive, prefix) {
    const hlActive = topo.hl.size > 0;
    const edgesG = svg('g', { 'aria-hidden': 'true' });
    const nodesG = svg('g', interactive ? { role: 'tree', 'aria-label': VIEWS[M.key].label + ' topology' } : null);
    g.appendChild(edgesG);
    g.appendChild(nodesG);
    // tree links (elbow)
    L.links.forEach(function (lk) {
      const a = L.pos.get(lk.from), b = L.pos.get(lk.to);
      if (!a || !b) return;
      const r = lk.rel !== undefined ? rels[lk.rel] : null;
      const type = r ? str(r.type) : 'contains';
      const st = EDGE_STYLE[type] || EDGE_STYLE.contains;
      const x1 = a.x + NODE_W + PILL_W, y1 = a.y + NODE_H / 2, x2 = b.x, y2 = b.y + NODE_H / 2;
      const mx = x1 + (x2 - x1) / 2;
      const isHl = lk.rel !== undefined && topo.hlEdges.has(lk.rel);
      edgesG.appendChild(svg('path', {
        d: 'M' + x1 + ',' + y1 + ' H' + mx + ' V' + y2 + ' H' + x2, fill: 'none',
        stroke: isHl ? pal.accent : edgeColor(type, pal), 'stroke-width': isHl ? st.w + 2 : st.w, 'stroke-dasharray': st.dash || null,
        opacity: hlActive && !isHl ? 0.35 : 1
      }));
    });
    // overlay edges (curves)
    M.overlay.forEach(function (i) {
      const r = rels[i];
      const a = L.pos.get(str(r.source)), b = L.pos.get(str(r.target));
      if (!a || !b) return;
      const type = str(r.type);
      const st = EDGE_STYLE[type] || EDGE_STYLE.contains;
      const isHl = topo.hlEdges.has(i);
      let x1, x2;
      const y1 = a.y + NODE_H / 2, y2 = b.y + NODE_H / 2;
      if (Math.abs(a.x - b.x) < 1) { x1 = a.x; x2 = b.x; } else if (a.x < b.x) { x1 = a.x + NODE_W; x2 = b.x; } else { x1 = a.x; x2 = b.x + NODE_W; }
      let d;
      if (Math.abs(a.x - b.x) < 1) { const bend = Math.min(160, 30 + Math.abs(y2 - y1) * 0.25); d = 'M' + x1 + ',' + y1 + ' C' + (x1 - bend) + ',' + y1 + ' ' + (x2 - bend) + ',' + y2 + ' ' + x2 + ',' + y2; }
      else { const dx = (x2 - x1) * 0.5; d = 'M' + x1 + ',' + y1 + ' C' + (x1 + dx) + ',' + y1 + ' ' + (x2 - dx) + ',' + y2 + ' ' + x2 + ',' + y2; }
      edgesG.appendChild(svg('path', {
        d: d, fill: 'none', stroke: isHl ? pal.accent : edgeColor(type, pal), 'stroke-width': isHl ? st.w + 2 : st.w,
        'stroke-dasharray': st.dash || null, 'stroke-linecap': type === 'member-of' ? 'round' : null,
        'marker-end': st.arrow ? 'url(#' + prefix + (isHl ? 'arr-hl' : 'arr-' + type) + ')' : null,
        opacity: hlActive && !isHl ? 0.25 : (STRUCTURAL[type] ? 0.75 : 0.95)
      }));
    });
    // nodes
    const exp = topo.expanded[M.key];
    L.items.forEach(function (it) {
      if (it.kind === 'more') {
        const mg = svg('g', { transform: 'translate(' + it.x + ',' + it.y + ')', class: interactive ? 'gnode' : null, 'data-more': interactive ? it.parent : null, tabindex: interactive ? '0' : null, role: interactive ? 'button' : null, 'aria-label': interactive ? 'Show ' + Math.min(CHILD_PAGE, it.hidden) + ' more of ' + it.hidden + ' hidden items' : null });
        mg.appendChild(svg('rect', { width: NODE_W, height: NODE_H, rx: '6', fill: pal.more, stroke: pal.nodeStroke, 'stroke-dasharray': '4 3' }));
        mg.appendChild(svg('text', { x: '14', y: '26', 'font-size': '12.5', 'font-family': FONT, fill: pal.text2, 'font-weight': '600' }, '+ ' + fmtN(it.hidden) + ' more — show next ' + Math.min(CHILD_PAGE, it.hidden)));
        if (interactive) mg.appendChild(svg('rect', { class: 'gfocus', x: '-4', y: '-4', width: NODE_W + 8, height: NODE_H + 8, rx: '9', fill: 'none', stroke: pal.accent, 'stroke-width': '2.5' }));
        nodesG.appendChild(mg);
        return;
      }
      const id = it.id;
      const a = assetById.get(id);
      const agg = M.agg.get(id) || { fail: 0, worst: null, count: 0 };
      const own = assetWorst(a);
      const ownFails = assetFails(a);
      const kids = (M.children.get(id) || []).filter(function (c) { return nodePasses(M, c); }).length;
      const isExp = exp.has(id);
      const sel = topo.selected === id;
      const isHl = topo.hl.has(id);
      const dim = hlActive && !isHl && !sel;
      const critical = a && str(a.criticality) === 'high';
      const label = typeLabel(a.type) + ' ' + str(a.name) + (own ? ', worst failing severity ' + own + ', ' + ownFails + ' failing' : ', no failing findings') +
        (kids ? (isExp ? ', expanded, ' : ', collapsed, ') + kids + ' children' : '') + (!isExp && agg.fail > ownFails ? ', ' + (agg.fail - ownFails) + ' failing below' : '') + (critical ? ', critical asset' : '');
      const ng = svg('g', { transform: 'translate(' + it.x + ',' + it.y + ')', class: interactive ? 'gnode' : null, 'data-node': interactive ? id : null, tabindex: interactive ? '0' : null,
        role: interactive ? 'treeitem' : null, 'aria-label': interactive ? label : null, 'aria-expanded': interactive && kids ? String(isExp) : null, 'aria-selected': interactive ? String(sel) : null, opacity: dim ? 0.35 : null });
      if (interactive) ng.appendChild(svg('title', null, str(a.name) + ' (' + typeLabel(a.type) + ')'));
      ng.appendChild(svg('rect', { width: NODE_W, height: NODE_H, rx: '6', fill: own ? pal.tint[own] : pal.node, stroke: sel || isHl ? pal.accent : own ? pal.sev[own] : pal.nodeStroke, 'stroke-width': sel ? 3 : isHl ? 2.5 : 1.2 }));
      ng.appendChild(svg('rect', { x: '0', y: '0', width: '5', height: NODE_H, rx: '2', fill: own ? pal.sev[own] : pal.nodeStroke }));
      ng.appendChild(svg('text', { x: '13', y: '15', 'font-size': '9.5', 'font-family': FONT, fill: pal.text2, 'font-weight': '700', 'letter-spacing': '0.06em' }, typeLabel(a.type).toUpperCase() + (critical ? ' · ★ CRITICAL' : '')));
      ng.appendChild(svg('text', { x: '13', y: '32', 'font-size': '12.5', 'font-family': FONT, fill: pal.text, 'font-weight': '600' }, trunc(a.name, own ? 21 : 27)));
      if (own) ng.appendChild(svg('text', { x: NODE_W - 8, y: '32', 'font-size': '10', 'font-family': FONT, fill: pal.sev[own], 'font-weight': '800', 'text-anchor': 'end' }, own.toUpperCase() + ' ×' + ownFails));
      if (critical) ng.appendChild(svg('path', { d: 'M' + (NODE_W - 12) + ',4 l6,6 l-6,6 l-6,-6 z', fill: pal.crit }));
      if (kids) {
        const pillStroke = !isExp && agg.worst ? pal.sev[agg.worst] : pal.nodeStroke;
        const pg = svg('g', { transform: 'translate(' + (NODE_W + 4) + ',' + (NODE_H / 2 - 11) + ')', 'data-toggle': interactive ? '1' : null });
        pg.appendChild(svg('rect', { width: PILL_W - 8, height: '22', rx: '11', fill: pal.pill, stroke: pillStroke, 'stroke-width': !isExp && agg.worst ? 2 : 1 }));
        pg.appendChild(svg('text', { x: (PILL_W - 8) / 2, y: '15', 'font-size': '10.5', 'font-family': FONT, fill: pal.text, 'font-weight': '700', 'text-anchor': 'middle' }, isExp ? '−' : '+' + (kids > 999 ? '999+' : kids)));
        ng.appendChild(pg);
      }
      if (interactive) ng.appendChild(svg('rect', { class: 'gfocus', x: '-4', y: '-4', width: NODE_W + 8, height: NODE_H + 8, rx: '9', fill: 'none', stroke: pal.accent, 'stroke-width': '2.5' }));
      nodesG.appendChild(ng);
    });
  }

  function legendTypes(M) {
    const set = [];
    M.V.tree.forEach(function (r) { if (set.indexOf(r.t) < 0) set.push(r.t); });
    M.V.overlay.forEach(function (t) { if (set.indexOf(t) < 0) set.push(t); });
    return set;
  }
  function edgeSample(type, pal, prefix, w) {
    const st = EDGE_STYLE[type] || EDGE_STYLE.contains;
    const s = svg('svg', { width: w || 36, height: '10', viewBox: '0 0 ' + (w || 36) + ' 10', 'aria-hidden': 'true', focusable: 'false' });
    s.appendChild(svg('line', { x1: '1', y1: '5', x2: (w || 36) - (st.arrow ? 6 : 1), y2: '5', stroke: edgeColor(type, pal), 'stroke-width': st.w, 'stroke-dasharray': st.dash || null }));
    if (st.arrow) s.appendChild(svg('path', { d: 'M' + ((w || 36) - 7) + ',1 L' + (w || 36) + ',5 L' + ((w || 36) - 7) + ',9 z', fill: edgeColor(type, pal) }));
    void prefix;
    return s;
  }

  function scopeLabel() {
    return 'VSAT ' + str(tool.version) + ' · ' + VIEWS[topo.view].label + ' view · run ' + (str(run.id) || '-') + ' · generated ' + fmtTime(D.generatedUtc || run.endedUtc) +
      (topo.site ? ' · site ' + topo.site : '') + (topo.sevMin >= 0 ? ' · severity ≥ ' + SEV[4 - topo.sevMin] : '') + (topo.hlLabel ? ' · ' + topo.hlLabel : '');
  }

  function renderTopo() {
    if (!topo.ready) return;
    const M = model(topo.view);
    const L = computeLayout(M);
    topo.layout = L;
    const pal = PALETTE[effectiveTheme()];
    const s = topo.svg;
    clear(s);
    const defs = svg('defs');
    addMarkers(defs, pal, 'v-');
    s.appendChild(defs);
    s.appendChild(svg('rect', { x: '-100000', y: '-100000', width: '200000', height: '200000', fill: pal.bg, 'data-bg': '1' }));
    const vp = svg('g', { transform: 'translate(' + topo.tx + ' ' + topo.ty + ') scale(' + topo.k + ')' });
    topo.vp = vp;
    s.appendChild(vp);
    drawGraph(vp, M, L, pal, true, 'v-');
    topo.scopeEl.textContent = scopeLabel();
    // legend
    clear(topo.legendEl);
    topo.legendEl.appendChild(h('ul', { class: 'legend' }, legendTypes(M).map(function (t) { return h('li', null, edgeSample(t, pal, 'v-'), (EDGE_STYLE[t] || { label: t }).label); })));
    topo.legendEl.appendChild(h('p', { class: 'legend-note' }, 'Structural edges (contains, runs on, stores, membership) show hierarchy and placement only — they are not traffic paths.'));
    topo.sevLegendEl && renderSevLegend(pal);
    if (topo.focusId) {
      const f = s.querySelector('[data-node="' + cssEsc(topo.focusId) + '"]') || s.querySelector('[data-more="' + cssEsc(topo.focusId.replace(/^more:/, '')) + '"]');
      if (f) f.focus({ preventScroll: true });
      topo.focusId = null;
    }
    if (topo.table) renderAssetTable();
  }
  topo.render = renderTopo;
  function cssEsc(s) { return window.CSS && CSS.escape ? CSS.escape(s) : String(s).replace(/["\\\]]/g, '\\$&'); }
  function renderSevLegend(pal) {
    clear(topo.sevLegendEl);
    topo.sevLegendEl.appendChild(h('ul', { class: 'legend' }, SEV.map(function (sv) {
      const s = svg('svg', { width: '16', height: '12', viewBox: '0 0 16 12', 'aria-hidden': 'true', focusable: 'false' });
      s.appendChild(svg('rect', { x: '1', y: '1', width: '14', height: '10', rx: '2', fill: pal.tint[sv], stroke: pal.sev[sv], 'stroke-width': '1.5' }));
      return h('li', null, s, sv.charAt(0).toUpperCase() + sv.slice(1) + ' (label shown on node)');
    }), h('li', null, (function () { const s = svg('svg', { width: '16', height: '12', viewBox: '0 0 16 12', 'aria-hidden': 'true', focusable: 'false' }); s.appendChild(svg('path', { d: 'M8,0 l6,6 l-6,6 l-6,-6 z', fill: pal.crit })); return s; })(), 'Critical asset (★)'),
      h('li', null, (function () { const s = svg('svg', { width: '24', height: '12', viewBox: '0 0 24 12', 'aria-hidden': 'true', focusable: 'false' }); s.appendChild(svg('rect', { x: '1', y: '1', width: '22', height: '10', rx: '5', fill: pal.pill, stroke: pal.sev.high, 'stroke-width': '1.5' })); return s; })(), 'Collapsed; outline = worst severity below')));
  }

  function applyTransform() { if (topo.vp) topo.vp.setAttribute('transform', 'translate(' + topo.tx + ' ' + topo.ty + ') scale(' + topo.k + ')'); }
  function canvasSize() { const r = topo.svg.getBoundingClientRect(); return { w: r.width || 800, h: r.height || 500 }; }
  function zoomBy(f, cx, cy) {
    const c = canvasSize();
    if (cx === undefined) { cx = c.w / 2; cy = c.h / 2; }
    const k2 = Math.max(0.1, Math.min(3, topo.k * f));
    topo.tx = cx - (cx - topo.tx) * (k2 / topo.k);
    topo.ty = cy - (cy - topo.ty) * (k2 / topo.k);
    topo.k = k2;
    applyTransform();
  }
  function fit() {
    const L = topo.layout; if (!L) return;
    const c = canvasSize();
    const kFit = Math.min((c.w - 60) / Math.max(1, L.w), (c.h - 60) / Math.max(1, L.h));
    // Keep labels readable: never shrink below 0.6 when fitting; overflow is reachable by panning.
    const k = Math.max(0.6, Math.min(1.1, kFit));
    topo.k = k;
    topo.tx = Math.max(30, (c.w - L.w * k) / 2);
    topo.ty = L.h * k + 60 <= c.h ? (c.h - L.h * k) / 2 : 40;
    applyTransform();
  }
  function centerOn(id) {
    const L = topo.layout; if (!L) return;
    const p = L.pos.get(id); if (!p) return;
    const c = canvasSize();
    if (topo.k < 0.7) topo.k = 0.9;
    topo.tx = c.w / 2 - (p.x + NODE_W / 2) * topo.k;
    topo.ty = c.h / 2 - (p.y + NODE_H / 2) * topo.k;
    applyTransform();
  }
  function toggleNode(id) {
    const exp = topo.expanded[topo.view];
    if (exp.has(id)) exp.delete(id); else exp.add(id);
    topo.focusId = id;
    renderTopo();
  }
  function showMore(parentKey) {
    const m = topo.shown[topo.view];
    m.set(parentKey, (m.get(parentKey) || CHILD_PAGE) + CHILD_PAGE);
    topo.focusId = 'more:' + parentKey;
    renderTopo();
  }
  function adjacentEdges(id) { return new Set(relsByAsset.get(str(id)) || []); }
  function selectNode(id, openInfo) {
    topo.selected = id;
    topo.hl = new Set([id]);
    topo.hlEdges = adjacentEdges(id);
    topo.hlLabel = 'selected ' + trunc(assetName(id), 40);
    (relsByAsset.get(id) || []).forEach(function (i) { const r = rels[i]; topo.hl.add(str(r.source)); topo.hl.add(str(r.target)); });
    topo.focusId = id;
    renderTopo();
    if (openInfo) openAsset(id);
  }
  function clearHighlight() { topo.selected = null; topo.hl = new Set(); topo.hlEdges = new Set(); topo.hlLabel = ''; renderTopo(); }
  function viewFor(id) {
    const t = assetType(id);
    if (VIEWS[topo.view].types.indexOf(t) >= 0) return topo.view;
    for (let i = 0; i < VIEW_KEYS.length; i++) if (VIEWS[VIEW_KEYS[i]].types.indexOf(t) >= 0) return VIEW_KEYS[i];
    return null;
  }
  // expand ancestors so that id becomes visible; returns true if placed
  function revealIn(M, id) {
    if (!M.has(id)) return false;
    const exp = topo.expanded[M.key];
    const shown = topo.shown[M.key];
    let c = id, p = M.parent.get(c);
    while (p !== undefined) {
      exp.add(p);
      const list = (M.children.get(p) || []).filter(function (x) { return nodePasses(M, x); });
      const idx = list.indexOf(c);
      if (idx >= (shown.get(p) || CHILD_PAGE)) shown.set(p, Math.ceil((idx + 1) / CHILD_PAGE) * CHILD_PAGE);
      c = p; p = M.parent.get(c);
    }
    const rl = M.roots.filter(function (x) { return nodePasses(M, x); });
    const ri = rl.indexOf(c);
    if (ri >= (shown.get('__root__') || CHILD_PAGE)) shown.set('__root__', Math.ceil((ri + 1) / CHILD_PAGE) * CHILD_PAGE);
    return true;
  }
  function ensureFiltersAllow(M, ids) {
    let relaxed = false;
    ids.forEach(function (id) {
      let c = id;
      while (c !== undefined) { if (!nodePasses(M, c)) { relaxed = true; break; } c = M.parent.get(c); }
    });
    if (relaxed) { topo.sevMin = -1; topo.site = ''; syncFilterControls(); announce('Topology filters were cleared to show the requested asset.'); }
  }
  function focusAssets(ids, opts) {
    opts = opts || {};
    ids = ids.map(str).filter(function (id) { return assetById.has(id); });
    if (!ids.length) { announce('The asset is not part of the topology.'); return false; }
    const v = opts.view && VIEWS[opts.view].types.indexOf(assetType(ids[0])) >= 0 ? opts.view : viewFor(ids[0]);
    if (!v) { announce('This asset type is not shown in any topology view.'); return false; }
    setView(v, true);
    const M = model(v);
    ensureFiltersAllow(M, ids);
    ids.forEach(function (id) { revealIn(M, id); });
    return true;
  }
  function showOnTopology(id) {
    closePanelIfCovering();
    go('topology');
    if (!focusAssets([id])) return;
    topoPage.showSub('');
    selectNode(str(id), false);
    requestAnimationFrame(function () { centerOn(str(id)); const n = topo.svg.querySelector('[data-node="' + cssEsc(str(id)) + '"]'); if (n) n.focus({ preventScroll: true }); });
    announce('Showing ' + assetName(id) + ' on the topology.');
  }
  function highlightSet(ids, edgeIdx, label, view) {
    go('topology');
    if (!focusAssets(ids, { view: view })) return;
    topoPage.showSub('');
    topo.selected = null;
    topo.hl = new Set(ids.map(str));
    topo.hlEdges = edgeIdx;
    topo.hlLabel = label;
    renderTopo();
    requestAnimationFrame(function () { fit(); });
    announce(label);
  }
  function closePanelIfCovering() { if (!panelEl.hidden && window.innerWidth < 1400) closePanel(); }
  function relsBetween(a, b) {
    const out = [];
    (relsByAsset.get(str(a)) || []).forEach(function (i) { const r = rels[i]; if ((str(r.source) === str(a) && str(r.target) === str(b)) || (str(r.source) === str(b) && str(r.target) === str(a))) out.push(i); });
    return out;
  }
  function setView(v, keep) {
    if (!VIEWS[v]) return;
    if (topo.view !== v) { topo.view = v; if (!keep) { topo.selected = null; topo.hl = new Set(); topo.hlEdges = new Set(); topo.hlLabel = ''; } }
    if (topo.viewBtns) topo.viewBtns.forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-view') === v)); });
    if (topo.viewDesc) topo.viewDesc.textContent = VIEWS[v].desc;
  }
  let syncFilterControls = function () {};

  function renderAssetTable() {
    const M = model(topo.view);
    const rows = M.all.filter(function (id) { return nodePasses(M, id); }).map(function (id) { return assetById.get(id); });
    topo.assetTable.setRows(rows, true);
    topo.assetTableTitle.textContent = VIEWS[topo.view].label + ' view — ' + fmtN(rows.length) + ' assets (accessible equivalent of the graph)';
  }

  // ---------- export ----------
  function buildExportSvg() {
    const M = model(topo.view);
    const L = topo.layout || computeLayout(M);
    const pal = PALETTE.light;
    const types = legendTypes(M);
    const pad = 24, headH = 56;
    const legendCols = 3, legendRowH = 20;
    const legendItems = types.length + SEV.length + 1;
    const legendH = 40 + Math.ceil(legendItems / legendCols) * legendRowH;
    const W = Math.max(760, Math.ceil(L.w + pad * 2));
    const H = Math.ceil(headH + L.h + pad * 2 + legendH);
    const root = svg('svg', { width: W, height: H, viewBox: '0 0 ' + W + ' ' + H });
    const defs = svg('defs');
    addMarkers(defs, pal, 'x-');
    root.appendChild(defs);
    root.appendChild(svg('rect', { x: '0', y: '0', width: W, height: H, fill: '#ffffff' }));
    root.appendChild(svg('text', { x: pad, y: '26', 'font-size': '16', 'font-weight': '800', 'font-family': FONT, fill: pal.text }, 'VSAT topology — ' + VIEWS[topo.view].label));
    root.appendChild(svg('text', { x: pad, y: '44', 'font-size': '11', 'font-family': FONT, fill: pal.text2 }, scopeLabel() + ' · CONTAINS SENSITIVE INFRASTRUCTURE DATA'));
    const g = svg('g', { transform: 'translate(' + pad + ',' + (headH + pad / 2) + ')' });
    root.appendChild(g);
    drawGraph(g, M, L, pal, false, 'x-');
    const ly = headH + L.h + pad * 1.5;
    const lg = svg('g', { transform: 'translate(' + pad + ',' + ly + ')' });
    lg.appendChild(svg('line', { x1: '0', y1: '0', x2: W - pad * 2, y2: '0', stroke: '#d5dce4' }));
    lg.appendChild(svg('text', { x: '0', y: '20', 'font-size': '11', 'font-weight': '700', 'font-family': FONT, fill: pal.text }, 'Legend — structural edges (contains, runs on, stores, membership) are not traffic paths'));
    const colW = (W - pad * 2) / legendCols;
    let n = 0;
    function cell() { const cx = (n % legendCols) * colW, cy = 34 + Math.floor(n / legendCols) * legendRowH; n++; return [cx, cy]; }
    types.forEach(function (t) {
      const p = cell(); const st = EDGE_STYLE[t] || EDGE_STYLE.contains;
      lg.appendChild(svg('line', { x1: p[0], y1: p[1] + 4, x2: p[0] + 34, y2: p[1] + 4, stroke: edgeColor(t, pal), 'stroke-width': st.w, 'stroke-dasharray': st.dash || null, 'marker-end': st.arrow ? 'url(#x-arr-' + t + ')' : null }));
      lg.appendChild(svg('text', { x: p[0] + 44, y: p[1] + 8, 'font-size': '11', 'font-family': FONT, fill: pal.text }, st.label));
    });
    SEV.forEach(function (sv) {
      const p = cell();
      lg.appendChild(svg('rect', { x: p[0], y: p[1] - 2, width: '34', height: '12', rx: '2', fill: pal.tint[sv], stroke: pal.sev[sv], 'stroke-width': '1.5' }));
      lg.appendChild(svg('text', { x: p[0] + 44, y: p[1] + 8, 'font-size': '11', 'font-family': FONT, fill: pal.text }, 'Severity: ' + sv));
    });
    const pc = cell();
    lg.appendChild(svg('path', { d: 'M' + (pc[0] + 17) + ',' + (pc[1] - 3) + ' l7,7 l-7,7 l-7,-7 z', fill: pal.crit }));
    lg.appendChild(svg('text', { x: pc[0] + 44, y: pc[1] + 8, 'font-size': '11', 'font-family': FONT, fill: pal.text }, 'Critical asset'));
    root.appendChild(lg);
    return { el: root, w: W, h: H };
  }
  function exportSvg() {
    ensureTopoReady();
    const x = buildExportSvg();
    const text = '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(x.el);
    download('vsat-topology-' + topo.view + '-' + safeFilePart(run.id) + '.svg', new Blob([text], { type: 'image/svg+xml' }));
  }
  function exportPng() {
    ensureTopoReady();
    const x = buildExportSvg();
    const text = new XMLSerializer().serializeToString(x.el);
    const url = URL.createObjectURL(new Blob([text], { type: 'image/svg+xml' }));
    const img = new Image();
    img.onload = function () {
      let scale = 2;
      const maxDim = 16000, maxArea = 120000000;
      scale = Math.min(scale, maxDim / x.w, maxDim / x.h, Math.sqrt(maxArea / (x.w * x.h)));
      const c = document.createElement('canvas');
      c.width = Math.max(1, Math.floor(x.w * scale)); c.height = Math.max(1, Math.floor(x.h * scale));
      const ctx = c.getContext('2d');
      ctx.fillStyle = '#ffffff'; ctx.fillRect(0, 0, c.width, c.height);
      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      ctx.drawImage(img, 0, 0, x.w, x.h);
      URL.revokeObjectURL(url);
      c.toBlob(function (blob) { if (blob) download('vsat-topology-' + topo.view + '-' + safeFilePart(run.id) + '.png', blob); else announce('PNG export failed; use SVG export instead.'); }, 'image/png');
    };
    img.onerror = function () { URL.revokeObjectURL(url); announce('PNG export failed; use SVG export instead.'); };
    img.src = url;
  }

  // ---------- topology page ----------
  const topoPage = (function () {
    let graphSec, attackSec, impactSec, subBtns = [];
    let attackRendered = false, impactRendered = false;
    function render(el) {
      el.appendChild(pageHead('h-topology', 'Topology', 'Configuration-derived relationships. Start collapsed; expand nodes to explore. Containment is structure, not a packet path.'));
      const sub = h('div', { class: 'btn-group subnav', role: 'tablist', 'aria-label': 'Topology views' });
      [['', 'Graph'], ['attack', 'Attack paths'], ['impact', 'Failure impact']].forEach(function (s) {
        const b = btn(s[1], function () { go('topology', s[0]); }, '', { role: 'tab', 'data-sub': s[0], 'aria-selected': 'false' });
        subBtns.push(b); sub.appendChild(b);
      });
      el.appendChild(sub);
      graphSec = h('div', { role: 'tabpanel' });
      attackSec = h('div', { role: 'tabpanel', hidden: true });
      impactSec = h('div', { role: 'tabpanel', hidden: true });
      el.appendChild(graphSec); el.appendChild(attackSec); el.appendChild(impactSec);
      renderGraphSection(graphSec);
    }
    function showSub(s) {
      if (!graphSec) return;
      const key = s === 'attack' || s === 'impact' ? s : '';
      subBtns.forEach(function (b) { b.setAttribute('aria-selected', String(b.getAttribute('data-sub') === key)); });
      graphSec.hidden = key !== ''; attackSec.hidden = key !== 'attack'; impactSec.hidden = key !== 'impact';
      if (key === 'attack' && !attackRendered) { attackRendered = true; renderAttack(attackSec); }
      if (key === 'impact' && !impactRendered) { impactRendered = true; renderImpact(impactSec); }
      if (key === '') requestAnimationFrame(function () { if (topo.needsFit) { topo.needsFit = false; fit(); } });
    }
    return { render: render, showSub: showSub };
  })();
  renderers.topology = topoPage.render;
  function ensureTopoReady() { ensureRendered('topology'); }

  function renderGraphSection(el) {
    const viewGroup = h('div', { class: 'btn-group', role: 'group', 'aria-label': 'Topology view' });
    topo.viewBtns = VIEW_KEYS.map(function (k) {
      const b = btn(VIEWS[k].label, function () { setView(k); renderTopo(); fit(); }, '', { 'data-view': k, 'aria-pressed': String(k === topo.view) });
      viewGroup.appendChild(b); return b;
    });
    topo.viewDesc = h('span', { class: 'muted small' }, VIEWS[topo.view].desc);
    // filters
    const sevSel = h('select', { id: 't-sev' }, h('option', { value: '-1' }, 'All assets'), SEV.slice(0, 4).map(function (s) { return h('option', { value: String(SEV_RANK[s]) }, 'Branches with ' + s + (s === 'critical' ? '' : ' or worse')); }));
    on(sevSel, 'change', function () { topo.sevMin = Number(sevSel.value); renderTopo(); });
    const sites = Array.from(new Set(assets.map(function (a) { return str(a.site); }).filter(Boolean))).sort();
    const siteSel = h('select', { id: 't-site' }, h('option', { value: '' }, 'All sites'), sites.map(function (s) { return h('option', { value: s }, s); }));
    on(siteSel, 'change', function () { topo.site = siteSel.value; renderTopo(); });
    syncFilterControls = function () { sevSel.value = String(topo.sevMin); siteSel.value = topo.site; };
    // search
    const search = h('input', { type: 'search', id: 't-search', placeholder: 'Find asset by name or ID…', autocomplete: 'off', spellcheck: 'false', 'aria-controls': 't-results' });
    const results = h('ul', { class: 'search-results', id: 't-results', hidden: true });
    function doSearch() {
      const q = search.value.trim().toLowerCase();
      clear(results);
      if (q.length < 1) { results.hidden = true; return; }
      const hits = [];
      for (let i = 0; i < assets.length && hits.length < 12; i++) {
        const a = assets[i];
        if (!viewFor(str(a.id))) continue;
        if (str(a.name).toLowerCase().indexOf(q) >= 0 || str(a.id).toLowerCase().indexOf(q) >= 0) hits.push(a);
      }
      if (!hits.length) results.appendChild(h('li', null, h('span', { class: 'muted small' }, ' No matching asset')));
      hits.forEach(function (a) {
        results.appendChild(h('li', null, on(h('button', { type: 'button' }, str(a.name), h('span', { class: 'sub' }, ' — ' + typeLabel(a.type))), 'click', function () { results.hidden = true; showOnTopology(a.id); })));
      });
      results.hidden = false;
    }
    on(search, 'input', debounce(doSearch, 120));
    on(search, 'keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); const b = results.querySelector('button'); if (b) b.click(); else doSearch(); } if (e.key === 'ArrowDown') { const b = results.querySelector('button'); if (b) { e.preventDefault(); b.focus(); } } });
    const tableBtn = btn('Table view', function () {
      topo.table = !topo.table;
      tableBtn.setAttribute('aria-pressed', String(topo.table));
      tableWrap.hidden = !topo.table;
      if (topo.table) renderAssetTable();
    }, '', { 'aria-pressed': 'false' });
    const toolbar = h('div', { class: 'toolbar' },
      h('div', { class: 'field' }, h('span', null, 'View'), viewGroup),
      h('label', { class: 'field', for: 't-sev' }, h('span', null, 'Severity'), sevSel),
      h('label', { class: 'field', for: 't-site' }, h('span', null, 'Site'), siteSel),
      h('div', { class: 'field' }, h('span', null, ' '), h('div', { class: 'btn-group' },
        btn('Collapse all', function () { topo.expanded[topo.view] = new Set(); topo.shown[topo.view] = new Map(); renderTopo(); fit(); }),
        btn('Expand level', function () { expandLevel(); }),
        btn('Clear highlight', clearHighlight))),
      h('div', { class: 'field' }, h('span', null, 'Accessible'), tableBtn),
      h('div', { class: 'field' }, h('span', null, 'Export view'), h('div', { class: 'btn-group' }, btn('SVG', exportSvg), btn('PNG', exportPng))));
    el.appendChild(toolbar);
    el.appendChild(h('p', { class: 'small muted' }, topo.viewDesc));
    // canvas
    const s = svg('svg', { role: 'group', 'aria-label': 'Topology graph. Tab to nodes; Enter expands or collapses and selects; Space toggles.', focusable: 'false' });
    topo.svg = s;
    topo.scopeEl = h('div', { class: 'topo-scope' });
    const canvas = h('div', { class: 'topo-canvas' }, s,
      h('div', { class: 'topo-hint no-print', 'aria-hidden': 'true' }, 'Drag to pan · wheel to zoom · click node to select/expand'),
      h('div', { class: 'topo-zoom no-print' },
        btn('+', function () { zoomBy(1.25); }, '', { 'aria-label': 'Zoom in' }),
        btn('−', function () { zoomBy(0.8); }, '', { 'aria-label': 'Zoom out' }),
        btn('⤢', fit, '', { 'aria-label': 'Fit to view', title: 'Fit' })),
      topo.scopeEl);
    topo.legendEl = h('div');
    topo.sevLegendEl = h('div');
    const side = h('div', { class: 'topo-side' },
      h('div', { class: 'card' }, h('label', { class: 'field', for: 't-search' }, h('span', null, 'Find asset'), search), results),
      h('div', { class: 'card' }, h('h3', null, 'Edges'), topo.legendEl),
      h('div', { class: 'card' }, h('h3', null, 'Nodes'), topo.sevLegendEl));
    el.appendChild(h('div', { class: 'topo-layout' }, canvas, side));
    // accessible table
    topo.assetTableTitle = h('h3', null, '');
    topo.assetTable = new DataTable({
      caption: 'Assets in current topology view', sortKey: 'sev', sortDir: 'desc', empty: 'No assets in this view.',
      columns: [
        { key: 'name', label: 'Asset', sort: function (a) { return str(a.name); }, render: function (a) { return linkBtn(str(a.name), function () { openAsset(a.id); }); } },
        { key: 'type', label: 'Type', sort: function (a) { return str(a.type); }, render: function (a) { return typeLabel(a.type); } },
        { key: 'parent', label: 'Parent (this view)', sort: function (a) { const p = model(topo.view).parent.get(str(a.id)); return p ? assetName(p) : ''; }, render: function (a) { const p = model(topo.view).parent.get(str(a.id)); return p ? h('span', { class: 'break' }, assetName(p)) : h('span', { class: 'muted' }, 'top level'); } },
        { key: 'site', label: 'Site', sort: function (a) { return str(a.site); }, render: function (a) { return str(a.site); } },
        { key: 'sev', label: 'Worst severity', defaultDir: 'desc', sort: function (a) { const s = assetWorst(a); return s ? SEV_RANK[s] + 1 : 0; }, render: function (a) { return sevBadge(assetWorst(a)); } },
        { key: 'fail', label: 'Failing', num: true, defaultDir: 'desc', sort: function (a) { return assetFails(a); }, render: function (a) { return String(assetFails(a)); } },
        { key: 'act', label: 'Graph', render: function (a) { return btn('Show', function () { showOnTopology(a.id); }, 'btn-sm'); } }
      ],
      onRowClick: function (a) { openAsset(a.id); }
    });
    const tableWrap = h('div', { class: 'section', hidden: true }, topo.assetTableTitle, topo.assetTable.el);
    el.appendChild(tableWrap);

    // interactions
    let drag = null;
    on(s, 'pointerdown', function (e) {
      if (e.button !== 0) return;
      if (e.target.closest && e.target.closest('.gnode')) return;
      drag = { x: e.clientX, y: e.clientY, tx: topo.tx, ty: topo.ty, id: e.pointerId };
      s.setPointerCapture(e.pointerId);
      s.classList.add('dragging');
    });
    on(s, 'pointermove', function (e) { if (!drag) return; topo.tx = drag.tx + (e.clientX - drag.x); topo.ty = drag.ty + (e.clientY - drag.y); applyTransform(); });
    const endDrag = function () { if (drag) { try { s.releasePointerCapture(drag.id); } catch (err) { /* ignore */ } } drag = null; s.classList.remove('dragging'); };
    on(s, 'pointerup', endDrag); on(s, 'pointercancel', endDrag);
    on(s, 'wheel', function (e) { e.preventDefault(); const r = s.getBoundingClientRect(); zoomBy(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX - r.left, e.clientY - r.top); }, { passive: false });
    on(s, 'click', function (e) {
      const more = e.target.closest && e.target.closest('[data-more]');
      if (more) { showMore(more.getAttribute('data-more')); return; }
      const n = e.target.closest && e.target.closest('[data-node]');
      if (!n) return;
      const id = n.getAttribute('data-node');
      if (e.target.closest('[data-toggle]')) { toggleNode(id); return; }
      const M = model(topo.view);
      if ((M.children.get(id) || []).length && !topo.expanded[topo.view].has(id)) topo.expanded[topo.view].add(id);
      selectNode(id, true);
    });
    on(s, 'keydown', function (e) {
      const more = e.target.closest && e.target.closest('[data-more]');
      if (more && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); showMore(more.getAttribute('data-more')); return; }
      const n = e.target.closest && e.target.closest('[data-node]');
      if (!n) return;
      const id = n.getAttribute('data-node');
      if (e.key === 'Enter') { e.preventDefault(); const M = model(topo.view); if ((M.children.get(id) || []).length) { const exp = topo.expanded[topo.view]; if (exp.has(id)) exp.delete(id); else exp.add(id); } selectNode(id, false); }
      else if (e.key === ' ') { e.preventDefault(); toggleNode(id); }
      else if (e.key === 'i' || e.key === 'I') { openAsset(id); }
    });
    topo.ready = true;
    // initial: expand the first root level if there is a single root
    const M = model(topo.view);
    if (M.roots.length <= 3) M.roots.forEach(function (r) { topo.expanded[topo.view].add(r); });
    renderTopo();
    topo.needsFit = true;
    requestAnimationFrame(function () { if (!document.getElementById('page-topology').hidden) { topo.needsFit = false; fit(); } });
  }
  function expandLevel() {
    const M = model(topo.view);
    const L = topo.layout; if (!L) return;
    const exp = topo.expanded[topo.view];
    // Render budget: keep the number of drawn nodes bounded for very large estates.
    const BUDGET = 1500;
    let visible = L.items.length, capped = false;
    L.items.forEach(function (it) {
      if (it.kind !== 'node' || exp.has(it.id)) return;
      const n = Math.min(CHILD_PAGE, (M.children.get(it.id) || []).length);
      if (!n) return;
      if (visible + n > BUDGET) { capped = true; return; }
      exp.add(it.id); visible += n;
    });
    renderTopo(); fit();
    if (capped) announce('Expansion stopped at about ' + BUDGET + ' nodes to keep the view responsive. Expand individual nodes or use search.');
  }

  // ---------- attack paths ----------
  function renderAttack(el) {
    const paths = arr(analysis.attackPaths).filter(function (p) { return p && typeof p === 'object'; });
    el.appendChild(h('div', { class: 'notice notice-warn' }, h('strong', null, 'Configuration-inferred — not proof of exploitability'),
      'Paths are derived from collected configuration (segments, gateways, DFW rules). Guest firewalls, physical ACLs and runtime state may change the outcome.'));
    if (!paths.length) { el.appendChild(h('p', { class: 'muted' }, 'No attack paths were computed for this run.')); }
    const srcSel = h('select', { id: 'ap-src' }, h('option', { value: '' }, 'Any source'));
    const zones = Array.from(new Set(paths.map(function (p) { return str(p.sourceZone); }).filter(Boolean))).sort();
    zones.forEach(function (z) { srcSel.appendChild(h('option', { value: 'zone:' + z }, 'Zone: ' + z)); });
    Array.from(new Set(paths.map(function (p) { return str(p.source); }))).sort(function (a, b) { return assetName(a).localeCompare(assetName(b)); }).forEach(function (s) { srcSel.appendChild(h('option', { value: 'asset:' + s }, 'Asset: ' + assetName(s))); });
    const tgtSel = h('select', { id: 'ap-tgt' }, h('option', { value: '' }, 'Any target'));
    Array.from(new Set(paths.map(function (p) { return str(p.target); }))).sort(function (a, b) { return assetName(a).localeCompare(assetName(b)); }).forEach(function (t) { tgtSel.appendChild(h('option', { value: t }, assetName(t))); });
    const decSel = h('select', { id: 'ap-dec' }, h('option', { value: '' }, 'Any decision'), ['allow', 'deny', 'unknown'].map(function (d) { return h('option', { value: d }, d); }));
    const list = h('ul', { class: 'path-list' });
    const detail = h('div', { class: 'card' });
    let current = null;
    function matches(p) {
      const sv = srcSel.value;
      if (sv.indexOf('zone:') === 0 && str(p.sourceZone) !== sv.slice(5)) return false;
      if (sv.indexOf('asset:') === 0 && str(p.source) !== sv.slice(6)) return false;
      if (tgtSel.value && str(p.target) !== tgtSel.value) return false;
      if (decSel.value && str(p.decision) !== decSel.value) return false;
      return true;
    }
    function refresh() {
      clear(list);
      const m = paths.filter(matches);
      if (!m.length) list.appendChild(h('li', { class: 'muted small' }, 'No paths match.'));
      m.forEach(function (p) {
        const b = on(h('button', { type: 'button', 'aria-current': String(current === p) },
          h('span', { class: 'state decision-' + (['allow', 'deny', 'unknown'].indexOf(p.decision) >= 0 ? p.decision : 'unknown') }, str(p.decision).toUpperCase() || 'UNKNOWN'), ' ',
          h('strong', null, assetName(p.source)), ' → ', h('strong', null, assetName(p.target)),
          h('span', { class: 'sub muted small' }, str(p.id) + (p.sourceZone ? ' · from zone ' + str(p.sourceZone) : '') + ' · ' + arr(p.hops).length + ' hops')), 'click', function () { current = p; refresh(); showPath(p); });
        list.appendChild(h('li', null, b));
      });
      if (!current && m.length) { current = m[0]; list.querySelector('button').setAttribute('aria-current', 'true'); showPath(m[0]); }
      if (!m.length) { clear(detail); detail.appendChild(h('p', { class: 'muted' }, 'Select a source and target to see a path.')); }
    }
    function showPath(p) {
      clear(detail);
      const hops = arr(p.hops);
      const dec = ['allow', 'deny', 'unknown'].indexOf(p.decision) >= 0 ? p.decision : 'unknown';
      detail.appendChild(h('div', { class: 'card-head' }, h('h2', null, str(p.id) + ': ' + assetName(p.source) + ' → ' + assetName(p.target)),
        h('span', { class: 'state decision-' + dec }, 'Decision: ' + dec.toUpperCase())));
      detail.appendChild(h('p', null, h('span', { class: 'inferred-label' }, (str(p.confidence) || 'configuration-inferred') + ' — not proof of exploitability')));
      if (p.explanation) detail.appendChild(h('p', { class: 'break' }, str(p.explanation)));
      detail.appendChild(h('div', { class: 'actions' }, btn('Highlight on topology', function () {
        const ids = hops.map(function (x) { return str(obj(x).asset); });
        const edges = new Set();
        for (let i = 1; i < ids.length; i++) relsBetween(ids[i - 1], ids[i]).forEach(function (e) { edges.add(e); });
        highlightSet(ids, edges, 'attack path ' + str(p.id), 'network');
      }, 'btn-primary btn-sm')));
      detail.appendChild(section('Hops', h('ol', { class: 'hops' }, hops.map(function (x) {
        x = obj(x);
        return h('li', null, linkBtn(assetName(x.asset), function () { openAsset(x.asset); }), h('span', { class: 'muted small' }, ' ' + typeLabel(assetType(x.asset))), x.via ? h('span', { class: 'via' }, 'via ' + str(x.via)) : null);
      }))));
      const rr = arr(p.rules);
      detail.appendChild(section('Matched DFW rules', rr.length ? h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Rule'), h('th', { scope: 'col' }, 'Action'), h('th', { scope: 'col' }, 'Reason'))),
        h('tbody', null, rr.map(function (r) {
          r = obj(r);
          const a = str(r.action).toUpperCase();
          return h('tr', null, h('td', { class: 'break' }, assetById.has(str(r.ruleAssetId)) ? linkBtn(str(r.name) || assetName(r.ruleAssetId), function () { openAsset(r.ruleAssetId); }) : str(r.name)),
            h('td', null, h('span', { class: 'state state-' + (a === 'ALLOW' ? 'bad' : a === 'DROP' || a === 'REJECT' ? 'ok' : 'neutral') }, a || '-')), h('td', { class: 'break' }, str(r.reason)));
        })))) : h('p', { class: 'muted' }, 'No rule decision could be derived for this path.')));
      detail.appendChild(section('Prerequisites', listOf(p.prerequisites) || h('p', { class: 'muted' }, 'None recorded.')));
      detail.appendChild(section('Uncertainty', listOf(p.uncertainty) || h('p', { class: 'muted' }, 'None recorded.')));
    }
    [srcSel, tgtSel, decSel].forEach(function (s) { on(s, 'change', function () { current = null; refresh(); }); });
    el.appendChild(h('div', { class: 'toolbar' },
      h('label', { class: 'field', for: 'ap-src' }, h('span', null, 'Source zone / asset'), srcSel),
      h('label', { class: 'field', for: 'ap-tgt' }, h('span', null, 'Target'), tgtSel),
      h('label', { class: 'field', for: 'ap-dec' }, h('span', null, 'Decision'), decSel)));
    el.appendChild(h('div', { class: 'explorer' }, h('div', null, h('h2', { class: 'sr-only' }, 'Paths'), list), detail));
    refresh();
    // chokepoints
    const ch = arr(analysis.chokepoints);
    el.appendChild(h('div', { class: 'card section' }, h('h2', null, 'Chokepoints'), h('p', { class: 'small muted' }, 'Rules whose change would interrupt the most inferred paths.'),
      ch.length ? h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Rule'), h('th', { scope: 'col', class: 'num' }, 'Paths interrupted'), h('th', { scope: 'col' }, 'Policy'))),
        h('tbody', null, ch.map(function (c) {
          c = obj(c);
          const a = assetById.get(str(c.ruleAssetId));
          return h('tr', null, h('td', { class: 'break' }, a ? linkBtn(str(c.name) || str(a.name), function () { openAsset(a.id); }) : str(c.name)), h('td', { class: 'num' }, fmtN(c.pathsInterrupted)), h('td', { class: 'break' }, a ? str(obj(a.props).policyName) || assetName(obj(a.props).policy) : '-'));
        })))) : h('p', { class: 'muted' }, 'No chokepoints computed.')));
    // privilege paths
    const pp = arr(analysis.privilegePaths);
    el.appendChild(h('div', { class: 'card section' }, h('h2', null, 'Privilege layer'), h('p', { class: 'small muted' }, 'vCenter permissions granting roles on inventory objects. Separate from network reachability.'),
      pp.length ? h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { scope: 'col' }, 'Principal'), h('th', { scope: 'col' }, 'Role'), h('th', { scope: 'col' }, 'Object'), h('th', { scope: 'col' }, 'Propagates'))),
        h('tbody', null, pp.map(function (p) {
          p = obj(p);
          return h('tr', null, h('td', { class: 'mono break' }, str(p.principal)), h('td', null, str(p.role) === 'Admin' ? h('span', { class: 'state state-warn' }, 'Admin') : str(p.role)),
            h('td', { class: 'break' }, assetById.has(str(p.object)) ? linkBtn(assetName(p.object), function () { openAsset(p.object); }) : str(p.object), h('span', { class: 'sub' }, typeLabel(assetType(p.object)))),
            h('td', null, p.propagate ? 'yes — to all children' : 'no'));
        })))) : h('p', { class: 'muted' }, 'No privilege data collected.')));
  }

  // ---------- failure impact ----------
  function renderImpact(el) {
    const imp = arr(analysis.impact).filter(function (x) { return x && typeof x === 'object'; });
    el.appendChild(h('div', { class: 'notice notice-info' }, h('strong', null, 'Configuration-based model, no failure injection'), 'Effects are predicted from HA, placement and redundancy configuration. Physical redundancy outside the collected scope is marked unknown.'));
    if (!imp.length) { el.appendChild(h('p', { class: 'muted' }, 'No failure-impact analysis in this run.')); return; }
    const sel = h('select', { id: 'imp-comp' }, imp.map(function (x, i) { return h('option', { value: String(i) }, assetName(x.component) + ' (' + typeLabel(x.componentType || assetType(x.component)) + ') — ' + arr(x.affected).length + ' affected'); }));
    const detail = h('div', { class: 'card' });
    function show() {
      const x = imp[Number(sel.value)] || imp[0];
      clear(detail);
      const red = str(x.redundancy);
      const aff = arr(x.affected);
      detail.appendChild(h('div', { class: 'card-head' }, h('h2', null, 'If ' + assetName(x.component) + ' fails'), h('span', { class: 'state state-' + (red === 'redundant' ? 'ok' : red === 'none' ? 'bad' : 'warn') }, 'Redundancy: ' + (red || 'unknown'))));
      detail.appendChild(h('p', null, h('span', { class: 'inferred-label' }, 'configuration-based model, no failure injection')));
      detail.appendChild(h('div', { class: 'actions' },
        btn('Highlight on topology', function () {
          const ids = [str(x.component)].concat(aff.map(function (a) { return str(obj(a).asset); }));
          const edges = new Set();
          aff.forEach(function (a) { relsBetween(x.component, obj(a).asset).forEach(function (e) { edges.add(e); }); });
          highlightSet(ids, edges, 'failure impact of ' + trunc(assetName(x.component), 40), 'resilience');
        }, 'btn-primary btn-sm'),
        btn('Component details', function () { openAsset(x.component); }, 'btn-sm')));
      detail.appendChild(section('Notes', listOf(x.notes)));
      const counts = {};
      aff.forEach(function (a) { const e = str(obj(a).effect) || 'unknown'; counts[e] = (counts[e] || 0) + 1; });
      detail.appendChild(h('p', { class: 'small' }, Object.keys(counts).map(function (k, i) { return h('span', null, i ? ' · ' : '', h('strong', null, String(counts[k])), ' ' + k); })));
      const t = new DataTable({
        caption: 'Affected workloads', sortKey: 'effect', sortDir: 'asc', empty: 'No dependents recorded.',
        columns: [
          { key: 'asset', label: 'Affected asset', sort: function (a) { return assetName(a.asset); }, render: function (a) { return linkBtn(assetName(a.asset), function () { openAsset(a.asset); }); } },
          { key: 'type', label: 'Type', sort: function (a) { return assetType(a.asset); }, render: function (a) { return typeLabel(assetType(a.asset)); } },
          { key: 'effect', label: 'Effect', sort: function (a) { return ['outage', 'degraded', 'restart-expected', 'unknown'].indexOf(str(a.effect)); }, render: function (a) { const e = str(a.effect); return h('span', { class: 'state state-' + (e === 'outage' ? 'bad' : e === 'restart-expected' ? 'neutral' : 'warn') }, e || 'unknown'); } },
          { key: 'reason', label: 'Reason', sort: function (a) { return str(a.reason); }, render: function (a) { return h('span', { class: 'break' }, str(a.reason)); } }
        ]
      });
      t.setRows(aff.map(obj));
      detail.appendChild(t.el);
    }
    on(sel, 'change', show);
    el.appendChild(h('div', { class: 'toolbar' }, h('label', { class: 'field', for: 'imp-comp' }, h('span', null, 'Component'), sel)));
    el.appendChild(detail);
    show();
  }

  // =====================================================================
  // NSX page
  // =====================================================================
  renderers.nsx = function (el) {
    const nsx = obj(D.nsx);
    const disc = obj(nsx.discovery);
    const dom = coverageDomains().find(function (d) { return d.id === 'nsx'; });
    el.appendChild(pageHead('h-nsx', 'NSX', 'NSX is a mandatory domain. When NSX is present but not assessed, the report is INCOMPLETE.'));
    const ds = str(disc.status) || 'unknown';
    const discCard = h('div', { class: 'card' }, h('div', { class: 'card-head' }, h('h2', null, 'Discovery'), h('span', { class: 'state state-' + (ds === 'not-detected' ? 'neutral' : ds === 'detected' ? 'ok' : 'warn') }, ds.toUpperCase())),
      h('p', { class: 'small muted' }, ds === 'detected' ? 'NSX was detected from vSphere evidence.' : ds === 'not-detected' ? 'No NSX evidence was found in the collected vSphere inventory.' : 'Discovery could not determine whether NSX is deployed.'),
      section('Evidence', listOf(disc.evidence) || h('p', { class: 'muted' }, 'No discovery evidence recorded.')),
      section('Managers discovered', listOf(disc.managersDiscovered) || h('p', { class: 'muted' }, 'None.')));
    const mgrs = assets.filter(function (a) { return a.type === 'nsx-manager'; });
    const mgrCard = h('div', { class: 'card' }, h('h2', null, 'NSX Managers assessed (' + mgrs.length + ')'),
      mgrs.length ? h('ul', { class: 'mini-list' }, mgrs.map(function (a) {
        return h('li', null, sevBadge(assetWorst(a)), h('span', { class: 'grow' }, linkBtn(str(a.name), function () { openAsset(a.id); }), h('span', { class: 'sub muted small' }, 'Version ' + (str(a.version) || '?') + (a.build ? ' build ' + str(a.build) : '') + ' · endpoint ' + str(a.endpoint))));
      })) : h('p', { class: 'muted' }, 'No NSX Manager was assessed.'));
    el.appendChild(h('div', { class: 'grid grid-3' }, coverageCard(dom), discCard, mgrCard));
    // NSX findings
    const nf = findings.filter(function (f) { return f.domain === 'nsx'; });
    const ft = new DataTable({
      caption: 'NSX findings', sortKey: 'result', sortDir: 'desc', empty: 'No NSX findings.',
      columns: [
        { key: 'result', label: 'Result', defaultDir: 'desc', sort: function (f) { return (RESULT_RANK[f.result] || 0) * 10 + (SEV_RANK[f.severity] || 0); }, render: function (f) { return resBadge(f.result); } },
        { key: 'severity', label: 'Severity', defaultDir: 'desc', sort: function (f) { return SEV_RANK[f.severity] || 0; }, render: function (f) { return sevBadge(f.severity); } },
        { key: 'title', label: 'Finding', cls: 'title-cell', sort: function (f) { return str(f.title); }, render: function (f) { return [linkBtn(str(f.title), function () { openFinding(f); }), h('span', { class: 'sub mono' }, str(f.ruleId))]; } },
        { key: 'asset', label: 'Asset', sort: function (f) { return str(f.assetName); }, render: function (f) { return h('span', { class: 'break' }, str(f.assetName), h('span', { class: 'sub' }, typeLabel(f.assetType))); } },
        { key: 'conf', label: 'Confidence', sort: function (f) { return str(f.confidence); }, render: function (f) { return str(f.confidence); } }
      ],
      onRowClick: openFinding
    });
    ft.setRows(nf);
    el.appendChild(h('div', { class: 'card section' }, h('h2', null, 'NSX findings (' + fmtN(nf.length) + ')'), ft.el));
    // DFW rule table
    const CAT = ['Ethernet', 'Emergency', 'Infrastructure', 'Environment', 'Application'];
    const ruleAssets = assets.filter(function (a) { return a.type === 'nsx-rule'; });
    const polSeq = function (a) { const p = assetById.get(str(obj(a.props).policy)); return p ? num(obj(p.props).sequence) : 1e9; };
    const catIdx = function (a) { const i = CAT.indexOf(str(obj(a.props).category)); return i < 0 ? 99 : i; };
    ruleAssets.sort(function (a, b) { return catIdx(a) - catIdx(b) || polSeq(a) - polSeq(b) || num(obj(a.props).sequence) - num(obj(b.props).sequence); });
    const nameList = function (v) { const l = arr(v); if (!l.length) return h('span', { class: 'muted' }, '-'); return l.map(function (x) { const isAny = str(x).toUpperCase() === 'ANY'; return h('span', { class: 'tag', title: str(x) }, isAny ? 'ANY' : assetById.has(str(x)) ? assetName(x) : str(x)); }); };
    const rt = new DataTable({
      caption: 'Distributed firewall rules in evaluation order', pageSize: PAGE_SIZE, empty: 'No DFW rules collected.',
      columns: [
        { key: 'cat', label: 'Category', render: function (a) { return str(obj(a.props).category); } },
        { key: 'pol', label: 'Policy (seq)', render: function (a) { const p = assetById.get(str(obj(a.props).policy)); return h('span', { class: 'break' }, p ? str(p.name) : str(obj(a.props).policyName) || str(obj(a.props).policy), h('span', { class: 'sub' }, p ? 'seq ' + str(obj(p.props).sequence) : '')); } },
        { key: 'seq', label: 'Seq', num: true, render: function (a) { return str(obj(a.props).sequence); } },
        { key: 'name', label: 'Rule', cls: 'title-cell', render: function (a) { return [linkBtn(str(a.name), function () { openAsset(a.id); }), obj(a.props).ruleId !== undefined ? h('span', { class: 'sub mono' }, 'ID ' + str(obj(a.props).ruleId)) : null]; } },
        { key: 'src', label: 'Sources', render: function (a) { return nameList(obj(a.props).sources); } },
        { key: 'dst', label: 'Destinations', render: function (a) { return nameList(obj(a.props).destinations); } },
        { key: 'svc', label: 'Services', render: function (a) { return nameList(obj(a.props).services); } },
        { key: 'app', label: 'Applied to', render: function (a) { return nameList(obj(a.props).appliedTo); } },
        { key: 'act', label: 'Action', render: function (a) { const x = str(obj(a.props).action).toUpperCase(); return h('span', { class: 'state state-' + (x === 'ALLOW' ? 'warn' : x === 'DROP' || x === 'REJECT' ? 'ok' : 'neutral') }, x || '-'); } },
        { key: 'state', label: 'State', render: function (a) { return obj(a.props).disabled ? h('span', { class: 'state state-neutral' }, 'disabled') : 'enabled'; } },
        { key: 'log', label: 'Logged', render: function (a) { return obj(a.props).logged ? 'yes' : h('span', { class: 'muted' }, 'no'); } },
        { key: 'find', label: 'Findings', render: function (a) { const w = assetWorst(a); return w ? sevBadge(w) : h('span', { class: 'muted' }, '-'); } }
      ],
      onRowClick: function (a) { openAsset(a.id); }
    });
    rt.setRows(ruleAssets);
    el.appendChild(h('div', { class: 'card section' }, h('div', { class: 'card-head' }, h('h2', null, 'Distributed firewall rules (' + fmtN(ruleAssets.length) + ')'), h('span', { class: 'muted small' }, 'Ordered by category, policy sequence, rule sequence.')), rt.el));
  };

  // =====================================================================
  // Changes page
  // =====================================================================
  renderers.changes = function (el) {
    const d = analysis.drift;
    el.appendChild(pageHead('h-changes', 'Changes', 'Comparison against a previous VSAT run (baseline).'));
    if (!d || typeof d !== 'object') {
      el.appendChild(h('div', { class: 'card' }, h('h2', null, 'No baseline comparison in this report'),
        h('p', null, 'To track drift, keep the results.json from a previous run and pass it as the baseline on the next run:'),
        h('pre', { class: 'mono card' }, '.\\vsat.ps1 -Baseline .\\previous\\results.json'),
        h('p', { class: 'muted small' }, 'The comparison shows new, resolved, changed and unassessed findings (keyed by rule and asset), added/removed assets and NSX rule changes.')));
      return;
    }
    const c = obj(d.counts);
    el.appendChild(h('p', { class: 'muted' }, 'Baseline run ', h('span', { class: 'mono' }, str(d.baselineRunId) || '-'), ' from ' + fmtTime(d.baselineUtc) + '.'));
    const tiles = [['new', 'New', 'Newly failing or newly evaluated'], ['resolved', 'Resolved', 'Previously failing, now passing or asset removed'], ['changed', 'Changed', 'Result details changed'],
      ['unassessed', 'Unassessed', 'Evidence disappeared — not resolved'], ['unchanged', 'Unchanged', 'Same result as baseline']];
    el.appendChild(h('div', { class: 'metric-row' }, tiles.map(function (t) {
      return h('div', { class: 'metric' }, h('div', { class: 'm-val' }, fmtN(c[t[0]])), h('div', { class: 'm-lbl' }, t[1]), h('div', { class: 'small muted' }, t[2]));
    })));
    const as = obj(d.assets), nr = obj(d.nsxRules);
    el.appendChild(h('div', { class: 'grid grid-2 section' },
      h('div', { class: 'card' }, h('h2', null, 'Assets'),
        h('p', { class: 'small' }, h('strong', null, fmtN(arr(as.added).length)), ' added · ', h('strong', null, fmtN(arr(as.removed).length)), ' removed'),
        arr(as.added).length ? h('div', null, h('h4', null, 'Added'), h('div', { class: 'link-list' }, arr(as.added).slice(0, 50).map(function (id) { return assetById.has(str(id)) ? linkBtn(assetName(id), function () { openAsset(id); }) : h('span', { class: 'mono small' }, str(id)); }))) : null,
        arr(as.removed).length ? h('div', null, h('h4', null, 'Removed'), h('div', { class: 'link-list' }, arr(as.removed).slice(0, 50).map(function (id) { return h('span', { class: 'mono small' }, str(id)); }))) : null),
      h('div', { class: 'card' }, h('h2', null, 'NSX rules'), kv([['Added', fmtN(nr.added)], ['Removed', fmtN(nr.removed)], ['Modified', fmtN(nr.modified)]]))));
    const changeSel = h('select', { id: 'd-change' }, h('option', { value: '' }, 'All changes'), ['new', 'resolved', 'changed', 'unassessed'].map(function (x) { return h('option', { value: x }, x); }));
    const items = arr(d.items).filter(function (x) { return x && typeof x === 'object'; });
    const CH = { new: 'bad', resolved: 'ok', changed: 'warn', unassessed: 'warn' };
    const t = new DataTable({
      caption: 'Drift items', sortKey: 'change', sortDir: 'asc', empty: 'No drift items.',
      columns: [
        { key: 'change', label: 'Change', sort: function (x) { return ['new', 'unassessed', 'changed', 'resolved'].indexOf(str(x.change)); }, render: function (x) { const k = str(x.change); return h('span', null, h('span', { class: 'state state-' + (CH[k] || 'neutral') }, k || '?'), k === 'unassessed' ? h('span', { class: 'sub small' }, 'evidence disappeared — not resolved') : null); } },
        { key: 'rule', label: 'Rule', sort: function (x) { return str(x.ruleId); }, render: function (x) { return h('span', { class: 'mono' }, str(x.ruleId)); } },
        { key: 'asset', label: 'Asset', sort: function (x) { return str(x.assetName); }, render: function (x) { return assetById.has(str(x.assetId)) ? linkBtn(str(x.assetName) || assetName(x.assetId), function () { openAsset(x.assetId); }) : h('span', { class: 'break' }, str(x.assetName) || str(x.assetId), h('span', { class: 'sub' }, 'not in current run')); } },
        { key: 'before', label: 'Before', render: function (x) { return h('span', { class: 'break' }, x.before === null || x.before === undefined ? '—' : valueText(x.before)); } },
        { key: 'after', label: 'After', render: function (x) { return h('span', { class: 'break' }, x.after === null || x.after === undefined ? '—' : valueText(x.after)); } }
      ],
      onRowClick: function (x) { const f = findings.find(function (ff) { return ff.key === x.key; }); if (f) openFinding(f); }
    });
    on(changeSel, 'change', function () { t.setRows(items.filter(function (x) { return !changeSel.value || x.change === changeSel.value; })); });
    t.setRows(items);
    el.appendChild(h('div', { class: 'card section' }, h('div', { class: 'card-head' }, h('h2', null, 'Finding changes'), h('label', { class: 'field', for: 'd-change' }, h('span', null, 'Filter'), changeSel)), t.el));
  };

  // =====================================================================
  // Remediation page
  // =====================================================================
  function gotoWorkPackage(id) {
    go('remediation');
    closePanelIfCovering();
    requestAnimationFrame(function () {
      const card = document.querySelector('[data-wp="' + cssEsc(str(id)) + '"]');
      if (card) { card.scrollIntoView({ block: 'start' }); const hd = card.querySelector('h3'); if (hd) { hd.setAttribute('tabindex', '-1'); hd.focus(); } }
    });
  }
  renderers.remediation = function (el) {
    const wps = arr(analysis.workPackages).filter(function (w) { return w && typeof w === 'object'; });
    el.appendChild(pageHead('h-remediation', 'Remediation', 'Work packages group failing findings by owning team and change window.'));
    el.appendChild(h('div', { class: 'notice notice-info', role: 'note' }, h('strong', null, 'Guidance only — VSAT never applies changes.'), 'Review every step against your change-management process and test in a non-production environment first.'));
    if (!wps.length) { el.appendChild(h('p', { class: 'muted' }, 'No work packages in this report.')); return; }
    el.appendChild(h('div', { class: 'wp-grid' }, wps.map(function (w) {
      const fids = arr(w.findingIds), aids = arr(w.assetIds);
      return h('article', { class: 'card wp-card', 'data-wp': str(w.id) },
        h('div', { class: 'wp-meta' }, sevBadge(w.maxSeverity), h('span', { class: 'mono' }, str(w.id)), h('span', null, '· Team: ', h('strong', null, str(w.team) || '-')),
          w.maintenanceWindow ? h('span', { class: 'state state-warn' }, 'Maintenance window') : h('span', { class: 'state state-neutral' }, 'No window needed')),
        h('h3', null, str(w.title) || str(w.id)),
        w.outcome ? h('p', { class: 'break' }, h('strong', null, 'Outcome: '), str(w.outcome)) : null,
        h('div', { class: 'wp-cols' },
          h('div', null, h('h4', null, 'Impact'), h('p', { class: 'break' }, str(w.impact) || '-')),
          h('div', null, h('h4', null, 'Prerequisites'), listOf(w.prerequisites) || h('p', { class: 'muted' }, '-')),
          h('div', null, h('h4', null, 'Validation'), h('p', { class: 'break' }, str(w.validation) || '-')),
          h('div', null, h('h4', null, 'Rollback'), h('p', { class: 'break' }, str(w.rollback) || '-'))),
        section('Steps', listOf(w.steps, true)),
        h('details', null, h('summary', null, 'Affected assets (' + fmtN(aids.length) + ')'),
          h('div', { class: 'link-list' }, aids.slice(0, 40).map(function (id) { return linkBtn(assetName(id), function () { openAsset(id); }); }), aids.length > 40 ? h('span', { class: 'muted small' }, 'and ' + fmtN(aids.length - 40) + ' more') : null)),
        h('details', null, h('summary', null, 'Linked findings (' + fmtN(fids.length) + ')'),
          h('div', { class: 'link-list' }, fids.slice(0, 40).map(function (id) { const f = findingById.get(str(id)); return f ? linkBtn(str(id) + ' ' + trunc(f.assetName, 30), function () { openFinding(f); }) : h('span', { class: 'mono small' }, str(id)); })),
          h('div', { class: 'actions' }, btn('Show all in Findings', function () { findingsPage.filterWp(w.id); }, 'btn-sm'))));
    })));
  };

  // =====================================================================
  // Exports
  // =====================================================================
  function download(name, blob) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = name.replace(/[^A-Za-z0-9._-]+/g, '_');
    a.rel = 'noopener';
    a.hidden = true;
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); a.remove(); }, 1500);
    announce('Download started: ' + a.download);
  }
  function csvCell(v) {
    let s = v === null || v === undefined ? '' : (typeof v === 'object' ? jsonText(v) : String(v));
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }
  function toCsv(header, rows) { return '﻿' + [header].concat(rows).map(function (r) { return r.map(csvCell).join(','); }).join('\r\n') + '\r\n'; }
  function findingsCsv(list) {
    const header = ['id', 'key', 'ruleId', 'title', 'domain', 'result', 'severity', 'priorityScore', 'confidence', 'assetId', 'assetName', 'assetType', 'observed', 'expected', 'exceptionOwner', 'exceptionExpires', 'exceptionActive', 'workPackage', 'mitigation', 'frameworks'];
    const rows = list.map(function (f) {
      const m = obj(fx(f, 'mitigation')), ex = f.exception && typeof f.exception === 'object' ? f.exception : {};
      return [f.id, f.key, f.ruleId, fx(f, 'title'), f.domain, f.result, f.severity, num(obj(f.priority).score), f.confidence, f.assetId, f.assetName, f.assetType, f.observed, f.expected,
        ex.owner, ex.expires, ex.active === undefined ? '' : String(!!ex.active), m.workPackage, m.summary,
        arr(fx(f, 'frameworks')).map(function (x) { x = obj(x); return str(x.framework) + ' ' + str(x.control) + (x.mappingStatus === 'verified' ? '' : ' (unverified)'); }).join('; ')];
    });
    return toCsv(header, rows);
  }
  function worklistCsv() {
    const header = ['workPackage', 'title', 'team', 'maxSeverity', 'maintenanceWindow', 'findingId', 'ruleId', 'assetName', 'assetId', 'severity', 'result', 'exception', 'mitigation', 'validation', 'rollback'];
    const rows = [];
    arr(analysis.workPackages).forEach(function (w) {
      w = obj(w);
      arr(w.findingIds).forEach(function (fid) {
        const f = findingById.get(str(fid)) || {};
        const m = obj(f.mitigation);
        rows.push([w.id, w.title, w.team, w.maxSeverity, w.maintenanceWindow ? 'yes' : 'no', fid, f.ruleId, f.assetName, f.assetId, f.severity, f.result,
          f.exception ? (f.exception.active ? 'accepted' : 'expired') : '', m.summary, m.validation || w.validation, m.rollback || w.rollback]);
      });
    });
    return toCsv(header, rows);
  }
  renderers.exports = function (el) {
    const base = 'vsat-' + safeFilePart(run.id);
    el.appendChild(pageHead('h-exports', 'Exports', 'All exports are generated locally in your browser. Nothing is uploaded.'));
    el.appendChild(h('div', { class: 'notice notice-warn' }, h('strong', null, 'Handle exports as sensitive'), 'Exports contain infrastructure names, addresses and security weaknesses. Store and share them under your organization’s data-classification rules.'));
    function card(title, desc, actions) { return h('div', { class: 'card' }, h('h2', null, title), h('p', null, desc), h('div', { class: 'actions' }, actions)); }
    el.appendChild(h('div', { class: 'export-grid' },
      card('Results JSON', 'The complete results.json embedded in this report (findings, assets, relationships, analysis).', [btn('Download JSON', function () { download(base + '-results.json', new Blob([JSON.stringify(D, null, 2)], { type: 'application/json' })); }, 'btn-primary')]),
      card('Findings CSV', 'One row per finding. Cells beginning with = + - @ are prefixed with a quote to prevent spreadsheet formula execution.', [
        btn('All findings', function () { download(base + '-findings.csv', new Blob([findingsCsv(findings)], { type: 'text/csv;charset=utf-8' })); }, 'btn-primary'),
        btn('FAIL / UNKNOWN / ERROR', function () { download(base + '-findings-open.csv', new Blob([findingsCsv(findings.filter(function (f) { return f.result === 'FAIL' || f.result === 'UNKNOWN' || f.result === 'ERROR'; }))], { type: 'text/csv;charset=utf-8' })); })]),
      card('Worklist CSV', 'Work packages expanded to one row per linked finding, for ticketing and change planning.', [btn('Download worklist', function () { download(base + '-worklist.csv', new Blob([worklistCsv()], { type: 'text/csv;charset=utf-8' })); }, 'btn-primary')]),
      card('Topology image', 'Current topology view with legend and scope label (run ID and time). Expand the graph first to include more detail.', [btn('SVG', exportSvg, 'btn-primary'), btn('PNG', exportPng)]),
      card('Print / PDF', 'Prints all sections with navigation hidden. Use your browser’s "Save as PDF" for a PDF copy.', [btn('Print report', function () { PAGES.forEach(ensureRendered); window.print(); })])));
  };

  // =====================================================================
  // Boot
  // =====================================================================
  route();
})();
