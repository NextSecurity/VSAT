/* VSAT 2.0 local guided UI (served on 127.0.0.1).
 * Security model: session token lives only in this closure (removed from the URL immediately);
 * every API call is same-origin fetch with credentials:'omit' and the X-VSAT-Token header.
 * All server data is rendered via textContent/createElement only. Passwords are cleared from the
 * DOM as soon as the request is built and are never stored in JS variables. */
(function () {
  'use strict';

  // ---------------------------------------------------------------- token
  let token = null;
  (function () {
    const m = /(?:^#|&)token=([A-Za-z0-9._~-]{16,512})(?:&|$)/.exec(location.hash || '');
    if (m) token = m[1];
    try { history.replaceState(null, '', location.pathname); } catch (e) { /* ignore */ }
  })();

  // ---------------------------------------------------------------- safe DOM
  const SAFE_ATTR = /^(?:class|id|role|tabindex|title|type|value|name|for|placeholder|checked|selected|disabled|hidden|autocomplete|spellcheck|required|maxlength|open|aria-[a-z]+|data-[a-z-]+)$/;
  function appendKids(el, kids) {
    kids.forEach(function (k) {
      if (k === null || k === undefined || k === false) return;
      if (Array.isArray(k)) appendKids(el, k);
      else if (k instanceof Node) el.appendChild(k);
      else el.appendChild(document.createTextNode(String(k)));
    });
  }
  function h(tag, attrs) {
    const el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      const v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (!SAFE_ATTR.test(k)) throw new Error('Attribute not allowed: ' + k);
      el.setAttribute(k, v === true ? '' : String(v));
    });
    appendKids(el, Array.prototype.slice.call(arguments, 2));
    return el;
  }
  function on(el, ev, fn) { el.addEventListener(ev, fn); return el; }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); return el; }
  function str(v) { return v === null || v === undefined ? '' : String(v); }
  function arr(v) { return Array.isArray(v) ? v : []; }
  function obj(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
  function num(v) { const n = Number(v); return isFinite(n) ? n : 0; }
  function btn(label, fn, cls, attrs) { const b = h('button', Object.assign({ type: 'button', class: 'btn ' + (cls || '') }, attrs || {}), label); if (fn) on(b, 'click', fn); return b; }
  function announce(msg) { const l = document.getElementById('live'); l.textContent = ''; l.textContent = msg; }
  function fmtTime(s) { const d = new Date(str(s)); return isNaN(d.getTime()) ? str(s) : d.toISOString().slice(11, 19); }
  function state(cls, text) { return h('span', { class: 'state state-' + cls }, text); }

  const alertEl = document.getElementById('alert');
  function showError(msg) { alertEl.textContent = msg; alertEl.hidden = false; }
  function clearError() { alertEl.hidden = true; alertEl.textContent = ''; }

  // ---------------------------------------------------------------- API
  const API_PATHS = { state: '/api/state', endpoints: '/api/endpoints', remove: '/api/endpoints/remove', nsx: '/api/nsx', discover: '/api/discover', run: '/api/run', cancel: '/api/cancel', shutdown: '/api/shutdown' };
  function plainError(status) {
    if (status === 401 || status === 403) return 'This browser session is not authorized. Open VSAT from the link printed in the terminal.';
    if (status === 404) return 'The VSAT service did not recognize this request.';
    if (status >= 500) return 'VSAT reported an internal problem. Check the terminal window for details.';
    return 'The request could not be completed.';
  }
  async function api(key, body) {
    const path = API_PATHS[key];
    const init = {
      method: body === undefined ? 'GET' : 'POST', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      headers: { 'X-VSAT-Token': token, 'Content-Type': 'application/json' }
    };
    if (body !== undefined) init.body = JSON.stringify(body);
    let res;
    try { res = await fetch(path, init); } catch (e) { throw new Error('VSAT is not reachable. It may have been stopped — check the terminal window.'); }
    let data = null;
    try { data = await res.json(); } catch (e) { data = null; }
    if (!res.ok || !data || data.ok === false) {
      const msg = data && typeof data.error === 'string' && data.error.length < 600 ? data.error : plainError(res.status);
      throw new Error(msg);
    }
    return data;
  }

  // ---------------------------------------------------------------- state
  let S = null;
  let current = 1;
  let userPicked = false;
  let pollTimer = 0;
  let discoverRequested = false;
  let stopped = false;
  const STEPS = [
    { n: 1, label: 'Readiness' }, { n: 2, label: 'vCenter / ESXi' }, { n: 3, label: 'NSX', req: true },
    { n: 4, label: 'Review scope' }, { n: 5, label: 'Run' }, { n: 6, label: 'Results' }
  ];
  function vsphereEndpoints() { return arr(S && S.endpoints).filter(function (e) { return e.type === 'vcenter' || e.type === 'esxi'; }); }
  function nsxEndpoints() { return arr(S && S.endpoints).filter(function (e) { return e.type === 'nsx'; }); }
  function doctorFails() { return arr(obj(S && S.doctor).checks).filter(function (c) { return c.status === 'fail'; }).length; }
  function nsxSatisfied() { return nsxEndpoints().some(function (e) { return e.authenticated; }) || !!obj(S && S.nsx).declaredAbsent; }
  function phase() { return str(S && S.phase); }
  function isActive() { return phase() === 'running' || phase() === 'discovering'; }
  function maxStep() {
    if (!S) return 1;
    if (S.result || ['done', 'failed', 'canceled'].indexOf(phase()) >= 0) return 6;
    if (phase() === 'running') return 5;
    if (doctorFails()) return 1;
    if (!vsphereEndpoints().some(function (e) { return e.authenticated; })) return 2;
    if (!nsxSatisfied()) return 3;
    return 4;
  }

  function go(n) { if (n < 1 || n > maxStep()) return; current = n; userPicked = true; clearError(); render(true); }

  async function refresh() {
    try {
      S = await api('state');
      clearError();
    } catch (e) { showError(e.message); }
    if (!S) return;
    // server phase drives the flow for run/results
    if (phase() === 'running' && current !== 5) current = 5;
    if ((S.result || ['done', 'failed', 'canceled'].indexOf(phase()) >= 0) && current === 5) current = 6;
    if (!userPicked) current = Math.min(maxStep(), Math.max(current, 1));
    if (current > maxStep()) current = maxStep();
    render(false);
    schedulePoll();
  }
  function schedulePoll() { clearTimeout(pollTimer); if (!stopped && isActive()) pollTimer = setTimeout(refresh, 1500); }

  async function action(key, body, busyBtn, okMsg) {
    clearError();
    if (busyBtn) busyBtn.disabled = true;
    try {
      const r = await api(key, body);
      if (okMsg) announce(okMsg);
      await refresh();
      return r;
    } catch (e) { showError(e.message); return null; } finally { if (busyBtn && document.contains(busyBtn)) busyBtn.disabled = false; }
  }

  // ---------------------------------------------------------------- stepper
  function renderStepper() {
    const ol = clear(document.getElementById('steps'));
    const max = maxStep();
    STEPS.forEach(function (s) {
      const done = s.n < max && s.n !== current;
      const b = btn([h('span', { class: 'num', 'aria-hidden': 'true' }, done ? '✓' : String(s.n)), h('span', { class: 'lbl-text' }, s.label), s.req ? h('span', { class: 'req' }, 'Required') : null], function () { go(s.n); }, '', {
        'aria-current': s.n === current ? 'step' : null, disabled: s.n > max, 'aria-label': 'Step ' + s.n + ': ' + s.label + (s.n > max ? ' (not available yet)' : done ? ' (completed)' : '')
      });
      b.className = done ? 'done' : '';
      ol.appendChild(h('li', null, b));
    });
  }

  // ---------------------------------------------------------------- views
  const view = document.getElementById('view');
  let builtStep = 0;
  let stepUpdate = null;
  function render(stepChanged) {
    renderStepper();
    const ver = document.getElementById('hdr-version');
    ver.textContent = 'VSAT ' + str(S && S.version);
    document.getElementById('hdr-mode').hidden = !(S && S.mode === 'demo');
    if (stepChanged || builtStep !== current) {
      clear(view);
      builtStep = current;
      stepUpdate = BUILDERS[current](view);
      const hd = view.querySelector('h1');
      if (stepChanged && hd) { hd.setAttribute('tabindex', '-1'); hd.focus(); }
    }
    if (stepUpdate) stepUpdate();
  }
  function head(title, sub) { return h('div', { class: 'step-head' }, h('h1', null, title), sub ? h('p', null, sub) : null); }
  function nav(prev, next, nextLabel) {
    const nb = next ? btn(nextLabel || 'Continue', function () { go(next); }, 'btn-primary') : null;
    return { el: h('div', { class: 'actions' }, prev ? btn('Back', function () { go(prev); }) : null, h('span', { class: 'spacer' }), nb), next: nb };
  }

  const BUILDERS = {};

  // 1 Readiness
  BUILDERS[1] = function (root) {
    root.appendChild(head('Readiness', 'VSAT checks this computer before connecting to your environment. VSAT only reads configuration; it never changes it.'));
    const list = h('ul', { class: 'checks' });
    const msg = h('div');
    const n = nav(null, 2);
    root.appendChild(h('div', { class: 'card' }, h('h2', null, 'System checks'), list));
    root.appendChild(msg);
    root.appendChild(n.el);
    return function () {
      clear(list);
      const checks = arr(obj(S.doctor).checks);
      if (!checks.length) list.appendChild(h('li', null, state('neutral', 'Pending'), h('span', { class: 'muted' }, 'No readiness results yet.')));
      checks.forEach(function (c) {
        const st = str(c.status);
        list.appendChild(h('li', null, state(st === 'ok' ? 'ok' : st === 'warn' ? 'warn' : 'bad', st === 'ok' ? 'Ready' : st === 'warn' ? 'Warning' : 'Problem'),
          h('div', null, h('strong', null, str(c.name)), c.detail ? h('div', { class: 'small muted break' }, str(c.detail)) : null)));
      });
      clear(msg);
      const f = doctorFails();
      if (f) msg.appendChild(h('div', { class: 'notice notice-bad' }, h('strong', null, f === 1 ? 'One problem must be fixed before continuing.' : f + ' problems must be fixed before continuing.'), 'Fix the items marked Problem, then restart VSAT.'));
      n.next.disabled = f > 0;
    };
  };

  // endpoint form (used by step 2 and 3)
  function endpointForm(types, defaults, submitLabel) {
    const id = 'f' + Math.random().toString(36).slice(2, 8);
    const typeSel = h('select', { id: id + '-type' }, types.map(function (t) { return h('option', { value: t[0] }, t[1]); }));
    const addr = h('input', { type: 'text', id: id + '-addr', autocomplete: 'off', spellcheck: 'false', placeholder: 'vc01.example.local', maxlength: '253', required: true });
    if (defaults && defaults.address) addr.value = defaults.address;
    const user = h('input', { type: 'text', id: id + '-user', autocomplete: 'off', spellcheck: 'false', placeholder: 'audit@vsphere.local', maxlength: '256', required: true });
    const pw = h('input', { type: 'password', id: id + '-pw', autocomplete: 'off', maxlength: '512', required: true });
    const thumb = h('input', { type: 'text', id: id + '-thumb', autocomplete: 'off', spellcheck: 'false', placeholder: 'optional', maxlength: '200' });
    const submit = h('button', { type: 'submit', class: 'btn btn-primary' }, submitLabel || 'Add and sign in');
    const form = h('form', { 'aria-label': 'Add endpoint' },
      h('div', { class: 'form-grid' },
        types.length > 1 ? h('div', { class: 'field' }, h('label', { for: id + '-type' }, 'Type'), typeSel) : null,
        h('div', { class: 'field' + (types.length > 1 ? '' : ' full') }, h('label', { for: id + '-addr' }, 'Address'), addr, h('span', { class: 'hint' }, 'Host name or IP address.')),
        h('div', { class: 'field' }, h('label', { for: id + '-user' }, 'User name'), user, h('span', { class: 'hint' }, 'A read-only account is sufficient.')),
        h('div', { class: 'field' }, h('label', { for: id + '-pw' }, 'Password'), pw, h('span', { class: 'hint' }, 'Sent once to the local VSAT process; not stored by this page.')),
        h('div', { class: 'field full' }, h('label', { for: id + '-thumb' }, 'Certificate thumbprint (SHA-256)'), thumb, h('span', { class: 'hint' }, 'Only needed when the server certificate is not trusted by this computer.'))),
      h('div', { class: 'actions' }, submit));
    on(form, 'submit', async function (e) {
      e.preventDefault();
      clearError();
      if (!addr.value.trim() || !user.value.trim() || !pw.value) { showError('Enter the address, user name and password.'); return; }
      submit.disabled = true;
      // Build the request body and clear the password field immediately; no JS variable keeps it.
      const req = api('endpoints', { type: types.length > 1 ? typeSel.value : types[0][0], address: addr.value.trim(), username: user.value.trim(), password: pw.value, thumbprint: thumb.value.trim() });
      pw.value = '';
      try {
        const r = await req;
        announce('Endpoint ' + str(obj(r.endpoint).address) + ' added.');
        addr.value = ''; thumb.value = '';
        await refresh();
      } catch (err) { showError(err.message); } finally { submit.disabled = false; }
    });
    return form;
  }
  function endpointTable(list) {
    if (!list.length) return h('p', { class: 'muted' }, 'No endpoints added yet.');
    return h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, h('th', null, 'Type'), h('th', null, 'Address'), h('th', null, 'Status'), h('th', null, ''))),
      h('tbody', null, list.map(function (e) {
        const rm = btn('Remove', function () { action('remove', { id: str(e.id) }, rm, 'Endpoint removed.'); }, 'btn-sm btn-danger', { 'aria-label': 'Remove ' + str(e.address) });
        return h('tr', null, h('td', null, e.type === 'vcenter' ? 'vCenter' : e.type === 'esxi' ? 'ESXi' : e.type === 'nsx' ? 'NSX Manager' : str(e.type)),
          h('td', { class: 'mono' }, str(e.address)),
          h('td', null, e.authenticated ? state('ok', 'Signed in') : state(e.error ? 'bad' : 'neutral', str(e.status) || 'Not signed in'), e.error ? h('div', { class: 'small break' }, str(e.error)) : null),
          h('td', null, rm));
      }))));
  }

  // 2 Endpoints
  BUILDERS[2] = function (root) {
    root.appendChild(head('vCenter and ESXi', 'Add the vCenter Server (recommended) or standalone ESXi hosts to assess.'));
    const tbl = h('div');
    root.appendChild(h('div', { class: 'card' }, h('h2', null, 'Endpoints in scope'), tbl));
    root.appendChild(h('div', { class: 'card' }, h('h2', null, 'Add an endpoint'), endpointForm([['vcenter', 'vCenter Server'], ['esxi', 'ESXi host']])));
    const n = nav(1, 3);
    const msg = h('p', { class: 'small muted' });
    root.appendChild(msg);
    root.appendChild(n.el);
    return function () {
      clear(tbl).appendChild(endpointTable(vsphereEndpoints()));
      const ok = vsphereEndpoints().some(function (e) { return e.authenticated; });
      n.next.disabled = !ok;
      msg.textContent = ok ? '' : 'Sign in to at least one vCenter or ESXi endpoint to continue.';
    };
  };

  // 3 NSX (mandatory)
  BUILDERS[3] = function (root) {
    root.appendChild(head('NSX', 'This step is required. NSX coverage is part of every assessment, so VSAT must either assess NSX or record that it is not deployed.'));
    const disc = h('div', { class: 'card' });
    const eps = h('div');
    const absentBox = h('input', { type: 'checkbox', id: 'nsx-absent' });
    const absentWarn = h('div');
    const formHolder = h('div');
    root.appendChild(disc);
    root.appendChild(h('div', { class: 'card' }, h('h2', null, 'Option A — Assess NSX'), h('p', { class: 'muted small' }, 'Add the NSX Manager with an account that has at least the Auditor role.'), eps, formHolder));
    root.appendChild(h('div', { class: 'card' }, h('h2', null, 'Option B — NSX is not deployed'),
      h('label', { class: 'check-row', for: 'nsx-absent' }, absentBox, h('span', null, h('strong', null, 'NSX is not deployed in this scope'), h('span', { class: 'small muted' }, ' — this declaration is recorded in the report together with the discovery evidence.'))),
      absentWarn));
    on(absentBox, 'change', function () { action('nsx', { declaredAbsent: absentBox.checked }, null, absentBox.checked ? 'Recorded: NSX not deployed.' : 'Declaration removed.'); });
    const n = nav(2, 4);
    const msg = h('p', { class: 'small muted' });
    root.appendChild(msg);
    root.appendChild(n.el);
    let formBuiltFor = null;
    if (!discoverRequested && phase() !== 'discovering' && str(obj(obj(S.nsx).discovery).status) === 'unknown' && vsphereEndpoints().some(function (e) { return e.authenticated; })) {
      discoverRequested = true;
      action('discover', {}, null, 'Looking for NSX in the connected vCenter.');
    }
    return function () {
      const nsx = obj(S.nsx), d = obj(nsx.discovery), st = str(d.status) || 'unknown';
      clear(disc);
      const rediscover = btn(phase() === 'discovering' ? 'Detecting…' : 'Detect again', function () { action('discover', {}, rediscover, 'Detecting NSX.'); }, 'btn-sm', { disabled: phase() === 'discovering' });
      disc.appendChild(h('div', { class: 'row' }, h('h2', null, 'Discovery result'), h('span', { class: 'spacer' }),
        state(st === 'detected' ? 'warn' : st === 'not-detected' ? 'ok' : 'neutral', phase() === 'discovering' ? 'Detecting…' : st === 'detected' ? 'NSX detected' : st === 'not-detected' ? 'No NSX found' : 'Unknown'), rediscover));
      disc.appendChild(h('p', { class: 'small muted' }, st === 'detected' ? 'Evidence of NSX was found. Assess it with Option A for a complete report.' : st === 'not-detected' ? 'No NSX evidence was found in the connected inventory.' : 'VSAT could not tell whether NSX is deployed.'));
      if (arr(d.evidence).length) disc.appendChild(h('ul', { class: 'small' }, arr(d.evidence).map(function (x) { return h('li', { class: 'break' }, str(x)); })));
      if (arr(d.managersDiscovered).length) disc.appendChild(h('p', { class: 'small' }, 'NSX Manager found: ', h('span', { class: 'mono' }, arr(d.managersDiscovered).map(str).join(', '))));
      if (nsx.coverageHint) disc.appendChild(h('div', { class: 'notice notice-info small' }, str(nsx.coverageHint)));
      clear(eps).appendChild(endpointTable(nsxEndpoints()));
      const suggested = str(arr(d.managersDiscovered)[0]);
      if (formBuiltFor !== suggested) { formBuiltFor = suggested; clear(formHolder).appendChild(endpointForm([['nsx', 'NSX Manager']], { address: suggested }, 'Add NSX Manager and sign in')); }
      absentBox.checked = !!nsx.declaredAbsent;
      clear(absentWarn);
      {
        const risky = st === 'detected' || st === 'unknown';
        absentWarn.appendChild(h('div', { class: 'notice ' + (risky ? 'notice-warn' : 'notice-info') + ' small' },
          h('strong', null, risky ? 'The report will be marked INCOMPLETE / REVIEW' : 'Recorded in the report'),
          risky ? 'Discovery ' + (st === 'detected' ? 'found evidence of NSX' : 'could not rule NSX out') + '. If you declare NSX absent, the report records your declaration next to that evidence and flags NSX coverage for review.' : 'Your declaration and the discovery evidence are both recorded.'));
      }
      n.next.disabled = !nsxSatisfied();
      msg.textContent = nsxSatisfied() ? '' : 'Sign in to an NSX Manager or declare that NSX is not deployed to continue.';
    };
  };

  // 4 Review
  BUILDERS[4] = function (root) {
    root.appendChild(head('Review scope', 'Confirm what VSAT will assess. The assessment is read-only.'));
    const summary = h('div', { class: 'card' });
    const prof = h('select', { id: 'profile' }, h('option', { value: 'standard', selected: true }, 'Standard (recommended)'), h('option', { value: 'strict' }, 'Strict'));
    if (S.profile === 'strict') prof.value = 'strict';
    root.appendChild(summary);
    root.appendChild(h('div', { class: 'card' }, h('div', { class: 'field' }, h('label', { for: 'profile' }, 'Profile'), prof),
      h('details', null, h('summary', null, 'Advanced — about profiles'),
        h('p', { class: 'small' }, h('strong', null, 'Standard'), ' applies controls that are broadly recommended for production vSphere and NSX environments and suitable for most organizations.'),
        h('p', { class: 'small' }, h('strong', null, 'Strict'), ' adds hardening controls intended for high-security environments. Expect more findings, some of which may conflict with operational tooling.'),
        h('p', { class: 'small muted' }, 'The profile changes which expectations are evaluated, not what is collected. VSAT never applies changes in either profile.'))));
    const start = btn('Start assessment', function () { action('run', { profile: prof.value === 'strict' ? 'strict' : 'standard' }, start, 'Assessment started.').then(function (r) { if (r) { current = 5; userPicked = false; render(true); } }); }, 'btn-primary');
    root.appendChild(h('div', { class: 'actions' }, btn('Back', function () { go(3); }), h('span', { class: 'spacer' }), start));
    return function () {
      clear(summary);
      const nsx = obj(S.nsx);
      summary.appendChild(h('h2', null, 'Scope'));
      summary.appendChild(h('dl', { class: 'kv' },
        h('dt', null, 'vCenter / ESXi'), h('dd', null, vsphereEndpoints().map(function (e) { return h('div', { class: 'mono' }, str(e.address) + (e.authenticated ? '' : ' (not signed in)')); })),
        h('dt', null, 'NSX'), h('dd', null, nsxEndpoints().filter(function (e) { return e.authenticated; }).length ? nsxEndpoints().map(function (e) { return h('div', { class: 'mono' }, str(e.address)); }) : nsx.declaredAbsent ? 'Declared not deployed (recorded; discovery: ' + str(obj(nsx.discovery).status || 'unknown') + ')' : 'Not configured'),
        h('dt', null, 'Mode'), h('dd', null, S.mode === 'demo' ? 'Demo (synthetic data)' : 'Live')));
      if (nsx.declaredAbsent && ['detected', 'unknown'].indexOf(str(obj(nsx.discovery).status)) >= 0) summary.appendChild(h('div', { class: 'notice notice-warn small' }, 'NSX is declared absent but discovery could not confirm it. The report will be INCOMPLETE / REVIEW for NSX.'));
      start.disabled = isActive();
    };
  };

  // 5 Run
  BUILDERS[5] = function (root) {
    root.appendChild(head('Running assessment', 'Progress is reported by step. VSAT does not estimate remaining time.'));
    const body = h('div', { class: 'card' });
    const log = h('ol', { class: 'log', 'aria-label': 'Recent log' });
    let confirmArmed = false;
    const cancel = btn('Cancel run', function () {
      if (!confirmArmed) { confirmArmed = true; cancel.textContent = 'Confirm cancel'; announce('Press again to confirm canceling the run.'); return; }
      action('cancel', {}, cancel, 'Cancel requested.');
    }, 'btn-danger');
    root.appendChild(body);
    root.appendChild(h('div', { class: 'card' }, h('h2', null, 'Recent log'), log));
    root.appendChild(h('div', { class: 'actions' }, h('span', { class: 'spacer' }), cancel));
    return function () {
      const p = obj(S.progress);
      const step = num(p.step), total = num(p.totalSteps);
      clear(body);
      body.appendChild(h('div', { class: 'row' }, h('h2', null, str(p.phase) || str(S.phase) || 'Working'), h('span', { class: 'spacer' }), total ? h('strong', null, 'Step ' + step + ' of ' + total) : h('span', { class: 'muted' }, 'Preparing')));
      const bar = h('div', { class: 'progress' + (total ? '' : ' indeterminate'), role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': String(total || 1), 'aria-valuenow': String(step), 'aria-label': 'Assessment progress' }, h('span'));
      if (total) bar.firstChild.style.width = Math.min(100, Math.round((step / total) * 100)) + '%';
      body.appendChild(bar);
      if (p.message) body.appendChild(h('p', { class: 'break' }, str(p.message)));
      const counts = obj(p.counts);
      const keys = Object.keys(counts);
      if (keys.length) body.appendChild(h('div', { class: 'counts' }, keys.map(function (k) { return h('div', { class: 'count' }, h('div', { class: 'v' }, String(num(counts[k]))), h('div', { class: 'l' }, k)); })));
      clear(log);
      arr(p.log).slice(-60).forEach(function (l) { l = obj(l); const lv = str(l.level); log.appendChild(h('li', { class: 'lv-' + (lv === 'warn' || lv === 'error' ? lv : 'info') }, fmtTime(l.t) + '  ' + lv.toUpperCase() + '  ' + str(l.message))); });
      log.scrollTop = log.scrollHeight;
      cancel.disabled = phase() !== 'running';
    };
  };

  // 6 Results
  BUILDERS[6] = function (root) {
    root.appendChild(head('Results', 'The assessment has finished. The report contains sensitive infrastructure data — store it securely.'));
    const body = h('div');
    root.appendChild(body);
    const finish = btn('Finish and stop VSAT', async function () {
      finish.disabled = true;
      try { await api('shutdown', {}); } catch (e) { /* the service may close the connection while stopping */ }
      stopped = true; clearTimeout(pollTimer);
      clear(view);
      view.appendChild(h('div', { class: 'center-msg' }, h('h1', null, 'VSAT has stopped'), h('p', { class: 'muted' }, 'You can close this tab. Your report and results remain in the output folder.')));
      clear(document.getElementById('steps'));
    }, 'btn-primary');
    root.appendChild(h('div', { class: 'actions' }, btn('Start over', function () { go(4); }, '', { title: 'Review scope and run again' }), h('span', { class: 'spacer' }), finish));
    return function () {
      clear(body);
      const r = S.result ? obj(S.result) : null;
      if (!r) {
        body.appendChild(h('div', { class: 'status-banner st-bad' }, h('p', { class: 'label' }, phase() === 'canceled' ? 'CANCELED' : phase() === 'failed' ? 'FAILED' : 'NO RESULT'),
          h('p', null, phase() === 'canceled' ? 'The run was canceled before results were produced.' : 'The run did not produce results. See the log in the terminal window for details.')));
        return;
      }
      const st = obj(r.status), overall = str(st.overall).toLowerCase();
      const cls = overall === 'complete' ? 'st-ok' : overall === 'incomplete' ? 'st-warn' : 'st-bad';
      body.appendChild(h('div', { class: 'status-banner ' + cls, role: 'status' },
        h('p', { class: 'label' }, str(st.label) || (overall ? overall.toUpperCase() : 'UNKNOWN')),
        arr(st.reasons).length ? h('ul', null, arr(st.reasons).map(function (x) { return h('li', null, str(x)); })) : null,
        h('p', { class: 'small muted' }, 'Exit code ' + str(st.exitCode))));
      const sum = obj(r.summary), sev = obj(sum.severity), res = obj(sum.results);
      body.appendChild(h('div', { class: 'card' }, h('h2', null, 'Failing checks by severity'),
        h('div', { class: 'counts' }, ['critical', 'high', 'medium', 'low', 'info'].map(function (k) { return h('div', { class: 'count sev-' + k }, h('div', { class: 'v' }, String(num(sev[k]))), h('div', { class: 'l' }, k)); })),
        h('h3', null, 'All results'),
        h('div', { class: 'counts' }, ['PASS', 'FAIL', 'MANUAL', 'UNKNOWN', 'ERROR', 'NOT_APPLICABLE'].map(function (k) { return h('div', { class: 'count' }, h('div', { class: 'v' }, String(num(res[k]))), h('div', { class: 'l' }, k === 'NOT_APPLICABLE' ? 'N/A' : k)); })),
        overall !== 'complete' ? h('p', { class: 'small muted' }, 'UNKNOWN and ERROR results mean evidence was missing; they are not counted as compliant.') : null));
      // Report link: constant same-origin path, never built from server data.
      const link = document.createElement('a');
      link.href = '/report';
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.className = 'btn btn-primary';
      link.textContent = 'Open report';
      body.appendChild(h('div', { class: 'card' }, h('h2', null, 'Output'),
        h('dl', { class: 'kv' }, h('dt', null, 'Folder'), h('dd', { class: 'mono' }, str(r.outputDir) || '-'),
          h('dt', null, 'Files'), h('dd', null, arr(r.files).length ? arr(r.files).map(function (f) { return h('div', { class: 'mono' }, str(f)); }) : '-')),
        h('div', { class: 'actions' }, link, h('span', { class: 'small muted' }, 'Opens in a new tab.'))));
    };
  };

  // ---------------------------------------------------------------- boot
  if (!token) {
    clear(view);
    view.appendChild(h('div', { class: 'center-msg card' }, h('h1', null, 'Open VSAT from the link printed in the terminal'),
      h('p', { class: 'muted' }, 'For your security, this page only works when opened with the one-time link that VSAT prints when it starts. Copy that link from the terminal window into your browser.')));
    document.getElementById('steps').appendChild(h('li', null, h('span', { class: 'muted small' }, 'Not connected')));
    return;
  }
  refresh();
})();
