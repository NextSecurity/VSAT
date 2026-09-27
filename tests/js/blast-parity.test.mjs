// Browser/engine parity for the Blast radius view. Run: node --test tests/js/
// The fixtures are written by tests/Graph.Tests.ps1 ('Browser parity' BeforeAll), so run Pester first.
// No npm packages: node:test, node:assert and node:fs only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const core = require(join(here, '..', '..', 'assets', 'report', 'blast-core.js'));

const fixtures = existsSync(here) ? readdirSync(here).filter((f) => /^fixture-.*results\.json$/.test(f)).sort() : [];

test('parity fixtures exist (run the Pester suite first)', () => {
  assert.ok(fixtures.length > 0, 'no tests/js/fixture-*results.json; run Invoke-Pester -Path tests/Graph.Tests.ps1 first');
});

for (const name of fixtures) {
  const raw = readFileSync(join(here, name), 'utf8').replace(/^﻿/, '');
  const blast = JSON.parse(raw).analysis.blastRadius;
  const M = core.model(blast);
  const engine = Array.isArray(blast.paths) ? blast.paths : [];
  const browser = core.allPaths(M, new Set());
  const key = (p) => p.entry + '\n' + p.crown;

  test(`${name}: every engine path is found by the browser, edge for edge`, () => {
    assert.ok(engine.length > 0, 'fixture has no paths');
    const byKey = new Map(browser.map((p) => [key(p), p]));
    for (const p of engine) {
      const b = byKey.get(key(p));
      assert.ok(b, `browser misses ${p.id} ${key(p)}`);
      assert.deepEqual(b.edges.map((e) => e.id), p.edgeIds, `${p.id} edges differ`);
      assert.equal(b.cost, p.cost, `${p.id} cost`);
      assert.equal(b.hops, p.hops, `${p.id} hops`);
      assert.equal(b.confidence, p.confidence, `${p.id} confidence`);
    }
  });

  test(`${name}: the browser finds no path the engine did not count`, () => {
    if (blast.bounds && blast.bounds.truncated) return; // partial engine results are a subset by design
    assert.equal(browser.length, blast.bounds.pathsFound);
    assert.equal(browser.length, engine.length);
    assert.equal(new Set(browser.map((p) => p.crown)).size, blast.bounds.crownsReachable);
  });

  test(`${name}: the browser's greedy fix order equals the engine fixPlan`, () => {
    const plan = core.fixPlan(browser);
    assert.deepEqual(plan.map((f) => f.fixId), (blast.fixPlan || []).map((f) => f.fixId));
    assert.deepEqual(plan.map((f) => f.pathsBroken), (blast.fixPlan || []).map((f) => f.pathsBroken));
  });

  test(`${name}: the browser search does the same work as the engine (dominated states skipped)`, () => {
    const pops = (JSON.parse(raw).probe || {}).pops || {};
    assert.ok(Object.keys(pops).length > 0, 'fixture has no engine search probe');
    for (const en of Object.keys(pops)) assert.equal(core.search(M, en, null).pops, pops[en], `pops from ${en}`);
  });

  test(`${name}: with the first fix applied, the browser equals the engine re-run on the cut graph`, () => {
    const cut = JSON.parse(raw).cut;
    if (!cut) return;
    const after = core.allPaths(M, new Set([cut.fixId]));
    for (const p of after) assert.ok(!p.edges.some((e) => e.fixId === cut.fixId), 'a cut edge was used');
    const engineCut = new Map(cut.paths.map((p) => [key(p), p]));
    const browserCut = new Map(after.map((p) => [key(p), p]));
    assert.deepEqual([...browserCut.keys()].sort(), [...engineCut.keys()].sort(), 'same (entry, crown) pairs after the cut');
    for (const [k, p] of engineCut) {
      const b = browserCut.get(k);
      assert.deepEqual(b.edges.map((e) => e.id), p.edgeIds, `${k} edges after the cut`);
      assert.equal(b.cost, p.cost, `${k} cost after the cut`);
    }
  });
}
