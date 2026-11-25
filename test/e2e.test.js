import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import { after, before, test } from 'node:test';

// Configure isolated test ports before importing PatchGuard modules
process.env.PORT = '18080';
process.env.STORE_PORT = '14100';

const { TARGET_DB_PATH, TARGET_SERVER_PATH, assertLocalTargetUrl } = await import('../src/config.js');
const { bootPatchGuard, shutdownPatchGuard } = await import('../src/server.js');
const { auditZeroSecrets } = await import('../src/sprite-runtime.js');
const { computeDbHash, resetSeedDb } = await import('../target-store/db.js');

const BASE_URL = 'http://127.0.0.1:18080';
let initialVulnerableServer = '';

async function postJson(route, body = {}) {
  const res = await fetch(`${BASE_URL}${route}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return { status: res.status, data };
}

async function getJson(route) {
  const res = await fetch(`${BASE_URL}${route}`);
  const data = await res.json();
  return { status: res.status, data };
}

before(async () => {
  initialVulnerableServer = fs.readFileSync(TARGET_SERVER_PATH, 'utf8');
  resetSeedDb(TARGET_DB_PATH);
  await bootPatchGuard(18080);
});

after(async () => {
  try {
    await postJson('/api/reset-demo', {});
  } catch {}
  if (initialVulnerableServer) {
    fs.writeFileSync(TARGET_SERVER_PATH, initialVulnerableServer, 'utf8');
  }
  resetSeedDb(TARGET_DB_PATH);
  await shutdownPatchGuard();
});

test('1. Enforces strict loopback-only QA target safety invariant', () => {
  assert.equal(assertLocalTargetUrl('http://127.0.0.1:14100/'), 'http://127.0.0.1:14100');
  assert.equal(assertLocalTargetUrl('http://localhost:4100'), 'http://localhost:4100');
  assert.throws(() => assertLocalTargetUrl('https://example.com'), /Safety invariant violation/);
  assert.throws(() => assertLocalTargetUrl('http://192.168.1.10:3000'), /Safety invariant violation/);
  assert.throws(() => assertLocalTargetUrl('not-a-url'), /Invalid target URL/);
});

test('2. Mission Control & PixelMart reverse proxy serve HTTP 200', async () => {
  const health = await getJson('/api/health');
  assert.equal(health.status, 200);
  assert.equal(health.data.ok, true);
  assert.equal(health.data.storeHealthy, true);
  assert.ok(health.data.dbHash);

  const stateRes = await getJson('/api/state');
  assert.equal(stateRes.status, 200);
  assert.equal(stateRes.data.store.isPatched, false);

  const uiRes = await fetch(`${BASE_URL}/`);
  assert.equal(uiRes.status, 200);
  assert.match(await uiRes.text(), /PatchGuard/);

  const storeProxyRes = await fetch(`${BASE_URL}/pixelmart/`);
  assert.equal(storeProxyRes.status, 200);
  assert.match(await storeProxyRes.text(), /PixelMart/);
});

test('3. Full Self-Heal Loop: Checkpoint -> Chromium Before QA (5 fails) -> Restore (hash match) -> Patch -> Chromium After QA (6/6 pass)', async () => {
  const baselineHash = computeDbHash(TARGET_DB_PATH);
  assert.ok(baselineHash);

  // Step A: Create baseline checkpoint
  const cpRes = await postJson('/api/checkpoints/create', { comment: 'test-baseline' });
  assert.equal(cpRes.status, 200);
  assert.equal(cpRes.data.ok, true);
  const cpId = cpRes.data.checkpoint.id;

  // Step B: Run real headless Chromium QA against vulnerable PixelMart
  const runId = `test-run-${Date.now()}`;
  const beforeRes = await postJson('/api/qa/run', { runId, phase: 'before' });
  assert.equal(beforeRes.status, 200);
  const before = beforeRes.data.report;

  assert.equal(before.totalChecks, 6);
  assert.equal(before.failedCount, 5);
  assert.equal(before.passedCount, 1);
  assert.equal(before.revenueLeakCents, 129899);
  assert.notEqual(before.dbHashAfter, baselineHash, 'Exploit checks must mutate SQLite DB');

  const checkById = new Map(before.checks.map((c) => [c.id, c]));
  assert.equal(checkById.get('CHECK-01').passed, false);
  assert.equal(checkById.get('CHECK-02').passed, false);
  assert.equal(checkById.get('CHECK-03').passed, false);
  assert.equal(checkById.get('CHECK-04').passed, false);
  assert.equal(checkById.get('CHECK-05').passed, false);
  assert.equal(checkById.get('CHECK-06').passed, true);

  for (const c of before.checks) {
    assert.ok(fs.existsSync(c.screenshotPath), `Missing Before PNG: ${c.screenshotPath}`);
    assert.ok(fs.statSync(c.screenshotPath).size > 5000, `Empty Before PNG: ${c.screenshotPath}`);
  }

  // Step C: Restore baseline snapshot and verify exact SHA-256 DB rollback
  const restoreRes = await postJson('/api/checkpoints/restore', { checkpointId: cpId });
  assert.equal(restoreRes.status, 200);
  assert.equal(restoreRes.data.restored, true);
  assert.equal(restoreRes.data.dbHash, baselineHash, 'Restored DB SHA-256 must exactly match baseline');

  // Step D: Apply defensive security patch & auto-verify 6/6 in Chromium
  const patchRes = await postJson('/api/patch/apply', { runId, autoVerify: true });
  assert.equal(patchRes.status, 200);
  assert.equal(patchRes.data.ok, true);
  assert.ok(patchRes.data.patch.lineStats.added > 0);
  assert.match(patchRes.data.patch.unifiedDiff, /\+.*role !== 'admin'/);

  // Syntax check patched file with Node
  execFileSync('node', ['--check', TARGET_SERVER_PATH], { stdio: 'pipe' });

  const after = patchRes.data.afterReport;
  assert.equal(after.totalChecks, 6);
  assert.equal(after.passedCount, 6);
  assert.equal(after.failedCount, 0);
  assert.equal(after.revenueLeakCents, 0);

  for (const c of after.checks) {
    assert.equal(c.passed, true, `Expected ${c.id} to pass after patch: ${c.evidence}`);
    assert.ok(fs.existsSync(c.screenshotPath), `Missing After PNG: ${c.screenshotPath}`);
    assert.ok(fs.statSync(c.screenshotPath).size > 5000, `Empty After PNG: ${c.screenshotPath}`);
  }

  // Step E: Verify checkpoint list & diff API
  const cpList = await getJson('/api/checkpoints');
  assert.equal(cpList.status, 200);
  assert.ok(cpList.data.checkpoints.length >= 1);

  const cpDiff = await getJson(`/api/checkpoints/${encodeURIComponent(cpId)}/diff`);
  assert.equal(cpDiff.status, 200);
  assert.equal(cpDiff.data.available, true);
  assert.equal(cpDiff.data.identical, false);
});

test('4. Zero-Secret audit finds zero leaked raw tokens in process env', () => {
  const audit = auditZeroSecrets();
  assert.equal(typeof audit.totalEnvVars, 'number');
  assert.equal(audit.sensitiveEnvKeys.length, 0, `Unexpected sensitive keys: ${audit.sensitiveEnvKeys.join(', ')}`);
  assert.equal(audit.secretFilesFound.length, 0);
  assert.equal(audit.zeroSecretsVerified, true);
});
