import { spawn } from 'node:child_process';
import express from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeDbHash, resetSeedDb } from '../target-store/db.js';
import {
  ARTIFACTS_DIR,
  assertLocalTargetUrl,
  PORT,
  ROOT_DIR,
  SNAPSHOT_DIR,
  STORE_PORT,
  STORE_URL,
  TARGET_DB_PATH,
  TARGET_SERVER_PATH,
} from './config.js';
import {
  discoverConnectors,
  openVerifiedPullRequest,
  testConnectorGuardrails,
} from './connectors.js';
import { applyPatch } from './patcher.js';
import { runQaSuite } from './qa-engine.js';
import { auditPublicRepo } from './repo-sandbox.js';
import {
  auditZeroSecrets,
  createCheckpoint,
  diffAgainstCheckpoint,
  getRuntimeInfo,
  listCheckpoints,
  restoreCheckpoint,
} from './sprite-runtime.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: '1mb' }));

const sseClients = new Set();
let storeProc = null;

const state = {
  baselineDbHash: null,
  baselineCheckpointId: null,
  latestRunId: null,
  beforeReport: null,
  afterReport: null,
  latestPatch: null,
  latestGuardrailTest: null,
  latestPr: null,
  lastRestoreResult: null,
  logs: [],
};

function emitLog(level, message, data = null) {
  const entry = {
    ts: new Date().toISOString(),
    level,
    message,
    data,
  };
  state.logs.push(entry);
  if (state.logs.length > 250) {
    state.logs.shift();
  }
  const payload = `data: ${JSON.stringify(entry)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch {}
  }
}

async function waitForStoreHealth(timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(`${STORE_URL}/api/health`, { signal: AbortSignal.timeout(1000) });
      if (r.ok) {
        return await r.json();
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  throw new Error(`PixelMart target-store failed to become healthy on ${STORE_URL}`);
}

export async function stopStore() {
  if (!storeProc) return;
  const proc = storeProc;
  storeProc = null;
  await new Promise((resolve) => {
    let settled = false;
    const done = () => {
      if (!settled) {
        settled = true;
        resolve();
      }
    };
    proc.once('exit', done);
    try {
      proc.kill('SIGTERM');
    } catch {
      done();
    }
    setTimeout(() => {
      try {
        proc.kill('SIGKILL');
      } catch {}
      done();
    }, 1500);
  });
}

export async function startStore() {
  if (storeProc && !storeProc.killed && storeProc.exitCode === null) {
    try {
      await waitForStoreHealth(1500);
      return;
    } catch {
      await stopStore();
    }
  }

  if (!fs.existsSync(TARGET_DB_PATH)) {
    resetSeedDb(TARGET_DB_PATH);
  }

  storeProc = spawn(process.execPath, ['--no-warnings', TARGET_SERVER_PATH], {
    cwd: ROOT_DIR,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      NODE_ENV: process.env.NODE_ENV || 'production',
      STORE_PORT: String(STORE_PORT),
      STORE_DB_PATH: TARGET_DB_PATH,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  storeProc.stdout.on('data', (chunk) => {
    const msg = chunk.toString('utf8').trim();
    if (msg) emitLog('store', msg);
  });
  storeProc.stderr.on('data', (chunk) => {
    const msg = chunk.toString('utf8').trim();
    if (msg && !msg.includes('ExperimentalWarning')) emitLog('warn', msg);
  });

  await waitForStoreHealth();
  if (!state.baselineDbHash) {
    state.baselineDbHash = computeDbHash(TARGET_DB_PATH);
  }
}

function captureInitialVulnerableCopyIfPresent() {
  const initialDir = path.join(SNAPSHOT_DIR, '_initial_vulnerable');
  const initialServer = path.join(initialDir, 'server.js');
  if (!fs.existsSync(initialServer) && fs.existsSync(TARGET_SERVER_PATH)) {
    const content = fs.readFileSync(TARGET_SERVER_PATH, 'utf8');
    if (content.includes('BUG 1')) {
      fs.mkdirSync(initialDir, { recursive: true });
      fs.writeFileSync(initialServer, content, 'utf8');
    }
  }
}

// Static assets & artifacts
app.use('/artifacts', express.static(ARTIFACTS_DIR));
app.use('/', express.static(path.join(__dirname, 'public')));

// Reverse proxy /pixelmart -> 127.0.0.1:4100 so storefront is viewable directly on Sprite URL
app.use('/pixelmart', (req, res) => {
  if (req.originalUrl === '/pixelmart') {
    return res.redirect(302, '/pixelmart/');
  }
  const targetPath = req.url || '/';
  const proxyReq = http.request(
    {
      hostname: '127.0.0.1',
      port: STORE_PORT,
      path: targetPath,
      method: req.method,
      headers: {
        ...req.headers,
        host: `127.0.0.1:${STORE_PORT}`,
      },
    },
    (proxyRes) => {
      res.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
      proxyRes.pipe(res, { end: true });
    }
  );
  proxyReq.on('error', (err) => {
    if (!res.headersSent) {
      res.status(502).json({ error: 'Target store restarting', detail: err.message });
    }
  });
  if (req.readable && !['GET', 'HEAD'].includes(req.method) && req.body && Object.keys(req.body).length > 0) {
    const raw = JSON.stringify(req.body);
    proxyReq.setHeader('content-length', Buffer.byteLength(raw));
    proxyReq.write(raw);
    proxyReq.end();
  } else {
    req.pipe(proxyReq, { end: true });
  }
});

app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders?.();

  sseClients.add(res);
  res.write(`data: ${JSON.stringify({ ts: new Date().toISOString(), level: 'info', message: 'Connected to PatchGuard SSE stream' })}\n\n`);

  req.on('close', () => {
    sseClients.delete(res);
  });
});

app.get('/api/health', async (_req, res) => {
  let storeHealth = null;
  try {
    const r = await fetch(`${STORE_URL}/api/health`, { signal: AbortSignal.timeout(1200) });
    if (r.ok) storeHealth = await r.json();
  } catch {}
  res.json({
    ok: true,
    runtime: getRuntimeInfo(),
    storeHealthy: Boolean(storeHealth?.ok),
    storeUrl: STORE_URL,
    dbHash: storeHealth?.dbHash || computeDbHash(TARGET_DB_PATH),
    baselineDbHash: state.baselineDbHash,
    orderCount: storeHealth?.orderCount ?? null,
    activeRunId: state.latestRunId,
  });
});

app.get('/api/state', async (_req, res) => {
  const [connectors, checkpoints, health] = await Promise.all([
    discoverConnectors(),
    listCheckpoints(),
    fetch(`${STORE_URL}/api/health`, { signal: AbortSignal.timeout(1200) })
      .then((r) => (r.ok ? r.json() : null))
      .catch(() => null),
  ]);

  res.json({
    runtime: getRuntimeInfo(),
    zeroSecrets: auditZeroSecrets(),
    connectors,
    checkpoints,
    store: {
      url: STORE_URL,
      healthy: Boolean(health?.ok),
      dbHash: health?.dbHash || computeDbHash(TARGET_DB_PATH),
      baselineDbHash: state.baselineDbHash,
      orderCount: health?.orderCount ?? null,
      isPatched: !fs.readFileSync(TARGET_SERVER_PATH, 'utf8').includes('BUG 1'),
    },
    latestRunId: state.latestRunId,
    beforeReport: state.beforeReport,
    afterReport: state.afterReport,
    latestPatch: state.latestPatch,
    latestGuardrailTest: state.latestGuardrailTest,
    latestPr: state.latestPr,
    lastRestoreResult: state.lastRestoreResult,
    logs: state.logs.slice(-80),
  });
});

app.post('/api/checkpoints/create', async (req, res) => {
  try {
    const comment = req.body?.comment || `PatchGuard clean baseline (${new Date().toISOString()})`;
    emitLog('info', `Creating filesystem checkpoint: ${comment}`);
    const cp = await createCheckpoint(comment);
    if (!state.baselineCheckpointId || comment.toLowerCase().includes('baseline')) {
      state.baselineCheckpointId = cp.id;
    }
    emitLog('success', `Checkpoint ${cp.id} ready (${cp.durationMs}ms, mode=${cp.mode})`, cp);
    res.json({ ok: true, checkpoint: cp });
  } catch (err) {
    emitLog('error', `Checkpoint create failed: ${err.message}`);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/checkpoints', async (_req, res) => {
  try {
    res.json(await listCheckpoints());
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/checkpoints/:id/diff', async (req, res) => {
  try {
    const relPath = req.query.path ? String(req.query.path) : 'target-store/server.js';
    const diff = await diffAgainstCheckpoint(req.params.id, relPath);
    res.json(diff);
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/checkpoints/restore', async (req, res) => {
  try {
    const list = await listCheckpoints();
    const targetId = req.body?.checkpointId || state.baselineCheckpointId || list.baselineId;
    emitLog('warn', `Restoring filesystem to checkpoint ${targetId}...`);
    const result = await restoreCheckpoint(targetId, { stopStore, startStore });
    state.lastRestoreResult = result;
    if (!result.restoring) {
      emitLog('success', `Restored to ${targetId} in ${result.durationMs}ms (dbHash=${result.dbHash?.slice(0, 12)})`);
    } else {
      emitLog('warn', `Fly Sprite CoW restore initiated for ${targetId}; awaiting VM reconnect`);
    }
    res.json({ ok: true, ...result });
  } catch (err) {
    emitLog('error', `Checkpoint restore failed: ${err.message}`);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/qa/run', async (req, res) => {
  try {
    const phase = req.body?.phase === 'after' ? 'after' : 'before';
    const runId = req.body?.runId || state.latestRunId || `run-${Date.now()}`;
    const targetUrl = assertLocalTargetUrl(req.body?.targetUrl || STORE_URL);

    state.latestRunId = runId;
    emitLog('info', `Launching Playwright Chromium QA (${phase}) against ${targetUrl}`);

    const report = await runQaSuite({
      storeUrl: targetUrl,
      runId,
      phase,
      onProgress: (ev) => {
        if (ev.type === 'qa_check') {
          const c = ev.check;
          emitLog(c.passed ? 'success' : 'error', `[${phase.toUpperCase()}] ${c.id} ${c.title}: ${c.passed ? 'PASS' : 'FAIL'} — ${c.evidence}`);
        }
      },
    });

    if (phase === 'before') {
      state.beforeReport = report;
      state.afterReport = null;
    } else {
      state.afterReport = report;
    }
    emitLog('info', `Playwright QA (${phase}) finished: ${report.passedCount}/${report.totalChecks} passed in ${report.durationMs}ms`);
    res.json({ ok: true, report });
  } catch (err) {
    emitLog('error', `QA suite failed: ${err.message}`);
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/patch/apply', async (req, res) => {
  try {
    const runId = req.body?.runId || state.latestRunId || `run-${Date.now()}`;
    const autoVerify = req.body?.autoVerify !== false;
    state.latestRunId = runId;

    emitLog('info', 'Generating defensive security patch (Zero-Secret LLM Connector / verifier)...');
    let patch = await applyPatch({
      qaReport: state.beforeReport,
      hooks: { stopStore, startStore },
    });
    emitLog('success', `Patch applied via ${patch.source} (${patch.lineStats.added}+ / ${patch.lineStats.removed}- lines)`);

    let afterReport = null;
    if (autoVerify) {
      emitLog('info', 'Re-running Playwright Chromium QA verification suite after patch...');
      afterReport = await runQaSuite({
        storeUrl: STORE_URL,
        runId,
        phase: 'after',
        onProgress: (ev) => {
          if (ev.type === 'qa_check') {
            const c = ev.check;
            emitLog(c.passed ? 'success' : 'error', `[AFTER] ${c.id} ${c.title}: ${c.passed ? 'PASS' : 'FAIL'}`);
          }
        },
      });

      if (afterReport.failedCount > 0 && patch.source !== 'local-deterministic-verifier') {
        const failedDesc = afterReport.checks
          .filter((c) => !c.passed)
          .map((c) => `${c.id}: ${c.evidence}`)
          .join('; ');
        emitLog('warn', `Self-heal loop detected ${afterReport.failedCount} remaining failures; refining patch (${failedDesc})`);
        patch = await applyPatch({
          qaReport: afterReport,
          previousError: failedDesc,
          forceReference: true,
          hooks: { stopStore, startStore },
        });
        afterReport = await runQaSuite({ storeUrl: STORE_URL, runId, phase: 'after' });
      }
      state.afterReport = afterReport;
    }

    state.latestPatch = patch;
    res.json({ ok: true, patch, afterReport });
  } catch (err) {
    emitLog('error', `Patch apply failed: ${err.message}`);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/connectors/test-guardrails', async (_req, res) => {
  try {
    emitLog('info', 'Testing Fly Zero-Secret Connector guardrails (ALLOW 200 vs BLOCK 403)...');
    const result = await testConnectorGuardrails();
    state.latestGuardrailTest = result;
    emitLog(result.ok ? 'success' : 'warn', `Guardrail test finished: ok=${result.ok}, probes=${result.probes.length}`);
    res.json(result);
  } catch (err) {
    emitLog('error', `Guardrail test error: ${err.message}`);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/pr/open', async (req, res) => {
  try {
    if (!state.latestPatch?.patchedCode) {
      return res.status(400).json({ error: 'Apply and verify a patch before opening a Pull Request' });
    }
    const runId = state.latestRunId || `run-${Date.now()}`;
    const branchName = req.body?.branchName || `patchguard/fix-${Date.now()}`;
    emitLog('info', `Opening verified GitHub PR on branch ${branchName} via Fly Zero-Secret Connector...`);

    const pr = await openVerifiedPullRequest({
      runId,
      branchName,
      patchedCode: state.latestPatch.patchedCode,
      unifiedDiff: state.latestPatch.unifiedDiff,
      beforeReport: state.beforeReport,
      afterReport: state.afterReport,
      restoreMs: state.lastRestoreResult?.durationMs ?? null,
      zeroSecretAudit: auditZeroSecrets(),
    });
    state.latestPr = pr;
    emitLog('success', `Opened PR #${pr.prNumber}: ${pr.prUrl}`);
    res.json(pr);
  } catch (err) {
    emitLog('warn', `PR creation skipped/failed: ${err.message}`);
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/repo/audit', async (req, res) => {
  try {
    const repoUrl = String(req.body?.repoUrl || '').trim();
    emitLog('info', `Running sandboxed static hygiene audit on ${repoUrl}...`);
    const audit = await auditPublicRepo(repoUrl);
    emitLog('success', `Audited ${audit.repo}: ${audit.filesScanned} files, ${audit.findingsCount} findings`);
    res.json(audit);
  } catch (err) {
    emitLog('error', `Repo audit failed: ${err.message}`);
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/reset-demo', async (_req, res) => {
  try {
    emitLog('info', 'Resetting PixelMart store to clean vulnerable baseline...');
    await stopStore();

    const initialServer = path.join(SNAPSHOT_DIR, '_initial_vulnerable', 'server.js');
    if (fs.existsSync(initialServer)) {
      fs.copyFileSync(initialServer, TARGET_SERVER_PATH);
    }
    const cleanHash = resetSeedDb(TARGET_DB_PATH);
    state.baselineDbHash = cleanHash;
    state.beforeReport = null;
    state.afterReport = null;
    state.latestPatch = null;
    state.latestPr = null;
    state.lastRestoreResult = null;
    await startStore();

    emitLog('success', `Demo reset complete (dbHash=${cleanHash.slice(0, 12)})`);
    res.json({ ok: true, dbHash: cleanHash });
  } catch (err) {
    emitLog('error', `Reset failed: ${err.message}`);
    res.status(500).json({ ok: false, error: err.message });
  }
});

let httpServer = null;

export async function bootPatchGuard(listenPort = PORT) {
  captureInitialVulnerableCopyIfPresent();
  await startStore();
  return new Promise((resolve) => {
    httpServer = app.listen(listenPort, '0.0.0.0', () => {
      emitLog('success', `PatchGuard Mission Control listening on http://0.0.0.0:${listenPort}`);
      resolve({ app, server: httpServer, port: listenPort });
    });
  });
}

export async function shutdownPatchGuard() {
  for (const res of sseClients) {
    try {
      res.end();
    } catch {}
  }
  sseClients.clear();
  await stopStore();
  if (httpServer) {
    await new Promise((resolve) => httpServer.close(() => resolve()));
    httpServer = null;
  }
}

const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  bootPatchGuard(PORT).catch((err) => {
    console.error('[patchguard] fatal boot error:', err);
    process.exit(1);
  });

  const handleSig = async () => {
    await shutdownPatchGuard();
    process.exit(0);
  };
  process.on('SIGINT', handleSig);
  process.on('SIGTERM', handleSig);
}
