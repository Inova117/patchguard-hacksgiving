import crypto from 'node:crypto';
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
import { auditPublicRepo, healPublicRepo } from './repo-sandbox.js';
import {
  auditZeroSecrets,
  createCheckpoint,
  diffAgainstCheckpoint,
  getRuntimeInfo,
  listCheckpoints,
  restoreCheckpoint,
} from './sprite-runtime.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BOOT_ID = crypto.randomUUID();
const app = express();
app.use(express.json({ limit: '5mb' }));

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
  latestRepoAudit: null,
  latestRepoHeal: null,
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
    bootId: BOOT_ID,
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
    res.json({ ok: true, previousBootId: BOOT_ID, ...result });
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
    const previousError = req.body?.previousError || null;
    state.latestRunId = runId;

    emitLog('info', 'Generating defensive security patch (Zero-Secret LLM Connector / verifier)...');
    let patch = await applyPatch({
      qaReport: state.beforeReport,
      previousError,
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
        emitLog('warn', `Self-heal round 2: feeding ${afterReport.failedCount} remaining failures back to LLM Connector (${failedDesc})`);
        patch = await applyPatch({
          qaReport: afterReport,
          previousError: failedDesc,
          hooks: { stopStore, startStore },
        });
        afterReport = await runQaSuite({ storeUrl: STORE_URL, runId, phase: 'after' });

        if (afterReport.failedCount > 0 && patch.source !== 'local-deterministic-verifier') {
          const remainingDesc = afterReport.checks
            .filter((c) => !c.passed)
            .map((c) => `${c.id}: ${c.evidence}`)
            .join('; ');
          emitLog('warn', `Self-heal fallback: applying deterministic verified patch for (${remainingDesc})`);
          patch = await applyPatch({
            qaReport: afterReport,
            previousError: remainingDesc,
            forceReference: true,
            hooks: { stopStore, startStore },
          });
          afterReport = await runQaSuite({ storeUrl: STORE_URL, runId, phase: 'after' });
        }
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
    emitLog('info', `Starting FULL real-repo audit on ${repoUrl}...`);
    const audit = await auditPublicRepo(repoUrl, {
      onProgress: (msg) => emitLog('info', `[REPO] ${msg}`),
    });
    state.latestRepoAudit = audit;
    state.latestRepoHeal = null;
    emitLog(
      'success',
      `Audited ${audit.fullName} (${audit.framework}): ${audit.filesScanned} files, ${audit.cveAudit.total} CVEs, ${audit.staticFindingsCount} static, liveHeaders=${audit.liveBrowser?.headersPassed}`
    );
    res.json(audit);
  } catch (err) {
    emitLog('error', `Repo audit failed: ${err.message}`);
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/repo/heal', async (req, res) => {
  try {
    const repoUrl = String(req.body?.repoUrl || '').trim();
    emitLog('info', `Starting Zero-Secret LLM Self-Heal on real repo ${repoUrl}...`);
    const heal = await healPublicRepo({
      repoUrl,
      previousAudit: state.latestRepoAudit?.fullName && repoUrl.includes(state.latestRepoAudit.fullName)
        ? state.latestRepoAudit
        : null,
      onProgress: (msg) => emitLog('info', `[HEAL] ${msg}`),
    });
    state.latestRepoHeal = heal;
    emitLog(
      'success',
      `Healed ${heal.fullName} via ${heal.llm.source} (${heal.llm.model}, ${heal.llm.latencyMs}ms): touched ${heal.touchedFiles.join(', ')}, afterMissingHeaders=${heal.after.missingHeaders.length}`
    );
    res.json(heal);
  } catch (err) {
    emitLog('error', `Repo self-heal failed: ${err.message}`);
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/repo/pr', async (req, res) => {
  try {
    const heal = state.latestRepoHeal;
    if (!heal || !heal.committedFiles?.length) {
      return res.status(400).json({ ok: false, error: 'Run "AI Self-Heal" on a real repo before opening a PR' });
    }
    const runId = `repo-${Date.now()}`;
    const branchName = req.body?.branchName || `patchguard/harden-${Date.now()}`;
    const body = `## PatchGuard Real-Repo Autonomous Self-Heal (\`${heal.fullName}\`)

Audited, patched, built, and re-verified live inside a **Fly.io Sprite** using **Playwright Chromium** and **Zero-Secret Connectors**.

- **LLM Connector:** \`${heal.llm.source}\` (\`${heal.llm.model}\`, \`${heal.llm.latencyMs}ms\`)
- **Files Patched:** ${heal.touchedFiles.map((f) => `\`${f}\``).join(', ')}
- **Live Missing Security Headers:** \`${heal.before.missingHeaders.length}\` → **\`${heal.after.missingHeaders.length}\`**
- **Build Verification:** \`${heal.after.buildAndTest?.build ? (heal.after.buildAndTest.build.ok ? 'PASS' : 'FAIL') : 'N/A'}\`
- **Zero-Secret Attestation:** \`${auditZeroSecrets().attestation}\`

### Summary
${heal.llm.summary}

<details>
<summary>Verified Git Diff</summary>

\`\`\`diff
${heal.gitDiff.slice(0, 6000)}
\`\`\`

</details>
`;
    const pr = await openVerifiedPullRequest({
      owner: heal.owner,
      repo: heal.repo,
      runId,
      branchName,
      files: heal.committedFiles,
      unifiedDiff: heal.gitDiff,
      prTitle: `fix(security): PatchGuard verified hardening (${heal.touchedFiles.join(', ')})`,
      prBodyMarkdown: body,
      zeroSecretAudit: auditZeroSecrets(),
    });
    state.latestPr = pr;
    emitLog('success', `Opened real PR #${pr.prNumber} on ${heal.fullName}: ${pr.prUrl}`);
    res.json(pr);
  } catch (err) {
    emitLog('warn', `Real repo PR failed: ${err.message}`);
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.post('/api/state/hydrate-before', (req, res) => {
  try {
    const { runId, beforeReport, restoreMs, screenshots } = req.body || {};
    if (!runId || !/^[\w-]+$/.test(String(runId))) {
      return res.status(400).json({ ok: false, error: 'Invalid runId' });
    }
    if (!beforeReport || typeof beforeReport !== 'object') {
      return res.status(400).json({ ok: false, error: 'Missing beforeReport' });
    }

    const beforeDir = path.join(ARTIFACTS_DIR, 'runs', String(runId), 'before');
    fs.mkdirSync(beforeDir, { recursive: true });

    let restoredFiles = 0;
    if (screenshots && typeof screenshots === 'object') {
      for (const [filename, b64] of Object.entries(screenshots)) {
        if (!/^[\w.-]+\.png$/.test(filename) || typeof b64 !== 'string') continue;
        const cleanB64 = b64.replace(/^data:image\/png;base64,/, '');
        fs.writeFileSync(path.join(beforeDir, filename), Buffer.from(cleanB64, 'base64'));
        restoredFiles += 1;
      }
    }

    state.latestRunId = String(runId);
    state.beforeReport = beforeReport;
    state.lastRestoreResult = {
      restored: true,
      mode: 'fly-sprite-cow',
      durationMs: Number.isFinite(Number(restoreMs)) ? Number(restoreMs) : state.lastRestoreResult?.durationMs ?? null,
    };

    emitLog(
      'success',
      `Hydrated pre-restore Before QA state (${runId}, ${restoredFiles} PNGs, restore=${state.lastRestoreResult.durationMs ?? '—'}ms)`
    );
    return res.json({ ok: true, restoredFiles });
  } catch (err) {
    emitLog('error', `State hydrate failed: ${err.message}`);
    return res.status(500).json({ ok: false, error: err.message });
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
