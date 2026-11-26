import { execFile, spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { promisify } from 'node:util';
import { chromium } from 'playwright';
import { ARTIFACTS_DIR } from './config.js';
import { generateSurgicalEditsViaLlm } from './connectors.js';

const execFileAsync = promisify(execFile);
const SANDBOX_ROOT = path.join(ARTIFACTS_DIR, 'repos');

const STATIC_RULES = [
  {
    id: 'SEC-01',
    severity: 'high',
    title: 'Potential hardcoded secret or API key in source',
    regex: /(?:SECRET|API_KEY|SERVICE_ROLE_KEY|PRIVATE_KEY|ACCESS_TOKEN)\s*[:=]\s*['"`][A-Za-z0-9_\-.]{16,}['"`]/g,
  },
  {
    id: 'SEC-02',
    severity: 'high',
    title: 'Unsafe dynamic code execution (eval / new Function)',
    regex: /\b(eval|new Function)\s*\(/g,
  },
  {
    id: 'SEC-03',
    severity: 'high',
    title: 'Unsafe raw HTML injection (dangerouslySetInnerHTML / innerHTML)',
    regex: /(dangerouslySetInnerHTML|\.innerHTML\s*=)/g,
  },
  {
    id: 'SEC-04',
    severity: 'medium',
    title: 'Permissive wildcard CORS policy',
    regex: /Access-Control-Allow-Origin['"`:\s]+\*/g,
  },
  {
    id: 'SEC-05',
    severity: 'medium',
    title: 'Tabnabbing risk: target="_blank" without rel="noopener"',
    regex: /target=["']_blank["'](?![^>]*noopener)/g,
  },
  {
    id: 'SEC-06',
    severity: 'medium',
    title: 'Potential client-side price/amount trust in API handler',
    regex: /req\.body\.[a-zA-Z0-9_]*(price|total|amount|discount)/g,
  },
];

function parseGitHubRepoUrl(repoUrl) {
  let parsed;
  try {
    parsed = new URL(repoUrl);
  } catch {
    throw new Error('Invalid GitHub repository URL');
  }
  if (parsed.hostname !== 'github.com') {
    throw new Error('Only public https://github.com/<owner>/<repo> URLs are supported');
  }
  const parts = parsed.pathname.replace(/^\/|\.git$/g, '').split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new Error('Expected URL format: https://github.com/<owner>/<repo>');
  }
  return {
    owner: parts[0],
    repo: parts[1],
    slug: `${parts[0]}--${parts[1]}`.replace(/[^a-zA-Z0-9_-]/g, ''),
    cloneUrl: `https://github.com/${parts[0]}/${parts[1]}.git`,
  };
}

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => resolve(addr.port));
    });
    srv.on('error', reject);
  });
}

function walkSourceFiles(dir, acc = [], depth = 0) {
  if (depth > 5 || acc.length > 300) return acc;
  let entries = [];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (['node_modules', '.git', 'dist', 'build', '.next', 'coverage'].includes(e.name)) continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      walkSourceFiles(full, acc, depth + 1);
    } else if (/\.(js|mjs|cjs|ts|tsx|jsx|html|py)$/.test(e.name)) {
      acc.push(full);
    }
  }
  return acc;
}

function scanStaticFindings(repoDir) {
  const files = walkSourceFiles(repoDir);
  const findings = [];
  for (const file of files) {
    const rel = path.relative(repoDir, file);
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split('\n');
    for (const rule of STATIC_RULES) {
      lines.forEach((line, idx) => {
        if (rule.regex.test(line)) {
          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            title: rule.title,
            file: rel,
            line: idx + 1,
            snippet: line.trim().slice(0, 140),
          });
        }
        rule.regex.lastIndex = 0;
      });
    }
  }
  return { filesScanned: files.length, findings };
}

function detectStack(repoDir, pkg) {
  const deps = { ...(pkg?.dependencies || {}), ...(pkg?.devDependencies || {}) };
  const scripts = pkg?.scripts || {};
  if (deps.next) return { framework: 'next', scripts };
  if (deps.vite || fs.existsSync(path.join(repoDir, 'vite.config.ts')) || fs.existsSync(path.join(repoDir, 'vite.config.js'))) {
    return { framework: 'vite', scripts };
  }
  if (deps.express) return { framework: 'express', scripts };
  if (fs.existsSync(path.join(repoDir, 'requirements.txt')) || fs.existsSync(path.join(repoDir, 'pyproject.toml'))) {
    return { framework: 'python', scripts };
  }
  return { framework: pkg ? 'node' : 'static', scripts };
}

async function runNpmAudit(repoDir) {
  try {
    const { stdout } = await execFileAsync('npm', ['audit', '--json'], {
      cwd: repoDir,
      timeout: 25000,
    });
    return parseNpmAuditJson(stdout);
  } catch (err) {
    if (err.stdout) {
      return parseNpmAuditJson(err.stdout);
    }
    return { available: false, total: 0, severities: {}, topPackages: [] };
  }
}

function parseNpmAuditJson(raw) {
  try {
    const parsed = JSON.parse(raw);
    const meta = parsed?.metadata?.vulnerabilities || {};
    const vulns = parsed?.vulnerabilities || {};
    const topPackages = Object.entries(vulns)
      .slice(0, 10)
      .map(([name, info]) => ({
        name,
        severity: info.severity || 'unknown',
        fixAvailable: Boolean(info.fixAvailable),
      }));
    return {
      available: true,
      total: Number(meta.total || topPackages.length),
      severities: {
        critical: Number(meta.critical || 0),
        high: Number(meta.high || 0),
        moderate: Number(meta.moderate || 0),
        low: Number(meta.low || 0),
      },
      topPackages,
    };
  } catch {
    return { available: false, total: 0, severities: {}, topPackages: [] };
  }
}

async function runRepoBuildOrTest(repoDir, stack) {
  const scripts = stack.scripts || {};
  // Prefer non-watch unit tests if clearly configured, plus build check
  const results = { build: null, test: null };

  if (scripts.build && ['vite', 'express', 'node'].includes(stack.framework)) {
    const t0 = Date.now();
    try {
      await execFileAsync('npm', ['run', 'build'], {
        cwd: repoDir,
        timeout: 45000,
        env: { ...process.env, CI: 'true' },
      });
      results.build = { ok: true, durationMs: Date.now() - t0 };
    } catch (err) {
      results.build = {
        ok: false,
        durationMs: Date.now() - t0,
        error: String(err.stderr || err.stdout || err.message).slice(-500),
      };
    }
  }

  if (scripts.test && !/watch/i.test(scripts.test) && /vitest\s+run|node\s+--test|jest/i.test(scripts.test)) {
    const t0 = Date.now();
    try {
      const { stdout } = await execFileAsync('npm', ['test'], {
        cwd: repoDir,
        timeout: 45000,
        env: { ...process.env, CI: 'true' },
      });
      results.test = { ok: true, durationMs: Date.now() - t0, summary: stdout.trim().slice(-300) };
    } catch (err) {
      results.test = {
        ok: false,
        durationMs: Date.now() - t0,
        error: String(err.stderr || err.stdout || err.message).slice(-500),
      };
    }
  }

  return results;
}

async function waitForHttp(url, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(1200) });
      if (r.status > 0) return r;
    } catch {}
    await new Promise((r) => setTimeout(r, 250));
  }
  return null;
}

/**
 * Boot the real repo locally on 127.0.0.1:<freePort> and run real headless Chromium runtime & header audit.
 */
async function runLiveBrowserAuditOnRepo({ repoDir, stack, slug, phase = 'before' }) {
  if (!['vite', 'express', 'node'].includes(stack.framework)) {
    return { ran: false, reason: `Live auto-boot currently supports Vite/Express/Node (detected: ${stack.framework})` };
  }

  const port = await getFreePort();
  const baseUrl = `http://127.0.0.1:${port}`;
  let cmd = null;
  let args = [];

  if (stack.framework === 'vite') {
    const hasDist = fs.existsSync(path.join(repoDir, 'dist', 'index.html'));
    cmd = 'npx';
    args = hasDist
      ? ['vite', 'preview', '--host', '127.0.0.1', '--port', String(port), '--strictPort']
      : ['vite', '--host', '127.0.0.1', '--port', String(port), '--strictPort'];
  } else if (stack.scripts?.start) {
    cmd = 'npm';
    args = ['run', 'start'];
  } else {
    return { ran: false, reason: 'No runnable start/vite script found' };
  }

  const child = spawn(cmd, args, {
    cwd: repoDir,
    env: {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      PORT: String(port),
      HOST: '127.0.0.1',
      NODE_ENV: 'production',
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let bootLogs = '';
  child.stdout.on('data', (d) => { bootLogs += d.toString('utf8').slice(-400); });
  child.stderr.on('data', (d) => { bootLogs += d.toString('utf8').slice(-400); });

  const stopChild = () =>
    new Promise((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('exit', resolve);
      try { child.kill('SIGTERM'); } catch { resolve(); }
      setTimeout(() => { try { child.kill('SIGKILL'); } catch {} resolve(); }, 1200);
    });

  try {
    const initialRes = await waitForHttp(baseUrl, 16000);
    if (!initialRes) {
      return { ran: false, reason: `Server did not bind ${baseUrl} within 16s`, bootLogs: bootLogs.slice(-300) };
    }

    const headers = {
      xContentTypeOptions: initialRes.headers.get('x-content-type-options'),
      xFrameOptions: initialRes.headers.get('x-frame-options'),
      contentSecurityPolicy: initialRes.headers.get('content-security-policy'),
      referrerPolicy: initialRes.headers.get('referrer-policy'),
    };
    const missingHeaders = [];
    if (headers.xContentTypeOptions !== 'nosniff') missingHeaders.push('X-Content-Type-Options: nosniff');
    if (!headers.xFrameOptions) missingHeaders.push('X-Frame-Options: SAMEORIGIN');
    if (!headers.referrerPolicy) missingHeaders.push('Referrer-Policy: strict-origin-when-cross-origin');
    if (!headers.contentSecurityPolicy) missingHeaders.push('Content-Security-Policy');

    // Probe accidental exposure of sensitive dotfiles on loopback
    const envProbe = await fetch(`${baseUrl}/.env`).catch(() => null);
    const gitProbe = await fetch(`${baseUrl}/.git/config`).catch(() => null);
    const dotfileExposed =
      (envProbe?.status === 200 && (await envProbe.text()).includes('=')) ||
      (gitProbe?.status === 200 && (await gitProbe.text()).includes('[core]'));

    const shotDir = path.join(ARTIFACTS_DIR, 'runs', `repo-${slug}`);
    fs.mkdirSync(shotDir, { recursive: true });
    const shotFilename = `${phase}-live.png`;
    const shotPath = path.join(shotDir, shotFilename);

    const browser = await chromium.launch({ headless: true });
    const consoleErrors = [];
    const pageErrors = [];
    const failedRequests = [];
    let pageTitle = '';
    let bodyTextLength = 0;

    try {
      const page = await browser.newPage({ viewport: { width: 1280, height: 760 } });
      page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 180)); });
      page.on('pageerror', (e) => pageErrors.push(e.message.slice(0, 180)));
      page.on('response', (r) => {
        if (r.status() >= 400 && r.url().startsWith(baseUrl)) {
          failedRequests.push(`${r.status()} ${r.url().replace(baseUrl, '')}`);
        }
      });

      await page.goto(baseUrl, { waitUntil: 'networkidle', timeout: 15000 }).catch(() => {});
      await page.waitForTimeout(500);
      pageTitle = await page.title();
      bodyTextLength = await page.evaluate(() => (document.body?.innerText || '').trim().length);
      await page.screenshot({ path: shotPath, fullPage: false });
    } finally {
      await browser.close();
    }

    return {
      ran: true,
      url: baseUrl,
      httpStatus: initialRes.status,
      pageTitle,
      bodyTextLength,
      headers,
      missingHeaders,
      headersPassed: missingHeaders.length === 0,
      dotfileExposed: Boolean(dotfileExposed),
      consoleErrors,
      pageErrors,
      failedRequests,
      screenshotUrl: `/artifacts/runs/repo-${slug}/${shotFilename}`,
      screenshotPath: shotPath,
    };
  } finally {
    await stopChild();
  }
}

/**
 * Real Repo Full Audit: Clone -> Install -> npm audit (CVEs) -> Static Scan -> Build/Test -> Live Chromium Boot!
 */
export async function auditPublicRepo(repoUrl, { onProgress = () => {} } = {}) {
  const meta = parseGitHubRepoUrl(repoUrl);
  fs.mkdirSync(SANDBOX_ROOT, { recursive: true });
  const repoDir = path.join(SANDBOX_ROOT, meta.slug);

  if (fs.existsSync(repoDir)) {
    fs.rmSync(repoDir, { recursive: true, force: true });
  }

  onProgress(`Cloning ${meta.owner}/${meta.repo} into Sprite persistent disk...`);
  await execFileAsync('git', ['clone', '--depth', '1', meta.cloneUrl, repoDir], {
    timeout: 30000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  });

  const pkgPath = path.join(repoDir, 'package.json');
  const pkg = fs.existsSync(pkgPath) ? JSON.parse(fs.readFileSync(pkgPath, 'utf8')) : null;
  const stack = detectStack(repoDir, pkg);

  let installOk = false;
  if (pkg) {
    onProgress(`Installing dependencies for ${meta.owner}/${meta.repo} (${stack.framework})...`);
    try {
      await execFileAsync('npm', ['install', '--no-audit', '--no-fund', '--prefer-offline'], {
        cwd: repoDir,
        timeout: 90000,
        env: { ...process.env, CI: 'true' },
      });
      installOk = true;
    } catch (err) {
      onProgress(`npm install warning: ${err.message.slice(0, 120)}`);
    }
  }

  onProgress('Running real npm audit (CVE scan) and deep static security scan...');
  const [cveAudit, staticScan] = await Promise.all([
    pkg && installOk ? runNpmAudit(repoDir) : Promise.resolve({ available: false, total: 0, severities: {}, topPackages: [] }),
    Promise.resolve(scanStaticFindings(repoDir)),
  ]);

  let buildAndTest = { build: null, test: null };
  let liveBrowser = { ran: false, reason: 'Dependencies not installed' };

  if (pkg && installOk) {
    onProgress(`Building/testing ${meta.owner}/${meta.repo}...`);
    buildAndTest = await runRepoBuildOrTest(repoDir, stack);
    onProgress(`Booting real ${stack.framework} server on 127.0.0.1 and running Chromium Playwright audit...`);
    liveBrowser = await runLiveBrowserAuditOnRepo({
      repoDir,
      stack,
      slug: meta.slug,
      phase: 'before',
    });
  }

  const actionableFindings = [];
  if (liveBrowser.ran && liveBrowser.missingHeaders?.length) {
    actionableFindings.push(
      `Live HTTP server missing security headers: ${liveBrowser.missingHeaders.join(', ')}`
    );
  }
  if (liveBrowser.ran && liveBrowser.consoleErrors?.length) {
    actionableFindings.push(
      `Live Chromium runtime console errors (${liveBrowser.consoleErrors.length}): ${liveBrowser.consoleErrors[0]}`
    );
  }
  if (cveAudit.total > 0) {
    actionableFindings.push(
      `npm audit found ${cveAudit.total} dependency vulnerabilities (critical=${cveAudit.severities.critical}, high=${cveAudit.severities.high})`
    );
  }
  for (const f of staticScan.findings.slice(0, 6)) {
    actionableFindings.push(`${f.ruleId} [${f.severity}] ${f.file}:${f.line} — ${f.title}`);
  }

  return {
    ok: true,
    owner: meta.owner,
    repo: meta.repo,
    fullName: `${meta.owner}/${meta.repo}`,
    slug: meta.slug,
    repoDir,
    framework: stack.framework,
    installOk,
    filesScanned: staticScan.filesScanned,
    staticFindingsCount: staticScan.findings.length,
    staticFindings: staticScan.findings.slice(0, 25),
    cveAudit,
    buildAndTest,
    liveBrowser,
    actionableFindings,
  };
}

/**
 * Autonomous Real-Repo Self-Healer:
 * Uses REAL Fly Zero-Secret LLM Connector (surgical find/replace edits) -> applies -> rebuilds -> re-verifies in live Chromium!
 * Rolls back automatically via git checkout if a patch breaks build/tests.
 */
export async function healPublicRepo({ repoUrl, previousAudit = null, onProgress = () => {} }) {
  const meta = parseGitHubRepoUrl(repoUrl);
  const repoDir = path.join(SANDBOX_ROOT, meta.slug);

  let beforeAudit = previousAudit;
  if (!fs.existsSync(repoDir) || !beforeAudit) {
    beforeAudit = await auditPublicRepo(repoUrl, { onProgress });
  }

  const pkgPath = path.join(repoDir, 'package.json');
  const pkg = fs.existsSync(pkgPath) ? JSON.parse(fs.readFileSync(pkgPath, 'utf8')) : null;
  const stack = detectStack(repoDir, pkg);

  // Pick candidate real files to hand to the Zero-Secret LLM Connector
  const candidateRelPaths = [];
  for (const cfg of ['vite.config.ts', 'vite.config.js', 'vite.config.mjs', 'next.config.ts', 'next.config.mjs', 'next.config.js', 'server.js', 'src/server.js', 'index.html']) {
    if (fs.existsSync(path.join(repoDir, cfg))) {
      candidateRelPaths.push(cfg);
    }
  }
  for (const f of (beforeAudit.staticFindings || []).slice(0, 3)) {
    if (!candidateRelPaths.includes(f.file) && fs.existsSync(path.join(repoDir, f.file))) {
      candidateRelPaths.push(f.file);
    }
  }

  const filesContext = candidateRelPaths.slice(0, 4).map((rel) => ({
    path: rel,
    content: fs.readFileSync(path.join(repoDir, rel), 'utf8'),
  }));

  if (filesContext.length === 0) {
    throw new Error('No editable config or source files found in repository');
  }

  const targetFindings = [...(beforeAudit.actionableFindings || [])];
  if (stack.framework === 'vite' && beforeAudit.liveBrowser?.missingHeaders?.length) {
    targetFindings.unshift(
      `Add server.headers AND preview.headers to vite.config with EXACT keys: "X-Content-Type-Options": "nosniff", "X-Frame-Options": "SAMEORIGIN", "Referrer-Policy": "strict-origin-when-cross-origin", "Content-Security-Policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:" so Vite serves hardened security headers live.`
    );
  }

  onProgress(`Requesting surgical patch for ${meta.owner}/${meta.repo} from Fly Zero-Secret LLM Connector...`);
  let llmRes = await generateSurgicalEditsViaLlm({
    repoName: `${meta.owner}/${meta.repo} (${stack.framework})`,
    findings: targetFindings,
    filesContext,
  });

  if (!llmRes) {
    throw new Error('No active Fly Zero-Secret LLM Connector discovered. Run inside Fly Sprite with OpenRouter/Ollama Connector.');
  }

  const applyEditsToRepo = (edits) => {
    const touched = new Set();
    for (const edit of edits) {
      if (!edit?.file || !edit?.find || typeof edit.replace !== 'string') continue;
      const targetPath = path.resolve(repoDir, edit.file);
      if (!targetPath.startsWith(repoDir) || !fs.existsSync(targetPath)) continue;
      const current = fs.readFileSync(targetPath, 'utf8');
      if (current.includes(edit.find)) {
        fs.writeFileSync(targetPath, current.replace(edit.find, edit.replace), 'utf8');
        touched.add(edit.file);
      }
    }
    return [...touched];
  };

  let touchedFiles = applyEditsToRepo(llmRes.edits);
  if (touchedFiles.length === 0) {
    throw new Error(`Zero-Secret LLM (${llmRes.model}) returned edits that did not match verbatim strings in repo files`);
  }

  onProgress(`Applied ${touchedFiles.length} file edit(s) from ${llmRes.model} (${llmRes.latencyMs}ms). Re-verifying build & live Chromium...`);

  let afterBuildAndTest = await runRepoBuildOrTest(repoDir, stack);

  // Self-heal retry if LLM patch broke build or tests!
  if ((afterBuildAndTest.build && !afterBuildAndTest.build.ok) || (afterBuildAndTest.test && !afterBuildAndTest.test.ok)) {
    const errText = afterBuildAndTest.build?.error || afterBuildAndTest.test?.error || 'Build failed';
    onProgress(`Patch broke build/tests — rolling back cleanly and running LLM refinement round 2...`);
    await execFileAsync('git', ['checkout', '--', '.'], { cwd: repoDir });

    llmRes = await generateSurgicalEditsViaLlm({
      repoName: `${meta.owner}/${meta.repo} (${stack.framework})`,
      findings: targetFindings,
      filesContext,
      previousError: errText,
    });
    touchedFiles = applyEditsToRepo(llmRes.edits);
    afterBuildAndTest = await runRepoBuildOrTest(repoDir, stack);
  }

  const afterStatic = scanStaticFindings(repoDir);
  const afterLiveBrowser = await runLiveBrowserAuditOnRepo({
    repoDir,
    stack,
    slug: meta.slug,
    phase: 'after',
  });

  const { stdout: gitDiff } = await execFileAsync('git', ['diff'], { cwd: repoDir });
  const committedFiles = touchedFiles.map((rel) => ({
    path: rel,
    content: fs.readFileSync(path.join(repoDir, rel), 'utf8'),
  }));

  return {
    ok: true,
    owner: meta.owner,
    repo: meta.repo,
    fullName: `${meta.owner}/${meta.repo}`,
    framework: stack.framework,
    llm: {
      source: llmRes.source,
      model: llmRes.model,
      latencyMs: llmRes.latencyMs,
      summary: llmRes.summary,
      fixes: llmRes.fixes,
      usage: llmRes.usage,
    },
    touchedFiles,
    committedFiles,
    gitDiff,
    before: {
      staticFindingsCount: beforeAudit.staticFindingsCount,
      missingHeaders: beforeAudit.liveBrowser?.missingHeaders || [],
      screenshotUrl: beforeAudit.liveBrowser?.screenshotUrl || null,
    },
    after: {
      staticFindingsCount: afterStatic.findings.length,
      buildAndTest: afterBuildAndTest,
      liveBrowser: afterLiveBrowser,
      missingHeaders: afterLiveBrowser?.missingHeaders || [],
      screenshotUrl: afterLiveBrowser?.screenshotUrl || null,
    },
  };
}
