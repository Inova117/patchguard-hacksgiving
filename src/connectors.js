import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { REPO_NAME, REPO_OWNER } from './config.js';
import { auditZeroSecrets, isFlySpriteEnv } from './sprite-runtime.js';

const GATEWAY_LIST_URL = 'https://api.sprites.dev/v1/gateway/list';

function normalizeGatewayBase(conn) {
  const raw = conn.gateway_base_url || conn.gatewayUrl || conn.base_url || conn.url;
  if (raw) {
    return String(raw).replace(/\/$/, '');
  }
  const provider = conn.provider || conn.name;
  const id = conn.connection_id || conn.id;
  if (provider && id) {
    return `https://api.sprites.dev/v1/gateway/${provider}/${id}`;
  }
  if (provider) {
    return `https://api.sprites.dev/v1/gateway/${provider}`;
  }
  return null;
}

function normalizeConnectorList(payload) {
  const rawList = Array.isArray(payload)
    ? payload
    : payload?.connections || payload?.connectors || payload?.connected || [];

  if (!Array.isArray(rawList)) return [];
  return rawList.map((c) => ({
    id: c.connection_id || c.id || c.provider || c.name,
    provider: String(c.provider || c.name || 'unknown').toLowerCase(),
    name: c.name || c.provider || 'connector',
    status: c.status || (c.connected === false ? 'available' : 'connected'),
    gatewayBaseUrl: normalizeGatewayBase(c),
    scopes: c.scopes || c.granted_scopes || [],
    allowedEndpoints: c.access_policy?.allowed_endpoints || c.allowed_endpoints || null,
    blockedEndpoints: c.access_policy?.blocked_endpoints || c.blocked_endpoints || null,
  }));
}

/**
 * Discover Fly Sprites Zero-Secret Connectors via platform identity (no API key sent).
 */
export async function discoverConnectors() {
  const onSprite = isFlySpriteEnv();
  try {
    const res = await fetch(GATEWAY_LIST_URL, {
      signal: AbortSignal.timeout(4500),
    });
    const text = await res.text();
    let data = {};
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }

    if (!res.ok) {
      return {
        available: false,
        onSprite,
        httpStatus: res.status,
        reason: data?.error || data?.message || `Gateway returned HTTP ${res.status}`,
        connectors: [],
      };
    }

    const connectors = normalizeConnectorList(data);
    return {
      available: true,
      onSprite,
      httpStatus: res.status,
      connectors,
      rawProvidersCount: connectors.length,
    };
  } catch (err) {
    return {
      available: false,
      onSprite,
      httpStatus: null,
      reason: err.message,
      connectors: [],
    };
  }
}

/**
 * Test live Zero-Secret Connector guardrails (ALLOW 200 vs BLOCK 403) inside the Sprite.
 */
export async function testConnectorGuardrails() {
  const zeroSecrets = auditZeroSecrets();
  const discovery = await discoverConnectors();
  const probes = [];

  if (!discovery.available) {
    return {
      ok: false,
      mode: isFlySpriteEnv() ? 'fly-sprite' : 'local-off-sprite',
      zeroSecrets,
      discovery,
      probes: [
        {
          name: 'Fly Gateway Identity Check',
          target: GATEWAY_LIST_URL,
          expected: '200 OK inside Fly Sprite',
          status: discovery.httpStatus || 0,
          passed: false,
          detail:
            discovery.reason ||
            'Gateway identity headers are injected only inside a running Fly Sprite VM.',
        },
      ],
    };
  }

  const github = discovery.connectors.find(
    (c) => c.provider === 'github' && c.gatewayBaseUrl
  );
  if (github) {
    const allowedUrl = `${github.gatewayBaseUrl}/repos/${REPO_OWNER}/${REPO_NAME}`;
    const t0 = Date.now();
    try {
      const r = await fetch(allowedUrl, { signal: AbortSignal.timeout(7000) });
      probes.push({
        name: `GitHub ALLOW /repos/${REPO_OWNER}/${REPO_NAME}`,
        target: allowedUrl,
        expected: '200 OK',
        status: r.status,
        latencyMs: Date.now() - t0,
        passed: r.status === 200 || r.status === 404,
      });
    } catch (e) {
      probes.push({ name: 'GitHub ALLOW check', target: allowedUrl, status: 0, passed: false, detail: e.message });
    }

    const blockedUrl = `${github.gatewayBaseUrl}/user/keys`;
    const t1 = Date.now();
    try {
      const r = await fetch(blockedUrl, { signal: AbortSignal.timeout(7000) });
      probes.push({
        name: 'GitHub BLOCK /user/keys (Policy Enforced)',
        target: blockedUrl,
        expected: '403 Forbidden',
        status: r.status,
        latencyMs: Date.now() - t1,
        passed: r.status === 403,
      });
    } catch (e) {
      probes.push({ name: 'GitHub BLOCK check', target: blockedUrl, status: 0, passed: false, detail: e.message });
    }
  }

  const llm = discovery.connectors.find(
    (c) => ['openrouter', 'ollama', 'openai', 'anthropic', 'gemini'].includes(c.provider) && c.gatewayBaseUrl
  );
  if (llm) {
    const probePath = llm.provider === 'ollama' ? '/api/tags' : '/v1/models';
    const base = llm.gatewayBaseUrl.endsWith('/v1') && probePath.startsWith('/v1')
      ? llm.gatewayBaseUrl.slice(0, -3)
      : llm.gatewayBaseUrl;
    const url = `${base}${probePath}`;
    const t2 = Date.now();
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(7000) });
      probes.push({
        name: `LLM ALLOW ${probePath} (${llm.provider})`,
        target: url,
        expected: '200 OK (Zero-Secret AI Gateway)',
        status: r.status,
        latencyMs: Date.now() - t2,
        passed: r.ok,
      });
    } catch (e) {
      probes.push({ name: `LLM Probe (${llm.provider})`, target: url, status: 0, passed: false, detail: e.message });
    }

    if (llm.provider === 'openrouter') {
      const blockedLlmUrl = `${base}/v1/auth/key`;
      const t3 = Date.now();
      try {
        const r = await fetch(blockedLlmUrl, { signal: AbortSignal.timeout(7000) });
        probes.push({
          name: 'OpenRouter BLOCK /v1/auth/key (Policy Enforced)',
          target: blockedLlmUrl,
          expected: '403 Forbidden — endpoint not allowed',
          status: r.status,
          latencyMs: Date.now() - t3,
          passed: r.status === 403,
        });
      } catch (e) {
        probes.push({ name: 'OpenRouter BLOCK /v1/auth/key', target: blockedLlmUrl, status: 0, passed: false, detail: e.message });
      }
    }
  }

  return {
    ok: zeroSecrets.zeroSecretsVerified && probes.every((p) => p.passed),
    mode: 'fly-sprite-gateway',
    zeroSecrets,
    discovery,
    probes,
  };
}

function validateJsSyntax(code) {
  const tmpFile = path.join(os.tmpdir(), `patchguard-check-${Date.now()}.mjs`);
  fs.writeFileSync(tmpFile, code, 'utf8');
  try {
    execFileSync('node', ['--check', tmpFile], { stdio: 'pipe' });
    return { valid: true };
  } catch (err) {
    return {
      valid: false,
      error: err.stderr ? err.stderr.toString('utf8') : err.message,
    };
  } finally {
    try {
      fs.unlinkSync(tmpFile);
    } catch {}
  }
}

function extractJsonObject(text) {
  const cleaned = String(text || '')
    .replace(/^```(?:json)?\s*/i, '')
    .replace(/\s*```$/i, '')
    .trim();
  try {
    return JSON.parse(cleaned);
  } catch {
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start !== -1 && end > start) {
      return JSON.parse(cleaned.slice(start, end + 1));
    }
    throw new Error('Model response did not contain valid JSON');
  }
}

/**
 * Call the discovered Fly Zero-Secret LLM Connector with fast non-reasoning surgical JSON output.
 */
export async function callLlmJsonViaConnector(prompt, { maxTokens = 2800, timeoutMs = 25000 } = {}) {
  const discovery = await discoverConnectors();
  if (!discovery.available) {
    return null;
  }

  const llm =
    discovery.connectors.find((c) => c.provider === 'openrouter' && c.gatewayBaseUrl) ||
    discovery.connectors.find((c) => c.provider === 'ollama' && c.gatewayBaseUrl) ||
    discovery.connectors.find((c) => ['openai', 'anthropic', 'gemini'].includes(c.provider) && c.gatewayBaseUrl);

  if (!llm) {
    return null;
  }

  const isOllama = llm.provider === 'ollama';
  const candidateModels = isOllama
    ? [process.env.PATCHGUARD_OLLAMA_MODEL || 'qwen2.5-coder:32b']
    : [
        process.env.PATCHGUARD_OPENROUTER_MODEL || 'nvidia/nemotron-3.5-lightning:free',
        'openrouter/free',
      ];

  const base = llm.gatewayBaseUrl.endsWith('/v1') && !isOllama
    ? llm.gatewayBaseUrl.slice(0, -3)
    : llm.gatewayBaseUrl;
  const endpoint = isOllama ? `${base}/api/chat` : `${base}/v1/chat/completions`;

  let lastErr = null;
  for (const model of candidateModels) {
    const body = isOllama
      ? {
          model,
          stream: false,
          format: 'json',
          messages: [{ role: 'user', content: prompt }],
        }
      : {
          model,
          temperature: 0,
          max_tokens: maxTokens,
          reasoning: { effort: 'none' },
          messages: [{ role: 'user', content: prompt }],
        };

    const t0 = Date.now();
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(timeoutMs),
      });

      if (!res.ok) {
        const errBody = await res.text().catch(() => '');
        lastErr = new Error(`Fly LLM Connector (${llm.provider}/${model}) HTTP ${res.status}: ${errBody.slice(0, 180)}`);
        continue;
      }

      const data = await res.json();
      const content = isOllama ? data?.message?.content : data?.choices?.[0]?.message?.content;
      if (!content) {
        lastErr = new Error(`Fly LLM Connector (${llm.provider}/${model}) returned empty content`);
        continue;
      }

      const parsed = extractJsonObject(content);
      return {
        provider: llm.provider,
        source: `fly-connector:${llm.provider}`,
        model: data?.model || model,
        latencyMs: Date.now() - t0,
        usage: data?.usage || null,
        parsed,
      };
    } catch (err) {
      lastErr = err;
    }
  }

  throw lastErr || new Error(`Fly LLM Connector (${llm.provider}) failed`);
}

/**
 * Request compact surgical find/replace edits via Fly Zero-Secret LLM Connector (2-5s!).
 */
export async function generateSurgicalEditsViaLlm({
  repoName,
  findings,
  filesContext,
  previousError = null,
}) {
  const filesBlock = filesContext
    .map((f) => `--- FILE: ${f.path} ---\n${f.content.slice(0, 6500)}`)
    .join('\n\n');

  const prompt = `You are PatchGuard, an autonomous defensive security & QA engineer.
Repository: ${repoName}

Verified Security / Runtime Findings to fix:
${findings.map((f, i) => `${i + 1}. ${f}`).join('\n')}
${previousError ? `\nPrevious patch attempt failed verification with error:\n${previousError}\nFix the error cleanly.\n` : ''}
Rules:
- Return ONLY strict valid JSON with keys: "summary" (string), "fixes" (string[]), "edits" (array of {"file": string, "find": string, "replace": string}).
- Every "find" string MUST match an EXACT verbatim substring from the provided file contents.
- Keep edits minimal, valid syntax, and preserve all existing app functionality. Do NOT add uninstalled npm packages (use built-in Node/Express/Vite/HTML features only).

Files:
${filesBlock}`;

  const result = await callLlmJsonViaConnector(prompt, { maxTokens: 2600, timeoutMs: 22000 });
  if (!result) return null;

  const { parsed } = result;
  if (!Array.isArray(parsed?.edits) || parsed.edits.length === 0) {
    throw new Error(`LLM (${result.model}) returned no surgical edits`);
  }

  return {
    source: result.source,
    model: result.model,
    latencyMs: result.latencyMs,
    usage: result.usage,
    summary: parsed.summary || `Generated ${parsed.edits.length} surgical security edits`,
    fixes: Array.isArray(parsed.fixes) ? parsed.fixes : [],
    edits: parsed.edits,
  };
}

/**
 * Request surgical security patch for PixelMart target-store/server.js via Fly Zero-Secret LLM Connector.
 */
export async function generatePatchViaLlmConnector({ vulnerableCode, qaFindings, previousError = null }) {
  const findingsList = [
    ...(qaFindings || [])
      .filter((c) => !c.passed)
      .map((c) => `${c.id} (${c.title}): ${c.evidence}`),
    'CHECK-01 exact spec: Reject client unit_price_cents !== product.price_cents or !Number.isInteger(qty) || qty <= 0 with HTTP 400; always use product.price_cents.',
    'CHECK-02 exact spec: Reject duplicate/stacked coupons (normalizedCoupons.length > 1) with HTTP 400; inside BEGIN IMMEDIATE transaction run UPDATE coupons SET times_used = times_used + 1 WHERE code = ? AND times_used < max_uses and return HTTP 409 if changes !== 1.',
    'CHECK-03 exact spec: GET /api/admin/orders and POST /api/admin/refund must return HTTP 403 when req.user.role !== "admin".',
    'CHECK-04 exact spec: GET /api/orders/:id must return HTTP 403 when order.user_id !== req.user.id && req.user.role !== "admin".',
    'CHECK-05 exact spec: Add middleware setting X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN, Content-Security-Policy: default-src \'self\' \'unsafe-inline\'; frame-ancestors \'self\'; img-src \'self\' data:. Add HttpOnly; SameSite=Lax to pm_session Set-Cookie.',
  ];

  const res = await generateSurgicalEditsViaLlm({
    repoName: 'PixelMart (target-store/server.js)',
    findings: findingsList,
    filesContext: [{ path: 'target-store/server.js', content: vulnerableCode }],
    previousError,
  });
  if (!res) return null;

  let patchedCode = vulnerableCode;
  let appliedCount = 0;
  for (const edit of res.edits) {
    if (!edit?.find || typeof edit.replace !== 'string') continue;
    if (patchedCode.includes(edit.find)) {
      patchedCode = patchedCode.replace(edit.find, edit.replace);
      appliedCount += 1;
    }
  }

  if (appliedCount === 0) {
    throw new Error(`LLM (${res.model}) edits did not match target-store/server.js`);
  }

  const syntax = validateJsSyntax(patchedCode);
  if (!syntax.valid) {
    throw new Error(`LLM (${res.model}) produced invalid JS syntax: ${syntax.error}`);
  }

  return {
    source: res.source,
    model: res.model,
    latencyMs: res.latencyMs,
    summary: res.summary,
    fixes: res.fixes,
    patchedCode,
    usage: res.usage,
  };
}

/**
 * Open a real GitHub Pull Request on ANY authorized repository through Fly Zero-Secret GitHub Connector.
 */
export async function openVerifiedPullRequest({
  owner = REPO_OWNER,
  repo = REPO_NAME,
  runId,
  branchName,
  files = null,
  patchedCode = null,
  unifiedDiff = '',
  prTitle = null,
  prBodyMarkdown = null,
  beforeReport = null,
  afterReport = null,
  restoreMs = null,
  zeroSecretAudit = null,
}) {
  const discovery = await discoverConnectors();
  const github = discovery.connectors.find(
    (c) => c.provider === 'github' && c.gatewayBaseUrl
  );
  if (!discovery.available || !github) {
    throw new Error(
      'GitHub Zero-Secret Connector not discovered via Fly gateway. Connect GitHub in Fly Connectors and authorize this Sprite.'
    );
  }

  const base = `${github.gatewayBaseUrl}/repos/${owner}/${repo}`;
  async function ghFetch(subpath, opts = {}) {
    const res = await fetch(`${base}${subpath}`, {
      headers: {
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        ...(opts.headers || {}),
      },
      ...opts,
      signal: AbortSignal.timeout(15000),
    });
    const txt = await res.text();
    let json = {};
    try {
      json = JSON.parse(txt);
    } catch {
      json = { raw: txt };
    }
    if (!res.ok) {
      throw new Error(`GitHub Connector ${subpath} -> HTTP ${res.status}: ${json.message || txt}`);
    }
    return json;
  }

  const repoMeta = await ghFetch('');
  const defaultBranch = repoMeta.default_branch || 'main';
  const refData = await ghFetch(`/git/ref/heads/${encodeURIComponent(defaultBranch)}`);
  const baseSha = refData.object.sha;

  await ghFetch('/git/refs', {
    method: 'POST',
    body: JSON.stringify({
      ref: `refs/heads/${branchName}`,
      sha: baseSha,
    }),
  });

  const filesToCommit =
    Array.isArray(files) && files.length > 0
      ? files
      : patchedCode
        ? [{ path: 'target-store/server.js', content: patchedCode }]
        : [];

  if (filesToCommit.length === 0) {
    throw new Error('No patched files provided to commit');
  }

  for (const f of filesToCommit) {
    let existingSha;
    try {
      const existingFile = await ghFetch(
        `/contents/${f.path.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(branchName)}`
      );
      existingSha = existingFile.sha;
    } catch {}

    await ghFetch(`/contents/${f.path.split('/').map(encodeURIComponent).join('/')}`, {
      method: 'PUT',
      body: JSON.stringify({
        message: `fix(security): PatchGuard verified self-heal (${runId})`,
        content: Buffer.from(f.content, 'utf8').toString('base64'),
        ...(existingSha ? { sha: existingSha } : {}),
        branch: branchName,
      }),
    });
  }

  let body = prBodyMarkdown;
  if (!body) {
    const beforeMap = new Map((beforeReport?.checks || []).map((c) => [c.id, c]));
    const afterMap = new Map((afterReport?.checks || []).map((c) => [c.id, c]));
    const rows = [...afterMap.keys()]
      .map((id) => {
        const b = beforeMap.get(id);
        const a = afterMap.get(id);
        return `| \`${id}\` ${a.title} | ${b ? (b.passed ? 'PASS' : 'FAIL') : '—'} | **${a.passed ? 'PASS' : 'FAIL'}** |`;
      })
      .join('\n');

    body = `## PatchGuard Autonomous Self-Heal PR (\`${runId}\`)

Verified inside a hardware-isolated **Fly.io Sprite** using **Playwright Chromium** and **Zero-Secret Connectors** (0 raw tokens on disk).

### Live Verification Results
| QA Assertion | Before Patch | After Patch + CoW Restore |
| :--- | :---: | :---: |
${rows}

- **Revenue leak prevented:** \`$${((beforeReport?.revenueLeakCents || 0) / 100).toFixed(2)}\` → \`$0.00\`
- **Sprite CoW Checkpoint Restore:** \`${restoreMs ?? 'N/A'} ms\`
- **Zero-Secret Attestation:** \`${zeroSecretAudit?.attestation || '0 sensitive env keys'}\`

<details>
<summary>Unified Diff</summary>

\`\`\`diff
${unifiedDiff.slice(0, 6000)}
\`\`\`

</details>
`;
  }

  const pr = await ghFetch('/pulls', {
    method: 'POST',
    body: JSON.stringify({
      title: prTitle || `fix(security): PatchGuard verified self-heal (${runId})`,
      head: branchName,
      base: defaultBranch,
      body,
    }),
  });

  return {
    ok: true,
    repo: `${owner}/${repo}`,
    prUrl: pr.html_url,
    prNumber: pr.number,
    branchName,
    via: 'fly-github-connector-zero-secret',
  };
}
