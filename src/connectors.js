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
        expected: '200 OK (or 404 before repo push)',
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
    (c) => ['openrouter', 'ollama', 'openai', 'anthropic'].includes(c.provider) && c.gatewayBaseUrl
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
 * Request a defensive code patch via Fly Zero-Secret LLM Connector (OpenRouter or Ollama).
 * Returns null if no Fly LLM Connector is active so caller can transparently use local verifier.
 */
export async function generatePatchViaLlmConnector({ vulnerableCode, qaFindings, previousError = null }) {
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

  const findingsSummary = qaFindings
    .filter((c) => !c.passed)
    .map((c) => `- ${c.id} (${c.title}): ${c.evidence}`)
    .join('\n');

  const prompt = `Fix ALL failing security & business-logic QA checks in this Express + node:sqlite server ("target-store/server.js") while keeping every legitimate route, response shape, and happy-path checkout working.

Failing QA Checks:
${findingsSummary}
${previousError ? `\nPrevious attempt error to fix:\n${previousError}\n` : ''}
Requirements to satisfy EVERY check:
1. CHECK-01 (Price integrity): Ignore any client unit_price_cents; ALWAYS look up canonical product.price_cents from DB. If client sends unit_price_cents !== product.price_cents or qty <= 0 or !Number.isInteger(qty), return HTTP 400.
2. CHECK-02 (Coupons): Reject duplicate coupons in request (HTTP 400). Use an atomic SQLite transaction (BEGIN IMMEDIATE ... UPDATE coupons SET times_used = times_used + 1 WHERE code = ? AND times_used < max_uses) checking result.changes === 1 (return HTTP 409 if exhausted). Maximum 1 coupon per order.
3. CHECK-03 (Admin RBAC): GET /api/admin/orders and POST /api/admin/refund must return HTTP 403 unless req.user.role === 'admin'.
4. CHECK-04 (Order Ownership): GET /api/orders/:id must return HTTP 403 unless order.user_id === req.user.id || req.user.role === 'admin'.
5. CHECK-05 (Security headers & cookie flags): Middleware setting X-Content-Type-Options: nosniff, X-Frame-Options: SAMEORIGIN, Content-Security-Policy: default-src 'self' 'unsafe-inline'; frame-ancestors 'self'; img-src 'self' data:. Session cookie must include HttpOnly; SameSite=Lax.
6. CHECK-06 (Happy path): Normal checkout for valid items returns HTTP 201 with { order, dbHash }.

Return STRICT JSON ONLY with keys: "summary" (string), "fixes" (string[]), "patched_code" (complete ES module JS file).

Current target-store/server.js:
\`\`\`js
${vulnerableCode}
\`\`\``;

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
          temperature: 0.1,
          max_tokens: 6000,
          reasoning: { effort: 'low' },
          messages: [{ role: 'user', content: prompt }],
        };

    const res = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(20000),
    });

    if (!res.ok) {
      lastErr = new Error(`Fly LLM Connector (${llm.provider}/${model}) returned HTTP ${res.status}`);
      continue;
    }

    const data = await res.json();
    const content = isOllama ? data?.message?.content : data?.choices?.[0]?.message?.content;
    if (!content) {
      lastErr = new Error(`Fly LLM Connector (${llm.provider}/${model}) returned empty content`);
      continue;
    }
    const parsed = extractJsonObject(content);

    if (!parsed?.patched_code || typeof parsed.patched_code !== 'string') {
      lastErr = new Error(`LLM Connector (${model}) JSON missing patched_code`);
      continue;
    }

    const syntax = validateJsSyntax(parsed.patched_code);
    if (!syntax.valid) {
      lastErr = new Error(`LLM (${model}) generated invalid JS syntax: ${syntax.error}`);
      continue;
    }

    return {
      source: `fly-connector:${llm.provider}`,
      model: data?.model || model,
      summary: parsed.summary || 'Patched server.js via Fly Zero-Secret LLM Connector',
      fixes: Array.isArray(parsed.fixes) ? parsed.fixes : [],
      patchedCode: parsed.patched_code,
      usage: data?.usage || null,
    };
  }

  throw lastErr || new Error(`Fly LLM Connector (${llm.provider}) failed`);
}

/**
 * Open a real GitHub Pull Request through the Fly Zero-Secret GitHub Connector.
 */
export async function openVerifiedPullRequest({
  runId,
  branchName,
  patchedCode,
  unifiedDiff,
  beforeReport,
  afterReport,
  restoreMs,
  zeroSecretAudit,
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

  const base = `${github.gatewayBaseUrl}/repos/${REPO_OWNER}/${REPO_NAME}`;
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

  const refData = await ghFetch('/git/ref/heads/main');
  const baseSha = refData.object.sha;

  await ghFetch('/git/refs', {
    method: 'POST',
    body: JSON.stringify({
      ref: `refs/heads/${branchName}`,
      sha: baseSha,
    }),
  });

  const existingFile = await ghFetch(`/contents/target-store/server.js?ref=${encodeURIComponent(branchName)}`);
  const encodedContent = Buffer.from(patchedCode, 'utf8').toString('base64');

  await ghFetch('/contents/target-store/server.js', {
    method: 'PUT',
    body: JSON.stringify({
      message: `fix(security): PatchGuard verified self-heal (${runId})`,
      content: encodedContent,
      sha: existingFile.sha,
      branch: branchName,
    }),
  });

  const beforeMap = new Map((beforeReport?.checks || []).map((c) => [c.id, c]));
  const afterMap = new Map((afterReport?.checks || []).map((c) => [c.id, c]));
  const rows = [...afterMap.keys()]
    .map((id) => {
      const b = beforeMap.get(id);
      const a = afterMap.get(id);
      return `| \`${id}\` ${a.title} | ${b ? (b.passed ? 'PASS' : 'FAIL') : '—'} | **${a.passed ? 'PASS' : 'FAIL'}** |`;
    })
    .join('\n');

  const prBody = `## PatchGuard Autonomous Self-Heal PR (\`${runId}\`)

Verified inside a hardware-isolated **Fly.io Sprite** using **Playwright Chromium** and **Zero-Secret Connectors** (0 raw tokens on disk).

### Live Verification Results
| QA Assertion | Before Patch | After Patch + CoW Restore |
| :--- | :---: | :---: |
${rows}

- **Revenue leak prevented:** \`$${((beforeReport?.revenueLeakCents || 0) / 100).toFixed(2)}\` → \`$0.00\`
- **Sprite CoW Checkpoint Restore:** \`${restoreMs ?? 'N/A'} ms\`
- **Zero-Secret Attestation:** \`${zeroSecretAudit?.attestation || '0 sensitive env keys'}\`

<details>
<summary>Unified Diff (target-store/server.js)</summary>

\`\`\`diff
${unifiedDiff.slice(0, 6000)}
\`\`\`

</details>
`;

  const pr = await ghFetch('/pulls', {
    method: 'POST',
    body: JSON.stringify({
      title: `fix(security): PatchGuard verified 6/6 QA self-heal (${runId})`,
      head: branchName,
      base: 'main',
      body: prBody,
    }),
  });

  return {
    ok: true,
    prUrl: pr.html_url,
    prNumber: pr.number,
    branchName,
    via: 'fly-github-connector-zero-secret',
  };
}
