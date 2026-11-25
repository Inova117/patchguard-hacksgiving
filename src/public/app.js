const CHECK_DEFINITIONS = [
  { id: 'CHECK-01', title: 'Checkout Price-Tampering Guard', category: 'Business Logic' },
  { id: 'CHECK-02', title: 'Single-Use Coupon Stacking & Race Guard', category: 'Concurrency / Logic' },
  { id: 'CHECK-03', title: 'Admin Endpoint RBAC Guard', category: 'Access Control' },
  { id: 'CHECK-04', title: 'Order Ownership (IDOR) Guard', category: 'Access Control' },
  { id: 'CHECK-05', title: 'Security Headers & Cookie Hygiene', category: 'HTTP Hardening' },
  { id: 'CHECK-06', title: 'Legitimate Checkout Regression (Happy Path)', category: 'Functional Regression' },
];

const uiState = {
  data: null,
  busy: false,
};

async function api(url, opts = {}) {
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok && body.ok !== true) {
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return body;
}

function setStep(num, status, metaText) {
  const el = document.querySelector(`.step[data-step="${num}"]`);
  if (!el) return;
  el.classList.remove('active', 'done', 'fail');
  if (status) el.classList.add(status);
  const meta = document.getElementById(`step${num}Meta`);
  if (meta && metaText !== undefined) meta.textContent = metaText;
}

function appendLogLine(entry) {
  const term = document.getElementById('sseTerminal');
  const line = document.createElement('div');
  line.className = `log-line ${entry.level || 'info'}`;
  const time = (entry.ts || '').slice(11, 19);
  line.textContent = `[${time}] [${(entry.level || 'info').toUpperCase()}] ${entry.message}`;
  term.appendChild(line);
  term.scrollTop = term.scrollHeight;
}

function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

function renderDiff(diffText) {
  const el = document.getElementById('diffView');
  if (!diffText) {
    el.textContent = 'No patch generated yet.';
    return;
  }
  el.innerHTML = diffText
    .split('\n')
    .map((line) => {
      if (line.startsWith('+') && !line.startsWith('+++')) {
        return `<span class="diff-add">${escapeHtml(line)}</span>`;
      }
      if (line.startsWith('-') && !line.startsWith('---')) {
        return `<span class="diff-del">${escapeHtml(line)}</span>`;
      }
      if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) {
        return `<span class="diff-hdr">${escapeHtml(line)}</span>`;
      }
      return escapeHtml(line);
    })
    .join('\n');
}

function renderState(d) {
  uiState.data = d;

  const rt = d.runtime;
  const rtPill = document.getElementById('runtimePill');
  rtPill.textContent = rt.isFlySprite ? `Fly Sprite (${rt.hostname})` : `Local Sandbox (${rt.mode})`;
  rtPill.className = `pill ${rt.isFlySprite ? 'ok' : 'warn'}`;

  const dbPill = document.getElementById('dbPill');
  const hashShort = d.store?.dbHash ? d.store.dbHash.slice(0, 12) : '—';
  const dbDirty = d.store?.baselineDbHash && d.store?.dbHash !== d.store.baselineDbHash;
  dbPill.textContent = `DB ${hashShort}… ${dbDirty ? '(MODIFIED)' : '(CLEAN)'}`;
  dbPill.className = `pill ${dbDirty ? 'warn' : 'ok'}`;

  const secPill = document.getElementById('secretsPill');
  secPill.textContent = d.zeroSecrets?.zeroSecretsVerified
    ? 'Zero-Secret Verified (0 keys)'
    : `Secrets found: ${d.zeroSecrets?.sensitiveEnvKeys?.length || 0}`;
  secPill.className = `pill ${d.zeroSecrets?.zeroSecretsVerified ? 'ok' : 'danger'}`;
  document.getElementById('secretCountMetric').textContent = String(
    d.zeroSecrets?.sensitiveEnvKeys?.length || 0
  );

  const b = d.beforeReport;
  const a = d.afterReport;
  document.getElementById('passMetric').textContent = b && a
    ? `${b.passedCount}/6 → ${a.passedCount}/6`
    : b
      ? `${b.passedCount}/6 (Before)`
      : a
        ? `${a.passedCount}/6 (After)`
        : '— / 6';

  const leak = b ? (b.revenueLeakCents || 0) / 100 : 0;
  document.getElementById('leakMetric').textContent = `$${leak.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;

  if (d.lastRestoreResult?.durationMs !== undefined) {
    document.getElementById('restoreMetric').textContent = `${d.lastRestoreResult.durationMs} ms`;
  }

  // Render checks
  const beforeMap = new Map((b?.checks || []).map((c) => [c.id, c]));
  const afterMap = new Map((a?.checks || []).map((c) => [c.id, c]));
  const list = document.getElementById('checksList');
  list.innerHTML = '';

  for (const def of CHECK_DEFINITIONS) {
    const bc = beforeMap.get(def.id);
    const ac = afterMap.get(def.id);
    const row = document.createElement('div');
    row.className = 'check-item';
    row.innerHTML = `
      <div class="check-top">
        <div class="check-title">${def.id} · ${def.title}</div>
        <div class="badges">
          <span class="b ${bc ? (bc.passed ? 'b-pass' : 'b-fail') : 'b-idle'}">
            Before: ${bc ? (bc.passed ? 'PASS' : 'FAIL') : '—'}
          </span>
          <span class="b ${ac ? (ac.passed ? 'b-pass' : 'b-fail') : 'b-idle'}">
            After: ${ac ? (ac.passed ? 'PASS' : 'FAIL') : '—'}
          </span>
        </div>
      </div>
      <div class="check-evidence">${escapeHtml((ac || bc)?.evidence || def.category)}</div>
    `;
    list.appendChild(row);
  }

  // Render screenshots
  const shotsGrid = document.getElementById('shotsGrid');
  shotsGrid.innerHTML = '';
  const activeChecks = (a?.checks || b?.checks || []).filter((c) => c.screenshotUrl);
  for (const c of activeChecks) {
    const bc = beforeMap.get(c.id);
    const ac = afterMap.get(c.id);
    const card = document.createElement('button');
    card.className = 'shot-card';
    card.innerHTML = `
      <img src="${c.screenshotUrl}?t=${Date.now()}" alt="${c.id}" />
      <div class="shot-cap">${c.id} (${ac ? 'After' : 'Before'})</div>
    `;
    card.addEventListener('click', () => openModal(c.id, c.title, bc?.screenshotUrl, ac?.screenshotUrl));
    shotsGrid.appendChild(card);
  }

  // Patch diff
  if (d.latestPatch) {
    document.getElementById('patchMeta').textContent =
      `Source: ${d.latestPatch.source} (${d.latestPatch.model}) · +${d.latestPatch.lineStats.added} / -${d.latestPatch.lineStats.removed}`;
    renderDiff(d.latestPatch.unifiedDiff);
  } else {
    document.getElementById('patchMeta').textContent = 'Run the self-heal loop or apply patch to view diff.';
    renderDiff(null);
  }

  // Checkpoints list
  const cpWrap = document.getElementById('checkpointsList');
  cpWrap.innerHTML = '';
  for (const cp of d.checkpoints?.checkpoints || []) {
    const div = document.createElement('div');
    div.className = 'cp-item';
    div.innerHTML = `
      <div>
        <strong>${escapeHtml(cp.id)}</strong> · ${escapeHtml(cp.comment || '')}
        <div class="muted">${escapeHtml(cp.mode)} · db=${cp.dbHash ? cp.dbHash.slice(0, 10) : '—'}</div>
      </div>
      <button class="btn sm" data-restore="${escapeHtml(cp.id)}">Restore</button>
    `;
    div.querySelector('button').addEventListener('click', () => triggerRestore(cp.id));
    cpWrap.appendChild(div);
  }

  // Zero-Secret Vault
  const vault = document.getElementById('vaultSummary');
  const conns = d.connectors?.connectors || [];
  let guardrailHtml = '';
  if (d.latestGuardrailTest) {
    guardrailHtml = `<div style="margin-top:6px;"><strong>Live Gateway Probes:</strong></div>` +
      d.latestGuardrailTest.probes
        .map(
          (p) =>
            `<div class="muted">${p.passed ? '✅' : '⚠️'} ${escapeHtml(p.name)} → HTTP ${p.status} (${p.latencyMs ?? 0}ms)</div>`
        )
        .join('');
  }
  vault.innerHTML = `
    <div><strong>Zero-Secret Attestation:</strong> ${escapeHtml(d.zeroSecrets?.attestation)}</div>
    <div><strong>Total env vars scanned:</strong> ${d.zeroSecrets?.totalEnvVars ?? 0}</div>
    <div><strong>Fly Gateway Discovery:</strong> ${
      d.connectors?.available
        ? `${conns.length} active connectors (${conns.map((c) => c.provider).join(', ') || 'none'})`
        : `Off-Sprite local mode (${escapeHtml(d.connectors?.reason || 'gateway identity requires Fly Sprite')})`
    }</div>
    ${guardrailHtml}
  `;

  const prBox = document.getElementById('prBox');
  prBox.innerHTML = d.latestPr?.prUrl
    ? `<strong>Verified GitHub PR #${d.latestPr.prNumber}:</strong> <a style="color:#60a5fa;" href="${escapeHtml(d.latestPr.prUrl)}" target="_blank" rel="noopener">${escapeHtml(d.latestPr.prUrl)}</a>`
    : `<span class="muted">PR not opened yet. Once patched and verified on Fly Sprite with GitHub Connector, click "Open Verified GitHub PR".</span>`;
}

function openModal(id, title, beforeUrl, afterUrl) {
  document.getElementById('modalTitle').textContent = `${id} — ${title}`;
  const wrap = document.getElementById('modalImgs');
  wrap.innerHTML = '';
  if (beforeUrl) {
    wrap.innerHTML += `<div><div class="muted" style="margin-bottom:4px;">BEFORE PATCH</div><img src="${beforeUrl}?t=${Date.now()}" /></div>`;
  }
  if (afterUrl) {
    wrap.innerHTML += `<div><div class="muted" style="margin-bottom:4px;">AFTER PATCH</div><img src="${afterUrl}?t=${Date.now()}" /></div>`;
  }
  document.getElementById('shotModal').classList.add('open');
}

document.getElementById('closeModalBtn').addEventListener('click', () => {
  document.getElementById('shotModal').classList.remove('open');
});

async function refreshState() {
  const data = await api('/api/state');
  renderState(data);
  return data;
}

async function waitForSpriteReconnect(startedAtMs) {
  const metricEl = document.getElementById('restoreMetric');
  while (true) {
    const elapsed = Date.now() - startedAtMs;
    setStep(3, 'active', `Restoring CoW... ${elapsed} ms`);
    metricEl.textContent = `${elapsed} ms`;
    try {
      const res = await fetch('/api/health', { cache: 'no-store' });
      if (res.ok) {
        const health = await res.json();
        const totalMs = Date.now() - startedAtMs;
        metricEl.textContent = `${totalMs} ms`;
        setStep(3, 'done', `${totalMs} ms (CoW)`);
        return { totalMs, health };
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
}

async function finishPostRestorePipeline(runId) {
  setStep(4, 'active', 'Patching...');
  const patchRes = await api('/api/patch/apply', {
    method: 'POST',
    body: JSON.stringify({ runId, autoVerify: false }),
  });
  setStep(4, 'done', patchRes.patch.source.replace('fly-connector:', ''));

  setStep(5, 'active', 'Chromium QA...');
  const afterRes = await api('/api/qa/run', {
    method: 'POST',
    body: JSON.stringify({ runId, phase: 'after' }),
  });
  setStep(
    5,
    afterRes.report.failedCount === 0 ? 'done' : 'fail',
    `${afterRes.report.passedCount}/6 (${afterRes.report.durationMs}ms)`
  );

  setStep(6, 'active', 'Opening PR...');
  try {
    const pr = await api('/api/pr/open', { method: 'POST', body: JSON.stringify({}) });
    setStep(6, 'done', `PR #${pr.prNumber}`);
  } catch (err) {
    setStep(6, 'done', 'Local verified (no GH Conn)');
    appendLogLine({ ts: new Date().toISOString(), level: 'warn', message: `PR skipped: ${err.message}` });
  }

  await refreshState();
  document.getElementById('storeFrame').src = `/pixelmart/?t=${Date.now()}`;
}

async function runFullAutonomousLoop() {
  if (uiState.busy) return;
  uiState.busy = true;
  document.getElementById('runLoopBtn').disabled = true;
  const runId = `run-${Date.now()}`;

  try {
    setStep(1, 'active', 'Snapshotting...');
    const cpRes = await api('/api/checkpoints/create', {
      method: 'POST',
      body: JSON.stringify({ comment: `baseline-${runId}` }),
    });
    setStep(1, 'done', `${cpRes.checkpoint.id} (${cpRes.checkpoint.durationMs}ms)`);

    setStep(2, 'active', 'Chromium QA...');
    const beforeRes = await api('/api/qa/run', {
      method: 'POST',
      body: JSON.stringify({ runId, phase: 'before' }),
    });
    setStep(2, 'done', `${beforeRes.report.passedCount}/6 (${beforeRes.report.durationMs}ms)`);
    await refreshState();

    setStep(3, 'active', 'Restoring...');
    const tRestore = Date.now();
    const restoreRes = await api('/api/checkpoints/restore', {
      method: 'POST',
      body: JSON.stringify({ checkpointId: cpRes.checkpoint.id }),
    });

    if (restoreRes.restoring) {
      sessionStorage.setItem('patchguard_resume', JSON.stringify({ runId, restoreStartedAt: tRestore }));
      await waitForSpriteReconnect(tRestore);
      sessionStorage.removeItem('patchguard_resume');
    } else {
      setStep(3, 'done', `${restoreRes.durationMs} ms`);
      document.getElementById('restoreMetric').textContent = `${restoreRes.durationMs} ms`;
    }

    await finishPostRestorePipeline(runId);
  } catch (err) {
    appendLogLine({ ts: new Date().toISOString(), level: 'error', message: err.message });
  } finally {
    uiState.busy = false;
    document.getElementById('runLoopBtn').disabled = false;
  }
}

async function triggerRestore(checkpointId) {
  const t0 = Date.now();
  const res = await api('/api/checkpoints/restore', {
    method: 'POST',
    body: JSON.stringify({ checkpointId }),
  });
  if (res.restoring) {
    await waitForSpriteReconnect(t0);
  }
  await refreshState();
}

// Tabs switching
document.querySelectorAll('.tab').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach((t) => t.classList.remove('active'));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add('active');
  });
});

document.getElementById('runLoopBtn').addEventListener('click', runFullAutonomousLoop);
document.getElementById('resetBtn').addEventListener('click', async () => {
  await api('/api/reset-demo', { method: 'POST', body: '{}' });
  for (let i = 1; i <= 6; i++) setStep(i, null, 'Idle');
  document.getElementById('restoreMetric').textContent = '— ms';
  await refreshState();
  document.getElementById('storeFrame').src = `/pixelmart/?t=${Date.now()}`;
});

document.getElementById('runBeforeBtn').addEventListener('click', async () => {
  await api('/api/qa/run', { method: 'POST', body: JSON.stringify({ phase: 'before' }) });
  await refreshState();
});
document.getElementById('runAfterBtn').addEventListener('click', async () => {
  await api('/api/qa/run', { method: 'POST', body: JSON.stringify({ phase: 'after' }) });
  await refreshState();
});
document.getElementById('applyPatchBtn').addEventListener('click', async () => {
  await api('/api/patch/apply', { method: 'POST', body: JSON.stringify({ autoVerify: true }) });
  await refreshState();
});
document.getElementById('createCpBtn').addEventListener('click', async () => {
  await api('/api/checkpoints/create', { method: 'POST', body: '{}' });
  await refreshState();
});
document.getElementById('restoreCpBtn').addEventListener('click', () => triggerRestore(null));
document.getElementById('diffCpBtn').addEventListener('click', async () => {
  const id = uiState.data?.checkpoints?.baselineId || uiState.data?.checkpoints?.checkpoints?.[0]?.id;
  if (!id) return;
  const diff = await api(`/api/checkpoints/${encodeURIComponent(id)}/diff`);
  document.getElementById('cpDiffView').textContent = diff.diff || 'No diff available';
});
document.getElementById('testGuardrailsBtn').addEventListener('click', async () => {
  await api('/api/connectors/test-guardrails', { method: 'POST', body: '{}' });
  await refreshState();
});
document.getElementById('openPrBtn').addEventListener('click', async () => {
  try {
    await api('/api/pr/open', { method: 'POST', body: '{}' });
  } catch (err) {
    appendLogLine({ ts: new Date().toISOString(), level: 'warn', message: err.message });
  }
  await refreshState();
});
document.getElementById('reloadStoreBtn').addEventListener('click', () => {
  document.getElementById('storeFrame').src = `/pixelmart/?t=${Date.now()}`;
});
document.getElementById('auditRepoBtn').addEventListener('click', async () => {
  const repoUrl = document.getElementById('repoUrlInput').value.trim();
  const out = document.getElementById('repoAuditResult');
  out.textContent = 'Shallow cloning into isolated /tmp sandbox...';
  try {
    const res = await api('/api/repo/audit', {
      method: 'POST',
      body: JSON.stringify({ repoUrl }),
    });
    out.textContent = JSON.stringify(res, null, 2);
  } catch (err) {
    out.textContent = `Audit error: ${err.message}`;
  }
});

// SSE listener
const evSource = new EventSource('/api/events');
evSource.onmessage = (ev) => {
  try {
    const entry = JSON.parse(ev.data);
    appendLogLine(entry);
  } catch {}
};

// Initial boot + check if returning from Fly Sprite CoW Restore
(async () => {
  const state = await refreshState();
  for (const entry of state.logs || []) {
    appendLogLine(entry);
  }
  const resumeRaw = sessionStorage.getItem('patchguard_resume');
  if (resumeRaw) {
    sessionStorage.removeItem('patchguard_resume');
    const { runId, restoreStartedAt } = JSON.parse(resumeRaw);
    setStep(3, 'done', `${Date.now() - restoreStartedAt} ms (CoW)`);
    await finishPostRestorePipeline(runId);
  }
})();
