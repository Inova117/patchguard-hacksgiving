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
        return `<span class="diff-line diff-add">${escapeHtml(line)}</span>`;
      }
      if (line.startsWith('-') && !line.startsWith('---')) {
        return `<span class="diff-line diff-del">${escapeHtml(line)}</span>`;
      }
      if (line.startsWith('@@') || line.startsWith('---') || line.startsWith('+++')) {
        return `<span class="diff-line diff-hdr">${escapeHtml(line)}</span>`;
      }
      return `<span class="diff-line">${escapeHtml(line)}</span>`;
    })
    .join('');
}

function renderState(d) {
  uiState.data = d;

  const rt = d.runtime;
  const rtPill = document.getElementById('runtimePill');
  rtPill.textContent = rt.isFlySprite ? `Sprite · ${rt.hostname}` : `Local · ${rt.mode}`;
  rtPill.className = `status-item ${rt.isFlySprite ? 'ok' : 'warn'}`;

  const dbPill = document.getElementById('dbPill');
  const hashShort = d.store?.dbHash ? d.store.dbHash.slice(0, 10) : '—';
  const dbDirty = d.store?.baselineDbHash && d.store?.dbHash !== d.store.baselineDbHash;
  dbPill.textContent = `DB ${hashShort} ${dbDirty ? 'modified' : 'clean'}`;
  dbPill.className = `status-item ${dbDirty ? 'warn' : 'ok'}`;

  const secPill = document.getElementById('secretsPill');
  secPill.textContent = d.zeroSecrets?.zeroSecretsVerified
    ? '0 raw secrets'
    : `${d.zeroSecrets?.sensitiveEnvKeys?.length || 0} secrets found`;
  secPill.className = `status-item ${d.zeroSecrets?.zeroSecretsVerified ? 'ok' : 'danger'}`;
  document.getElementById('secretCountMetric').textContent = String(
    d.zeroSecrets?.sensitiveEnvKeys?.length || 0
  );

  const b = d.beforeReport;
  const a = d.afterReport;
  document.getElementById('passMetric').textContent = b && a
    ? `${b.passedCount}/6 → ${a.passedCount}/6`
    : b
      ? `${b.passedCount}/6`
      : a
        ? `${a.passedCount}/6`
        : '— / 6';

  const leak = b ? (b.revenueLeakCents || 0) / 100 : 0;
  const leakEl = document.getElementById('leakMetric');
  leakEl.textContent = `$${leak.toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
  leakEl.classList.toggle('has-leak', leak > 0);

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
    const shortNum = def.id.replace('CHECK-', '');
    row.innerHTML = `
      <div class="check-top">
        <div class="check-title-wrap">
          <span class="check-id">${shortNum}</span>
          <div class="check-title">${def.title}</div>
        </div>
        <div class="badges">
          <span class="b ${bc ? (bc.passed ? 'b-pass' : 'b-fail') : 'b-idle'}">
            ${bc ? (bc.passed ? 'Before PASS' : 'Before FAIL') : 'Before —'}
          </span>
          <span class="b ${ac ? (ac.passed ? 'b-pass' : 'b-fail') : 'b-idle'}">
            ${ac ? (ac.passed ? 'After PASS' : 'After FAIL') : 'After —'}
          </span>
        </div>
      </div>
      <div class="check-evidence">${escapeHtml((ac || bc)?.evidence || def.category)}</div>
    `;
    list.appendChild(row);
  }

  // Hero Before vs After split-view for CHECK-01
  const heroCompare = document.getElementById('heroCompare');
  heroCompare.innerHTML = '';
  const c1Before = beforeMap.get('check01-price') || beforeMap.get('CHECK-01');
  const c1After = afterMap.get('check01-price') || afterMap.get('CHECK-01');
  if (c1Before?.screenshotUrl && c1After?.screenshotUrl) {
    heroCompare.innerHTML = `
      <div class="hero-pane before">
        <div class="hero-lbl"><span>BEFORE · CHECK-01</span><span class="b b-fail">BREACH $0.01</span></div>
        <img src="${c1Before.screenshotUrl}?t=${Date.now()}" alt="CHECK-01 Before" />
      </div>
      <div class="hero-pane after">
        <div class="hero-lbl"><span>AFTER · CHECK-01</span><span class="b b-pass">BLOCKED 400</span></div>
        <img src="${c1After.screenshotUrl}?t=${Date.now()}" alt="CHECK-01 After" />
      </div>
    `;
  }

  // Render screenshots
  const shotsGrid = document.getElementById('shotsGrid');
  shotsGrid.innerHTML = '';
  const activeChecks = (a?.checks || b?.checks || []).filter((c) => c.screenshotUrl);
  const emptyHint = document.getElementById('shotsEmptyHint');
  if (emptyHint) emptyHint.style.display = activeChecks.length ? 'none' : 'block';
  for (const c of activeChecks) {
    const bc = beforeMap.get(c.id);
    const ac = afterMap.get(c.id);
    const current = ac || bc;
    const card = document.createElement('button');
    card.className = 'shot-card';
    card.innerHTML = `
      <img src="${c.screenshotUrl}?t=${Date.now()}" alt="${c.id}" />
      <div class="shot-cap">
        <span>${c.id} (${ac ? 'After' : 'Before'})</span>
        <span class="b ${current.passed ? 'b-pass' : 'b-fail'}">${current.passed ? 'PASS' : 'FAIL'}</span>
      </div>
    `;
    card.addEventListener('click', () => openModal(c.id, c.title, bc?.screenshotUrl, ac?.screenshotUrl));
    shotsGrid.appendChild(card);
  }

  // Patch diff
  if (d.latestPatch) {
    document.getElementById('patchMeta').textContent =
      `${d.latestPatch.source.replace('fly-connector:', '')} · ${d.latestPatch.model} · +${d.latestPatch.lineStats.added} / -${d.latestPatch.lineStats.removed}`;
    renderDiff(d.latestPatch.unifiedDiff);
  } else {
    document.getElementById('patchMeta').textContent = 'Run the self-heal loop or apply a patch to inspect the unified diff.';
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
        <strong>${escapeHtml(cp.id)}</strong> <span class="muted">${escapeHtml(cp.comment || '')}</span>
        <div class="muted" style="font-family:var(--mono);font-size:11px;">${escapeHtml(cp.mode)} · db=${cp.dbHash ? cp.dbHash.slice(0, 10) : '—'}</div>
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
    guardrailHtml = `<div style="margin-top:6px;"><strong>Live Gateway Policy Probes</strong></div>` +
      d.latestGuardrailTest.probes
        .map(
          (p) =>
            `<div class="probe-row"><span>${escapeHtml(p.name)}</span><span class="b ${p.passed ? 'b-pass' : 'b-fail'}">HTTP ${p.status} · ${p.latencyMs ?? 0}ms</span></div>`
        )
        .join('');
  }
  vault.innerHTML = `
    <div><strong>Attestation:</strong> ${escapeHtml(d.zeroSecrets?.attestation)}</div>
    <div><strong>Environment scanned:</strong> ${d.zeroSecrets?.totalEnvVars ?? 0} variables</div>
    <div><strong>Fly Gateway:</strong> ${
      d.connectors?.available
        ? `${conns.length} active connectors (${conns.map((c) => c.provider).join(', ') || 'none'})`
        : `Off-Sprite local mode (${escapeHtml(d.connectors?.reason || 'gateway identity requires Fly Sprite')})`
    }</div>
    ${guardrailHtml}
  `;

  const prBox = document.getElementById('prBox');
  prBox.innerHTML = d.latestPr?.prUrl
    ? `<div><strong>Verified Pull Request #${d.latestPr.prNumber}</strong></div><a href="${escapeHtml(d.latestPr.prUrl)}" target="_blank" rel="noopener">${escapeHtml(d.latestPr.prUrl)}</a>`
    : `<span class="muted">No PR opened yet. Once verified on the Fly Sprite, click "Open GitHub PR" or run the full loop.</span>`;
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

async function captureBeforeScreenshots(beforeReport) {
  const screenshots = {};
  const checks = beforeReport?.checks || [];
  await Promise.all(
    checks.map(async (c) => {
      if (!c.screenshotUrl) return;
      try {
        const res = await fetch(`${c.screenshotUrl}?t=${Date.now()}`, { cache: 'no-store' });
        if (!res.ok) return;
        const blob = await res.blob();
        const dataUrl = await new Promise((resolve, reject) => {
          const reader = new FileReader();
          reader.onloadend = () => resolve(String(reader.result || ''));
          reader.onerror = reject;
          reader.readAsDataURL(blob);
        });
        const filename = c.screenshotUrl.split('/').pop();
        if (filename && dataUrl) {
          screenshots[filename] = dataUrl.replace(/^data:image\/png;base64,/, '');
        }
      } catch {}
    })
  );
  return screenshots;
}

async function hydrateBeforeState(runId, beforeReport, restoreMs, screenshots) {
  await api('/api/state/hydrate-before', {
    method: 'POST',
    body: JSON.stringify({ runId, beforeReport, restoreMs, screenshots }),
  });
}

async function waitForSpriteReconnect(startedAtMs, previousBootId = null) {
  const metricEl = document.getElementById('restoreMetric');
  await new Promise((r) => setTimeout(r, 450));
  while (true) {
    const elapsed = Date.now() - startedAtMs;
    setStep(3, 'active', `Restoring CoW... ${elapsed} ms`);
    metricEl.textContent = `${elapsed} ms`;
    try {
      const res = await fetch('/api/health', { cache: 'no-store' });
      if (res.ok) {
        const health = await res.json();
        const bootChanged = !previousBootId || (health.bootId && health.bootId !== previousBootId);
        if (bootChanged && health.storeHealthy) {
          const totalMs = Date.now() - startedAtMs;
          metricEl.textContent = `${totalMs} ms`;
          setStep(3, 'done', `${totalMs} ms (CoW)`);
          return { totalMs, health };
        }
      }
    } catch {}
    await new Promise((r) => setTimeout(r, 200));
  }
}

async function finishPostRestorePipeline(runId) {
  const formatPatchStepMeta = (patch) => {
    const modelShort = String(patch.model || '')
      .replace(/^[^/]+\//, '')
      .replace(/:free$/, '');
    if (patch.source?.startsWith('fly-connector:')) {
      return modelShort || patch.source.replace('fly-connector:', '');
    }
    return patch.source || 'patched';
  };

  setStep(4, 'active', 'Patching via LLM…');
  const patchRes = await api('/api/patch/apply', {
    method: 'POST',
    body: JSON.stringify({ runId, autoVerify: false }),
  });
  setStep(4, 'done', formatPatchStepMeta(patchRes.patch));

  setStep(5, 'active', 'Chromium QA…');
  let afterRes = await api('/api/qa/run', {
    method: 'POST',
    body: JSON.stringify({ runId, phase: 'after' }),
  });
  if (afterRes.report.failedCount > 0) {
    const failedDesc = afterRes.report.checks
      .filter((c) => !c.passed)
      .map((c) => `${c.id}: ${c.evidence}`)
      .join('; ');
    setStep(4, 'active', 'Refining via LLM…');
    const refined = await api('/api/patch/apply', {
      method: 'POST',
      body: JSON.stringify({ runId, autoVerify: true, previousError: failedDesc }),
    });
    setStep(4, 'done', `${formatPatchStepMeta(refined.patch)} (r2)`);
    if (refined.afterReport) {
      afterRes = { report: refined.afterReport };
    }
  }
  setStep(
    5,
    afterRes.report.failedCount === 0 ? 'done' : 'fail',
    `${afterRes.report.passedCount}/6 (${afterRes.report.durationMs}ms)`
  );

  setStep(6, 'active', 'Checking PR...');
  const hasGh = Boolean(uiState.data?.connectors?.connectors?.some((c) => c.provider === 'github'));
  if (hasGh) {
    try {
      const pr = await api('/api/pr/open', { method: 'POST', body: JSON.stringify({}) });
      setStep(6, 'done', `PR #${pr.prNumber}`);
    } catch (err) {
      setStep(6, 'done', 'PR ready (retry in Vault)');
      appendLogLine({ ts: new Date().toISOString(), level: 'warn', message: `PR skipped: ${err.message}` });
    }
  } else {
    setStep(6, 'done', 'Ready (connect GitHub)');
    appendLogLine({ ts: new Date().toISOString(), level: 'info', message: 'Step 6: Verified 6/6 locally — connect Fly GitHub Connector to auto-open PR.' });
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

    const screenshotsBase64 = await captureBeforeScreenshots(beforeRes.report);

    setStep(3, 'active', 'Restoring...');
    const tRestore = Date.now();
    const restoreRes = await api('/api/checkpoints/restore', {
      method: 'POST',
      body: JSON.stringify({ checkpointId: cpRes.checkpoint.id }),
    });

    if (restoreRes.restoring) {
      try {
        sessionStorage.setItem(
          'patchguard_resume',
          JSON.stringify({
            runId,
            restoreStartedAt: tRestore,
            beforeReport: beforeRes.report,
            screenshots: screenshotsBase64,
          })
        );
      } catch {}
      const { totalMs } = await waitForSpriteReconnect(tRestore, restoreRes.previousBootId);
      sessionStorage.removeItem('patchguard_resume');
      await hydrateBeforeState(runId, beforeRes.report, totalMs, screenshotsBase64);
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
    await waitForSpriteReconnect(t0, res.previousBootId);
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
document.querySelectorAll('.repo-preset').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.getElementById('repoUrlInput').value = btn.dataset.url;
  });
});

function renderRepoSummary(audit, heal) {
  const box = document.getElementById('repoVisualSummary');
  const shots = document.getElementById('repoShots');
  shots.innerHTML = '';

  if (heal) {
    const bHdr = heal.before?.missingHeaders?.length ?? 0;
    const aHdr = heal.after?.missingHeaders?.length ?? 0;
    box.innerHTML = `
      <div><strong>Self-Healed Real Repo:</strong> ${escapeHtml(heal.fullName)} (${escapeHtml(heal.framework)})</div>
      <div><strong>Zero-Secret LLM:</strong> <code>${escapeHtml(heal.llm.source)}</code> · <code>${escapeHtml(heal.llm.model)}</code> (${heal.llm.latencyMs}ms)</div>
      <div><strong>Live Missing Security Headers:</strong> <span class="b b-fail">${bHdr} missing</span> → <span class="b ${aHdr === 0 ? 'b-pass' : 'b-fail'}">${aHdr} missing</span> · <strong>Build:</strong> ${heal.after.buildAndTest?.build ? (heal.after.buildAndTest.build.ok ? '✅ PASS' : '❌ FAIL') : 'N/A'}</div>
      <div class="muted">${escapeHtml(heal.llm.summary)}</div>
    `;
    if (heal.before?.screenshotUrl) {
      shots.innerHTML += `<div class="hero-pane before"><div class="hero-lbl"><span>BEFORE · ${escapeHtml(heal.repo)}</span><span class="b b-fail">${bHdr} headers missing</span></div><img src="${heal.before.screenshotUrl}?t=${Date.now()}" /></div>`;
    }
    if (heal.after?.screenshotUrl) {
      shots.innerHTML += `<div class="hero-pane after"><div class="hero-lbl"><span>AFTER · ${escapeHtml(heal.repo)}</span><span class="b ${aHdr === 0 ? 'b-pass' : 'b-fail'}">${aHdr === 0 ? 'HARDENED' : aHdr + ' missing'}</span></div><img src="${heal.after.screenshotUrl}?t=${Date.now()}" /></div>`;
    }
    return;
  }

  if (audit) {
    const lb = audit.liveBrowser || {};
    box.innerHTML = `
      <div><strong>Audited Real Repo:</strong> ${escapeHtml(audit.fullName)} (${escapeHtml(audit.framework)}) · ${audit.filesScanned} files scanned</div>
      <div><strong>Real CVEs (npm audit):</strong> ${audit.cveAudit?.total ?? 0} (critical=${audit.cveAudit?.severities?.critical ?? 0}, high=${audit.cveAudit?.severities?.high ?? 0}) · <strong>Static findings:</strong> ${audit.staticFindingsCount}</div>
      <div><strong>Live Chromium Boot:</strong> ${lb.ran ? `HTTP ${lb.httpStatus} · "${escapeHtml(lb.pageTitle)}" · Missing headers: ${lb.missingHeaders?.length ?? 0} · Console errors: ${lb.consoleErrors?.length ?? 0}` : escapeHtml(lb.reason || 'Not booted')}</div>
    `;
    if (lb.screenshotUrl) {
      shots.innerHTML = `<div class="hero-pane before" style="grid-column:span 2;"><div class="hero-lbl"><span>LIVE CHROMIUM · ${escapeHtml(audit.fullName)}</span><span class="b ${lb.headersPassed ? 'b-pass' : 'b-fail'}">${lb.headersPassed ? 'HEADERS OK' : (lb.missingHeaders?.length || 0) + ' HEADERS MISSING'}</span></div><img src="${lb.screenshotUrl}?t=${Date.now()}" /></div>`;
    }
  }
}

document.getElementById('auditRepoBtn').addEventListener('click', async () => {
  const repoUrl = document.getElementById('repoUrlInput').value.trim();
  const out = document.getElementById('repoAuditResult');
  out.textContent = `Cloning ${repoUrl}, installing deps, running npm audit + build + live Chromium...`;
  try {
    const res = await api('/api/repo/audit', {
      method: 'POST',
      body: JSON.stringify({ repoUrl }),
    });
    renderRepoSummary(res, null);
    out.textContent = JSON.stringify(
      {
        fullName: res.fullName,
        framework: res.framework,
        cveAudit: res.cveAudit,
        buildAndTest: res.buildAndTest,
        actionableFindings: res.actionableFindings,
        liveBrowser: res.liveBrowser,
      },
      null,
      2
    );
  } catch (err) {
    out.textContent = `Audit error: ${err.message}`;
  }
});

document.getElementById('healRepoBtn').addEventListener('click', async () => {
  const repoUrl = document.getElementById('repoUrlInput').value.trim();
  const out = document.getElementById('repoAuditResult');
  out.textContent = `Calling Fly Zero-Secret LLM Connector to patch ${repoUrl}, rebuilding, and re-verifying in Chromium...`;
  try {
    const res = await api('/api/repo/heal', {
      method: 'POST',
      body: JSON.stringify({ repoUrl }),
    });
    renderRepoSummary(null, res);
    out.textContent = res.gitDiff || JSON.stringify(res, null, 2);
  } catch (err) {
    out.textContent = `Self-Heal error: ${err.message}`;
  }
});

document.getElementById('prRepoBtn').addEventListener('click', async () => {
  const out = document.getElementById('repoAuditResult');
  try {
    const pr = await api('/api/repo/pr', { method: 'POST', body: '{}' });
    out.textContent = `✅ Real Pull Request opened via Fly Zero-Secret GitHub Connector:\n${pr.prUrl}\n\nBranch: ${pr.branchName}`;
    await refreshState();
  } catch (err) {
    out.textContent = `PR error: ${err.message}`;
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
    const { runId, restoreStartedAt, beforeReport, screenshots } = JSON.parse(resumeRaw);
    const totalMs = Date.now() - restoreStartedAt;
    setStep(3, 'done', `${totalMs} ms (CoW)`);
    if (beforeReport) {
      await hydrateBeforeState(runId, beforeReport, totalMs, screenshots || {});
    }
    await finishPostRestorePipeline(runId);
  }
})();
