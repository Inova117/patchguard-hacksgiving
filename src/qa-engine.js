import fs from 'node:fs';
import path from 'node:path';
import { chromium } from 'playwright';
import { computeDbHash } from '../target-store/db.js';
import {
  ARTIFACTS_DIR,
  assertLocalTargetUrl,
  TARGET_DB_PATH,
  TARGET_SERVER_PATH,
} from './config.js';

/**
 * Run the 6-check real headless Chromium defensive QA suite against a loopback storefront.
 */
export async function runQaSuite({
  storeUrl,
  runId = `run-${Date.now()}`,
  phase = 'before',
  onProgress = () => {},
} = {}) {
  const safeStoreUrl = assertLocalTargetUrl(storeUrl);
  const phaseDir = path.join(ARTIFACTS_DIR, 'runs', runId, phase);
  fs.mkdirSync(phaseDir, { recursive: true });

  const startedAt = Date.now();
  const dbHashBefore = computeDbHash(TARGET_DB_PATH);
  const checks = [];
  let revenueLeakCents = 0;

  onProgress({
    type: 'qa_start',
    runId,
    phase,
    storeUrl: safeStoreUrl,
    dbHashBefore,
  });

  const browser = await chromium.launch({ headless: true });

  try {
    const context = await browser.newContext({ viewport: { width: 1280, height: 760 } });
    const page = await context.newPage();

    const shotUrl = (file) => `/artifacts/runs/${runId}/${phase}/${file}`;
    const snap = async (filename) => {
      const absPath = path.join(phaseDir, filename);
      await page.screenshot({ path: absPath, fullPage: false });
      return { absPath, url: shotUrl(filename) };
    };

    // Navigate & log in as regular customer Alice via real UI button
    await page.goto(safeStoreUrl, { waitUntil: 'networkidle' });
    await page.click('[data-testid="login-alice"]');
    await page.waitForFunction(() => document.getElementById('userBadge')?.textContent?.includes('alice'));

    // =========================================================================
    // CHECK-01: Checkout Client-Side Price Integrity
    // =========================================================================
    await page.click('[data-testid="add-product-1"]');
    const c1Result = await page.evaluate(async () => {
      const { api, showBanner, refreshHealthAndOrders, fmtMoney } = window.__patchguardStore;
      const res = await api('/api/checkout', {
        method: 'POST',
        body: JSON.stringify({
          items: [{ productId: 1, qty: 1, unit_price_cents: 1 }],
          coupons: [],
        }),
      });
      if (res.ok && res.body?.order?.total_cents < 129900) {
        showBanner(
          'breach',
          `BREACH DETECTED · PAID ${fmtMoney(res.body.order.total_cents)} FOR $1,299.00 MACBOOK PRO (LEAK: $1,298.99)`,
          res.body
        );
      } else if (!res.ok) {
        showBanner('blocked', `HTTP ${res.status} · CLIENT PRICE TAMPERING BLOCKED`, res.body);
      } else {
        showBanner('blocked', `HTTP ${res.status} · SERVER ENFORCED CANONICAL $1,299.00`, res.body);
      }
      await refreshHealthAndOrders();
      return res;
    });
    const c1Shot = await snap('check01-price.png');
    const c1Passed = !c1Result.ok || c1Result.body?.order?.total_cents >= 129900;
    const c1Leak = c1Passed ? 0 : Math.max(0, 129900 - Number(c1Result.body?.order?.total_cents || 0));
    revenueLeakCents += c1Leak;
    checks.push({
      id: 'CHECK-01',
      title: 'Checkout Price-Tampering Guard',
      category: 'Business Logic',
      passed: c1Passed,
      httpStatus: c1Result.status,
      leakCents: c1Leak,
      screenshotUrl: c1Shot.url,
      screenshotPath: c1Shot.absPath,
      evidence: c1Passed
        ? `Server rejected tampered price ($0.01) with HTTP ${c1Result.status}`
        : `Checkout accepted unit_price_cents=1 ($0.01) for $1,299.00 MacBook Pro (HTTP ${c1Result.status})`,
    });
    onProgress({ type: 'qa_check', runId, phase, check: checks[checks.length - 1] });

    // =========================================================================
    // CHECK-02: Single-Use Coupon Stacking & Concurrency Guard
    // =========================================================================
    const c2Result = await page.evaluate(async () => {
      const { api, showBanner, refreshHealthAndOrders, fmtMoney } = window.__patchguardStore;
      const stackRes = await api('/api/checkout', {
        method: 'POST',
        body: JSON.stringify({
          items: [{ productId: 1, qty: 1 }],
          coupons: ['HACKS25', 'HACKS25', 'HACKS25', 'HACKS25'],
        }),
      });

      const [r1, r2] = await Promise.all([
        api('/api/checkout', {
          method: 'POST',
          body: JSON.stringify({ items: [{ productId: 3, qty: 1 }], coupons: ['HACKS25'] }),
        }),
        api('/api/checkout', {
          method: 'POST',
          body: JSON.stringify({ items: [{ productId: 3, qty: 1 }], coupons: ['HACKS25'] }),
        }),
      ]);

      const stackedBreach = stackRes.ok && stackRes.body?.order?.total_cents < 97425;
      const raceBreach = r1.ok && r2.ok;

      if (stackedBreach || raceBreach) {
        showBanner(
          'breach',
          `BREACH DETECTED · 4x COUPON STACK PAID ${fmtMoney(stackRes.body?.order?.total_cents || 0)} (100% OFF)`,
          { stackRes: stackRes.body, concurrentStatuses: [r1.status, r2.status] }
        );
      } else {
        showBanner(
          'blocked',
          `COUPON GUARD ENFORCED · STACK=${stackRes.status} RACE=[${r1.status}, ${r2.status}]`,
          { stackRes: stackRes.body, concurrentStatuses: [r1.status, r2.status] }
        );
      }
      await refreshHealthAndOrders();
      return {
        stackStatus: stackRes.status,
        stackTotal: stackRes.body?.order?.total_cents ?? null,
        r1Status: r1.status,
        r2Status: r2.status,
        stackedBreach,
        raceBreach,
      };
    });
    const c2Shot = await snap('check02-coupon.png');
    const c2Passed = !c2Result.stackedBreach && !c2Result.raceBreach;
    checks.push({
      id: 'CHECK-02',
      title: 'Single-Use Coupon Stacking & Race Guard',
      category: 'Concurrency / Logic',
      passed: c2Passed,
      httpStatus: c2Result.stackStatus,
      leakCents: 0,
      screenshotUrl: c2Shot.url,
      screenshotPath: c2Shot.absPath,
      evidence: c2Passed
        ? `Duplicate/stacked coupon blocked (HTTP ${c2Result.stackStatus}); concurrent use serialized [${c2Result.r1Status}, ${c2Result.r2Status}]`
        : `Single-use HACKS25 stacked 4x to $${((c2Result.stackTotal || 0) / 100).toFixed(2)} (HTTP ${c2Result.stackStatus})`,
    });
    onProgress({ type: 'qa_check', runId, phase, check: checks[checks.length - 1] });

    // =========================================================================
    // CHECK-03: Admin Endpoint RBAC Guard
    // =========================================================================
    const c3Result = await page.evaluate(async () => {
      const { api, showBanner } = window.__patchguardStore;
      const listRes = await api('/api/admin/orders');
      const refundRes = await api('/api/admin/refund', {
        method: 'POST',
        body: JSON.stringify({ orderId: 1002 }),
      });
      const breached = listRes.ok || refundRes.ok;
      showBanner(
        breached ? 'breach' : 'blocked',
        breached
          ? `BREACH DETECTED · CUSTOMER ALICE ACCESSED ADMIN API (LIST=${listRes.status}, REFUND=${refundRes.status})`
          : `HTTP 403 · ADMIN RBAC ENFORCED FOR CUSTOMER ROLE`,
        { adminOrdersStatus: listRes.status, adminRefundStatus: refundRes.status, sample: listRes.body?.orders?.[0] || listRes.body }
      );
      return { listStatus: listRes.status, refundStatus: refundRes.status, breached };
    });
    const c3Shot = await snap('check03-admin.png');
    const c3Passed = c3Result.listStatus === 403 && c3Result.refundStatus === 403;
    checks.push({
      id: 'CHECK-03',
      title: 'Admin Endpoint RBAC Guard',
      category: 'Access Control',
      passed: c3Passed,
      httpStatus: c3Result.listStatus,
      leakCents: 0,
      screenshotUrl: c3Shot.url,
      screenshotPath: c3Shot.absPath,
      evidence: c3Passed
        ? 'GET /api/admin/orders and POST /api/admin/refund both returned 403 Forbidden for customer role'
        : `Customer alice accessed admin endpoints (GET=${c3Result.listStatus}, POST refund=${c3Result.refundStatus})`,
    });
    onProgress({ type: 'qa_check', runId, phase, check: checks[checks.length - 1] });

    // =========================================================================
    // CHECK-04: Order Ownership (IDOR) Guard
    // =========================================================================
    const c4Result = await page.evaluate(async () => {
      const { api, showBanner } = window.__patchguardStore;
      const res = await api('/api/orders/1002');
      showBanner(
        res.ok ? 'breach' : 'blocked',
        res.ok
          ? `BREACH DETECTED · ALICE READ BOB'S PRIVATE ORDER #1002 (HTTP ${res.status})`
          : `HTTP ${res.status} · ORDER OWNERSHIP (IDOR) BLOCKED`,
        res.body
      );
      return res;
    });
    const c4Shot = await snap('check04-idor.png');
    const c4Passed = c4Result.status === 403;
    checks.push({
      id: 'CHECK-04',
      title: 'Order Ownership (IDOR) Guard',
      category: 'Access Control',
      passed: c4Passed,
      httpStatus: c4Result.status,
      leakCents: 0,
      screenshotUrl: c4Shot.url,
      screenshotPath: c4Shot.absPath,
      evidence: c4Passed
        ? 'GET /api/orders/1002 returned 403 Forbidden for non-owner alice'
        : `Customer alice read Bob's private order #1002 (HTTP ${c4Result.status})`,
    });
    onProgress({ type: 'qa_check', runId, phase, check: checks[checks.length - 1] });

    // =========================================================================
    // CHECK-05: Security Headers & Session Cookie Hygiene Audit
    // =========================================================================
    const homeRes = await fetch(`${safeStoreUrl}/`);
    const loginRes = await fetch(`${safeStoreUrl}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice', password: 'alice123' }),
    });
    const setCookieHeader = loginRes.headers.get('set-cookie') || '';
    const nosniff = homeRes.headers.get('x-content-type-options') === 'nosniff';
    const xfoVal = (homeRes.headers.get('x-frame-options') || '').toUpperCase();
    const xfo = xfoVal === 'SAMEORIGIN' || xfoVal === 'DENY';
    const csp = Boolean(homeRes.headers.get('content-security-policy'));
    const cookieHttpOnly = /httponly/i.test(setCookieHeader);
    const cookieSameSite = /samesite=lax/i.test(setCookieHeader);

    const serverSource = fs.existsSync(TARGET_SERVER_PATH)
      ? fs.readFileSync(TARGET_SERVER_PATH, 'utf8')
      : '';
    const staticClean = !/eval\s*\(|child_process/.test(serverSource);
    const c5Passed = nosniff && xfo && csp && cookieHttpOnly && cookieSameSite && staticClean;

    const missing = [];
    if (!nosniff) missing.push('X-Content-Type-Options: nosniff');
    if (!xfo) missing.push('X-Frame-Options: SAMEORIGIN');
    if (!csp) missing.push('Content-Security-Policy');
    if (!cookieHttpOnly) missing.push('Cookie HttpOnly');
    if (!cookieSameSite) missing.push('Cookie SameSite=Lax');

    await page.evaluate(
      ({ passed, missingList }) => {
        window.__patchguardStore.showBanner(
          passed ? 'blocked' : 'breach',
          passed
            ? 'HTTP HEADERS & COOKIE FLAGS VERIFIED (nosniff, SAMEORIGIN, CSP, HttpOnly, SameSite)'
            : `MISSING SECURITY CONTROLS: ${missingList.join(', ')}`,
          { missing: missingList }
        );
      },
      { passed: c5Passed, missingList: missing }
    );
    const c5Shot = await snap('check05-headers.png');
    checks.push({
      id: 'CHECK-05',
      title: 'Security Headers & Cookie Hygiene',
      category: 'HTTP Hardening',
      passed: c5Passed,
      httpStatus: homeRes.status,
      leakCents: 0,
      screenshotUrl: c5Shot.url,
      screenshotPath: c5Shot.absPath,
      evidence: c5Passed
        ? 'All required security headers (nosniff, SAMEORIGIN, CSP) and HttpOnly/SameSite cookie flags verified'
        : `Missing: ${missing.join(', ')}`,
    });
    onProgress({ type: 'qa_check', runId, phase, check: checks[checks.length - 1] });

    // =========================================================================
    // CHECK-06: Legitimate Customer Checkout Regression (Happy Path)
    // =========================================================================
    const c6Result = await page.evaluate(async () => {
      const { api, showBanner, refreshHealthAndOrders, fmtMoney } = window.__patchguardStore;
      const checkoutRes = await api('/api/checkout', {
        method: 'POST',
        body: JSON.stringify({
          items: [{ productId: 3, qty: 1 }],
          coupons: [],
        }),
      });
      let ownOrderRes = { status: 0, ok: false };
      if (checkoutRes.ok && checkoutRes.body?.order?.id) {
        ownOrderRes = await api(`/api/orders/${checkoutRes.body.order.id}`);
      }
      const ok =
        checkoutRes.status === 201 &&
        checkoutRes.body?.order?.total_cents === 18900 &&
        ownOrderRes.status === 200;

      showBanner(
        ok ? 'blocked' : 'breach',
        ok
          ? `HAPPY PATH VERIFIED · ORDER #${checkoutRes.body.order.id} PAID ${fmtMoney(checkoutRes.body.order.total_cents)}`
          : `REGRESSION FAILURE · HAPPY PATH STATUS=${checkoutRes.status} OWN=${ownOrderRes.status}`,
        { checkout: checkoutRes.body, ownOrderStatus: ownOrderRes.status }
      );
      await refreshHealthAndOrders();
      return {
        status: checkoutRes.status,
        totalCents: checkoutRes.body?.order?.total_cents ?? null,
        ownStatus: ownOrderRes.status,
        ok,
      };
    });
    const c6Shot = await snap('check06-happy.png');
    checks.push({
      id: 'CHECK-06',
      title: 'Legitimate Checkout Regression (Happy Path)',
      category: 'Functional Regression',
      passed: c6Result.ok,
      httpStatus: c6Result.status,
      leakCents: 0,
      screenshotUrl: c6Shot.url,
      screenshotPath: c6Shot.absPath,
      evidence: c6Result.ok
        ? 'Valid customer checkout created order (HTTP 201, $189.00) and owner read succeeded (HTTP 200)'
        : `Happy-path checkout regression failed (checkout=${c6Result.status}, total=${c6Result.totalCents}, read=${c6Result.ownStatus})`,
    });
    onProgress({ type: 'qa_check', runId, phase, check: checks[checks.length - 1] });
  } finally {
    await browser.close();
  }

  const dbHashAfter = computeDbHash(TARGET_DB_PATH);
  const passedCount = checks.filter((c) => c.passed).length;
  const failedCount = checks.length - passedCount;

  const report = {
    runId,
    phase,
    timestamp: new Date().toISOString(),
    durationMs: Date.now() - startedAt,
    dbHashBefore,
    dbHashAfter,
    passedCount,
    failedCount,
    totalChecks: checks.length,
    revenueLeakCents,
    checks,
  };

  onProgress({ type: 'qa_complete', runId, phase, report });
  return report;
}
