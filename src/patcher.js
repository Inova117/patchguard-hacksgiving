import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { TARGET_SERVER_PATH } from './config.js';
import { generatePatchViaLlmConnector } from './connectors.js';

/**
 * Deterministic reference patch used locally off-Sprite or as validated fallback.
 */
export function buildReferencePatchedServer() {
  return `import crypto from 'node:crypto';
import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { computeDbHash, initDb } from './db.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const STORE_HOST = '127.0.0.1';
const STORE_PORT = Number(process.env.STORE_PORT || 4100);
const DB_PATH = process.env.STORE_DB_PATH || path.join(__dirname, 'data', 'pixelmart.db');

const db = initDb(DB_PATH);
const sessions = new Map();
const app = express();

app.disable('x-powered-by');
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self' 'unsafe-inline'; img-src 'self' data:");
  next();
});

app.use(express.json({ limit: '256kb' }));
app.use(express.static(path.join(__dirname, 'public')));

function parseCookies(headerValue) {
  const out = {};
  if (!headerValue) return out;
  for (const pair of headerValue.split(';')) {
    const idx = pair.indexOf('=');
    if (idx === -1) continue;
    const key = pair.slice(0, idx).trim();
    const val = decodeURIComponent(pair.slice(idx + 1).trim());
    out[key] = val;
  }
  return out;
}

function attachUser(req, _res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies.pm_session;
  if (sid && sessions.has(sid)) {
    req.user = sessions.get(sid);
  } else {
    req.user = null;
  }
  next();
}

app.use(attachUser);

app.get('/api/health', (_req, res) => {
  const orderCount = db.prepare('SELECT COUNT(*) AS cnt FROM orders').get().cnt;
  res.json({
    ok: true,
    service: 'pixelmart',
    port: STORE_PORT,
    dbHash: computeDbHash(DB_PATH),
    orderCount,
  });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db
    .prepare('SELECT id, username, role, email FROM users WHERE username = ? AND password = ?')
    .get(String(username || ''), String(password || ''));
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const sid = crypto.randomBytes(16).toString('hex');
  sessions.set(sid, user);

  res.setHeader('Set-Cookie', \`pm_session=\${encodeURIComponent(sid)}; Path=/; HttpOnly; SameSite=Lax\`);
  return res.json({ user });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.pm_session) {
    sessions.delete(cookies.pm_session);
  }
  res.setHeader('Set-Cookie', 'pm_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax');
  return res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  return res.json({ user: req.user });
});

app.get('/api/products', (_req, res) => {
  const products = db.prepare('SELECT id, sku, name, price_cents, stock, image_tag FROM products ORDER BY id').all();
  return res.json({ products });
});

app.post('/api/checkout', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const { items = [], coupons = [], couponCode = null } = req.body || {};
  if (!Array.isArray(items) || items.length === 0) {
    return res.status(400).json({ error: 'Cart is empty' });
  }

  let subtotalCents = 0;
  const lineItems = [];
  for (const item of items) {
    const product = db
      .prepare('SELECT id, name, price_cents, stock FROM products WHERE id = ?')
      .get(Number(item.productId));
    if (!product) {
      return res.status(404).json({ error: \`Unknown product \${item.productId}\` });
    }
    const qty = Number(item.qty ?? 1);
    if (!Number.isInteger(qty) || qty <= 0 || qty > product.stock) {
      return res.status(400).json({ error: \`Invalid quantity for \${product.name}\` });
    }
    if (typeof item.unit_price_cents === 'number' && item.unit_price_cents !== product.price_cents) {
      return res.status(400).json({ error: 'Client unit price mismatch rejected; server enforces catalog price' });
    }
    // Always enforce canonical catalog price from SQLite
    const unitPriceCents = product.price_cents;
    subtotalCents += unitPriceCents * qty;
    lineItems.push({
      productId: product.id,
      name: product.name,
      qty,
      unit_price_cents: unitPriceCents,
    });
  }

  const rawCoupons = Array.isArray(coupons) && coupons.length > 0
    ? coupons
    : couponCode
      ? [couponCode]
      : [];
  const normalizedCoupons = rawCoupons.map((c) => String(c).trim().toUpperCase()).filter(Boolean);

  if (normalizedCoupons.length > 1 || new Set(normalizedCoupons).size !== normalizedCoupons.length) {
    return res.status(400).json({ error: 'Coupon stacking or duplicate coupon codes are not allowed' });
  }

  let totalDiscountPct = 0;
  let appliedCoupon = null;

  db.exec('BEGIN IMMEDIATE');
  try {
    if (normalizedCoupons.length === 1) {
      const code = normalizedCoupons[0];
      const row = db
        .prepare('SELECT code, discount_pct, max_uses, times_used FROM coupons WHERE code = ?')
        .get(code);
      if (!row) {
        db.exec('ROLLBACK');
        return res.status(400).json({ error: \`Invalid coupon \${code}\` });
      }
      const updateRes = db
        .prepare('UPDATE coupons SET times_used = times_used + 1 WHERE code = ? AND times_used < max_uses')
        .run(code);
      if (updateRes.changes !== 1) {
        db.exec('ROLLBACK');
        return res.status(409).json({ error: \`Coupon \${code} already exhausted\` });
      }
      totalDiscountPct = Math.min(row.discount_pct, 50);
      appliedCoupon = code;
    }

    const discountCents = Math.round((subtotalCents * totalDiscountPct) / 100);
    const totalCents = Math.max(0, subtotalCents - discountCents);

    const info = db
      .prepare(
        \`INSERT INTO orders
         (user_id, items_json, coupon_code, subtotal_cents, discount_cents, total_cents, status, shipping_note, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 'paid', ?, ?)\`
      )
      .run(
        req.user.id,
        JSON.stringify(lineItems),
        appliedCoupon,
        subtotalCents,
        discountCents,
        totalCents,
        \`Order by \${req.user.username}\`,
        new Date().toISOString()
      );

    db.exec('COMMIT');
    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(info.lastInsertRowid));
    return res.status(201).json({ order, dbHash: computeDbHash(DB_PATH) });
  } catch (err) {
    try {
      db.exec('ROLLBACK');
    } catch {}
    return res.status(500).json({ error: 'Checkout failed', detail: err.message });
  }
});

app.get('/api/orders', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const orders = db
    .prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC')
    .all(req.user.id);
  return res.json({ orders });
});

app.get('/api/orders/:id', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const orderId = Number(req.params.id);
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  if (order.user_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: you do not own this order' });
  }
  return res.json({ order });
});

app.get('/api/admin/orders', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin role required' });
  }
  const orders = db
    .prepare(
      \`SELECT orders.*, users.username, users.email
       FROM orders JOIN users ON users.id = orders.user_id
       ORDER BY orders.id DESC\`
    )
    .all();
  return res.json({ orders });
});

app.post('/api/admin/refund', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden: admin role required' });
  }
  const orderId = Number((req.body || {}).orderId);
  const existing = db.prepare('SELECT id FROM orders WHERE id = ?').get(orderId);
  if (!existing) {
    return res.status(404).json({ error: 'Order not found' });
  }
  db.prepare("UPDATE orders SET status = 'refunded' WHERE id = ?").run(orderId);
  const updated = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  return res.json({ ok: true, order: updated, dbHash: computeDbHash(DB_PATH) });
});

const server = app.listen(STORE_PORT, STORE_HOST, () => {
  console.log(\`[pixelmart] listening on http://\${STORE_HOST}:\${STORE_PORT}\`);
});

function shutdown() {
  server.close(() => {
    try {
      db.close();
    } catch {}
    process.exit(0);
  });
}

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
`;
}

/**
 * Compute real unified diff between two text strings using `diff -u`.
 */
export function computeUnifiedDiff(beforeText, afterText, labelA = 'a/target-store/server.js', labelB = 'b/target-store/server.js') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-diff-'));
  const fileA = path.join(dir, 'before.js');
  const fileB = path.join(dir, 'after.js');
  fs.writeFileSync(fileA, beforeText, 'utf8');
  fs.writeFileSync(fileB, afterText, 'utf8');
  try {
    execFileSync('diff', ['-u', '--label', labelA, '--label', labelB, fileA, fileB], {
      encoding: 'utf8',
    });
    return { diff: '--- identical ---', added: 0, removed: 0 };
  } catch (err) {
    const raw = typeof err.stdout === 'string' ? err.stdout : '';
    const lines = raw.split('\n');
    const added = lines.filter((l) => l.startsWith('+') && !l.startsWith('+++')).length;
    const removed = lines.filter((l) => l.startsWith('-') && !l.startsWith('---')).length;
    return { diff: raw, added, removed };
  } finally {
    try {
      fs.rmSync(dir, { recursive: true, force: true });
    } catch {}
  }
}

/**
 * Generate and apply a security patch to target-store/server.js, then restart the store.
 */
export async function applyPatch({
  qaReport,
  previousError = null,
  forceReference = false,
  hooks = {},
} = {}) {
  const beforeCode = fs.readFileSync(TARGET_SERVER_PATH, 'utf8');
  let patchResult = null;

  if (!forceReference) {
    try {
      patchResult = await generatePatchViaLlmConnector({
        vulnerableCode: beforeCode,
        qaFindings: qaReport?.checks || [],
        previousError,
      });
    } catch (err) {
      patchResult = null;
      previousError = err.message;
    }
  }

  if (!patchResult) {
    patchResult = {
      source: 'local-deterministic-verifier',
      model: 'patchguard-reference-v1',
      summary:
        'Enforced canonical catalog prices, atomic single-use coupon transactions, admin RBAC (403), order ownership IDOR protection (403), and HTTP security headers + HttpOnly/SameSite cookies.',
      fixes: [
        'CHECK-01: Enforce product.price_cents from SQLite and reject invalid qty or client price mismatches (400)',
        'CHECK-02: Reject stacked/duplicate coupons (400) and update times_used atomically inside BEGIN IMMEDIATE transaction (409)',
        'CHECK-03: Enforce req.user.role === "admin" on /api/admin/orders and /api/admin/refund (403)',
        'CHECK-04: Enforce order.user_id === req.user.id || admin on /api/orders/:id (403)',
        'CHECK-05: Add X-Content-Type-Options, X-Frame-Options, CSP headers and HttpOnly; SameSite=Lax cookies',
      ],
      patchedCode: buildReferencePatchedServer(),
      fallbackReason: previousError || 'No active Fly LLM Connector discovered (running in local mode)',
    };
  }

  if (typeof hooks.stopStore === 'function') {
    await hooks.stopStore();
  }

  fs.writeFileSync(TARGET_SERVER_PATH, patchResult.patchedCode, 'utf8');

  if (typeof hooks.startStore === 'function') {
    await hooks.startStore();
  }

  const diffStats = computeUnifiedDiff(beforeCode, patchResult.patchedCode);
  return {
    applied: true,
    source: patchResult.source,
    model: patchResult.model,
    summary: patchResult.summary,
    fixes: patchResult.fixes,
    patchedCode: patchResult.patchedCode,
    unifiedDiff: diffStats.diff,
    lineStats: { added: diffStats.added, removed: diffStats.removed },
    fallbackReason: patchResult.fallbackReason || null,
  };
}
