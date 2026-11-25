import crypto from 'node:crypto';
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

  // NOTE: Missing HttpOnly and SameSite flags in initial build
  res.setHeader('Set-Cookie', `pm_session=${encodeURIComponent(sid)}; Path=/`);
  return res.json({ user });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  if (cookies.pm_session) {
    sessions.delete(cookies.pm_session);
  }
  res.setHeader('Set-Cookie', 'pm_session=; Path=/; Max-Age=0');
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
      return res.status(404).json({ error: `Unknown product ${item.productId}` });
    }
    const qty = Number(item.qty || 1);
    // BUG 1: Trusts client-supplied unit_price_cents instead of enforcing catalog price_cents
    const unitPriceCents =
      typeof item.unit_price_cents === 'number' ? item.unit_price_cents : product.price_cents;
    subtotalCents += unitPriceCents * qty;
    lineItems.push({
      productId: product.id,
      name: product.name,
      qty,
      unit_price_cents: unitPriceCents,
    });
  }

  const requestedCoupons = Array.isArray(coupons) && coupons.length > 0
    ? coupons
    : couponCode
      ? [couponCode]
      : [];

  let totalDiscountPct = 0;
  // BUG 2: Stacks repeated coupon codes and performs non-atomic usage check
  for (const code of requestedCoupons) {
    const row = db
      .prepare('SELECT code, discount_pct, max_uses, times_used FROM coupons WHERE code = ?')
      .get(String(code).toUpperCase());
    if (!row) {
      return res.status(400).json({ error: `Invalid coupon ${code}` });
    }
    if (row.times_used >= row.max_uses) {
      return res.status(409).json({ error: `Coupon ${row.code} already exhausted` });
    }
    totalDiscountPct += row.discount_pct;
  }

  const clampedPct = Math.min(totalDiscountPct, 100);
  const discountCents = Math.round((subtotalCents * clampedPct) / 100);
  const totalCents = Math.max(0, subtotalCents - discountCents);

  if (requestedCoupons.length > 0) {
    const uniqueCodes = [...new Set(requestedCoupons.map((c) => String(c).toUpperCase()))];
    const incStmt = db.prepare('UPDATE coupons SET times_used = times_used + 1 WHERE code = ?');
    for (const c of uniqueCodes) {
      incStmt.run(c);
    }
  }

  const info = db
    .prepare(
      `INSERT INTO orders
       (user_id, items_json, coupon_code, subtotal_cents, discount_cents, total_cents, status, shipping_note, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'paid', ?, ?)`
    )
    .run(
      req.user.id,
      JSON.stringify(lineItems),
      requestedCoupons.join(',') || null,
      subtotalCents,
      discountCents,
      totalCents,
      `Order by ${req.user.username}`,
      new Date().toISOString()
    );

  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(info.lastInsertRowid));
  return res.status(201).json({ order, dbHash: computeDbHash(DB_PATH) });
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
  // BUG 4: Missing ownership check (order.user_id === req.user.id || req.user.role === 'admin')
  const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
  if (!order) {
    return res.status(404).json({ error: 'Order not found' });
  }
  return res.json({ order });
});

app.get('/api/admin/orders', (req, res) => {
  // BUG 3: Checks authentication only; missing req.user.role === 'admin' check
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  const orders = db
    .prepare(
      `SELECT orders.*, users.username, users.email
       FROM orders JOIN users ON users.id = orders.user_id
       ORDER BY orders.id DESC`
    )
    .all();
  return res.json({ orders });
});

app.post('/api/admin/refund', (req, res) => {
  // BUG 3: Checks authentication only; missing req.user.role === 'admin' check
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
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
  console.log(`[pixelmart] listening on http://${STORE_HOST}:${STORE_PORT}`);
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
