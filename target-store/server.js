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

app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  res.setHeader("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; frame-ancestors 'self'; img-src 'self' data:");
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

  res.setHeader('Set-Cookie', `pm_session=${encodeURIComponent(sid)}; Path=/; HttpOnly; SameSite=Lax`);
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
  return res.json({ user: req.user || null });
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
    if (item.unit_price_cents !== undefined && item.unit_price_cents !== product.price_cents) {
      return res.status(400).json({ error: 'Price tampering detected' });
    }
    if (!Number.isInteger(qty) || qty <= 0 || qty > product.stock) {
      return res.status(400).json({ error: 'Invalid quantity' });
    }
    const unitPriceCents = product.price_cents;
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

  if (requestedCoupons.length > 1) {
    return res.status(400).json({ error: 'Only one coupon allowed per order' });
  }

  let totalDiscountPct = 0;
  db.exec("BEGIN IMMEDIATE");
  try {
    for (const code of requestedCoupons) {
      const row = db
        .prepare('SELECT code, discount_pct, max_uses, times_used FROM coupons WHERE code = ?')
        .get(String(code).toUpperCase());
      if (!row) {
        db.exec("ROLLBACK");
        return res.status(400).json({ error: `Invalid coupon ${code}` });
      }
      const result = db.prepare('UPDATE coupons SET times_used = times_used + 1 WHERE code = ? AND times_used < max_uses').run(String(code).toUpperCase());
      if (result.changes !== 1) {
        db.exec("ROLLBACK");
        return res.status(409).json({ error: `Coupon ${row.code} already exhausted` });
      }
      totalDiscountPct += row.discount_pct;
    }

    const clampedPct = Math.min(totalDiscountPct, 100);
    const discountCents = Math.round((subtotalCents * clampedPct) / 100);
    const totalCents = Math.max(0, subtotalCents - discountCents);

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

    db.exec("COMMIT");

    const order = db.prepare('SELECT * FROM orders WHERE id = ?').get(Number(info.lastInsertRowid));
    return res.status(201).json({ order, dbHash: computeDbHash(DB_PATH) });
  } catch (err) {
    db.exec("ROLLBACK");
    return res.status(500).json({ error: 'Checkout failed' });
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
  if (order.user_id !== req.user.id && req.user.role !== "admin") {
    return res.status(403).json({ error: 'Forbidden' });
  }
  return res.json({ order });
});

app.get('/api/admin/orders', (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: 'Forbidden' });
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
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required' });
  }
  if (req.user.role !== "admin") {
    return res.status(403).json({ error: 'Forbidden' });
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
