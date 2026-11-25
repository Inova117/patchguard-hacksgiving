import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

/**
 * Initialize SQLite schema for PixelMart and seed baseline records if empty.
 */
export function initDb(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  const db = new DatabaseSync(dbPath);
  db.exec(`
    PRAGMA journal_mode = DELETE;
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL,
      email TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS products (
      id INTEGER PRIMARY KEY,
      sku TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      price_cents INTEGER NOT NULL,
      stock INTEGER NOT NULL,
      image_tag TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS coupons (
      code TEXT PRIMARY KEY,
      discount_pct INTEGER NOT NULL,
      max_uses INTEGER NOT NULL,
      times_used INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      items_json TEXT NOT NULL,
      coupon_code TEXT,
      subtotal_cents INTEGER NOT NULL,
      discount_cents INTEGER NOT NULL,
      total_cents INTEGER NOT NULL,
      status TEXT NOT NULL,
      shipping_note TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
  `);

  const userCount = db.prepare('SELECT COUNT(*) AS cnt FROM users').get().cnt;
  if (userCount === 0) {
    seedBaselineData(db);
  }
  return db;
}

/**
 * Populate deterministic seed users, products, coupons, and orders.
 */
export function seedBaselineData(db) {
  db.exec('DELETE FROM orders; DELETE FROM coupons; DELETE FROM products; DELETE FROM users;');

  const insertUser = db.prepare(
    'INSERT INTO users (id, username, password, role, email) VALUES (?, ?, ?, ?, ?)'
  );
  insertUser.run(1, 'alice', 'alice123', 'customer', 'alice@pixelmart.local');
  insertUser.run(2, 'bob', 'bob123', 'customer', 'bob@pixelmart.local');
  insertUser.run(3, 'admin', 'admin123', 'admin', 'secops@pixelmart.local');

  const insertProduct = db.prepare(
    'INSERT INTO products (id, sku, name, price_cents, stock, image_tag) VALUES (?, ?, ?, ?, ?, ?)'
  );
  insertProduct.run(1, 'PM-MBP16', 'MacBook Pro 16" M4', 129900, 15, 'laptop');
  insertProduct.run(2, 'PM-STD5K', 'Studio Display 5K', 159900, 8, 'display');
  insertProduct.run(3, 'PM-KB01', 'Mechanical Split Keyboard', 18900, 40, 'keyboard');

  const insertCoupon = db.prepare(
    'INSERT INTO coupons (code, discount_pct, max_uses, times_used) VALUES (?, ?, ?, ?)'
  );
  insertCoupon.run('HACKS25', 25, 1, 0);

  const insertOrder = db.prepare(
    `INSERT INTO orders
     (id, user_id, items_json, coupon_code, subtotal_cents, discount_cents, total_cents, status, shipping_note, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  );
  insertOrder.run(
    1001,
    1,
    JSON.stringify([{ productId: 3, name: 'Mechanical Split Keyboard', qty: 1, unit_price_cents: 18900 }]),
    null,
    18900,
    0,
    18900,
    'paid',
    'Deliver to Alice Lab Desk 4',
    '2026-11-25T10:00:00Z'
  );
  insertOrder.run(
    1002,
    2,
    JSON.stringify([{ productId: 2, name: 'Studio Display 5K', qty: 1, unit_price_cents: 159900 }]),
    null,
    159900,
    0,
    159900,
    'paid',
    'PRIVATE: Bob Smith - 742 Evergreen Terrace, Apt 9B - bob@pixelmart.local',
    '2026-11-25T11:30:00Z'
  );
}

/**
 * Reset SQLite database cleanly to exact deterministic seed bytes.
 */
export function resetSeedDb(dbPath) {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true });
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    const f = `${dbPath}${suffix}`;
    if (fs.existsSync(f)) {
      fs.unlinkSync(f);
    }
  }
  const db = initDb(dbPath);
  db.close();
  return computeDbHash(dbPath);
}

/**
 * Compute deterministic SHA-256 of the SQLite database file on disk.
 */
export function computeDbHash(dbPath) {
  if (!fs.existsSync(dbPath)) {
    return null;
  }
  const buf = fs.readFileSync(dbPath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}
