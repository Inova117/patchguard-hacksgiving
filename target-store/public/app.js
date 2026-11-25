function apiUrl(rel) {
  const path = window.location.pathname;
  const base = path.endsWith('/') ? path : path.replace(/\/[^/]*$/, '/');
  return `${base}${rel.replace(/^\//, '')}`;
}

function fmtMoney(cents) {
  return `$${(Number(cents || 0) / 100).toLocaleString('en-US', {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

const state = {
  user: null,
  products: [],
  cart: [],
  coupons: [],
};

async function api(rel, opts = {}) {
  const res = await fetch(apiUrl(rel), {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  let body = null;
  try {
    body = await res.json();
  } catch {
    body = { raw: await res.text() };
  }
  return { status: res.status, ok: res.ok, body };
}

function showBanner(kind, title, details) {
  const banner = document.getElementById('resultBanner');
  banner.className = `banner show ${kind}`;
  document.getElementById('bannerTitle').textContent = title;
  document.getElementById('bannerBody').textContent =
    typeof details === 'string' ? details : JSON.stringify(details, null, 2);
}

function renderProducts() {
  const grid = document.getElementById('productsGrid');
  grid.innerHTML = '';
  for (const p of state.products) {
    const row = document.createElement('div');
    row.className = 'product-card';
    row.innerHTML = `
      <div>
        <div class="product-name">${p.name}</div>
        <div class="product-sku">${p.sku} · Stock: ${p.stock}</div>
      </div>
      <div style="display:flex;align-items:center;">
        <span class="product-price">${fmtMoney(p.price_cents)}</span>
        <button data-testid="add-product-${p.id}">Add to Cart</button>
      </div>
    `;
    row.querySelector('button').addEventListener('click', () => {
      const existing = state.cart.find((c) => c.productId === p.id);
      if (existing) {
        existing.qty += 1;
      } else {
        state.cart.push({
          productId: p.id,
          name: p.name,
          qty: 1,
          unit_price_cents: p.price_cents,
        });
      }
      renderCart();
    });
    grid.appendChild(row);
  }
}

function renderCart() {
  const list = document.getElementById('cartList');
  const couponWrap = document.getElementById('appliedCoupons');
  list.innerHTML = '';
  couponWrap.innerHTML = '';

  if (state.cart.length === 0) {
    list.innerHTML = '<div class="badge">Cart is empty — add an item</div>';
  } else {
    for (const item of state.cart) {
      const row = document.createElement('div');
      row.className = 'cart-item';
      row.innerHTML = `
        <span>${item.qty}× ${item.name}</span>
        <strong>${fmtMoney(item.unit_price_cents * item.qty)}</strong>
      `;
      list.appendChild(row);
    }
  }

  for (const code of state.coupons) {
    const tag = document.createElement('span');
    tag.className = 'badge live';
    tag.textContent = `Coupon: ${code}`;
    couponWrap.appendChild(tag);
  }

  const subtotal = state.cart.reduce((s, i) => s + i.unit_price_cents * i.qty, 0);
  const pct = Math.min(state.coupons.length * 25, 100);
  const discount = Math.round((subtotal * pct) / 100);
  const total = Math.max(0, subtotal - discount);

  document.getElementById('subtotalText').textContent = fmtMoney(subtotal);
  document.getElementById('discountText').textContent = `-${fmtMoney(discount)} (${pct}%)`;
  document.getElementById('totalText').textContent = fmtMoney(total);
}

async function refreshHealthAndOrders() {
  const h = await api('/api/health');
  if (h.ok && h.body.dbHash) {
    document.getElementById('dbHashBadge').textContent =
      `DB SHA-256: ${h.body.dbHash.slice(0, 12)}… (${h.body.orderCount} orders)`;
  }
  const me = await api('/api/me');
  state.user = me.ok ? me.body.user : null;
  document.getElementById('userBadge').textContent = state.user
    ? `${state.user.username} (${state.user.role})`
    : 'Not logged in';

  const tbody = document.getElementById('ordersTableBody');
  tbody.innerHTML = '';
  if (state.user) {
    const ord = await api('/api/orders');
    if (ord.ok && Array.isArray(ord.body.orders)) {
      for (const o of ord.body.orders.slice(0, 8)) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>#${o.id}</td>
          <td>user:${o.user_id}</td>
          <td>${o.coupon_code || '—'}</td>
          <td>${fmtMoney(o.total_cents)}</td>
          <td>${o.status}</td>
        `;
        tbody.appendChild(tr);
      }
    }
  }
}

async function loginAs(username, password) {
  const r = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
  await refreshHealthAndOrders();
  return r;
}

document.getElementById('loginAliceBtn').addEventListener('click', () => loginAs('alice', 'alice123'));
document.getElementById('loginAdminBtn').addEventListener('click', () => loginAs('admin', 'admin123'));
document.getElementById('logoutBtn').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' });
  await refreshHealthAndOrders();
});

document.getElementById('applyCouponBtn').addEventListener('click', () => {
  const val = document.getElementById('couponInput').value.trim().toUpperCase();
  if (val) {
    state.coupons.push(val);
    document.getElementById('couponInput').value = '';
    renderCart();
  }
});

document.getElementById('checkoutBtn').addEventListener('click', async () => {
  const res = await api('/api/checkout', {
    method: 'POST',
    body: JSON.stringify({ items: state.cart, coupons: state.coupons }),
  });
  if (res.ok) {
    const order = res.body.order;
    showBanner(
      order.total_cents < order.subtotal_cents && state.coupons.length > 1
        ? 'breach'
        : 'info',
      `HTTP ${res.status} · ORDER #${order.id} CONFIRMED — PAID ${fmtMoney(order.total_cents)}`,
      res.body
    );
    state.cart = [];
    state.coupons = [];
    renderCart();
  } else {
    showBanner('blocked', `HTTP ${res.status} · CHECKOUT REJECTED`, res.body);
  }
  await refreshHealthAndOrders();
});

document.getElementById('probeAdminBtn').addEventListener('click', async () => {
  const res = await api('/api/admin/orders');
  showBanner(
    res.ok ? 'breach' : 'blocked',
    `GET /api/admin/orders → HTTP ${res.status}`,
    res.body
  );
});

document.getElementById('probeIdorBtn').addEventListener('click', async () => {
  const res = await api('/api/orders/1002');
  showBanner(
    res.ok ? 'breach' : 'blocked',
    `GET /api/orders/1002 → HTTP ${res.status}`,
    res.body
  );
});

document.getElementById('refreshOrdersBtn').addEventListener('click', refreshHealthAndOrders);

// Expose lightweight hook for PatchGuard headless Playwright QA assertions to trigger real browser fetch & render
window.__patchguardStore = {
  state,
  api,
  showBanner,
  refreshHealthAndOrders,
  renderCart,
  fmtMoney,
};

async function boot() {
  const prod = await api('/api/products');
  if (prod.ok) {
    state.products = prod.body.products;
    renderProducts();
  }
  renderCart();
  await refreshHealthAndOrders();
}

boot();
