#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.fly/bin:$PATH"
SPRITE_NAME="${SPRITE_NAME:-patchguard}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v sprite >/dev/null 2>&1; then
  echo "Error: sprite CLI not found. Install via: curl -fsSL https://sprites.dev/install.sh | bash" >&2
  exit 1
fi

echo "==> Checking existing Fly Sprites..."
if ! sprite list 2>/dev/null | grep -qw "$SPRITE_NAME"; then
  echo "==> Creating Sprite '$SPRITE_NAME' with labels patchguard, github, llm..."
  sprite create "$SPRITE_NAME" --skip-console --label patchguard --label github --label llm
else
  echo "==> Reusing existing Sprite '$SPRITE_NAME'"
fi

echo "==> Syncing PatchGuard workspace into /home/sprite/patchguard..."
sprite exec -s "$SPRITE_NAME" -- mkdir -p /home/sprite/patchguard
tar -C "$ROOT_DIR" \
  --exclude=node_modules \
  --exclude=artifacts \
  --exclude=.git \
  --exclude='target-store/data/*.db*' \
  --exclude='target-store/.clean-snapshot' \
  --exclude='target-store/.patched-backup' \
  -czf - . | sprite exec -s "$SPRITE_NAME" -- tar -xzf - -C /home/sprite/patchguard

echo "==> Installing dependencies, Playwright Chromium, and running E2E tests inside Sprite..."
sprite exec -s "$SPRITE_NAME" -- bash -lc '
  set -euo pipefail
  cd /home/sprite/patchguard
  node -v
  node -e "import(\"node:sqlite\").then(() => console.log(\"node:sqlite OK\"))"
  npm install --omit=dev
  npx playwright install chromium
  (sudo npx playwright install-deps chromium || npx playwright install-deps chromium || true)
  npm test
'

echo "==> Creating clean baseline CoW Checkpoint..."
sprite exec -s "$SPRITE_NAME" -- bash -lc '
  cd /home/sprite/patchguard
  sprite-env checkpoints create --comment "v-baseline-clean"
'

echo "==> Registering wake-on-HTTP Sprite service on port 8080..."
sprite exec -s "$SPRITE_NAME" -- bash -lc '
  cd /home/sprite/patchguard
  sprite-env services delete patchguard 2>/dev/null || true
  sprite-env services create patchguard \
    --cmd node \
    --args "--no-warnings,src/server.js" \
    --dir /home/sprite/patchguard \
    --http-port 8080 \
    --no-stream
'

echo "==> Publishing public Sprite URL..."
sprite url update --auth public -s "$SPRITE_NAME"
URL_OUT="$(sprite url -s "$SPRITE_NAME")"
echo "$URL_OUT"
PUBLIC_URL="$(echo "$URL_OUT" | grep -Eo 'https://[^[:space:]]+' | head -n1 || true)"

if [ -n "$PUBLIC_URL" ]; then
  echo "==> Probing live Sprite URL: $PUBLIC_URL/api/health"
  sleep 2
  curl -fsS "$PUBLIC_URL/api/health" | jq . || curl -fsS "$PUBLIC_URL/api/health"
fi
