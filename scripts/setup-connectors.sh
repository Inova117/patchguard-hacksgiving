#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:$HOME/.fly/bin:$PATH"
REPO_OWNER="${GITHUB_OWNER:-Inova117}"
REPO_NAME="${GITHUB_REPO:-patchguard-hacksgiving}"

# Obtain Sprites API token from env or local CLI config
TOKEN="${SPRITES_TOKEN:-}"
if [ -z "$TOKEN" ] && [ -f "$HOME/.sprites/sprites.json" ]; then
  TOKEN="$(jq -r '.urls["https://api.sprites.dev"].orgs | to_entries[0].value.token // empty' "$HOME/.sprites/sprites.json" 2>/dev/null || true)"
fi

if [ -z "$TOKEN" ]; then
  echo "SPRITES_TOKEN is not set and keyring token cannot be read from ~/.sprites/sprites.json."
  echo "Run: sprite org keyring disable  (or export SPRITES_TOKEN=<your-token>) and re-run."
  exit 1
fi

API="https://api.sprites.dev"

echo "==> 1. Provisioning Fly Managed OpenRouter Connector (Zero-Secret LLM)..."
OR_RES="$(curl -sS -X POST "$API/v1/oauth/connections/provision" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"provider":"openrouter"}')"
echo "$OR_RES"

echo "==> 2. Listing Connections (OpenAPI ConnectionListResponse)..."
CONNS="$(curl -sS "$API/v1/oauth/connections" -H "Authorization: Bearer $TOKEN")"
echo "$CONNS" | jq . 2>/dev/null || echo "$CONNS"

OR_ID="$(echo "$OR_RES" | jq -r '.id // .connection_id // .connection.id // empty' 2>/dev/null || true)"
if [ -z "$OR_ID" ]; then
  OR_ID="$(echo "$CONNS" | jq -r '(.connections // .)[]? | select(.provider=="openrouter") | (.id // .connection_id)' 2>/dev/null | head -n1 || true)"
fi
if [ -n "$OR_ID" ]; then
  echo "==> Restricting OpenRouter Connector ($OR_ID) to sprite_labels: [\"llm\"]..."
  curl -sS -X PUT "$API/v1/oauth/connections/$OR_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"access_policy":{"sprite_labels":["llm"]}}' | jq .
fi

GH_ID="$(echo "$CONNS" | jq -r '(.connections // .)[]? | select(.provider=="github") | (.id // .connection_id)' 2>/dev/null | head -n1 || true)"

if [ -n "$GH_ID" ]; then
  echo "==> Applying strict Zero-Secret GitHub path-scoping on Connector $GH_ID..."
  curl -sS -X PUT "$API/v1/oauth/connections/$GH_ID" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d "{
      \"access_policy\": {
        \"sprite_labels\": [\"github\"],
        \"allowed_endpoints\": [
          \"/user\",
          \"/repos/$REPO_OWNER/$REPO_NAME*\"
        ],
        \"blocked_endpoints\": [
          \"/user/keys*\",
          \"/repos/$REPO_OWNER/$REPO_NAME/git/refs/heads/main\",
          \"/orgs/*\"
        ]
      }
    }" | jq .
else
  echo "==> Starting GitHub OAuth flow..."
  AUTH_JSON="$(curl -sS "$API/v1/oauth/github/authorize?scopes=repo,read:org" \
    -H "Authorization: Bearer $TOKEN")"
  echo "$AUTH_JSON"
  echo "Open the authorize_url above in your browser, approve GitHub, then re-run this script to apply path-scoping."
fi
