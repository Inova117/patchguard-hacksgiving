# PatchGuard — 60-Second Hacksgiving Demo Script

## Video Recording Flow (0:00 – 1:00)

- **0:00 – 0:08 (Cold Hook):**
  - Open the live `https://patchguard-<org>.sprites.app` URL (wakes Sprite from `$0` idle in ~1s).
  - Click **▶ Run Autonomous Self-Heal Loop**.
- **0:08 – 0:24 (Real Headless Chromium Exploit Proof):**
  - Step 1 takes a live **Fly Sprite CoW Checkpoint (`v1`)**.
  - Step 2 launches real headless Chromium against PixelMart (`127.0.0.1:4100`), detects **5/5 security failures** (`$1,298.99` checkout leak + `4x` coupon stacking + Admin/IDOR `200 OK`), and mutates `pixelmart.db` (`CLEAN -> MODIFIED`).
  - Click the `CHECK-01` thumbnail briefly to show the red `BREACH DETECTED: PAID $0.01 FOR $1,299.00 MACBOOK PRO` screenshot.
- **0:24 – 0:36 (1-Second Sprite Time-Travel Restore):**
  - Step 3 triggers `sprite-env checkpoints restore` — UI stopwatch ticks live (`~1.1s`), reconnects automatically, and `pixelmart.db` SHA-256 snaps back to `CLEAN`.
- **0:36 – 0:50 (Zero-Secret LLM Patch + 6/6 Re-Verification):**
  - Step 4 calls the **OpenRouter / Ollama Connector** (highlight **Zero-Secret Verified: 0 keys in env**), writes the fix, and renders the green/red unified diff.
  - Step 5 re-runs real Chromium QA → **6/6 PASS**, `$0.00` revenue leak.
- **0:50 – 1:00 (403 Guardrail Proof & Verified GitHub PR):**
  - Switch to **Zero-Secret Vault** tab → click **Run Live 403 Guardrail Proof** (`GET /repos/... -> 200 OK`, `GET /user/keys -> 403 Forbidden`) and open the **Verified GitHub PR** created with zero tokens inside the Sprite.

---

## Social Post Template (X / Bluesky / LinkedIn)

> Built **PatchGuard** for @flydotio #Hacksgiving!
>
> Instead of asking an LLM to "guess" bugs from text, PatchGuard lives in a Fly Sprite, boots our store + headless Chromium, proves real checkout & access-control leaks (`$1,299 -> $0.01`) with screenshots, time-travels the dirty Linux disk back in ~1s via CoW Checkpoints, generates a patch via Zero-Secret Connectors (0 API keys on disk, `/user/keys` blocked `403`), re-verifies 6/6 in Chromium, and opens a verified GitHub PR.
>
> Code: https://github.com/Inova117/patchguard-hacksgiving
> Live Sprite: https://patchguard-b6xzj.sprites.app
