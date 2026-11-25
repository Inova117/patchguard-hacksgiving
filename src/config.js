import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const ROOT_DIR = path.resolve(__dirname, '..');
export const TARGET_DIR = path.join(ROOT_DIR, 'target-store');
export const TARGET_SERVER_PATH = path.join(TARGET_DIR, 'server.js');
export const TARGET_DB_PATH = path.join(TARGET_DIR, 'data', 'pixelmart.db');
export const ARTIFACTS_DIR = path.join(ROOT_DIR, 'artifacts');
export const SNAPSHOT_DIR = path.join(TARGET_DIR, '.clean-snapshot');

export const PORT = Number(process.env.PORT || 8080);
export const STORE_PORT = Number(process.env.STORE_PORT || 4100);
export const STORE_URL = `http://127.0.0.1:${STORE_PORT}`;

export const REPO_OWNER = process.env.GITHUB_OWNER || 'Inova117';
export const REPO_NAME = process.env.GITHUB_REPO || 'patchguard-hacksgiving';

/**
 * Enforce strict loopback-only QA target safety invariant.
 */
export function assertLocalTargetUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid target URL: ${rawUrl}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported target protocol: ${parsed.protocol}`);
  }
  if (parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
    throw new Error(
      `Safety invariant violation: PatchGuard QA only runs against loopback targets (127.0.0.1 / localhost), got "${parsed.hostname}"`
    );
  }
  return parsed.toString().replace(/\/$/, '');
}
