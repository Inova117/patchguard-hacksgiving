import { execFile, execFileSync, spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import { computeDbHash, resetSeedDb } from '../target-store/db.js';
import {
  ARTIFACTS_DIR,
  ROOT_DIR,
  SNAPSHOT_DIR,
  TARGET_DB_PATH,
  TARGET_DIR,
  TARGET_SERVER_PATH,
} from './config.js';

const execFileAsync = promisify(execFile);
const CHECKPOINTS_META_PATH = path.join(ARTIFACTS_DIR, 'checkpoints.json');

function commandExists(bin) {
  try {
    execFileSync('which', [bin], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

export function isFlySpriteEnv() {
  return commandExists('sprite-env') || fs.existsSync('/.sprite');
}

export function getRuntimeInfo() {
  const isFlySprite = isFlySpriteEnv();
  return {
    isFlySprite,
    mode: isFlySprite ? 'fly-sprite-cow' : 'local-snapshot-mirror',
    hostname: os.hostname(),
    nodeVersion: process.version,
    platform: `${process.platform}/${process.arch}`,
    spriteCheckpointsMounted: fs.existsSync('/.sprite/checkpoints'),
    uptimeSec: Math.round(process.uptime()),
  };
}

function readMeta() {
  try {
    if (fs.existsSync(CHECKPOINTS_META_PATH)) {
      return JSON.parse(fs.readFileSync(CHECKPOINTS_META_PATH, 'utf8'));
    }
  } catch {}
  return { baselineId: null, checkpoints: [] };
}

function writeMeta(meta) {
  fs.mkdirSync(ARTIFACTS_DIR, { recursive: true });
  fs.writeFileSync(CHECKPOINTS_META_PATH, JSON.stringify(meta, null, 2));
}

function parseSpriteCheckpointId(output) {
  const text = String(output || '');
  try {
    const parsed = JSON.parse(text);
    if (parsed?.id) return String(parsed.id);
  } catch {}
  const match =
    text.match(/Checkpoint\s+created:\s*(v\d+|[\w-]+)/i) ||
    text.match(/\b(v\d+)\b/);
  return match ? match[1] : `v-${Date.now()}`;
}

/**
 * Create a filesystem checkpoint (real Fly Sprite CoW snapshot or local snapshot mirror).
 */
export async function createCheckpoint(comment = 'PatchGuard baseline') {
  const started = Date.now();
  const meta = readMeta();

  if (isFlySpriteEnv() && commandExists('sprite-env')) {
    const { stdout, stderr } = await execFileAsync('sprite-env', [
      'checkpoints',
      'create',
      '--comment',
      comment,
    ]);
    const id = parseSpriteCheckpointId(`${stdout}\n${stderr}`);
    const entry = {
      id,
      comment,
      mode: 'fly-sprite-cow',
      createdAt: new Date().toISOString(),
      durationMs: Date.now() - started,
      dbHash: computeDbHash(TARGET_DB_PATH),
    };
    meta.checkpoints = [entry, ...meta.checkpoints.filter((c) => c.id !== id)];
    if (!meta.baselineId || comment.toLowerCase().includes('baseline')) {
      meta.baselineId = id;
    }
    writeMeta(meta);
    return entry;
  }

  fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
  const existing = fs.readdirSync(SNAPSHOT_DIR).filter((d) => /^local-v\d+$/.test(d));
  const nextNum =
    existing.reduce((max, name) => Math.max(max, Number(name.replace('local-v', '')) || 0), 0) + 1;
  const id = `local-v${nextNum}`;
  const snapDir = path.join(SNAPSHOT_DIR, id);
  fs.mkdirSync(snapDir, { recursive: true });

  fs.copyFileSync(TARGET_SERVER_PATH, path.join(snapDir, 'server.js'));
  fs.copyFileSync(path.join(TARGET_DIR, 'db.js'), path.join(snapDir, 'db.js'));
  if (!fs.existsSync(TARGET_DB_PATH)) {
    resetSeedDb(TARGET_DB_PATH);
  }
  fs.copyFileSync(TARGET_DB_PATH, path.join(snapDir, 'pixelmart.db'));

  const dbHash = computeDbHash(path.join(snapDir, 'pixelmart.db'));
  const entry = {
    id,
    comment,
    mode: 'local-snapshot-mirror',
    createdAt: new Date().toISOString(),
    durationMs: Date.now() - started,
    dbHash,
  };
  meta.checkpoints = [entry, ...meta.checkpoints.filter((c) => c.id !== id)];
  if (!meta.baselineId || comment.toLowerCase().includes('baseline')) {
    meta.baselineId = id;
  }
  writeMeta(meta);
  return entry;
}

/**
 * List available checkpoints from Fly Sprite runtime or local snapshot mirror.
 */
export async function listCheckpoints() {
  const meta = readMeta();

  if (isFlySpriteEnv() && commandExists('sprite-env')) {
    try {
      const { stdout } = await execFileAsync('sprite-env', ['checkpoints', 'list']);
      const metaById = new Map(meta.checkpoints.map((c) => [c.id, c]));
      const items = [];
      const lines = stdout.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);

      for (const line of lines) {
        if (/^(ID|NAME|---)/i.test(line)) continue;
        const m = line.match(/\b(v\d+|auto-[\w-]+)\b/);
        if (m) {
          const id = m[1];
          const known = metaById.get(id);
          items.push({
            id,
            comment: known?.comment || line,
            mode: 'fly-sprite-cow',
            createdAt: known?.createdAt || null,
            dbHash: known?.dbHash || null,
          });
        }
      }
      if (items.length > 0) {
        return {
          mode: 'fly-sprite-cow',
          baselineId: meta.baselineId || items[0].id,
          checkpoints: items,
        };
      }
    } catch {}
  }

  const localDirs = fs.existsSync(SNAPSHOT_DIR)
    ? fs.readdirSync(SNAPSHOT_DIR).filter((d) => /^local-v\d+$/.test(d))
    : [];
  const metaById = new Map(meta.checkpoints.map((c) => [c.id, c]));
  const items = localDirs
    .sort((a, b) => Number(b.replace('local-v', '')) - Number(a.replace('local-v', '')))
    .map((id) => {
      const known = metaById.get(id);
      return (
        known || {
          id,
          comment: 'Local filesystem mirror snapshot',
          mode: 'local-snapshot-mirror',
          createdAt: null,
          dbHash: computeDbHash(path.join(SNAPSHOT_DIR, id, 'pixelmart.db')),
        }
      );
    });

  return {
    mode: isFlySpriteEnv() ? 'fly-sprite-cow' : 'local-snapshot-mirror',
    baselineId: meta.baselineId || (items[0]?.id ?? null),
    checkpoints: items,
  };
}

/**
 * Diff a live workspace file against its read-only checkpoint copy.
 */
export async function diffAgainstCheckpoint(checkpointId, relPath = 'target-store/server.js') {
  const safeRel = relPath.replace(/^\/+/, '');
  const liveFile = path.resolve(ROOT_DIR, safeRel);
  if (!liveFile.startsWith(ROOT_DIR)) {
    throw new Error('Invalid diff path');
  }

  let snapFile = null;
  if (isFlySpriteEnv()) {
    const spriteMountCandidate = path.join('/.sprite/checkpoints', checkpointId, liveFile);
    if (fs.existsSync(spriteMountCandidate)) {
      snapFile = spriteMountCandidate;
    }
  }
  if (!snapFile) {
    const localCandidate = path.join(SNAPSHOT_DIR, checkpointId, path.basename(liveFile));
    if (fs.existsSync(localCandidate)) {
      snapFile = localCandidate;
    }
  }

  if (!snapFile || !fs.existsSync(liveFile)) {
    return {
      checkpointId,
      relPath: safeRel,
      available: false,
      diff: `Snapshot file not found for ${checkpointId}:${safeRel}`,
    };
  }

  try {
    await execFileAsync('diff', ['-u', snapFile, liveFile]);
    return {
      checkpointId,
      relPath: safeRel,
      available: true,
      identical: true,
      diff: '--- identical (0 lines changed) ---',
    };
  } catch (err) {
    if (err.code === 1 && typeof err.stdout === 'string') {
      return {
        checkpointId,
        relPath: safeRel,
        available: true,
        identical: false,
        diff: err.stdout,
      };
    }
    throw err;
  }
}

/**
 * Restore filesystem from checkpoint.
 * On Fly Sprite, schedules restore slightly after HTTP response flushes so the browser can time reconnection.
 */
export async function restoreCheckpoint(checkpointId, hooks = {}) {
  const started = Date.now();
  const targetId = checkpointId || readMeta().baselineId;
  if (!targetId) {
    throw new Error('No checkpoint ID available to restore');
  }

  if (isFlySpriteEnv() && commandExists('sprite-env') && !targetId.startsWith('local-')) {
    setTimeout(() => {
      try {
        const child = spawn('sprite-env', ['checkpoints', 'restore', targetId], {
          detached: true,
          stdio: 'ignore',
        });
        child.unref();
      } catch {}
    }, 150);

    return {
      restoring: true,
      restored: false,
      mode: 'fly-sprite-cow',
      checkpointId: targetId,
      message: `Triggered CoW restore to ${targetId}; Sprite VM restarting`,
    };
  }

  const snapDir = path.join(SNAPSHOT_DIR, targetId);
  if (!fs.existsSync(snapDir)) {
    throw new Error(`Checkpoint ${targetId} not found`);
  }

  if (typeof hooks.stopStore === 'function') {
    await hooks.stopStore();
  }

  fs.copyFileSync(path.join(snapDir, 'server.js'), TARGET_SERVER_PATH);
  fs.copyFileSync(path.join(snapDir, 'db.js'), path.join(TARGET_DIR, 'db.js'));
  for (const suffix of ['', '-wal', '-shm', '-journal']) {
    const f = `${TARGET_DB_PATH}${suffix}`;
    if (fs.existsSync(f)) fs.unlinkSync(f);
  }
  fs.mkdirSync(path.dirname(TARGET_DB_PATH), { recursive: true });
  fs.copyFileSync(path.join(snapDir, 'pixelmart.db'), TARGET_DB_PATH);

  if (typeof hooks.startStore === 'function') {
    await hooks.startStore();
  }

  return {
    restoring: false,
    restored: true,
    mode: 'local-snapshot-mirror',
    checkpointId: targetId,
    durationMs: Date.now() - started,
    dbHash: computeDbHash(TARGET_DB_PATH),
  };
}

/**
 * Verify zero raw credentials exist in process environment or standard credential files.
 * Never exposes secret values.
 */
export function auditZeroSecrets() {
  const sensitivePattern = /(TOKEN|KEY|SECRET|PASSWORD|AUTH|GITHUB|OPENROUTER|OLLAMA|FLY_API|API_KEY)/i;
  const ignoredSafeVars = new Set(['SSH_AUTH_SOCK', 'XAUTHORITY']);
  const envKeys = Object.keys(process.env);
  const sensitiveEnvKeys = envKeys.filter(
    (k) =>
      !ignoredSafeVars.has(k) &&
      !k.startsWith('T3_ACP_') &&
      sensitivePattern.test(k) &&
      Boolean(process.env[k])
  );

  const candidateFiles = [
    path.join(ROOT_DIR, '.env'),
    path.join(ROOT_DIR, '.git-credentials'),
    ...(isFlySpriteEnv()
      ? [path.join(os.homedir(), '.netrc'), path.join(os.homedir(), '.git-credentials')]
      : []),
  ];
  const secretFilesFound = candidateFiles.filter((f) => fs.existsSync(f)).map((f) => path.basename(f));

  const zeroSecretsVerified = sensitiveEnvKeys.length === 0 && secretFilesFound.length === 0;
  return {
    zeroSecretsVerified,
    sensitiveEnvKeys,
    totalEnvVars: envKeys.length,
    secretFilesFound,
    attestation: zeroSecretsVerified
      ? '0 raw API keys/tokens in Sprite env or credential files'
      : `Found ${sensitiveEnvKeys.length} sensitive env keys / ${secretFilesFound.length} credential files`,
  };
}
