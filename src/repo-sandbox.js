import { execFile } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

const STATIC_RULES = [
  {
    id: 'HYGIENE-01',
    severity: 'high',
    title: 'Potential client-side price/amount trust',
    regex: /req\.body\.[a-zA-Z0-9_]*(price|total|amount|discount)/g,
  },
  {
    id: 'HYGIENE-02',
    severity: 'high',
    title: 'Missing role check in admin route handler',
    regex: /\/admin\/[a-zA-Z0-9_-]+/g,
  },
  {
    id: 'HYGIENE-03',
    severity: 'medium',
    title: 'Permissive wildcard CORS policy',
    regex: /Access-Control-Allow-Origin['"`:\s]+\*/g,
  },
  {
    id: 'HYGIENE-04',
    severity: 'high',
    title: 'Dynamic eval / unsafe execution call',
    regex: /\b(eval|new Function)\s*\(/g,
  },
  {
    id: 'HYGIENE-05',
    severity: 'medium',
    title: 'Hardcoded secret-like assignment',
    regex: /(SECRET|API_KEY|PRIVATE_KEY|PASSWORD)\s*[:=]\s*['"`][A-Za-z0-9_\-]{12,}['"`]/g,
  },
];

function walkFiles(dir, acc = [], depth = 0) {
  if (depth > 4 || acc.length > 200) return acc;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const e of entries) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === 'dist') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) {
      walkFiles(full, acc, depth + 1);
    } else if (/\.(js|mjs|cjs|ts|tsx|jsx)$/.test(e.name)) {
      acc.push(full);
    }
  }
  return acc;
}

/**
 * Shallow-clone a public GitHub repository into an isolated /tmp sandbox and run defensive hygiene checks.
 */
export async function auditPublicRepo(repoUrl) {
  let parsed;
  try {
    parsed = new URL(repoUrl);
  } catch {
    throw new Error('Invalid GitHub repository URL');
  }
  if (parsed.hostname !== 'github.com') {
    throw new Error('Only public https://github.com/<owner>/<repo> URLs are supported');
  }
  const parts = parsed.pathname.replace(/^\/|\.git$/g, '').split('/').filter(Boolean);
  if (parts.length < 2) {
    throw new Error('Expected URL format: https://github.com/<owner>/<repo>');
  }

  const slug = `${parts[0]}-${parts[1]}`.replace(/[^a-zA-Z0-9_-]/g, '');
  const sandboxRoot = '/tmp/patchguard-sandbox';
  fs.mkdirSync(sandboxRoot, { recursive: true });
  const repoDir = path.join(sandboxRoot, `${slug}-${Date.now()}`);

  const cloneUrl = `https://github.com/${parts[0]}/${parts[1]}.git`;
  await execFileAsync('git', ['clone', '--depth', '1', cloneUrl, repoDir], {
    timeout: 25000,
    env: { ...process.env, GIT_TERMINAL_PROMPT: '0' },
  });

  try {
    const files = walkFiles(repoDir);
    const findings = [];

    for (const file of files) {
      const rel = path.relative(repoDir, file);
      const content = fs.readFileSync(file, 'utf8');
      const lines = content.split('\n');
      for (const rule of STATIC_RULES) {
        lines.forEach((line, idx) => {
          if (rule.regex.test(line)) {
            findings.push({
              ruleId: rule.id,
              severity: rule.severity,
              title: rule.title,
              file: rel,
              line: idx + 1,
              snippet: line.trim().slice(0, 140),
            });
          }
          rule.regex.lastIndex = 0;
        });
      }
    }

    const pkgPath = path.join(repoDir, 'package.json');
    const hasPackageJson = fs.existsSync(pkgPath);
    let packageSummary = null;
    if (hasPackageJson) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        packageSummary = {
          name: pkg.name || parts[1],
          scripts: Object.keys(pkg.scripts || {}),
          dependenciesCount: Object.keys(pkg.dependencies || {}).length,
        };
      } catch {}
    }

    return {
      ok: true,
      repo: `${parts[0]}/${parts[1]}`,
      filesScanned: files.length,
      hasPackageJson,
      packageSummary,
      findingsCount: findings.length,
      findings: findings.slice(0, 30),
    };
  } finally {
    try {
      fs.rmSync(repoDir, { recursive: true, force: true });
    } catch {}
  }
}
