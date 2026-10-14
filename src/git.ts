import type { Shell } from './adapters/shell.js';

export type ChangeStatus = 'A' | 'M' | 'D' | 'R';

export interface ChangedFile {
  status: ChangeStatus;
  path: string;
  /** Path at base when renamed. */
  oldPath?: string;
  /** Inclusive [start, end] line ranges in the head version that were added or modified. */
  addedRanges: [number, number][];
}

export class GitError extends Error {}

async function git(shell: Shell, cwd: string, args: string[]): Promise<string> {
  const r = await shell.run('git', args, { cwd });
  if (r.exitCode !== 0) {
    throw new GitError(
      `git ${args.join(' ')} failed (exit ${r.exitCode}): ${r.stderr.trim() || r.stdout.trim()}`,
    );
  }
  return r.stdout;
}

export function parseNameStatus(out: string): ChangedFile[] {
  const files: ChangedFile[] = [];
  for (const line of out.split('\n')) {
    if (!line.trim()) continue;
    const parts = line.split('\t');
    const code = parts[0] ?? '';
    if (code.startsWith('R')) {
      files.push({ status: 'R', oldPath: parts[1], path: parts[2] ?? '', addedRanges: [] });
    } else if (code === 'A' || code === 'M' || code === 'D') {
      files.push({ status: code, path: parts[1] ?? '', addedRanges: [] });
    }
  }
  return files.sort((a, b) => a.path.localeCompare(b.path));
}

/** Parse `git diff -U0` output into head-side added ranges per file. */
export function parseHunks(out: string): Map<string, [number, number][]> {
  const map = new Map<string, [number, number][]>();
  let current: string | undefined;
  for (const line of out.split('\n')) {
    if (line.startsWith('+++ ')) {
      const p = line.slice(4);
      current = p === '/dev/null' ? undefined : p.replace(/^b\//, '');
      if (current && !map.has(current)) map.set(current, []);
    } else if (line.startsWith('@@') && current) {
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/.exec(line);
      if (m) {
        const start = Number(m[1]);
        const count = m[2] === undefined ? 1 : Number(m[2]);
        if (count > 0) map.get(current)?.push([start, start + count - 1]);
      }
    }
  }
  return map;
}

export async function resolveRef(shell: Shell, cwd: string, ref: string): Promise<string> {
  return (await git(shell, cwd, ['rev-parse', '--verify', `${ref}^{commit}`])).trim();
}

/** Changed files between base and head (both commit-ish), with head-side added line ranges. */
export async function changedFiles(
  shell: Shell,
  cwd: string,
  base: string,
  head: string,
): Promise<ChangedFile[]> {
  const ns = parseNameStatus(
    await git(shell, cwd, ['diff', '--name-status', '-M', '--no-color', `${base}`, `${head}`]),
  );
  const hunks = parseHunks(
    await git(shell, cwd, ['diff', '-U0', '-M', '--no-color', `${base}`, `${head}`]),
  );
  for (const f of ns) f.addedRanges = hunks.get(f.path) ?? [];
  return ns;
}

export async function showFile(
  shell: Shell,
  cwd: string,
  ref: string,
  path: string,
): Promise<string | undefined> {
  const r = await shell.run('git', ['show', `${ref}:${path}`], { cwd });
  return r.exitCode === 0 ? r.stdout : undefined;
}
