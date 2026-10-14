import { execFileSync } from 'node:child_process';
import { cpSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', ['-c', 'core.hooksPath=/dev/null', ...args], {
    cwd,
    encoding: 'utf8',
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 't',
      GIT_AUTHOR_EMAIL: 't@example.com',
      GIT_COMMITTER_NAME: 't',
      GIT_COMMITTER_EMAIL: 't@example.com',
      GIT_AUTHOR_DATE: '2026-01-01T00:00:00Z',
      GIT_COMMITTER_DATE: '2026-01-01T00:00:00Z',
    },
  });
}

/** Create a temp git repo whose `main` is the fixture base and `pr` is the fixture head. */
export function makeFixtureRepo(name: string): { dir: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), `pg-${name}-`));
  git(dir, 'init', '-q', '-b', 'main');
  cpSync(join(FIXTURES, name, 'base'), dir, {
    recursive: true,
    filter: (s) => !/\/(out|cache)(\/|$)/.test(s),
  });
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'base');
  git(dir, 'checkout', '-q', '-b', 'pr');
  for (const entry of readdirSync(dir))
    if (entry !== '.git') rmSync(join(dir, entry), { recursive: true, force: true });
  cpSync(join(FIXTURES, name, 'head'), dir, {
    recursive: true,
    filter: (s) => !/\/(out|cache)(\/|$)/.test(s),
  });
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'head');
  return { dir, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}
