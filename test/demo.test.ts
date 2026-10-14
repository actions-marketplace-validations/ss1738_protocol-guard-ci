import { execFileSync } from 'node:child_process';
import {
  appendFileSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
  cpSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, describe, expect, it } from 'vitest';
import { RealShell } from '../src/adapters/shell.js';
import { main } from '../src/cli.js';
import { FIXTURES } from './helpers.js';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const tmp: string[] = [];
afterAll(() => tmp.forEach((d) => rmSync(d, { recursive: true, force: true })));
const mk = () => {
  const d = mkdtempSync(join(tmpdir(), 'pg-demo-'));
  tmp.push(d);
  return d;
};
const git = (cwd: string, ...a: string[]) =>
  execFileSync(
    'git',
    ['-c', 'core.hooksPath=/dev/null', '-c', 'user.name=t', '-c', 'user.email=t@e.invalid', ...a],
    { cwd, encoding: 'utf8' },
  );

async function run(repo: string, base: string, extra: string[] = []) {
  const out = mk();
  const code = await main(
    ['run', '--repo', repo, '--base', base, '--out', out, '--skip-tests', ...extra],
    new RealShell(),
    { out: () => {}, err: () => {} },
  );
  return { code, report: JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')) };
}

describe('demo repository', () => {
  it('builds branches that behave as documented', async () => {
    const dir = join(mk(), 'demo');
    execFileSync(join(root, 'scripts/make-demo-repo.sh'), [dir]);
    expect(
      git(dir, 'branch', '--format=%(refname:short)').split('\n').filter(Boolean).sort(),
    ).toEqual(['main', 'safe-pr', 'unsafe-pr']);
    git(dir, 'checkout', '-q', 'unsafe-pr');
    const bad = await run(dir, 'main', ['--fail-on', 'high']);
    expect(bad.code).toBe(1);
    git(dir, 'checkout', '-q', 'safe-pr');
    const good = await run(dir, 'main', ['--fail-on', 'high']);
    expect(good.code).toBe(0);
    expect(good.report.summary.counts.high + good.report.summary.counts.critical).toBe(0);
  }, 120_000);

  it('refuses a non-empty destination', () => {
    const d = mk();
    writeFileSync(join(d, 'x'), '1');
    expect(() =>
      execFileSync(join(root, 'scripts/make-demo-repo.sh'), [d], { stdio: 'pipe' }),
    ).toThrow();
  });
});

describe('untracked dependencies (gitignored node_modules)', () => {
  it('compares storage in the base worktree by reusing the head checkout dependencies', async () => {
    const dir = mk();
    git(dir, 'init', '-q', '-b', 'main');
    cpSync(join(FIXTURES, 'safe-append', 'base'), dir, {
      recursive: true,
      filter: (s) => !/\/(out|cache)(\/|$)/.test(s),
    });
    mkdirSync(join(dir, 'node_modules/dep'), { recursive: true });
    writeFileSync(
      join(dir, 'node_modules/dep/L.sol'),
      'pragma solidity 0.8.28;\nlibrary L { function one() internal pure returns (uint256) { return 1; } }\n',
    );
    writeFileSync(join(dir, '.gitignore'), 'node_modules\nout\ncache\n');
    writeFileSync(
      join(dir, 'foundry.toml'),
      readFileSync(join(dir, 'foundry.toml'), 'utf8') + 'remappings = ["dep/=node_modules/dep/"]\n',
    );
    const vault = join(dir, 'src/Vault.sol');
    const src = readFileSync(vault, 'utf8');
    writeFileSync(
      vault,
      src
        .replace('contract Vault {', 'import {L} from "dep/L.sol";\n\ncontract Vault {')
        .replace('return 1;', 'return L.one();'),
    );
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'base');
    git(dir, 'checkout', '-q', '-b', 'pr');
    writeFileSync(
      vault,
      readFileSync(vault, 'utf8').replace(
        'mapping(address => uint256) public balances;',
        'mapping(address => uint256) public balances;\n    uint256 public extra;',
      ),
    );
    git(dir, 'commit', '-qam', 'head');
    const r = await run(dir, 'main');
    expect(r.report.upgradeSafety.storage.map((s: any) => s.verdict)).toEqual(['append-only']);
    expect(r.report.findings.some((f: any) => f.rule === 'storage-layout-unavailable')).toBe(false);
  }, 120_000);
});

describe('git submodule lib/', () => {
  const sg = (cwd: string, ...a: string[]) => git(cwd, '-c', 'protocol.file.allow=always', ...a);
  it('handles gitlink libs, and flags a submodule bump instead of staying silent', async () => {
    const lib = mk();
    git(lib, 'init', '-q', '-b', 'main');
    writeFileSync(
      join(lib, 'L.sol'),
      'pragma solidity 0.8.28;\nlibrary L { function one() internal pure returns (uint256) { return 1; } }\n',
    );
    git(lib, 'add', '-A');
    git(lib, 'commit', '-qm', 'lib');

    const dir = mk();
    git(dir, 'init', '-q', '-b', 'main');
    cpSync(join(FIXTURES, 'safe-append', 'base'), dir, {
      recursive: true,
      filter: (s) => !/\/(out|cache)(\/|$)/.test(s),
    });
    writeFileSync(join(dir, '.gitignore'), 'out\ncache\n');
    writeFileSync(
      join(dir, 'foundry.toml'),
      readFileSync(join(dir, 'foundry.toml'), 'utf8') + 'remappings = ["dep/=lib/dep/"]\n',
    );
    const vault = join(dir, 'src/Vault.sol');
    writeFileSync(
      vault,
      readFileSync(vault, 'utf8')
        .replace('contract Vault {', 'import {L} from "dep/L.sol";\n\ncontract Vault {')
        .replace('return 1;', 'return L.one();'),
    );
    sg(dir, 'submodule', 'add', '-q', lib, 'lib/dep');
    git(dir, 'add', '-A');
    git(dir, 'commit', '-q', '-m', 'base');
    expect(git(dir, 'ls-files', '-s', 'lib/dep')).toMatch(/^160000/);

    git(dir, 'checkout', '-q', '-b', 'append');
    writeFileSync(
      vault,
      readFileSync(vault, 'utf8').replace(
        'mapping(address => uint256) public balances;',
        'mapping(address => uint256) public balances;\n    uint256 public extra;',
      ),
    );
    git(dir, 'commit', '-qam', 'append');
    const a = await run(dir, 'main');
    expect(a.report.upgradeSafety.storage.map((x: any) => x.verdict)).toEqual(['append-only']);
    expect(a.report.findings.map((f: any) => f.rule)).toEqual(['storage-append']);

    git(dir, 'checkout', '-q', 'main');
    git(dir, 'checkout', '-q', '-b', 'bump');
    appendFileSync(join(dir, 'lib/dep/L.sol'), '// bump\n');
    git(join(dir, 'lib/dep'), 'commit', '-qam', 'bump');
    git(dir, 'commit', '-qam', 'bump submodule');
    const b = await run(dir, 'main');
    expect(b.report.findings.map((f: any) => [f.rule, f.file])).toEqual([
      ['dependency-changed', 'lib/dep'],
    ]);
  }, 120_000);
});
