import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { RealShell } from '../src/adapters/shell.js';
import { main } from '../src/cli.js';
import type { Report } from '../src/report.js';
import { makeFixtureRepo } from './helpers.js';

const cleanups: (() => void)[] = [];
afterAll(() => cleanups.forEach((c) => c()));

async function runFixture(name: string, extra: string[] = []) {
  const repo = makeFixtureRepo(name);
  cleanups.push(repo.cleanup);
  const out = mkdtempSync(join(tmpdir(), 'pg-out-'));
  cleanups.push(() => rmSync(out, { recursive: true, force: true }));
  const err: string[] = [];
  const code = await main(
    [
      'run',
      '--repo',
      repo.dir,
      '--base',
      'main',
      '--head',
      'pr',
      '--out',
      out,
      '--fuzz-runs',
      '8',
      '--invariant-runs',
      '4',
      ...extra,
    ],
    new RealShell(),
    { out: () => {}, err: (s) => err.push(s) },
  );
  const report = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')) as Report;
  const md = readFileSync(join(out, 'report.md'), 'utf8');
  return { code, report, md, err: err.join('') };
}

describe('integration (real git + forge, offline)', () => {
  it('flags a newly introduced privileged withdrawal with file and line', async () => {
    const r = await runFixture('new-privileged-withdraw', ['--fail-on', 'high']);
    const f = r.report.findings.find((x) => x.rule === 'new-privileged-function');
    expect(f).toBeDefined();
    expect(f!.symbol).toBe('Vault.withdrawAll(address)');
    expect(f!.file).toBe('src/Vault.sol');
    expect(f!.line).toBeGreaterThan(0);
    expect(r.code).toBe(1);
    expect(r.err).toContain('--fail-on high');
    expect(r.report.execution.map((s) => [s.name, s.exitCode])).toEqual([
      ['fmt', 0],
      ['build', 0],
      ['test', 0],
    ]);
    expect(r.report.execution[2]!.command).toBe(
      'FOUNDRY_FUZZ_RUNS=8 FOUNDRY_INVARIANT_RUNS=4 forge test',
    );
    expect(r.md).toContain('withdrawAll');
  }, 120_000);

  it('lists a changed external function but no high finding for a safe change', async () => {
    const r = await runFixture('safe-upgrade', ['--fail-on', 'high']);
    expect(r.report.inspection.changedFunctions.map((f) => f.signature)).toEqual(['version()']);
    expect(r.report.summary.counts.high + r.report.summary.counts.critical).toBe(0);
    expect(r.code).toBe(0);
  }, 120_000);

  it('is warning-only by default even when findings exist', async () => {
    const r = await runFixture('new-privileged-withdraw', ['--skip-tests']);
    expect(r.code).toBe(0);
    expect(r.report.execution.find((s) => s.name === 'test')!.skipped).toBe(true);
  }, 120_000);

  it('produces identical output across runs', async () => {
    const a = await runFixture('unsafe-delegatecall', ['--skip-tests']);
    const b = await runFixture('unsafe-delegatecall', ['--skip-tests']);
    const strip = (r: Report) => ({ ...r, base: undefined, head: undefined });
    expect(strip(a.report)).toEqual(strip(b.report));
  }, 120_000);

  it('ACCEPTANCE unsafe: storage warning, upgrade auth, privileged change, file:line, non-zero exit', async () => {
    const r = await runFixture('unsafe-combined', ['--fail-on', 'high']);
    const by = (rule: string) => r.report.findings.filter((f) => f.rule === rule);
    expect(by('storage-slot-moved').length).toBeGreaterThan(0);
    expect(by('unprotected-upgrade-authorization')).toHaveLength(1);
    expect(by('new-privileged-function').map((f) => f.symbol)).toEqual([
      'Vault.withdrawAll(address)',
    ]);
    expect(by('signal-delegatecall-arbitrary-target')).toHaveLength(1);
    for (const f of r.report.findings.filter((x) => x.severity !== 'info')) {
      if (f.rule.startsWith('forge-')) continue;
      expect(f.file).toBe('src/Vault.sol');
      expect(f.line).toBeGreaterThan(0);
    }
    expect(r.report.upgradeSafety.storage[0]!.verdict).toBe('unsafe');
    expect(r.report.upgradeSafety.proxyPatterns.map((p) => p.pattern)).toContain('uups');
    expect(r.code).toBe(1);
  }, 120_000);

  it('ACCEPTANCE safe: append and authorised upgrade finish with no high findings', async () => {
    for (const name of ['safe-append', 'safe-upgrade']) {
      const r = await runFixture(name, ['--fail-on', 'high']);
      expect(r.report.summary.counts.high + r.report.summary.counts.critical, name).toBe(0);
      expect(r.code, name).toBe(0);
      expect(
        r.report.execution.every((s) => s.exitCode === 0),
        name,
      ).toBe(true);
    }
  }, 120_000);

  it('writes SARIF and a privilege map, and cleans up its base worktree', async () => {
    const repo = makeFixtureRepo('unsafe-storage-reorder');
    cleanups.push(repo.cleanup);
    const out = mkdtempSync(join(tmpdir(), 'pg-out-'));
    cleanups.push(() => rmSync(out, { recursive: true, force: true }));
    await main(
      ['run', '--repo', repo.dir, '--base', 'main', '--head', 'pr', '--out', out, '--skip-tests'],
      new RealShell(),
      { out: () => {}, err: () => {} },
    );
    const sarif = JSON.parse(readFileSync(join(out, 'report.sarif'), 'utf8'));
    expect(
      sarif.runs[0].results.some((x: { ruleId: string }) => x.ruleId === 'storage-slot-moved'),
    ).toBe(true);
    const pm = JSON.parse(readFileSync(join(out, 'privilege-map.json'), 'utf8'));
    expect(Object.keys(pm.capabilities)).toEqual(expect.arrayContaining(['pauser', 'upgrader']));
    const wt = execFileSync('git', ['worktree', 'list', '--porcelain'], {
      cwd: repo.dir,
      encoding: 'utf8',
    });
    expect(wt.match(/^worktree /gm)).toHaveLength(1);
  }, 120_000);
});
