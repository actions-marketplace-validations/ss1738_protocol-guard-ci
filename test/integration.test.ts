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
});
