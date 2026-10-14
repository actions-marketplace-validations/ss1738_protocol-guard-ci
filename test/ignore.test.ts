import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { RealShell } from '../src/adapters/shell.js';
import { main } from '../src/cli.js';
import { makeFinding } from '../src/findings.js';
import { applyIgnore, parseIgnore } from '../src/ignore.js';
import type { Report } from '../src/report.js';
import { makeFixtureRepo } from './helpers.js';

const ID = 'PG-NEW-PRIVILEGED-FUNCTION-d73e9ee6';

describe('parseIgnore', () => {
  it('reads id and reason, skips blanks and full-line comments', () => {
    const r = parseIgnore(
      `# header\n\n${ID} # audited, owner is a 3/5 multisig\n   # indented comment\n`,
    );
    expect(r.entries).toEqual([{ id: ID, reason: 'audited, owner is a 3/5 multisig', line: 3 }]);
    expect(r.problems).toEqual([]);
  });
  it('rejects missing or empty reasons, bad ids and duplicates instead of applying them', () => {
    const r = parseIgnore(`${ID}\n${ID} #   \nnot-an-id # why\n${ID} # first\n${ID} # again\n`);
    expect(r.entries.map((e) => e.line)).toEqual([4]);
    expect(r.problems.map((p) => p.line)).toEqual([1, 2, 3, 5]);
    expect(r.problems[0]!.problem).toContain('missing required');
    expect(r.problems[2]!.problem).toContain('not a finding ID');
    expect(r.problems[3]!.problem).toContain('duplicate');
  });
});

describe('applyIgnore', () => {
  const sig = makeFinding({
    rule: 'x',
    severity: 'high',
    title: 't',
    message: 'm',
    file: 'a.sol',
    line: 1,
    symbol: 's',
    kind: 'signal',
  });
  const exec = makeFinding({
    rule: 'forge-test-failed',
    severity: 'high',
    title: 't',
    message: 'm',
    kind: 'execution',
  });
  it('suppresses signals, reports stale entries, and refuses to suppress execution findings', () => {
    const entries = [
      { id: sig.id, reason: 'ok', line: 1 },
      { id: exec.id, reason: 'flaky', line: 2 },
      { id: 'PG-GONE-00000000', reason: 'old', line: 3 },
    ];
    const r = applyIgnore([sig, exec], entries);
    expect(r.suppressed.map((f) => f.id)).toEqual([sig.id]);
    expect(r.suppressed[0]!.suppression.reason).toBe('ok');
    expect(r.active.map((f) => f.id)).toEqual([exec.id]);
    expect(r.refused[0]!.problem).toContain('cannot be suppressed');
    expect(r.stale.map((e) => e.id)).toEqual(['PG-GONE-00000000']);
  });
});

const cleanups: (() => void)[] = [];
afterAll(() => cleanups.forEach((c) => c()));

async function run(
  name: string,
  opts: { baseIgnore?: string; headIgnore?: string } = {},
  extra: string[] = [],
) {
  const repo = makeFixtureRepo(name, opts);
  cleanups.push(repo.cleanup);
  const out = mkdtempSync(join(tmpdir(), 'pg-ign-'));
  cleanups.push(() => rmSync(out, { recursive: true, force: true }));
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
      '--skip-tests',
      ...extra,
    ],
    new RealShell(),
    { out: () => {}, err: () => {} },
  );
  return {
    code,
    report: JSON.parse(readFileSync(join(out, 'report.json'), 'utf8')) as Report,
    md: readFileSync(join(out, 'report.md'), 'utf8'),
    sarif: JSON.parse(readFileSync(join(out, 'report.sarif'), 'utf8')),
  };
}

describe('.protocol-guard-ignore end to end (real git)', () => {
  // Learn the real IDs from a run with no ignore file.
  let ids: string[] = [];
  it('baseline: unsuppressed findings fail the build', async () => {
    const r = await run('new-privileged-withdraw', {}, ['--fail-on', 'high']);
    ids = r.report.findings.filter((f) => f.kind === 'signal').map((f) => f.id);
    expect(ids).toHaveLength(2);
    expect(r.code).toBe(1);
    expect(r.report.ignore).toBeNull();
  }, 120_000);

  it('SECURITY: an ignore file added only in the PR head does NOT suppress its findings', async () => {
    const headOnly = ids.map((id) => `${id} # trust me`).join('\n') + '\n';
    const r = await run('new-privileged-withdraw', { headIgnore: headOnly }, ['--fail-on', 'high']);
    expect(r.code).toBe(1);
    expect(r.report.suppressed).toEqual([]);
    expect(r.report.ignore).toBeNull();
    const active = r.report.findings.map((f) => f.id);
    for (const id of ids) expect(active).toContain(id);
    expect(r.report.findings.map((f) => f.rule)).toContain('ignore-file-changed');
  }, 120_000);

  it('SECURITY: a PR that extends the base ignore file only keeps the base entries', async () => {
    const base = `${ids[0]} # reviewed in audit\n`;
    const head = base + `${ids[1]} # added by the PR itself\n`;
    const r = await run('new-privileged-withdraw', { baseIgnore: base, headIgnore: head }, [
      '--fail-on',
      'low',
    ]);
    expect(r.report.suppressed.map((f) => f.id)).toEqual([ids[0]]);
    expect(r.report.findings.map((f) => f.id)).toContain(ids[1]);
    expect(r.report.findings.map((f) => f.rule)).toContain('ignore-file-changed');
  }, 120_000);

  it('--ignore-from-head is an explicit local-testing override', async () => {
    const headOnly = ids.map((id) => `${id} # local test`).join('\n') + '\n';
    const r = await run('new-privileged-withdraw', { headIgnore: headOnly }, [
      '--fail-on',
      'high',
      '--ignore-from-head',
    ]);
    expect(r.report.suppressed).toHaveLength(2);
    expect(r.report.ignore!.source).toBe('head');
    expect(r.md).toContain('local testing only');
    expect(r.code).toBe(0);
  }, 120_000);

  it('applies base entries that have a reason; suppressed findings leave fail-on, JSON, Markdown and SARIF', async () => {
    const base = `# accepted risks\n${ids[0]} # owner is a 3/5 multisig\n${ids[1]} # gated by onlyOwner, reviewed\n`;
    const r = await run('new-privileged-withdraw', { baseIgnore: base }, ['--fail-on', 'high']);
    expect(r.code).toBe(0);
    expect(r.report.findings.filter((f) => f.kind === 'signal')).toEqual([]);
    expect(r.report.suppressed.map((f) => f.suppression.reason).sort()).toEqual([
      'gated by onlyOwner, reviewed',
      'owner is a 3/5 multisig',
    ]);
    expect(r.report.summary).toMatchObject({ total: 0, suppressed: 2, maxSeverity: null });
    expect(r.report.ignore).toMatchObject({
      source: 'base',
      entries: 2,
      applied: 2,
      stale: [],
      problems: [],
    });
    expect(r.md).toContain('## Suppressed Findings (from base .protocol-guard-ignore)');
    expect(r.md).toContain('owner is a 3/5 multisig');
    const suppressedSarif = r.sarif.runs[0].results.filter(
      (x: { suppressions?: unknown[] }) => x.suppressions,
    );
    expect(suppressedSarif).toHaveLength(2);
    expect(suppressedSarif[0].suppressions[0]).toMatchObject({
      kind: 'external',
      status: 'accepted',
    });
  }, 120_000);

  it('rejects an entry with no reason: it is not applied and a finding says so', async () => {
    const base = `${ids[0]}\n${ids[1]} #\n`;
    const r = await run('new-privileged-withdraw', { baseIgnore: base }, ['--fail-on', 'high']);
    expect(r.code).toBe(1);
    expect(r.report.suppressed).toEqual([]);
    const bad = r.report.findings.filter((f) => f.rule === 'ignore-entry-invalid');
    expect(bad).toHaveLength(2);
    expect(bad.every((f) => f.severity === 'low' && f.file === '.protocol-guard-ignore')).toBe(
      true,
    );
    expect(r.report.findings.map((f) => f.id)).toEqual(expect.arrayContaining(ids));
    expect(r.md).toContain('Invalid entries (not applied)');
  }, 120_000);

  it('lists stale ids that matched nothing, without failing the build', async () => {
    const stale = 'PG-NEW-PRIVILEGED-FUNCTION-00000000';
    const base = `${ids[0]} # accepted\n${stale} # removed code\n`;
    const r = await run('new-privileged-withdraw', { baseIgnore: base }, ['--fail-on', 'critical']);
    expect(r.report.ignore!.stale).toEqual([{ id: stale, reason: 'removed code', line: 2 }]);
    expect(r.report.ignore!.applied).toBe(1);
    expect(r.report.findings.map((f) => f.rule)).not.toContain('ignore-entry-invalid');
    expect(r.md).toContain('Stale entries');
    expect(r.code).toBe(0);
  }, 120_000);
});
