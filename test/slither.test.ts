import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, describe, expect, it } from 'vitest';
import { FakeShell, RealShell } from '../src/adapters/shell.js';
import { main } from '../src/cli.js';
import { parseSlither, runSlither } from '../src/slither.js';
import { makeFixtureRepo } from './helpers.js';

const el = (type: string, name: string, file: string, lines: number[], parent?: string) => ({
  type,
  name,
  source_mapping: { filename_relative: file, lines, is_dependency: false },
  type_specific_fields: parent ? { parent: { name: parent } } : {},
});
const det = (check: string, impact: string, confidence: string, elements: unknown[]) => ({
  check,
  impact,
  confidence,
  description: `${check} found\n\t- detail`,
  elements,
});
const doc = (detectors: unknown[]) =>
  JSON.stringify({ success: true, error: null, results: { detectors } });

describe('parseSlither', () => {
  const changed = new Map<string, [number, number][] | 'all'>([['src/A.sol', [[10, 12]]]]);
  const sample = doc([
    det('controlled-delegatecall', 'High', 'Medium', [
      el('function', 'execute', 'src/A.sol', [8, 9, 10, 11, 12], 'A'),
      el('node', 'x.delegatecall(d)', 'src/A.sol', [11], 'execute'),
    ]),
    det('missing-zero-check', 'Low', 'Medium', [
      el('node', 'owner = o', 'src/A.sol', [3], 'initialize'),
    ]),
    det('reentrancy-eth', 'High', 'Low', [el('node', 'call', 'src/A.sol', [11], 'withdraw')]),
    det('cache-array-length', 'Optimization', 'High', [el('node', 'loop', 'src/A.sol', [11], 'f')]),
    det('naming-convention', 'Informational', 'High', [
      el('function', 'f', 'lib/dep/D.sol', [1], 'D'),
    ]),
  ]);

  it('keeps only changed-line results by default and counts the rest', () => {
    const r = parseSlither(sample, changed, 'changed') as Exclude<
      ReturnType<typeof parseSlither>,
      { error: string }
    >;
    expect(r.findings.map((f) => [f.rule, f.severity, f.line])).toEqual([
      ['slither-controlled-delegatecall', 'high', 10],
      ['slither-reentrancy-eth', 'medium', 11], // Low confidence lowers High by one step
    ]);
    expect(r.total).toBe(3); // optimisation and lib/ results never count
    expect(r.suppressed).toBe(1);
  });

  it('reports everything with scope all', () => {
    const r = parseSlither(sample, changed, 'all') as {
      findings: { rule: string }[];
      suppressed: number;
    };
    expect(r.findings).toHaveLength(3);
    expect(r.suppressed).toBe(0);
  });

  it('gives stable ids that survive line shifts and numbers repeats', () => {
    const twice = doc([
      det('missing-zero-check', 'Low', 'Medium', [el('node', 'a', 'src/A.sol', [10], 'f')]),
      det('missing-zero-check', 'Low', 'Medium', [el('node', 'b', 'src/A.sol', [11], 'f')]),
    ]);
    const a = parseSlither(twice, changed, 'all') as { findings: { id: string }[] };
    expect(new Set(a.findings.map((f) => f.id)).size).toBe(2);
    const shifted = twice.replace('[10]', '[40]').replace('[11]', '[41]');
    const b = parseSlither(shifted, changed, 'all') as { findings: { id: string }[] };
    expect(b.findings.map((f) => f.id)).toEqual(a.findings.map((f) => f.id));
  });

  it('turns malformed or failed output into an error, never an empty pass', () => {
    expect('error' in (parseSlither('not json', changed, 'all') as object)).toBe(true);
    const failed = JSON.stringify({
      success: false,
      error: 'Compilation failed\nmore',
      results: {},
    });
    expect(parseSlither(failed, changed, 'all')).toEqual({
      error: 'Slither reported an error: Compilation failed',
    });
  });
});

describe('runSlither with a fake shell', () => {
  const gitOut = (args: string[]) =>
    args[0] === 'diff' && args.includes('--name-status')
      ? { stdout: 'M\tsrc/A.sol\n' }
      : args[0] === 'diff'
        ? { stdout: '+++ b/src/A.sol\n@@ -1 +10,3 @@\n' }
        : {};

  it('says so loudly when slither is not installed', async () => {
    const sh = new FakeShell((cmd, args) => (cmd === 'slither' ? { exitCode: 127 } : gitOut(args)));
    const r = await runSlither(sh, '/repo', 'a', 'b', { scope: 'changed', timeoutMs: 1000 });
    expect(r.summary.ran).toBe(false);
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([
      ['slither-unavailable', 'medium'],
    ]);
    expect(r.findings[0]!.message).toContain('MISSING');
  });

  it('ignores a non-zero exit code when JSON is present and anchors the path filter to the repo', async () => {
    const sh = new FakeShell((cmd, args) => {
      if (cmd !== 'slither') return gitOut(args);
      if (args[0] === '--version') return { stdout: '0.11.6\n' };
      return {
        exitCode: 255,
        stdout: doc([
          det('controlled-delegatecall', 'High', 'Medium', [
            el('node', 'n', 'src/A.sol', [11], 'execute'),
          ]),
        ]),
      };
    });
    const r = await runSlither(sh, '/work/pg-test', 'a', 'b', {
      scope: 'changed',
      timeoutMs: 1000,
    });
    expect(r.summary).toMatchObject({ ran: true, version: '0.11.6', reported: 1, totalResults: 1 });
    const call = sh.calls.find((c) => c.cmd === 'slither' && c.args[0] === '.')!;
    expect(call.args[call.args.indexOf('--filter-paths') + 1]).toBe(
      '^/work/pg-test/(lib|node_modules|test|script)/',
    );
  });
});

const hasSlither = spawnSync('slither', ['--version']).status === 0;
const tmp: string[] = [];
afterAll(() => tmp.forEach((d) => rmSync(d, { recursive: true, force: true })));

describe.skipIf(!hasSlither)('integration with real Slither (skipped when not installed)', () => {
  it('merges Slither findings into report.json, report.md and SARIF', async () => {
    const repo = makeFixtureRepo('unsafe-combined');
    tmp.push(repo.dir);
    const out = mkdtempSync(join(tmpdir(), 'pg-sl-'));
    tmp.push(out);
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
        '--slither',
        '--fail-on',
        'high',
      ],
      new RealShell(),
      { out: () => {}, err: () => {} },
    );
    const r = JSON.parse(readFileSync(join(out, 'report.json'), 'utf8'));
    expect(code).toBe(1);
    expect(r.slither.ran).toBe(true);
    const sl = r.findings.filter((f: { rule: string }) => f.rule.startsWith('slither-'));
    expect(sl.map((f: { rule: string }) => f.rule)).toContain('slither-controlled-delegatecall');
    expect(
      sl.every((f: { file: string; line: number }) => f.file === 'src/Vault.sol' && f.line > 0),
    ).toBe(true);
    expect(readFileSync(join(out, 'report.md'), 'utf8')).toContain('## Slither');
    expect(readFileSync(join(out, 'report.sarif'), 'utf8')).toContain(
      'slither-controlled-delegatecall',
    );
  }, 180_000);
});
