import { describe, expect, it } from 'vitest';
import { FakeShell, redact, formatCommand } from '../src/adapters/shell.js';
import { parseHunks, parseNameStatus } from '../src/git.js';
import { makeFinding, sortFindings } from '../src/findings.js';
import { normaliseOutput, runFoundry } from '../src/foundry.js';
import { parseSolidity } from '../src/solidity.js';
import { buildReport, renderJson, renderMarkdown } from '../src/report.js';
import { main } from '../src/cli.js';

describe('git parsing', () => {
  it('parses name-status including renames', () => {
    const out = 'M\tsrc/A.sol\nA\tsrc/B.sol\nR100\told/C.sol\tnew/C.sol\nD\tsrc/D.sol\n';
    expect(parseNameStatus(out).map((f) => [f.status, f.path, f.oldPath])).toEqual(
      [
        ['A', 'src/B.sol', undefined],
        ['R', 'new/C.sol', 'old/C.sol'],
        ['D', 'src/D.sol', undefined],
        ['M', 'src/A.sol', undefined],
      ].sort((a, b) => String(a[1]).localeCompare(String(b[1]))),
    );
  });

  it('parses zero-context hunks into head-side ranges', () => {
    const diff = [
      'diff --git a/src/A.sol b/src/A.sol',
      '--- a/src/A.sol',
      '+++ b/src/A.sol',
      '@@ -10,0 +11,3 @@',
      '@@ -20 +23 @@',
      '@@ -30,2 +33,0 @@',
    ].join('\n');
    expect(parseHunks(diff).get('src/A.sol')).toEqual([
      [11, 13],
      [23, 23],
    ]);
  });
});

describe('redaction', () => {
  it('removes secrets, credentialed URLs, RPC URLs and 32-byte hex', () => {
    const key = '0x' + 'ab'.repeat(32);
    const text = `key ${key} url https://user:pw@example.com/x rpc https://eth-mainnet.alchemy.com/v2/abc tok sekret-value-123`;
    const out = redact(text, ['sekret-value-123']);
    expect(out).not.toContain('ab'.repeat(32));
    expect(out).not.toContain('user:pw');
    expect(out).not.toContain('alchemy');
    expect(out).not.toContain('sekret-value-123');
  });

  it('quotes awkward arguments in recorded commands', () => {
    expect(formatCommand('forge', ['test', '--match-test', 'a b'])).toBe(
      'forge test --match-test "a b"',
    );
  });
});

describe('findings', () => {
  it('has stable ids that ignore line number and sorts deterministically', () => {
    const a = makeFinding({
      rule: 'x',
      severity: 'low',
      title: 't',
      message: 'm',
      file: 'a.sol',
      line: 3,
      symbol: 'C.f()',
      kind: 'signal',
    });
    const b = makeFinding({
      rule: 'x',
      severity: 'low',
      title: 't',
      message: 'm',
      file: 'a.sol',
      line: 99,
      symbol: 'C.f()',
      kind: 'signal',
    });
    expect(a.id).toBe(b.id);
    expect(a.id).toMatch(/^PG-X-[0-9a-f]{8}$/);
    const hi = makeFinding({
      rule: 'y',
      severity: 'high',
      title: 't',
      message: 'm',
      kind: 'signal',
    });
    expect(sortFindings([a, hi]).map((f) => f.severity)).toEqual(['high', 'low']);
  });
});

describe('forge output normalisation', () => {
  it('strips timings and fuzz averages', () => {
    const n = normaliseOutput(
      '[PASS] t(uint8) (runs: 64, μ: 51065, ~: 51875)\nfinished in 11.52ms (13.63ms CPU time)',
    );
    expect(n).toBe('[PASS] t(uint8) (runs: 64)\nfinished in <t> (<t> CPU time)');
  });
});

describe('solidity analysis', () => {
  const src = `pragma solidity 0.8.28;
contract A {
  address owner;
  modifier onlyOwner() { require(msg.sender == owner); _; }
  function a() external onlyOwner {}
  function b(uint256 x) public {}
  function c() internal {}
  function d() external { require(msg.sender == owner, "x"); }
}`;
  it('finds functions, visibility and gates', () => {
    const f = parseSolidity('A.sol', src).contracts[0]!.functions;
    const by = Object.fromEntries(f.map((x) => [x.name, x]));
    expect(by.a!.gatedBy).toEqual(['modifier onlyOwner']);
    expect(by.b!.signature).toBe('b(uint256)');
    expect(by.b!.gatedBy).toEqual([]);
    expect(by.c!.visibility).toBe('internal');
    expect(by.d!.gatedBy).toEqual(['msg.sender comparison']);
    expect(by.a!.startLine).toBe(5);
  });
  it('reports parse errors instead of skipping', () => {
    expect(parseSolidity('Bad.sol', 'contract {').parseError).toBeTruthy();
  });
});

describe('foundry runner with fake shell', () => {
  it('skips tests after a failed build and reports a high finding', async () => {
    const sh = new FakeShell((_c, args) =>
      args[0] === 'build' ? { exitCode: 1, stderr: 'boom' } : {},
    );
    const r = await runFoundry(sh, '/x', { skipTests: false, timeoutMs: 1000 });
    expect(r.steps.map((s) => [s.name, s.skipped])).toEqual([
      ['fmt', false],
      ['build', false],
      ['test', true],
    ]);
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([['forge-build-failed', 'high']]);
  });

  it('passes configured run counts as environment, never on the command line', async () => {
    const sh = new FakeShell(() => ({}));
    const r = await runFoundry(sh, '/x', {
      fuzzRuns: 1000,
      invariantRuns: 50,
      skipTests: false,
      timeoutMs: 1000,
    });
    const testCall = sh.calls.find((c) => c.args[0] === 'test')!;
    expect(testCall.env).toEqual({ FOUNDRY_FUZZ_RUNS: '1000', FOUNDRY_INVARIANT_RUNS: '50' });
    expect(r.steps[2]!.command).toBe('FOUNDRY_FUZZ_RUNS=1000 FOUNDRY_INVARIANT_RUNS=50 forge test');
  });

  it('gives a helpful finding when forge is missing', async () => {
    const sh = new FakeShell(() => ({ exitCode: 127, stderr: "failed to start 'forge'" }));
    const r = await runFoundry(sh, '/x', { skipTests: true, timeoutMs: 1000 });
    expect(r.findings[0]!.title).toContain('not installed');
  });
});

describe('report', () => {
  it('is deterministic and versioned', () => {
    const mk = () =>
      buildReport({
        version: '0.1.0',
        base: { ref: 'main', sha: 'a'.repeat(40) },
        head: { ref: 'pr', sha: 'b'.repeat(40) },
        inspection: {
          isFoundry: true,
          solidityFilesChanged: [],
          changedContracts: [],
          changedFunctions: [],
          parseErrors: [],
          findings: [],
        },
        execution: [],
        upgradeSafety: { proxyPatterns: [], storage: [], notes: [] },
        privilegeMap: { schemaVersion: '1.0.0', capabilities: {} },
        extraFindings: [],
        commands: [],
      });
    expect(renderJson(mk())).toBe(renderJson(mk()));
    expect(renderMarkdown(mk())).toContain('not a security audit');
    expect(JSON.parse(renderJson(mk())).schemaVersion).toBe('1.3.0');
  });
});

describe('cli errors', () => {
  const io = () => {
    const e: string[] = [];
    return { e, io: { out: () => {}, err: (s: string) => e.push(s) } };
  };
  it('requires --base', async () => {
    const x = io();
    expect(await main(['run'], new FakeShell(() => ({})), x.io)).toBe(2);
    expect(x.e.join('')).toContain('--base is required');
  });
  it('rejects a bad --fail-on', async () => {
    const x = io();
    expect(
      await main(['run', '--base', 'a', '--fail-on', 'bogus'], new FakeShell(() => ({})), x.io),
    ).toBe(2);
    expect(x.e.join('')).toContain('--fail-on must be one of');
  });
  it('rejects a non-numeric run count', async () => {
    const x = io();
    const code = await main(
      ['run', '--base', 'a', '--repo', process.cwd(), '--fuzz-runs', 'abc'],
      new FakeShell(() => ({ stdout: 'a'.repeat(40) })),
      x.io,
    );
    expect(code).toBe(2);
    expect(x.e.join('')).toContain('--fuzz-runs must be a positive integer');
  });
});
