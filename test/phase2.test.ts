import { describe, expect, it } from 'vitest';
import { compareLayouts, type StorageLayout } from '../src/storage.js';
import { findSignals } from '../src/signals.js';
import { checkUpgradeSurface, detectProxyPatterns } from '../src/upgrade.js';
import { parseSolidity } from '../src/solidity.js';
import { renderSarif } from '../src/sarif.js';
import { buildReport } from '../src/report.js';
import { buildPrivilegeMap } from '../src/privileges.js';

const T = {
  t_address: { label: 'address', numberOfBytes: '20' },
  t_uint256: { label: 'uint256', numberOfBytes: '32' },
  t_bool: { label: 'bool', numberOfBytes: '1' },
  t_uint128: { label: 'uint128', numberOfBytes: '16' },
};
const L = (...e: [string, string, number, keyof typeof T][]): StorageLayout => ({
  storage: e.map(([label, slot, offset, type]) => ({ label, slot, offset, type })),
  types: T,
});
const cmp = (b: StorageLayout, h: StorageLayout) => compareLayouts('C', 'C.sol', () => 1, b, h);
const rules = (b: StorageLayout, h: StorageLayout) => cmp(b, h).findings.map((f) => f.rule);

describe('storage layout comparison', () => {
  const base = L(['a', '0', 0, 't_address'], ['b', '1', 0, 't_uint256']);
  it('accepts an append', () => {
    const r = cmp(
      base,
      L(['a', '0', 0, 't_address'], ['b', '1', 0, 't_uint256'], ['c', '2', 0, 't_uint256']),
    );
    expect(r.comparison.verdict).toBe('append-only');
    expect(r.findings.map((f) => f.severity)).toEqual(['info']);
  });
  it('flags reordering as critical', () => {
    const r = cmp(base, L(['b', '0', 0, 't_uint256'], ['a', '1', 0, 't_address']));
    expect(r.comparison.verdict).toBe('unsafe');
    expect(
      r.findings.every((f) => f.rule === 'storage-slot-moved' && f.severity === 'critical'),
    ).toBe(true);
  });
  it('flags removal, insertion and type change', () => {
    expect(rules(base, L(['a', '0', 0, 't_address']))).toEqual(['storage-variable-removed']);
    expect(
      rules(
        base,
        L(['a', '0', 0, 't_address'], ['x', '1', 0, 't_uint256'], ['b', '2', 0, 't_uint256']),
      ),
    ).toContain('storage-variable-inserted');
    expect(rules(base, L(['a', '0', 0, 't_address'], ['b', '1', 0, 't_uint128']))).toEqual([
      'storage-type-changed',
    ]);
  });
  it('reports a rename as medium, not safe-silent', () => {
    const r = cmp(base, L(['a', '0', 0, 't_address'], ['b2', '1', 0, 't_uint256']));
    expect(r.findings.map((f) => [f.rule, f.severity])).toEqual([
      ['storage-variable-renamed', 'medium'],
    ]);
  });
  it('treats identical layouts as compatible', () => {
    expect(cmp(base, base).comparison.verdict).toBe('compatible');
  });
});

describe('risk signals', () => {
  const src = `pragma solidity 0.8.28;
contract A {
  uint256 x;
  function f(address t, bytes calldata d) external { t.delegatecall(d); }
  function g(address t) external { t.call(""); }
  function h() external { assembly { x := 1 } unchecked { x += 1; } selfdestruct(payable(msg.sender)); require(tx.origin == msg.sender); }
  function k() internal { address(this).call(""); }
}`;
  const rules = (r: [number, number][] | 'all') =>
    findSignals('A.sol', src, r)
      .map((f) => f.rule)
      .sort();
  it('detects every signal type in a new file', () => {
    expect(rules('all')).toEqual([
      'signal-arbitrary-external-call',
      'signal-assembly',
      'signal-delegatecall-arbitrary-target',
      'signal-low-level-call',
      'signal-selfdestruct',
      'signal-tx-origin',
      'signal-unchecked',
    ]);
  });
  it('only reports lines that were added or modified', () => {
    expect(rules([[4, 4]])).toEqual(['signal-delegatecall-arbitrary-target']);
    expect(rules([[100, 101]])).toEqual([]);
  });
  it('gives stable ids that do not move with line numbers', () => {
    const shifted = '\n\n' + src;
    const a = findSignals('A.sol', src, 'all')
      .map((f) => f.id)
      .sort();
    const b = findSignals('A.sol', shifted, 'all')
      .map((f) => f.id)
      .sort();
    expect(a).toEqual(b);
  });
  it('does not treat a gate in the function signature as a gate in the body', () => {
    const p = parseSolidity(
      'A.sol',
      'contract A { function _authorizeUpgrade(address) internal {} }',
    );
    expect(p.contracts[0]!.functions[0]!.gatedBy).toEqual([]);
  });
});

describe('upgrade surface', () => {
  const c = (body: string) =>
    parseSolidity('U.sol', `contract U { modifier onlyOwner(){_;} ${body} }`).contracts[0]!;
  const run = (head: string, base?: string) =>
    checkUpgradeSurface({
      file: 'U.sol',
      head: c(head),
      base: base ? c(base) : undefined,
      isChanged: () => true,
    }).map((f) => f.rule);
  it('flags an ungated _authorizeUpgrade as critical', () => {
    expect(run('function _authorizeUpgrade(address) internal {}')).toContain(
      'unprotected-upgrade-authorization',
    );
  });
  it('accepts a gated one but notes the change', () => {
    expect(run('function _authorizeUpgrade(address) internal onlyOwner {}')).toEqual([
      'upgrade-authorization-changed',
    ]);
  });
  it('flags removed access control and changed initializers', () => {
    const r = run(
      'function setX() external {} function initialize() external {}',
      'function setX() external onlyOwner {} function initialize() external {}',
    );
    expect(r).toEqual(expect.arrayContaining(['access-control-removed', 'initializer-changed']));
  });
  it('flags a changed inheritance list', () => {
    const h = parseSolidity('U.sol', 'contract U is A, B {}').contracts[0]!;
    const b = parseSolidity('U.sol', 'contract U is A {}').contracts[0]!;
    expect(
      checkUpgradeSurface({ file: 'U.sol', head: h, base: b, isChanged: () => false }).map(
        (f) => f.rule,
      ),
    ).toEqual(['inheritance-changed']);
  });
  it('detects proxy patterns textually and sorts output', () => {
    const p = detectProxyPatterns([
      { path: 'a.sol', text: 'import "UpgradeableBeacon";\ncontract X is UUPSUpgradeable {}' },
    ]);
    expect(p.map((x) => x.pattern)).toEqual(['beacon', 'uups']);
  });
});

describe('privilege map and SARIF', () => {
  const parsed = parseSolidity(
    'P.sol',
    'contract P { modifier onlyOwner(){_;} function pause() external onlyOwner {} function upgradeTo(address a) external onlyOwner {} function open() external {} }',
  );
  it('groups capabilities and omits ungated functions', () => {
    const m = buildPrivilegeMap([
      { path: 'P.sol', contracts: parsed.contracts, status: () => 'added' },
    ]);
    expect(Object.keys(m.capabilities).sort()).toEqual(['pauser', 'upgrader']);
    expect(JSON.stringify(m)).not.toContain('open()');
  });
  it('emits valid-shaped SARIF with locations and fingerprints', () => {
    const sig = findSignals(
      'A.sol',
      'contract A { function f(address t) external { t.delegatecall(""); } }',
      'all',
    );
    const r = buildReport({
      version: '0.1.0',
      base: { ref: 'a', sha: 'a' },
      head: { ref: 'b', sha: 'b' },
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
      extraFindings: sig,
      commands: [],
    });
    const s = JSON.parse(renderSarif(r));
    expect(s.version).toBe('2.1.0');
    expect(s.runs[0].results[0].level).toBe('error');
    expect(s.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(1);
    expect(s.runs[0].results[0].partialFingerprints['protocolGuardId/v1']).toMatch(/^PG-/);
  });
});

describe('forge inspect cache retry', () => {
  const layout = JSON.stringify({ storage: [], types: {} });
  it('retries with --no-cache only when the artifact lacks a storage layout', async () => {
    const { FakeShell } = await import('../src/adapters/shell.js');
    const { compareStorage } = await import('../src/storage.js');
    const sh = new FakeShell((cmd, args) => {
      if (cmd === 'git') return {};
      if (args.includes('--no-cache')) return { stdout: layout };
      return {
        exitCode: 1,
        stderr:
          'Error: storage layout missing from artifact; this could be a spurious caching issue',
      };
    });
    const r = await compareStorage(
      sh,
      process.cwd(),
      'abc',
      [{ contract: 'C', file: 'src/C.sol', line: () => 1 }],
      1000,
    );
    expect(r.comparisons[0]!.verdict).toBe('compatible');
    expect(r.commands.some((c) => c.includes('--no-cache'))).toBe(true);
  });
  it('does not retry on unrelated failures and reports the layout as unavailable', async () => {
    const { FakeShell } = await import('../src/adapters/shell.js');
    const { compareStorage } = await import('../src/storage.js');
    const sh = new FakeShell((cmd) =>
      cmd === 'git' ? {} : { exitCode: 1, stderr: 'Error: compilation failed' },
    );
    const r = await compareStorage(
      sh,
      process.cwd(),
      'abc',
      [{ contract: 'C', file: 'src/C.sol', line: () => 1 }],
      1000,
    );
    expect(r.comparisons[0]!.verdict).toBe('unavailable');
    expect(sh.calls.filter((c) => c.args.includes('--no-cache'))).toHaveLength(0);
  });
});
