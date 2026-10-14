import { makeFinding, type Finding } from './findings.js';
import type { ContractInfo, FunctionInfo } from './solidity.js';

export interface ProxyPattern {
  pattern: 'uups' | 'transparent' | 'beacon' | 'erc1967-slot';
  file: string;
  line: number;
  evidence: string;
}

const PATTERNS: { pattern: ProxyPattern['pattern']; re: RegExp }[] = [
  { pattern: 'uups', re: /\bUUPSUpgradeable\b|\b_authorizeUpgrade\b|\bupgradeToAndCall\b/ },
  { pattern: 'transparent', re: /\bTransparentUpgradeableProxy\b|\bProxyAdmin\b/ },
  { pattern: 'beacon', re: /\bUpgradeableBeacon\b|\bBeaconProxy\b/ },
  {
    pattern: 'erc1967-slot',
    re: /\b_?IMPL(EMENTATION)?_SLOT\b|0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc/,
  },
];

/** First matching line per (pattern, file); sorted for determinism. */
export function detectProxyPatterns(files: { path: string; text: string }[]): ProxyPattern[] {
  const out: ProxyPattern[] = [];
  for (const f of files) {
    const lines = f.text.split('\n');
    for (const p of PATTERNS) {
      const i = lines.findIndex((l) => p.re.test(l.replace(/\/\/.*$/, '')));
      if (i >= 0)
        out.push({ pattern: p.pattern, file: f.path, line: i + 1, evidence: lines[i]!.trim() });
    }
  }
  return out.sort((a, b) => a.pattern.localeCompare(b.pattern) || a.file.localeCompare(b.file));
}

const UPGRADE_ENTRYPOINTS =
  /^(upgradeTo|upgradeToAndCall|upgrade|upgradeAndCall|setImplementation|changeAdmin)$/;
const INITIALIZER = /^(initialize\w*|reinitialize\w*|init|__\w+_init(_unchained)?)$/;

export interface UpgradeCheckInput {
  file: string;
  head: ContractInfo;
  base?: ContractInfo;
  isChanged: (fn: FunctionInfo) => boolean;
}

/** Upgrade-authorisation, entrypoint, initializer and inheritance checks for one contract. */
export function checkUpgradeSurface({ file, head, base, isChanged }: UpgradeCheckInput): Finding[] {
  const out: Finding[] = [];
  const baseFns = new Map((base?.functions ?? []).map((f) => [f.signature, f]));
  for (const fn of head.functions) {
    const sym = `${head.name}.${fn.signature}`;
    const prev = baseFns.get(fn.signature);
    const changed = isChanged(fn);
    if (fn.name === '_authorizeUpgrade') {
      if (fn.gatedBy.length === 0) {
        out.push(
          makeFinding({
            rule: 'unprotected-upgrade-authorization',
            severity: 'critical',
            title: 'Upgrade authorisation has no access check',
            message: `${sym} has no access-control modifier or sender check${prev && prev.gatedBy.length > 0 ? ` (base was gated by ${prev.gatedBy.join(', ')}: access control was REMOVED)` : ''}. Anyone able to call the upgrade entrypoint could replace the implementation.`,
            file,
            line: fn.startLine,
            symbol: sym,
            kind: 'signal',
          }),
        );
      } else if (changed) {
        out.push(
          makeFinding({
            rule: 'upgrade-authorization-changed',
            severity: 'medium',
            title: 'Upgrade authorisation changed',
            message: `${sym} changed and is gated by ${fn.gatedBy.join(', ')}. Confirm the gate still maps to the intended multisig or timelock.`,
            file,
            line: fn.startLine,
            symbol: sym,
            kind: 'signal',
          }),
        );
      }
    } else if (
      (fn.visibility === 'external' || fn.visibility === 'public') &&
      UPGRADE_ENTRYPOINTS.test(fn.name)
    ) {
      if (fn.gatedBy.length === 0 && (changed || !prev)) {
        out.push(
          makeFinding({
            rule: 'upgrade-entrypoint-unguarded',
            severity: 'high',
            title: 'Upgrade entrypoint without visible access check',
            message: `${sym} looks like an upgrade entrypoint but neither it nor a call to _authorizeUpgrade gates it.`,
            file,
            line: fn.startLine,
            symbol: sym,
            kind: 'signal',
          }),
        );
      }
    }
    if (INITIALIZER.test(fn.name) && (changed || !prev)) {
      out.push(
        makeFinding({
          rule: 'initializer-changed',
          severity: prev ? 'medium' : 'high',
          title: prev ? 'Initializer changed' : 'New initializer',
          message: `${sym} ${prev ? 'changed' : 'was added'}. Check it cannot be re-run or front-run after deployment, and that the implementation is initialised or disabled.`,
          file,
          line: fn.startLine,
          symbol: sym,
          kind: 'signal',
        }),
      );
    }
    if (
      prev &&
      prev.gatedBy.length > 0 &&
      fn.gatedBy.length === 0 &&
      (fn.visibility === 'external' || fn.visibility === 'public') &&
      fn.name !== '_authorizeUpgrade'
    ) {
      out.push(
        makeFinding({
          rule: 'access-control-removed',
          severity: 'high',
          title: 'Access control removed from a function',
          message: `${sym} was gated by ${prev.gatedBy.join(', ')} at base and has no visible gate now.`,
          file,
          line: fn.startLine,
          symbol: sym,
          kind: 'signal',
        }),
      );
    }
  }
  if (base && JSON.stringify(base.bases) !== JSON.stringify(head.bases)) {
    out.push(
      makeFinding({
        rule: 'inheritance-changed',
        severity: 'medium',
        title: 'Inheritance list changed',
        message: `${head.name} inherited [${base.bases.join(', ')}] at base and [${head.bases.join(', ')}] at head. Order and additions change the storage layout of inherited state.`,
        file,
        line: head.startLine,
        symbol: head.name,
        kind: 'signal',
      }),
    );
  }
  return out;
}
