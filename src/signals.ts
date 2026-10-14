import { visit } from '@solidity-parser/parser';
import { makeFinding, type Finding, type Severity } from './findings.js';
import { parseAst, MODIFIER_GATE } from './solidity.js';

type Range = [number, number];
const inRanges = (ranges: Range[] | 'all', line: number) =>
  ranges === 'all' || ranges.some(([a, b]) => line >= a && line <= b);

const LOW_LEVEL = new Set(['call', 'staticcall', 'callcode']);

interface Rule {
  rule: string;
  severity: Severity;
  title: string;
  message: string;
}

const R: Record<string, Rule> = {
  delegatecall: {
    rule: 'signal-delegatecall',
    severity: 'high',
    title: 'delegatecall introduced',
    message:
      "delegatecall runs foreign code with this contract's storage and balance. Confirm the target is fixed and trusted.",
  },
  'delegatecall-arbitrary': {
    rule: 'signal-delegatecall-arbitrary-target',
    severity: 'critical',
    title: 'delegatecall to a caller-controlled address',
    message:
      "The delegatecall target is a parameter of an externally callable function. If reachable by anyone, they can execute arbitrary code in this contract's context.",
  },
  selfdestruct: {
    rule: 'signal-selfdestruct',
    severity: 'high',
    title: 'selfdestruct introduced',
    message: 'selfdestruct can remove code or force-send ETH. Confirm who can reach it.',
  },
  'tx-origin': {
    rule: 'signal-tx-origin',
    severity: 'medium',
    title: 'tx.origin used',
    message: 'tx.origin is unsafe for authorisation because phishing contracts can relay calls.',
  },
  assembly: {
    rule: 'signal-assembly',
    severity: 'low',
    title: 'Inline assembly introduced',
    message: 'Inline assembly bypasses Solidity safety checks and needs manual review.',
  },
  unchecked: {
    rule: 'signal-unchecked',
    severity: 'low',
    title: 'unchecked block introduced',
    message: 'Arithmetic inside unchecked can overflow or underflow silently.',
  },
  'low-level-call': {
    rule: 'signal-low-level-call',
    severity: 'low',
    title: 'Low-level call introduced',
    message:
      'Low-level calls do not revert automatically and forward control to external code. Check return handling and reentrancy.',
  },
  'arbitrary-call': {
    rule: 'signal-arbitrary-external-call',
    severity: 'high',
    title: 'External call to a caller-controlled address',
    message:
      'A low-level call targets a parameter of an externally callable function. If unrestricted, callers can make this contract call anything.',
  },
};

/**
 * Review signals on lines added or modified in head. These are not vulnerabilities.
 * `ranges === 'all'` for new files.
 */
export function findSignals(file: string, source: string, ranges: Range[] | 'all'): Finding[] {
  const ast = parseAst(source);
  if (!ast) return [];
  const out: Finding[] = [];
  const seen = new Map<string, number>();
  let contract = '';
  let fn: { name: string; external: boolean; params: Set<string>; gate?: string } | undefined;

  const emit = (key: string, line: number) => {
    if (!inRanges(ranges, line)) return;
    const r = R[key]!;
    const where = fn ? `${contract}.${fn.name}` : contract;
    const n = (seen.get(`${r.rule}|${where}`) ?? 0) + 1;
    seen.set(`${r.rule}|${where}`, n);
    // A caller-controlled target behind an access modifier is still a signal, but a weaker one.
    const gated =
      fn?.gate !== undefined && (key === 'arbitrary-call' || key === 'delegatecall-arbitrary');
    const severity: Severity = gated ? (r.severity === 'critical' ? 'high' : 'medium') : r.severity;
    out.push(
      makeFinding({
        rule: r.rule,
        severity,
        title: r.title,
        message: `${where}: ${r.message}${gated ? ` (restricted by modifier ${fn!.gate}, so severity is reduced; review who holds that role)` : ''}`,
        file,
        line,
        symbol: `${where}#${n}`,
        kind: 'signal',
      }),
    );
  };

  visit(ast, {
    ContractDefinition: (n) => {
      contract = n.name;
    },
    FunctionDefinition: (n) => {
      const name = n.isConstructor
        ? 'constructor'
        : (n.name ?? (n.isReceiveEther ? 'receive' : 'fallback'));
      fn = {
        name,
        external:
          n.visibility === 'public' || n.visibility === 'external' || n.visibility === 'default',
        params: new Set(n.parameters.map((p) => p.name).filter((x): x is string => !!x)),
        gate: n.modifiers.map((m) => m.name).find((m) => MODIFIER_GATE.test(m)),
      };
    },
    'FunctionDefinition:exit': () => {
      fn = undefined;
    },
    InlineAssemblyStatement: (n) => emit('assembly', n.loc!.start.line),
    UncheckedStatement: (n) => emit('unchecked', n.loc!.start.line),
    FunctionCall: (n) => {
      const e = n.expression;
      if (e.type === 'Identifier' && (e.name === 'selfdestruct' || e.name === 'suicide'))
        emit('selfdestruct', n.loc!.start.line);
    },
    MemberAccess: (n) => {
      const line = n.loc!.start.line;
      const base = n.expression;
      if (base.type === 'Identifier' && base.name === 'tx' && n.memberName === 'origin')
        return emit('tx-origin', line);
      const arbitrary = base.type === 'Identifier' && !!fn?.external && fn.params.has(base.name);
      if (n.memberName === 'delegatecall')
        return emit(arbitrary ? 'delegatecall-arbitrary' : 'delegatecall', line);
      if (LOW_LEVEL.has(n.memberName)) emit(arbitrary ? 'arbitrary-call' : 'low-level-call', line);
    },
  });
  return out;
}
