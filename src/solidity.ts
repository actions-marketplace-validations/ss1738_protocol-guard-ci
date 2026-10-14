import { parse } from '@solidity-parser/parser';
import type {
  ContractDefinition,
  FunctionDefinition,
} from '@solidity-parser/parser/dist/src/ast-types.js';

export type Visibility = 'public' | 'external' | 'internal' | 'private';

export type Capability = 'owner' | 'admin' | 'role' | 'upgrader' | 'pauser' | 'guardian';

export interface FunctionInfo {
  contract: string;
  name: string;
  /** name(type,type) as written in source; used as a stable symbol. */
  signature: string;
  visibility: Visibility;
  modifiers: string[];
  startLine: number;
  endLine: number;
  /** Capabilities gating this function, derived from modifier names and in-body checks. */
  gates: Capability[];
  /** Why we think it is privileged (modifier names / in-body checks). Empty if not privileged. */
  gatedBy: string[];
}

export interface ContractInfo {
  name: string;
  kind: string;
  bases: string[];
  startLine: number;
  endLine: number;
  functions: FunctionInfo[];
}

export interface ParsedFile {
  path: string;
  contracts: ContractInfo[];
  /** Set when the file could not be parsed; the caller must report this, not skip silently. */
  parseError?: string;
}

export const MODIFIER_GATE =
  /^(only|auth|requiresAuth|restricted|whenAuthorized|isOwner|isAdmin|isGuardian|isPauser)/i;
const BODY_GATES: { re: RegExp; label: string }[] = [
  { re: /msg\.sender\s*==\s*\w+|\w+\s*==\s*msg\.sender/, label: 'msg.sender comparison' },
  { re: /\b_checkOwner\s*\(/, label: '_checkOwner()' },
  { re: /\b_checkRole\s*\(/, label: '_checkRole()' },
  { re: /\bhasRole\s*\(/, label: 'hasRole()' },
  { re: /\b_authorizeUpgrade\s*\(/, label: '_authorizeUpgrade()' },
];

export function capabilityOf(text: string): Capability {
  const t = text.toLowerCase();
  if (/upgrad/.test(t)) return 'upgrader';
  if (/paus/.test(t)) return 'pauser';
  if (/guardian/.test(t)) return 'guardian';
  if (/admin/.test(t)) return 'admin';
  if (/role|minter|operator|manager|keeper/.test(t)) return 'role';
  return 'owner';
}

function bodyText(src: string, fn: FunctionDefinition): string {
  const loc = fn.body?.loc;
  if (!loc) return '';
  const lines = src.split('\n');
  const slice = lines.slice(loc.start.line - 1, loc.end.line);
  if (slice.length === 0) return '';
  slice[slice.length - 1] = slice[slice.length - 1]!.slice(0, loc.end.column + 1);
  slice[0] = slice[0]!.slice(loc.start.column);
  return slice.join('\n');
}

function lineSlice(src: string, start: number, end: number): string {
  return src
    .split('\n')
    .slice(start - 1, end)
    .join('\n');
}

export function parseSolidity(path: string, source: string): ParsedFile {
  let ast;
  try {
    ast = parse(source, { loc: true, tolerant: false });
  } catch (e) {
    return {
      path,
      contracts: [],
      parseError: e instanceof Error ? e.message.split('\n')[0] : String(e),
    };
  }
  const contracts: ContractInfo[] = [];
  for (const child of ast.children) {
    if (child.type !== 'ContractDefinition' || !child.loc) continue;
    const node = child as ContractDefinition;
    const functions: FunctionInfo[] = [];
    for (const sub of node.subNodes) {
      if (sub.type !== 'FunctionDefinition' || !sub.loc) continue;
      const fnNode = sub as FunctionDefinition;
      const name = fnNode.isConstructor
        ? 'constructor'
        : fnNode.isReceiveEther
          ? 'receive'
          : fnNode.isFallback
            ? 'fallback'
            : (fnNode.name ?? '');
      const params = fnNode.parameters
        .map((p) =>
          p.typeName?.type === 'ElementaryTypeName'
            ? p.typeName.name
            : p.typeName?.type === 'UserDefinedTypeName'
              ? p.typeName.namePath
              : (p.typeName?.type ?? '?'),
        )
        .join(',');
      const startLine = fnNode.loc!.start.line;
      const endLine = fnNode.loc!.end.line;
      const modifiers = fnNode.modifiers.map((m) => m.name);
      const gatedBy: string[] = [];
      const gates = new Set<Capability>();
      for (const m of modifiers) {
        if (MODIFIER_GATE.test(m)) {
          gatedBy.push(`modifier ${m}`);
          gates.add(capabilityOf(`${m} ${name}`));
        }
      }
      if (fnNode.body) {
        const body = bodyText(source, fnNode);
        for (const g of BODY_GATES) {
          if (g.re.test(body)) {
            gatedBy.push(g.label);
            gates.add(capabilityOf(name + ' ' + g.label));
          }
        }
      }
      functions.push({
        contract: node.name,
        name,
        signature: `${name}(${params})`,
        visibility: (fnNode.visibility === 'default' ? 'public' : fnNode.visibility) as Visibility,
        modifiers,
        startLine,
        endLine,
        gates: [...gates].sort(),
        gatedBy: [...new Set(gatedBy)].sort(),
      });
    }
    contracts.push({
      name: node.name,
      kind: node.kind,
      bases: node.baseContracts.map((b) => b.baseName.namePath),
      startLine: child.loc.start.line,
      endLine: child.loc.end.line,
      functions,
    });
  }
  return { path, contracts };
}

/** Parse to a raw AST with locations, or undefined if the source cannot be parsed. */
export function parseAst(source: string) {
  try {
    return parse(source, { loc: true, tolerant: false });
  } catch {
    return undefined;
  }
}
