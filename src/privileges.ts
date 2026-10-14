import type { Capability, ContractInfo } from './solidity.js';

export interface PrivilegeEntry {
  contract: string;
  function: string;
  file: string;
  line: number;
  visibility: string;
  via: string[];
  status: 'added' | 'modified' | 'unchanged';
}

export interface PrivilegeMap {
  schemaVersion: '1.0.0';
  /** Syntactic detection only; see limitations. */
  capabilities: Partial<Record<Capability, PrivilegeEntry[]>>;
}

export function buildPrivilegeMap(
  files: {
    path: string;
    contracts: ContractInfo[];
    status: (c: ContractInfo, sig: string, start: number, end: number) => PrivilegeEntry['status'];
  }[],
): PrivilegeMap {
  const caps: PrivilegeMap['capabilities'] = {};
  for (const f of files) {
    for (const c of f.contracts) {
      for (const fn of c.functions) {
        if (
          fn.gatedBy.length === 0 ||
          (fn.visibility !== 'public' &&
            fn.visibility !== 'external' &&
            fn.name !== '_authorizeUpgrade')
        )
          continue;
        for (const cap of fn.gates) {
          (caps[cap] ??= []).push({
            contract: c.name,
            function: fn.signature,
            file: f.path,
            line: fn.startLine,
            visibility: fn.visibility,
            via: fn.gatedBy,
            status: f.status(c, fn.signature, fn.startLine, fn.endLine),
          });
        }
      }
    }
  }
  for (const list of Object.values(caps)) {
    list.sort(
      (a, b) =>
        a.file.localeCompare(b.file) || a.line - b.line || a.function.localeCompare(b.function),
    );
  }
  return { schemaVersion: '1.0.0', capabilities: Object.fromEntries(Object.entries(caps).sort()) };
}
