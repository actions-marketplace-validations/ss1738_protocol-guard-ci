import type { Shell } from './adapters/shell.js';
import { changedFiles, showFile, type ChangedFile } from './git.js';
import { makeFinding, type Finding } from './findings.js';
import { parseSolidity, type FunctionInfo, type ParsedFile } from './solidity.js';
import { existsSync } from 'node:fs';
import { join } from 'node:path';

export interface ChangedFunction {
  file: string;
  contract: string;
  signature: string;
  visibility: string;
  startLine: number;
  endLine: number;
  change: 'added' | 'modified';
  privileged: boolean;
  gatedBy: string[];
  gates: string[];
}

export interface Inspection {
  isFoundry: boolean;
  solidityFilesChanged: string[];
  changedContracts: { file: string; contract: string; startLine: number }[];
  changedFunctions: ChangedFunction[];
  parseErrors: { file: string; error: string }[];
  findings: Finding[];
}

function overlaps(ranges: [number, number][], start: number, end: number): boolean {
  return ranges.some(([a, b]) => a <= end && b >= start);
}

const isExternallyCallable = (f: FunctionInfo) =>
  f.visibility === 'public' || f.visibility === 'external';

export async function inspectRepo(
  shell: Shell,
  cwd: string,
  base: string,
  head: string,
): Promise<Inspection> {
  const isFoundry = existsSync(join(cwd, 'foundry.toml'));
  const files = (await changedFiles(shell, cwd, base, head)).filter((f) => f.path.endsWith('.sol'));
  const result: Inspection = {
    isFoundry,
    solidityFilesChanged: files.map((f) => f.path),
    changedContracts: [],
    changedFunctions: [],
    parseErrors: [],
    findings: [],
  };

  for (const f of files) {
    if (f.status === 'D') continue;
    const headSrc = await showFile(shell, cwd, head, f.path);
    if (headSrc === undefined) continue;
    const baseSrc = await showFile(shell, cwd, base, f.oldPath ?? f.path);
    const parsedHead = parseSolidity(f.path, headSrc);
    if (parsedHead.parseError) {
      result.parseErrors.push({ file: f.path, error: parsedHead.parseError });
      result.findings.push(
        makeFinding({
          rule: 'parse-error',
          severity: 'medium',
          title: 'Solidity file could not be parsed',
          message: `Analysis for ${f.path} is incomplete: ${parsedHead.parseError}`,
          file: f.path,
          kind: 'execution',
        }),
      );
      continue;
    }
    const parsedBase: ParsedFile | undefined =
      baseSrc === undefined ? undefined : parseSolidity(f.path, baseSrc);
    collect(result, f, parsedHead, parsedBase);
  }

  result.changedContracts.sort(
    (a, b) => a.file.localeCompare(b.file) || a.contract.localeCompare(b.contract),
  );
  result.changedFunctions.sort(
    (a, b) =>
      a.file.localeCompare(b.file) ||
      a.startLine - b.startLine ||
      a.signature.localeCompare(b.signature),
  );
  return result;
}

function collect(
  result: Inspection,
  f: ChangedFile,
  head: ParsedFile,
  base: ParsedFile | undefined,
): void {
  const baseFns = new Map<string, FunctionInfo>();
  for (const c of base?.contracts ?? [])
    for (const fn of c.functions) baseFns.set(`${c.name}.${fn.signature}`, fn);
  const wholeFile = f.status === 'A';

  for (const c of head.contracts) {
    const touched = wholeFile || overlaps(f.addedRanges, c.startLine, c.endLine);
    if (touched)
      result.changedContracts.push({ file: f.path, contract: c.name, startLine: c.startLine });
    for (const fn of c.functions) {
      if (!isExternallyCallable(fn)) continue;
      const changed = wholeFile || overlaps(f.addedRanges, fn.startLine, fn.endLine);
      if (!changed) continue;
      const prev = baseFns.get(`${c.name}.${fn.signature}`);
      const privileged = fn.gatedBy.length > 0;
      const entry: ChangedFunction = {
        file: f.path,
        contract: c.name,
        signature: fn.signature,
        visibility: fn.visibility,
        startLine: fn.startLine,
        endLine: fn.endLine,
        change: prev ? 'modified' : 'added',
        privileged,
        gatedBy: fn.gatedBy,
        gates: fn.gates,
      };
      result.changedFunctions.push(entry);
      if (privileged) {
        const isNew = !prev;
        result.findings.push(
          makeFinding({
            rule: isNew ? 'new-privileged-function' : 'privileged-function-changed',
            severity: isNew ? 'high' : 'medium',
            title: isNew ? 'New privileged function' : 'Privileged function changed',
            message: `${c.name}.${fn.signature} (${fn.visibility}) is gated by ${fn.gatedBy.join(', ')}. Review who holds this capability and what it can move or change.`,
            file: f.path,
            line: fn.startLine,
            symbol: `${c.name}.${fn.signature}`,
            kind: 'signal',
          }),
        );
      }
    }
  }
}
