import type { Shell } from './adapters/shell.js';
import { changedFiles, showFile } from './git.js';
import { makeFinding, type Finding } from './findings.js';
import { parseSolidity, type ContractInfo, type ParsedFile } from './solidity.js';
import { findSignals } from './signals.js';
import { checkUpgradeSurface, detectProxyPatterns, type ProxyPattern } from './upgrade.js';
import { buildPrivilegeMap, type PrivilegeMap } from './privileges.js';
import { compareStorage, type StorageComparison, type LayoutSource } from './storage.js';

export interface UpgradeSafety {
  proxyPatterns: ProxyPattern[];
  storage: StorageComparison[];
  notes: string[];
}

export interface Analysis {
  findings: Finding[];
  privilegeMap: PrivilegeMap;
  upgradeSafety: UpgradeSafety;
  commands: string[];
}

const isProjectSource = (p: string) =>
  p.endsWith('.sol') &&
  !/^(test|tests|script|scripts|lib|node_modules)\//.test(p) &&
  !/\.(t|s)\.sol$/.test(p);

const overlaps = (r: [number, number][], a: number, b: number) =>
  r.some(([x, y]) => x <= b && y >= a);

function varLine(src: string, c: ContractInfo, label: string): number {
  const lines = src.split('\n');
  for (let i = c.startLine - 1; i < Math.min(c.endLine, lines.length); i++) {
    if (new RegExp(`\\b${label}\\b\\s*(;|=)`).test(lines[i]!)) return i + 1;
  }
  return c.startLine;
}

const DEPENDENCY_FILES =
  /^(lib\/|node_modules\/|dependencies\/|foundry\.toml$|remappings\.txt$|\.gitmodules$|package\.json$|package-lock\.json$|yarn\.lock$|pnpm-lock\.yaml$|soldeer\.lock$|foundry\.lock$)/;

/**
 * The base worktree reuses the head checkout's dependencies, so when dependencies or compiler
 * configuration change, the storage comparison cannot see their effect. Say so instead of staying silent.
 */
export function dependencyFindings(paths: string[]): Finding[] {
  return paths
    .filter((p) => DEPENDENCY_FILES.test(p) && !p.endsWith('.sol'))
    .sort()
    .map((p) =>
      makeFinding({
        rule: 'dependency-changed',
        severity: 'medium',
        title: 'Dependency or build configuration changed',
        message: `${p} changed. Storage-layout checks reuse the head checkout's dependencies for both revisions, so a layout change caused by a library or compiler-setting change is NOT detected. Review the dependency diff and compare layouts of inheriting contracts manually.`,
        file: p,
        symbol: p,
        kind: 'signal',
      }),
    );
}

export async function analyze(
  shell: Shell,
  repo: string,
  baseSha: string,
  headSha: string,
  timeoutMs: number,
): Promise<Analysis> {
  const findings: Finding[] = [];
  const commands: string[] = [];
  const everything = await changedFiles(shell, repo, baseSha, headSha);
  findings.push(...dependencyFindings(everything.map((f) => f.path)));
  const changed = everything.filter((f) => f.path.endsWith('.sol') && f.status !== 'D');
  const changedBy = new Map(changed.map((f) => [f.path, f]));

  const ls = await shell.run('git', ['ls-tree', '-r', '--name-only', headSha], { cwd: repo });
  commands.push(ls.command);
  const allPaths = ls.stdout.split('\n').filter(isProjectSource).sort();

  const parsedHead = new Map<string, { parsed: ParsedFile; text: string }>();
  for (const p of allPaths) {
    const text = await showFile(shell, repo, headSha, p);
    if (text !== undefined) parsedHead.set(p, { parsed: parseSolidity(p, text), text });
  }

  const targets: LayoutSource[] = [];
  const baseSigs = new Map<string, Set<string>>();
  const notes: string[] = [];
  for (const f of changed) {
    if (!isProjectSource(f.path)) continue;
    const head = parsedHead.get(f.path);
    if (!head || head.parsed.parseError) continue;
    const wholeFile = f.status === 'A';
    findings.push(...findSignals(f.path, head.text, wholeFile ? 'all' : f.addedRanges));
    const baseText = wholeFile
      ? undefined
      : await showFile(shell, repo, baseSha, f.oldPath ?? f.path);
    const base = baseText === undefined ? undefined : parseSolidity(f.path, baseText);
    baseSigs.set(
      f.path,
      new Set(
        (base?.contracts ?? []).flatMap((c) =>
          c.functions.map((fn) => `${c.name}.${fn.signature}`),
        ),
      ),
    );
    for (const c of head.parsed.contracts) {
      const bc = base?.contracts.find((x) => x.name === c.name);
      findings.push(
        ...checkUpgradeSurface({
          file: f.path,
          head: c,
          base: bc,
          isChanged: (fn) => wholeFile || overlaps(f.addedRanges, fn.startLine, fn.endLine),
        }),
      );
      if (bc && c.kind === 'contract') {
        targets.push({ contract: c.name, file: f.path, line: (l) => varLine(head.text, c, l) });
      }
    }
  }

  const storage = await compareStorage(shell, repo, baseSha, targets, timeoutMs);
  findings.push(...storage.findings);
  commands.push(...storage.commands);

  const proxyPatterns = detectProxyPatterns(
    [...parsedHead].map(([path, v]) => ({ path, text: v.text })),
  );
  const hasInit = [...parsedHead.values()].some((v) =>
    v.parsed.contracts.some((c) =>
      c.functions.some((fn) => /^initialize|^reinitialize|_init$/.test(fn.name)),
    ),
  );
  if (hasInit && !proxyPatterns.some((p) => p.pattern !== 'erc1967-slot')) {
    notes.push(
      'Initializer functions exist but no UUPS, transparent or beacon proxy pattern was recognised.',
    );
    findings.push(
      makeFinding({
        rule: 'proxy-pattern-uncertain',
        severity: 'info',
        title: 'Upgrade pattern not recognised',
        message:
          'Initializer functions were found but no UUPS, transparent or beacon proxy pattern was detected. Upgrade-safety checks may be incomplete.',
        kind: 'execution',
      }),
    );
  }
  if (targets.length === 0)
    notes.push('No contract with a base counterpart changed, so no storage layout was compared.');

  const privilegeMap = buildPrivilegeMap(
    [...parsedHead].map(([path, v]) => {
      const f = changedBy.get(path);
      return {
        path,
        contracts: v.parsed.contracts,
        status: (c, sig, a, b) => {
          if (!f) return 'unchanged';
          if (f.status === 'A' || !baseSigs.get(path)?.has(`${c.name}.${sig}`)) return 'added';
          return overlaps(f.addedRanges, a, b) ? 'modified' : 'unchanged';
        },
      };
    }),
  );

  return {
    findings,
    privilegeMap,
    upgradeSafety: { proxyPatterns, storage: storage.comparisons, notes },
    commands,
  };
}
