import { mkdtempSync, existsSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { Shell } from './adapters/shell.js';
import { makeFinding, type Finding } from './findings.js';

export interface StorageEntry {
  label: string;
  offset: number;
  slot: string;
  type: string;
}

export interface StorageLayout {
  storage: StorageEntry[];
  types: Record<string, { label: string; numberOfBytes: string }>;
}

export interface StorageComparison {
  contract: string;
  file: string;
  verdict: 'compatible' | 'append-only' | 'unsafe' | 'unavailable';
  details: string[];
}

const pos = (e: StorageEntry) => BigInt(e.slot) * 32n + BigInt(e.offset);
const typeLabel = (l: StorageLayout, e: StorageEntry) => l.types?.[e.type]?.label ?? e.type;
const typeBytes = (l: StorageLayout, e: StorageEntry) =>
  BigInt(l.types?.[e.type]?.numberOfBytes ?? '32');

export function parseLayout(json: string): StorageLayout | undefined {
  try {
    const o = JSON.parse(json) as StorageLayout;
    return Array.isArray(o.storage) ? o : undefined;
  } catch {
    return undefined;
  }
}

/** Pure comparison of two storage layouts for one contract. */
export function compareLayouts(
  contract: string,
  file: string,
  line: (label: string) => number,
  base: StorageLayout,
  head: StorageLayout,
): { comparison: StorageComparison; findings: Finding[] } {
  const findings: Finding[] = [];
  const details: string[] = [];
  const mk = (
    rule: string,
    severity: Finding['severity'],
    title: string,
    message: string,
    label: string,
  ) => {
    details.push(`${rule}: ${message}`);
    findings.push(
      makeFinding({
        rule,
        severity,
        title,
        message,
        file,
        line: line(label),
        symbol: `${contract}.${label}`,
        kind: 'signal',
      }),
    );
  };
  const headBy = new Map(head.storage.map((e) => [e.label, e]));
  const baseLabels = new Set(base.storage.map((e) => e.label));
  const renamedTo = new Set<string>();

  for (const b of base.storage) {
    const h = headBy.get(b.label);
    if (!h) {
      const renamed = head.storage.find(
        (e) =>
          !baseLabels.has(e.label) &&
          e.slot === b.slot &&
          e.offset === b.offset &&
          typeLabel(head, e) === typeLabel(base, b),
      );
      if (renamed) {
        renamedTo.add(renamed.label);
        mk(
          'storage-variable-renamed',
          'medium',
          'Storage variable renamed',
          `${contract}: '${b.label}' at slot ${b.slot}+${b.offset} is now '${renamed.label}' with the same type. Layout is unchanged, but confirm this is a rename and not a different variable.`,
          renamed.label,
        );
      } else {
        mk(
          'storage-variable-removed',
          'high',
          'Storage variable removed',
          `${contract}: '${b.label}' (${typeLabel(base, b)}, slot ${b.slot}+${b.offset}) no longer exists. Removing variables shifts or orphans stored data; keep a placeholder instead.`,
          b.label,
        );
      }
      continue;
    }
    if (h.slot !== b.slot || h.offset !== b.offset) {
      mk(
        'storage-slot-moved',
        'critical',
        'Storage variable moved',
        `${contract}: '${b.label}' moved from slot ${b.slot}+${b.offset} to ${h.slot}+${h.offset}. Existing proxy storage would be read as the wrong variable.`,
        b.label,
      );
    } else if (typeLabel(base, b) !== typeLabel(head, h)) {
      const sameSize = typeBytes(base, b) === typeBytes(head, h);
      mk(
        'storage-type-changed',
        sameSize ? 'high' : 'critical',
        'Storage variable type changed',
        `${contract}: '${b.label}' changed type from ${typeLabel(base, b)} to ${typeLabel(head, h)} (${sameSize ? 'same size, meaning may differ' : 'size differs, neighbouring slots affected'}).`,
        b.label,
      );
    }
  }

  const baseEnd = base.storage.reduce((m, e) => {
    const end = pos(e) + typeBytes(base, e);
    return end > m ? end : m;
  }, 0n);
  let appended = 0;
  for (const h of head.storage) {
    if (baseLabels.has(h.label) || renamedTo.has(h.label)) continue;
    if (pos(h) >= baseEnd) {
      appended++;
      details.push(`storage-append: '${h.label}' appended at slot ${h.slot}+${h.offset}`);
      findings.push(
        makeFinding({
          rule: 'storage-append',
          severity: 'info',
          title: 'Storage variable appended',
          message: `${contract}: '${h.label}' (${typeLabel(head, h)}) appended after existing layout (slot ${h.slot}+${h.offset}). This is the expected safe upgrade pattern; confirm no inherited contract also gained variables.`,
          file,
          line: line(h.label),
          symbol: `${contract}.${h.label}`,
          kind: 'signal',
        }),
      );
    } else {
      mk(
        'storage-variable-inserted',
        'high',
        'Storage variable inserted before existing variables',
        `${contract}: '${h.label}' was inserted at slot ${h.slot}+${h.offset}, inside the existing layout.`,
        h.label,
      );
    }
  }
  const unsafe = findings.some(
    (f) => f.severity !== 'info' && f.rule !== 'storage-variable-renamed',
  );
  const verdict = unsafe ? 'unsafe' : appended > 0 ? 'append-only' : 'compatible';
  return { comparison: { contract, file, verdict, details: details.sort() }, findings };
}

/**
 * `forge inspect` fails with "storage layout missing from artifact" when an earlier `forge build`
 * cached artifacts without the storageLayout output. Retry once with --no-cache, which recompiles
 * in memory without clearing the project's out/ or cache/ directories.
 */
async function inspectLayout(
  shell: Shell,
  cwd: string,
  t: { contract: string; file: string },
  timeoutMs: number,
) {
  const base = ['inspect', '--json', `${t.file}:${t.contract}`, 'storage-layout'];
  const commands: string[] = [];
  let result = await shell.run('forge', base, { cwd, timeoutMs });
  commands.push(result.command);
  if (
    result.exitCode !== 0 &&
    /storage layout missing|spurious caching/i.test(result.stderr + result.stdout)
  ) {
    result = await shell.run('forge', ['inspect', '--no-cache', ...base.slice(1)], {
      cwd,
      timeoutMs,
    });
    commands.push(result.command);
  }
  return { result, commands };
}

export interface LayoutSource {
  contract: string;
  file: string;
  line: (label: string) => number;
}

/** Collect layouts for base (in a temporary git worktree) and head (the checked-out tree). */
export async function compareStorage(
  shell: Shell,
  repo: string,
  baseSha: string,
  targets: LayoutSource[],
  timeoutMs: number,
): Promise<{ comparisons: StorageComparison[]; findings: Finding[]; commands: string[] }> {
  const comparisons: StorageComparison[] = [];
  const findings: Finding[] = [];
  const commands: string[] = [];
  if (targets.length === 0) return { comparisons, findings, commands };

  const wt = mkdtempSync(join(tmpdir(), 'pg-base-'));
  const unavailable = (t: LayoutSource, why: string) => {
    comparisons.push({
      contract: t.contract,
      file: t.file,
      verdict: 'unavailable',
      details: [why],
    });
    findings.push(
      makeFinding({
        rule: 'storage-layout-unavailable',
        severity: 'medium',
        title: 'Storage layout could not be compared',
        message: `${t.contract}: ${why}. Upgrade safety for this contract is UNVERIFIED.`,
        file: t.file,
        symbol: t.contract,
        kind: 'execution',
      }),
    );
  };
  try {
    const add = await shell.run('git', ['worktree', 'add', '--detach', wt, baseSha], { cwd: repo });
    commands.push(add.command);
    if (add.exitCode !== 0) {
      for (const t of targets)
        unavailable(t, `could not check out base revision (${add.stderr.trim().split('\n')[0]})`);
      return { comparisons, findings, commands };
    }
    // Dependencies are usually untracked or submodules; reuse the head checkout's copies.
    for (const dir of ['lib', 'node_modules']) {
      if (existsSync(join(repo, dir))) {
        rmSync(join(wt, dir), { recursive: true, force: true });
        symlinkSync(join(repo, dir), join(wt, dir));
      }
    }
    for (const t of targets) {
      const [b, h] = [
        await inspectLayout(shell, wt, t, timeoutMs),
        await inspectLayout(shell, repo, t, timeoutMs),
      ];
      for (const c of [...b.commands, ...h.commands]) if (!commands.includes(c)) commands.push(c);
      const bl = b.result.exitCode === 0 ? parseLayout(b.result.stdout) : undefined;
      const hl = h.result.exitCode === 0 ? parseLayout(h.result.stdout) : undefined;
      if (!bl || !hl) {
        unavailable(t, `forge inspect failed for ${bl ? 'head' : 'base'} revision`);
        continue;
      }
      const r = compareLayouts(t.contract, t.file, t.line, bl, hl);
      comparisons.push(r.comparison);
      findings.push(...r.findings);
    }
  } finally {
    await shell.run('git', ['worktree', 'remove', '--force', wt], { cwd: repo });
    rmSync(wt, { recursive: true, force: true });
  }
  comparisons.sort((a, b) => a.file.localeCompare(b.file) || a.contract.localeCompare(b.contract));
  return { comparisons, findings, commands };
}
