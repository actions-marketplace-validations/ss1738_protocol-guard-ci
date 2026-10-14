import type { Shell } from './adapters/shell.js';
import { changedFiles } from './git.js';
import { makeFinding, type Finding, type Severity } from './findings.js';

export type SlitherScope = 'changed' | 'all';

export interface SlitherSummary {
  requested: true;
  ran: boolean;
  version?: string;
  command: string;
  scope: SlitherScope;
  /** Detector results Slither produced, excluding dependency and optimisation results. */
  totalResults: number;
  /** Results turned into findings. */
  reported: number;
  /** Results on unchanged lines that were left out because scope is "changed". */
  suppressedPreexisting: number;
  error?: string;
}

interface SlitherElement {
  type: string;
  name: string;
  source_mapping?: { filename_relative?: string; lines?: number[]; is_dependency?: boolean };
  type_specific_fields?: { parent?: { name?: string } };
}
interface SlitherDetector {
  check: string;
  impact: string;
  confidence: string;
  description: string;
  elements: SlitherElement[];
}

const IMPACT: Record<string, Severity | undefined> = {
  High: 'high',
  Medium: 'medium',
  Low: 'low',
  Informational: 'info',
  Optimization: undefined,
};
const DOWN: Record<Severity, Severity> = {
  critical: 'high',
  high: 'medium',
  medium: 'low',
  low: 'info',
  info: 'info',
};
const DEPENDENCY_DIR = /^(lib|node_modules|test|tests|script|scripts|dependencies)\//;

const escapeRegex = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const overlaps = (r: [number, number][] | 'all', lines: number[]) =>
  r === 'all' || lines.some((l) => r.some(([a, b]) => l >= a && l <= b));

/** Pure: turn Slither's JSON into findings, keeping only results that touch changed lines when scope is "changed". */
export function parseSlither(
  stdout: string,
  changed: Map<string, [number, number][] | 'all'>,
  scope: SlitherScope,
): { findings: Finding[]; total: number; suppressed: number } | { error: string } {
  let doc: {
    success?: boolean;
    error?: string | null;
    results?: { detectors?: SlitherDetector[] } | [];
  };
  try {
    doc = JSON.parse(stdout);
  } catch {
    return { error: 'Slither did not produce JSON output' };
  }
  if (doc.success === false)
    return { error: `Slither reported an error: ${String(doc.error ?? 'unknown').split('\n')[0]}` };
  const detectors = Array.isArray(doc.results) ? [] : (doc.results?.detectors ?? []);

  const findings: Finding[] = [];
  const seen = new Map<string, number>();
  let total = 0;
  let suppressed = 0;
  for (const d of detectors) {
    const base = IMPACT[d.impact];
    if (base === undefined) continue;
    const els = d.elements.filter(
      (e) =>
        e.source_mapping?.filename_relative &&
        !e.source_mapping.is_dependency &&
        !DEPENDENCY_DIR.test(e.source_mapping.filename_relative),
    );
    if (els.length === 0) continue;
    total++;
    // Prefer an element on a changed line; otherwise the most specific (last) element.
    const hit = els.find((e) =>
      overlaps(
        changed.get(e.source_mapping!.filename_relative!) ?? [],
        e.source_mapping!.lines ?? [],
      ),
    );
    if (scope === 'changed' && !hit) {
      suppressed++;
      continue;
    }
    const el = hit ?? els[els.length - 1]!;
    const file = el.source_mapping!.filename_relative!;
    const lines = el.source_mapping!.lines ?? [];
    const line = hit
      ? (lines.find((l) => overlaps(changed.get(file) ?? [], [l])) ?? lines[0])
      : lines[0];
    const where = el.type_specific_fields?.parent?.name ?? el.name;
    const key = `${d.check}|${file}|${where}`;
    const n = (seen.get(key) ?? 0) + 1;
    seen.set(key, n);
    const severity = d.confidence === 'Low' ? DOWN[base] : base;
    findings.push(
      makeFinding({
        rule: `slither-${d.check}`,
        severity,
        title: `Slither: ${d.check}`,
        message: `${d.description.split('\n')[0]!.trim()} (Slither impact ${d.impact}, confidence ${d.confidence}; https://github.com/crytic/slither/wiki/Detector-Documentation#${d.check})`,
        file,
        line,
        symbol: `${where}#${n}`,
        kind: 'signal',
      }),
    );
  }
  return { findings, total, suppressed };
}

export async function runSlither(
  shell: Shell,
  repo: string,
  baseSha: string,
  headSha: string,
  opts: { scope: SlitherScope; timeoutMs: number },
): Promise<{ findings: Finding[]; summary: SlitherSummary }> {
  const filter = `^${escapeRegex(repo)}/(lib|node_modules|test|script)/`;
  const args = ['.', '--json', '-', '--filter-paths', filter, '--exclude-optimization'];
  const summary: SlitherSummary = {
    requested: true,
    ran: false,
    command: `slither ${args.join(' ')}`,
    scope: opts.scope,
    totalResults: 0,
    reported: 0,
    suppressedPreexisting: 0,
  };
  const unavailable = (why: string): { findings: Finding[]; summary: SlitherSummary } => ({
    summary: { ...summary, error: why },
    findings: [
      makeFinding({
        rule: 'slither-unavailable',
        severity: 'medium',
        title: 'Slither was requested but did not run',
        message: `${why}. Slither results are MISSING from this report. Install it with: pip install slither-analyzer==0.11.6`,
        kind: 'execution',
      }),
    ],
  });

  const ver = await shell.run('slither', ['--version'], { cwd: repo, timeoutMs: 60_000 });
  if (ver.exitCode === 127) return unavailable('slither is not installed or not on PATH');
  summary.version = ver.stdout.trim().split('\n')[0] || undefined;

  const changed = new Map<string, [number, number][] | 'all'>();
  for (const f of await changedFiles(shell, repo, baseSha, headSha)) {
    if (f.status !== 'D') changed.set(f.path, f.status === 'A' ? 'all' : f.addedRanges);
  }

  const r = await shell.run('slither', args, { cwd: repo, timeoutMs: opts.timeoutMs });
  // Slither exits non-zero when it finds results, so parse stdout instead of trusting the exit code.
  if (r.timedOut) return unavailable('slither timed out');
  const parsed = parseSlither(r.stdout, changed, opts.scope);
  if ('error' in parsed)
    return unavailable(
      `${parsed.error}${r.stderr ? ` (${r.stderr.trim().split('\n').slice(-1)[0]})` : ''}`,
    );
  return {
    findings: parsed.findings,
    summary: {
      ...summary,
      ran: true,
      totalResults: parsed.total,
      reported: parsed.findings.length,
      suppressedPreexisting: parsed.suppressed,
    },
  };
}
