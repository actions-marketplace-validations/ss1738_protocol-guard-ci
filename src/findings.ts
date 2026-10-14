import { createHash } from 'node:crypto';

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

export function severityRank(s: Severity): number {
  return SEVERITIES.indexOf(s);
}

export interface Finding {
  /** Stable across runs for the same rule, file and symbol: PG-<RULE>-<8 hex>. */
  id: string;
  rule: string;
  severity: Severity;
  title: string;
  message: string;
  file?: string;
  line?: number;
  symbol?: string;
  /** Always a review signal unless a command failed; never a confirmed vulnerability. */
  kind: 'signal' | 'execution';
}

export function makeFinding(f: Omit<Finding, 'id'>): Finding {
  const key = [f.rule, f.file ?? '', f.symbol ?? ''].join('|');
  const hash = createHash('sha256').update(key).digest('hex').slice(0, 8);
  return { id: `PG-${f.rule.toUpperCase()}-${hash}`, ...f };
}

/** Deterministic order: severity desc, then file, line, id. */
export function sortFindings(fs: Finding[]): Finding[] {
  return [...fs].sort(
    (a, b) =>
      severityRank(b.severity) - severityRank(a.severity) ||
      (a.file ?? '').localeCompare(b.file ?? '') ||
      (a.line ?? 0) - (b.line ?? 0) ||
      a.id.localeCompare(b.id),
  );
}

export function maxSeverity(fs: Finding[]): Severity | undefined {
  let best: Severity | undefined;
  for (const f of fs)
    if (best === undefined || severityRank(f.severity) > severityRank(best)) best = f.severity;
  return best;
}
