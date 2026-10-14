import { makeFinding, type Finding } from './findings.js';

export const IGNORE_FILE = '.protocol-guard-ignore';

/** PG-<RULE>-<8 hex>, as produced by makeFinding. */
const ID_RE = /^PG-[A-Z0-9-]+-[0-9a-f]{8}$/;

export interface IgnoreEntry {
  id: string;
  reason: string;
  /** 1-based line in the ignore file. */
  line: number;
}

export interface IgnoreProblem {
  line: number;
  text: string;
  problem: string;
}

export type IgnoreSource = 'base' | 'head';

export interface SuppressedFinding extends Finding {
  suppression: { reason: string; line: number };
}

export interface IgnoreReport {
  file: string;
  /** Where the file was read from. "head" is for local testing only. */
  source: IgnoreSource;
  ref: string;
  entries: number;
  applied: number;
  stale: IgnoreEntry[];
  problems: IgnoreProblem[];
}

/**
 * Format: `<finding-id> # <required reason>`. Blank lines and full-line `#` comments are skipped.
 * An entry without a reason, or with a malformed ID, is a problem and is never applied.
 */
export function parseIgnore(text: string): { entries: IgnoreEntry[]; problems: IgnoreProblem[] } {
  const entries: IgnoreEntry[] = [];
  const problems: IgnoreProblem[] = [];
  const seen = new Set<string>();
  text.split(/\r?\n/).forEach((raw, i) => {
    const line = i + 1;
    const t = raw.trim();
    if (t === '' || t.startsWith('#')) return;
    const hash = t.indexOf('#');
    const id = (hash < 0 ? t : t.slice(0, hash)).trim();
    const reason = hash < 0 ? '' : t.slice(hash + 1).trim();
    const bad = (problem: string) => problems.push({ line, text: t, problem });
    if (!ID_RE.test(id)) bad('not a finding ID (expected PG-<RULE>-<8 hex>); entry NOT applied');
    else if (reason === '') bad('missing required "# reason" comment; entry NOT applied');
    else if (seen.has(id)) bad(`duplicate of an earlier entry for ${id}; entry NOT applied`);
    else {
      seen.add(id);
      entries.push({ id, reason, line });
    }
  });
  return { entries, problems };
}

/**
 * Split findings into active and suppressed. Only review signals can be suppressed: tooling and
 * execution findings (failed forge test, Slither not run, ...) have IDs that are not tied to a
 * specific code location, so an entry for one would hide every future occurrence.
 */
export function applyIgnore(
  findings: Finding[],
  entries: IgnoreEntry[],
): {
  active: Finding[];
  suppressed: SuppressedFinding[];
  stale: IgnoreEntry[];
  refused: IgnoreProblem[];
} {
  const byId = new Map(entries.map((e) => [e.id, e]));
  const used = new Set<string>();
  const refused: IgnoreProblem[] = [];
  const active: Finding[] = [];
  const suppressed: SuppressedFinding[] = [];
  for (const f of findings) {
    const e = byId.get(f.id);
    if (e && f.kind === 'signal') {
      used.add(e.id);
      suppressed.push({ ...f, suppression: { reason: e.reason, line: e.line } });
    } else {
      if (e && !used.has(e.id)) {
        used.add(e.id);
        refused.push({
          line: e.line,
          text: e.id,
          problem: `${f.rule} is a tooling or execution finding and cannot be suppressed; entry NOT applied`,
        });
      }
      active.push(f);
    }
  }
  return { active, suppressed, stale: entries.filter((e) => !used.has(e.id)), refused };
}

/** Findings that report a bad ignore file. kind "execution" so they can never be ignored themselves. */
export function problemFindings(problems: IgnoreProblem[]): Finding[] {
  return problems.map((p) =>
    makeFinding({
      rule: 'ignore-entry-invalid',
      severity: 'low',
      title: 'Invalid .protocol-guard-ignore entry',
      message: `${IGNORE_FILE} line ${p.line}: ${p.problem} (${p.text.slice(0, 80)})`,
      file: IGNORE_FILE,
      line: p.line,
      symbol: `line-${p.line}`,
      kind: 'execution',
    }),
  );
}

export function ignoreChangedFinding(): Finding {
  return makeFinding({
    rule: 'ignore-file-changed',
    severity: 'low',
    title: `${IGNORE_FILE} differs between base and head`,
    message: `This PR adds or edits ${IGNORE_FILE}. Entries are read from the BASE branch, so changes here take effect only after merge and do not suppress findings in this PR. Review them as carefully as code.`,
    file: IGNORE_FILE,
    symbol: 'changed',
    kind: 'execution',
  });
}
