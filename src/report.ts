import { maxSeverity, SEVERITIES, sortFindings, type Finding, type Severity } from './findings.js';
import type { Inspection } from './inspect.js';
import type { StepResult } from './foundry.js';
import type { UpgradeSafety } from './analyze.js';
import type { PrivilegeMap } from './privileges.js';

export const REPORT_SCHEMA_VERSION = '1.1.0';
export const TOOL_NAME = 'protocol-guard-ci';

export const LIMITATIONS = [
  'A report with no findings is not evidence that the contracts are secure. This tool surfaces review signals only.',
  'Detection of changed functions and privileged access is syntactic (parser output and modifier or comparison names). Custom access-control schemes can be missed or misclassified.',
  'Only changes between the two given commits are inspected. Code that is unchanged but interacts with changed code is not analysed.',
  'Foundry test results are only as strong as the repository tests. Passing tests do not rule out bugs.',
  'Storage-layout comparison covers contracts defined in changed files that exist at both revisions. A change in an unchanged parent contract that shifts a child layout is not detected.',
  'Risk signals (delegatecall, assembly, etc.) are reported only on added or modified lines and are review prompts, not confirmed vulnerabilities.',
  'Proxy pattern detection is textual. Unrecognised or custom proxy designs are reported as uncertain and are not analysed.',
  'No on-chain state, deployed bytecode, multisig configuration or off-chain operations are examined.',
];

export interface Report {
  schemaVersion: string;
  tool: { name: string; version: string };
  base: { ref: string; sha: string };
  head: { ref: string; sha: string };
  inspection: Omit<Inspection, 'findings'>;
  execution: StepResult[];
  upgradeSafety: UpgradeSafety;
  privilegeMap: PrivilegeMap;
  findings: Finding[];
  summary: { counts: Record<Severity, number>; maxSeverity: Severity | null; total: number };
  limitations: string[];
  commands: string[];
}

export interface BuildInput {
  version: string;
  base: { ref: string; sha: string };
  head: { ref: string; sha: string };
  inspection: Inspection;
  execution: StepResult[];
  upgradeSafety: UpgradeSafety;
  privilegeMap: PrivilegeMap;
  extraFindings: Finding[];
  /** Extra commands (e.g. git) that were run to produce the report. */
  commands: string[];
}

export function buildReport(i: BuildInput): Report {
  const { findings: inspFindings, ...inspection } = i.inspection;
  const findings = sortFindings([...inspFindings, ...i.extraFindings]);
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return {
    schemaVersion: REPORT_SCHEMA_VERSION,
    tool: { name: TOOL_NAME, version: i.version },
    base: i.base,
    head: i.head,
    inspection,
    execution: i.execution,
    upgradeSafety: i.upgradeSafety,
    privilegeMap: i.privilegeMap,
    findings,
    summary: { counts, maxSeverity: maxSeverity(findings) ?? null, total: findings.length },
    limitations: LIMITATIONS,
    commands: [...i.commands, ...i.execution.filter((s) => !s.skipped).map((s) => s.command)],
  };
}

export function renderJson(r: Report): string {
  return JSON.stringify(r, null, 2) + '\n';
}

const esc = (s: string) => s.replace(/\|/g, '\\|').replace(/\n/g, ' ');

export function renderMarkdown(r: Report): string {
  const L: string[] = [];
  L.push('# Protocol Guard CI report', '');
  L.push(
    `Base \`${r.base.ref}\` (${r.base.sha.slice(0, 12)}) → head \`${r.head.ref}\` (${r.head.sha.slice(0, 12)})`,
    '',
  );
  L.push(
    '> This is a list of review signals, not a security audit. No findings does not mean the code is safe. See Limitations.',
    '',
  );
  L.push('## Summary', '');
  L.push('| Severity | Count |', '|---|---|');
  for (const s of [...SEVERITIES].reverse()) L.push(`| ${s} | ${r.summary.counts[s]} |`);
  L.push('');

  L.push('## Findings', '');
  if (r.findings.length === 0) L.push('No findings.', '');
  for (const f of r.findings) {
    const loc = f.file ? ` — \`${f.file}${f.line ? ':' + f.line : ''}\`` : '';
    L.push(`### ${f.severity.toUpperCase()} ${f.id}: ${f.title}${loc}`, '', f.message, '');
  }

  L.push('## Changed contracts', '');
  if (r.inspection.changedContracts.length === 0) L.push('None.', '');
  else {
    L.push('| File | Contract | Line |', '|---|---|---|');
    for (const c of r.inspection.changedContracts)
      L.push(`| ${esc(c.file)} | ${c.contract} | ${c.startLine} |`);
    L.push('');
  }

  L.push('## Changed public/external functions', '');
  if (r.inspection.changedFunctions.length === 0) L.push('None.', '');
  else {
    L.push('| Function | Change | Visibility | Privileged | Location |', '|---|---|---|---|---|');
    for (const f of r.inspection.changedFunctions) {
      L.push(
        `| ${f.contract}.${esc(f.signature)} | ${f.change} | ${f.visibility} | ${f.privileged ? 'yes (' + esc(f.gatedBy.join(', ')) + ')' : 'no'} | ${esc(f.file)}:${f.startLine} |`,
      );
    }
    L.push('');
  }

  L.push('## Upgrade safety', '');
  L.push(
    'Proxy patterns detected: ' +
      (r.upgradeSafety.proxyPatterns.length
        ? [...new Set(r.upgradeSafety.proxyPatterns.map((p) => p.pattern))].join(', ')
        : 'none') +
      '',
    '',
  );
  if (r.upgradeSafety.storage.length === 0) L.push('No storage layouts compared.', '');
  else {
    L.push('| Contract | File | Storage verdict |', '|---|---|---|');
    for (const s of r.upgradeSafety.storage)
      L.push(`| ${s.contract} | ${esc(s.file)} | ${s.verdict} |`);
    L.push('');
  }
  for (const n of r.upgradeSafety.notes) L.push('- ' + n);
  if (r.upgradeSafety.notes.length) L.push('');

  L.push('## Privilege map', '');
  const caps = Object.entries(r.privilegeMap.capabilities);
  if (caps.length === 0) L.push('No privileged functions detected.', '');
  for (const [cap, list] of caps) {
    L.push(`**${cap}**`, '');
    for (const e of list ?? [])
      L.push(
        `- ${e.contract}.${e.function} (${e.status}) — ${e.file}:${e.line} via ${e.via.join(', ')}`,
      );
    L.push('');
  }

  L.push('## Foundry execution', '');
  for (const s of r.execution) {
    const status = s.skipped
      ? 'skipped'
      : s.exitCode === 0
        ? 'passed'
        : `FAILED (exit ${s.exitCode})`;
    L.push(`### ${s.name}: ${status}`, '', '`' + s.command + '`', '', '```', s.output, '```', '');
  }

  L.push('## Commands used', '');
  for (const c of r.commands) L.push('- `' + c + '`');
  L.push('', '## Limitations', '');
  for (const l of r.limitations) L.push('- ' + l);
  L.push('');
  return L.join('\n');
}
