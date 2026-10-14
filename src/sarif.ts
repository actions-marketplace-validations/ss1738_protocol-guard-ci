import type { Report } from './report.js';
import type { Severity } from './findings.js';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.0',
  low: '3.0',
  info: '1.0',
};

/** SARIF 2.1.0 so GitHub code scanning can annotate pull requests. Findings without a file are omitted from `results`. */
export function renderSarif(r: Report): string {
  const located = r.findings.filter((f) => f.file);
  const rules = [...new Map(located.map((f) => [f.rule, f])).values()]
    .sort((a, b) => a.rule.localeCompare(b.rule))
    .map((f) => ({
      id: f.rule,
      name: f.rule,
      shortDescription: { text: f.title },
      defaultConfiguration: { level: LEVEL[f.severity] },
      properties: { 'security-severity': SECURITY_SEVERITY[f.severity], tags: ['review-signal'] },
    }));
  const doc = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: r.tool.name,
            version: r.tool.version,
            rules,
          },
        },
        results: located.map((f) => ({
          ruleId: f.rule,
          level: LEVEL[f.severity],
          message: {
            text: `${f.title}: ${f.message} (review signal, not a confirmed vulnerability)`,
          },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file },
                region: { startLine: f.line ?? 1 },
              },
            },
          ],
          partialFingerprints: { 'protocolGuardId/v1': f.id },
          properties: { severity: f.severity, findingId: f.id },
        })),
      },
    ],
  };
  return JSON.stringify(doc, null, 2) + '\n';
}
