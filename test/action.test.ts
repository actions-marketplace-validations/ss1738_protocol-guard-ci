import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { parse } from 'yaml';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const load = (p: string) => parse(readFileSync(join(root, p), 'utf8')) as any;

describe('action.yml', () => {
  const action = load('action.yml');
  const steps: any[] = action.runs.steps;

  it('is a composite action with the documented inputs and outputs', () => {
    expect(action.runs.using).toBe('composite');
    expect(Object.keys(action.inputs)).toEqual(
      expect.arrayContaining([
        'base-ref',
        'fail-on',
        'fuzz-runs',
        'invariant-runs',
        'skip-tests',
        'upload-sarif',
      ]),
    );
    expect(action.inputs['fail-on'].default).toBe('none'); // warning-only by default
    expect(Object.keys(action.outputs)).toEqual(['exit-code', 'max-severity', 'report-dir']);
  });

  it('never interpolates expressions into shell scripts (injection safety)', () => {
    for (const s of steps.filter((x) => x.run)) {
      expect(s.run, s.name).not.toMatch(/\$\{\{/);
      expect(s.shell, s.name).toBe('bash');
      expect(s.run, s.name).not.toMatch(/set -[a-z]*x|xtrace/); // no command echo that could print env values
    }
  });

  it('pins every third-party action to a version tag or SHA', () => {
    for (const s of steps.filter((x) => x.uses)) {
      expect(s.uses, s.uses).toMatch(/@(v\d+(\.\d+)*|[0-9a-f]{40})$/);
    }
  });

  it('uploads reports even when analysis fails, then enforces the result last', () => {
    const names = steps.map((s) => s.name ?? s.uses);
    expect(steps.at(-1).name).toBe('Enforce result');
    for (const s of steps.filter((x) => x.uses?.includes('upload')))
      expect(String(s.if)).toContain('always()');
    expect(names.indexOf('Enforce result')).toBeGreaterThan(
      names.findIndex((n) => String(n).includes('upload-sarif')),
    );
  });

  it('installs Slither only on request, pinned and validated, outside the project', () => {
    const install = steps.find((x) => x.name === 'Install Slither');
    expect(action.inputs.slither.default).toBe('false');
    expect(String(install.if)).toContain("inputs.slither == 'true'");
    expect(install.run).toContain('python3 -m venv');
    expect(install.run).toMatch(/\^\[0-9\]\+/); // version format check before it reaches pip
    expect(steps.find((x) => x.id === 'run').run).toContain(
      '--slither --slither-scope "$SLITHER_SCOPE"',
    );
  });

  it('passes fail-on to the CLI and contains no secrets handling', () => {
    const run = steps.find((s) => s.id === 'run');
    expect(run.run).toContain('--fail-on "$FAIL_ON"');
    expect(JSON.stringify(action)).not.toMatch(/secrets\./i);
  });
});

describe('example workflow', () => {
  const wf = load('examples/workflows/protocol-guard.yml');
  it('uses pull_request (not pull_request_target) with least privilege and full history', () => {
    expect(Object.keys(wf.on)).toEqual(['pull_request']);
    expect(wf.permissions).toEqual({ contents: 'read', 'security-events': 'write' });
    const checkout = wf.jobs.guard.steps.find((s: any) => s.uses?.startsWith('actions/checkout'));
    expect(checkout.with['fetch-depth']).toBe(0);
  });
  it('does not reference secrets', () => {
    expect(readFileSync(join(root, 'examples/workflows/protocol-guard.yml'), 'utf8')).not.toMatch(
      /secrets\./,
    );
  });
});
