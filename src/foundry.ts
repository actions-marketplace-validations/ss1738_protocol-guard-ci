import type { Shell } from './adapters/shell.js';
import { makeFinding, type Finding } from './findings.js';

export interface StepResult {
  name: 'fmt' | 'build' | 'test';
  command: string;
  exitCode: number;
  skipped: boolean;
  timedOut: boolean;
  /** Normalised tail of combined output (durations and fuzz averages stripped for determinism). */
  output: string;
}

export interface FoundryOptions {
  fuzzRuns?: number;
  invariantRuns?: number;
  skipTests: boolean;
  timeoutMs: number;
}

const MAX_OUTPUT_LINES = 60;

/** Make forge output reproducible: drop wall-clock durations and fuzz mean/median gas. */
export function normaliseOutput(text: string): string {
  return text
    .replace(/\x1b\[[0-9;]*m/g, '')
    .replace(/\b\d+(\.\d+)?\s?(ms|µs|μs|ns|s)\b/g, '<t>')
    .replace(/\(runs: (\d+), [μµ]: \d+, ~: \d+\)/g, '(runs: $1)')
    .replace(/\(gas: \d+\)/g, '(gas: <n>)')
    .split('\n')
    .map((l) => l.trimEnd())
    .join('\n')
    .trim();
}

function tail(text: string): string {
  const lines = text.split('\n');
  return lines.length <= MAX_OUTPUT_LINES
    ? text
    : `... (${lines.length - MAX_OUTPUT_LINES} earlier lines omitted)\n` +
        lines.slice(-MAX_OUTPUT_LINES).join('\n');
}

async function step(
  shell: Shell,
  cwd: string,
  name: StepResult['name'],
  args: string[],
  env: Record<string, string>,
  timeoutMs: number,
): Promise<StepResult> {
  const r = await shell.run('forge', args, { cwd, env, timeoutMs });
  const envPrefix = Object.keys(env)
    .sort()
    .map((k) => `${k}=${env[k]} `)
    .join('');
  return {
    name,
    command: envPrefix + r.command,
    exitCode: r.exitCode,
    skipped: false,
    timedOut: r.timedOut,
    output: tail(normaliseOutput(`${r.stdout}\n${r.stderr}`)),
  };
}

export async function runFoundry(
  shell: Shell,
  cwd: string,
  opts: FoundryOptions,
): Promise<{ steps: StepResult[]; findings: Finding[] }> {
  const steps: StepResult[] = [];
  steps.push(await step(shell, cwd, 'fmt', ['fmt', '--check'], {}, opts.timeoutMs));
  const build = await step(shell, cwd, 'build', ['build'], {}, opts.timeoutMs);
  steps.push(build);

  const env: Record<string, string> = {};
  if (opts.fuzzRuns !== undefined) env.FOUNDRY_FUZZ_RUNS = String(opts.fuzzRuns);
  if (opts.invariantRuns !== undefined) env.FOUNDRY_INVARIANT_RUNS = String(opts.invariantRuns);

  if (opts.skipTests || build.exitCode !== 0) {
    steps.push({
      name: 'test',
      command: 'forge test',
      exitCode: 0,
      skipped: true,
      timedOut: false,
      output: opts.skipTests ? 'skipped by --skip-tests' : 'skipped because forge build failed',
    });
  } else {
    steps.push(await step(shell, cwd, 'test', ['test'], env, opts.timeoutMs));
  }

  const findings: Finding[] = [];
  for (const s of steps) {
    if (s.skipped || s.exitCode === 0) continue;
    const missing = s.exitCode === 127;
    findings.push(
      makeFinding({
        rule: `forge-${s.name}-failed`,
        severity: s.name === 'fmt' ? 'low' : 'high',
        title: missing
          ? 'Foundry (forge) is not installed or not on PATH'
          : s.timedOut
            ? `forge ${s.name} timed out`
            : `forge ${s.name} failed`,
        message: missing
          ? 'Install Foundry (https://getfoundry.sh) so builds and tests can run. No Solidity checks were executed.'
          : `\`${s.command}\` exited with code ${s.exitCode}. See the execution log for output.`,
        kind: 'execution',
      }),
    );
  }
  return { steps, findings };
}
