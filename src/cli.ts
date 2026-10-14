#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { RealShell, type Shell } from './adapters/shell.js';
import { resolveRef, GitError } from './git.js';
import { inspectRepo } from './inspect.js';
import { runFoundry } from './foundry.js';
import { analyze } from './analyze.js';
import { renderSarif } from './sarif.js';
import { buildReport, renderJson, renderMarkdown } from './report.js';
import { SEVERITIES, severityRank, type Severity } from './findings.js';

export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_USAGE = 2;

const USAGE = `protocol-guard-ci: review signals and evidence for Solidity/Foundry pull requests

Usage:
  protocol-guard run --base <ref> [--head <ref>] [options]

Options:
  --repo <dir>             Repository root (default: current directory)
  --base <ref>             Base commit-ish to compare against (required)
  --head <ref>             Head commit-ish (default: HEAD)
  --out <dir>              Output directory for report.md / report.json (default: protocol-guard-report)
  --fuzz-runs <n>          Sets FOUNDRY_FUZZ_RUNS for forge test
  --invariant-runs <n>     Sets FOUNDRY_INVARIANT_RUNS for forge test
  --skip-tests             Run fmt and build only
  --timeout <seconds>      Per-command timeout (default: 1800)
  --fail-on <severity>     Exit 1 if any finding is at or above: ${SEVERITIES.join('|')}|none (default: none)
  -h, --help               Show this help

A report with no findings is not evidence that code is secure.
`;

export interface Io {
  out: (s: string) => void;
  err: (s: string) => void;
}

function packageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const rel of ['../package.json', '../../package.json']) {
      const p = join(here, rel);
      if (existsSync(p))
        return (JSON.parse(readFileSync(p, 'utf8')) as { version: string }).version;
    }
  } catch {
    /* fall through */
  }
  return '0.0.0';
}

function positiveInt(name: string, v: string | undefined): number | undefined {
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0)
    throw new UsageError(`--${name} must be a positive integer, got '${v}'`);
  return n;
}

class UsageError extends Error {}

export async function main(
  argv: string[],
  shell: Shell = new RealShell(),
  io: Io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) },
): Promise<number> {
  try {
    const { values, positionals } = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        repo: { type: 'string' },
        base: { type: 'string' },
        head: { type: 'string' },
        out: { type: 'string' },
        'fuzz-runs': { type: 'string' },
        'invariant-runs': { type: 'string' },
        'skip-tests': { type: 'boolean' },
        timeout: { type: 'string' },
        'fail-on': { type: 'string' },
        help: { type: 'boolean', short: 'h' },
      },
    });
    if (values.help || positionals.length === 0) {
      io.out(USAGE);
      return values.help ? EXIT_OK : EXIT_USAGE;
    }
    if (positionals[0] !== 'run')
      throw new UsageError(`unknown command '${positionals[0]}' (expected 'run')`);
    if (!values.base) throw new UsageError('--base is required, e.g. --base origin/main');

    const failOn = values['fail-on'] ?? 'none';
    if (failOn !== 'none' && !SEVERITIES.includes(failOn as Severity)) {
      throw new UsageError(
        `--fail-on must be one of ${SEVERITIES.join(', ')}, none; got '${failOn}'`,
      );
    }

    const repo = resolve(values.repo ?? '.');
    if (!existsSync(join(repo, '.git')))
      throw new UsageError(`${repo} is not a git repository root (no .git found)`);
    const baseRef = values.base;
    const headRef = values.head ?? 'HEAD';
    const timeoutMs = (positiveInt('timeout', values.timeout) ?? 1800) * 1000;
    const fuzzRuns = positiveInt('fuzz-runs', values['fuzz-runs']);
    const invariantRuns = positiveInt('invariant-runs', values['invariant-runs']);

    const baseSha = await resolveRef(shell, repo, baseRef);
    const headSha = await resolveRef(shell, repo, headRef);

    const inspection = await inspectRepo(shell, repo, baseSha, headSha);
    if (!inspection.isFoundry) {
      throw new UsageError(`no foundry.toml in ${repo}; this tool supports Foundry projects only`);
    }

    // Foundry runs against the working tree, so it must be checked out at head.
    const foundry = await runFoundry(shell, repo, {
      fuzzRuns,
      invariantRuns,
      skipTests: values['skip-tests'] ?? false,
      timeoutMs,
    });

    const analysis = await analyze(shell, repo, baseSha, headSha, timeoutMs);

    const report = buildReport({
      version: packageVersion(),
      base: { ref: baseRef, sha: baseSha },
      head: { ref: headRef, sha: headSha },
      inspection,
      execution: foundry.steps,
      upgradeSafety: analysis.upgradeSafety,
      privilegeMap: analysis.privilegeMap,
      extraFindings: [...foundry.findings, ...analysis.findings],
      commands: [
        `git diff --name-status -M ${baseSha} ${headSha}`,
        `git diff -U0 -M ${baseSha} ${headSha}`,
      ],
    });

    const outDir = resolve(values.out ?? 'protocol-guard-report');
    mkdirSync(outDir, { recursive: true });
    writeFileSync(join(outDir, 'report.json'), renderJson(report));
    writeFileSync(join(outDir, 'report.md'), renderMarkdown(report));
    writeFileSync(join(outDir, 'report.sarif'), renderSarif(report));
    writeFileSync(
      join(outDir, 'privilege-map.json'),
      JSON.stringify(report.privilegeMap, null, 2) + '\n',
    );

    const c = report.summary.counts;
    io.out(
      `protocol-guard: ${report.summary.total} findings ` +
        `(critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info}). ` +
        `Wrote report.md, report.json, report.sarif and privilege-map.json to ${outDir}\n`,
    );

    if (
      failOn !== 'none' &&
      report.summary.maxSeverity &&
      severityRank(report.summary.maxSeverity) >= severityRank(failOn as Severity)
    ) {
      io.err(
        `protocol-guard: failing because a ${report.summary.maxSeverity} finding meets --fail-on ${failOn}\n`,
      );
      return EXIT_FINDINGS;
    }
    return EXIT_OK;
  } catch (e) {
    if (e instanceof UsageError || e instanceof GitError) {
      io.err(`protocol-guard: error: ${e.message}\n`);
      return EXIT_USAGE;
    }
    if (e instanceof TypeError && 'code' in e) {
      io.err(`protocol-guard: error: ${(e as Error).message}\n${USAGE}`);
      return EXIT_USAGE;
    }
    throw e;
  }
}

const invokedDirectly =
  process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1]);
if (invokedDirectly) {
  main(process.argv.slice(2)).then(
    (code) => process.exit(code),
    (e) => {
      process.stderr.write(
        `protocol-guard: internal error: ${e instanceof Error ? e.stack : String(e)}\n`,
      );
      process.exit(EXIT_USAGE);
    },
  );
}
