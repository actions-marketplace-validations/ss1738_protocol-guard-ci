# Protocol Guard CI: implementation plan

Protocol Guard CI inspects a Solidity/Foundry pull request and writes a risk report. It reports
review signals and evidence. A clean report does **not** mean a contract is secure.

## Environment (measured 2026-10-14)

- Node v22.19.0, npm 11.12.1, git 2.50.1, Foundry (forge) 1.7.1
- solc 0.8.24 / 0.8.26 / 0.8.28 cached in `~/.svm`, so fixtures pinned to 0.8.28 build offline
- No standalone `solc` binary; Foundry is the only compiler entry point

## Architecture (smallest that meets the MVP)

TypeScript CLI that orchestrates; Foundry supplies build and storage-layout data.

```
src/
  adapters/shell.ts    Shell interface + real (spawn, no shell string) + fake for tests; redacts secrets
  git.ts               name-status + zero-context hunks between base and head
  solidity.ts          @solidity-parser/parser: functions, visibility, modifiers, line ranges
  inspect.ts           changed contracts / public+external functions / privileged functions
  foundry.ts           fmt --check, build, test (fuzz/invariant runs via env), evidence capture
  findings.ts          Finding type, stable IDs (sha256 of rule+file+symbol), severity ordering
  report.ts            report.json (versioned schema), report.md; deterministic, no timestamps
  cli.ts               argument parsing, exit codes
  storage.ts           forge inspect layouts at base (git worktree) and head, pure comparison
  upgrade.ts           proxy patterns, _authorizeUpgrade / entrypoint / initializer / inheritance checks
  signals.ts           AST risk signals on added lines
  privileges.ts        privilege map;  sarif.ts  SARIF 2.1.0;  analyze.ts  orchestration
  (phase 3) action.yml, examples/workflow, docs
fixtures/<scenario>/{base,head}/   tiny Foundry projects, offline, no external libs
test/                  unit tests (fake shell) + integration tests (temp git repo from fixtures)
```

Design rules: all external commands go through `Shell`; output sorted for determinism; no network,
no telemetry; secrets (`RPC`/`KEY`/`TOKEN` env values, URLs with credentials) are redacted before
anything is stored.

## Phases

1. CLI, git diff, Foundry execution, Markdown + JSON reports, fixtures, tests.
2. Storage-layout comparison, privilege map, risk signals, SARIF.
3. Reusable GitHub Action, example workflow, install docs, demo repo.

Each phase ends with format check, typecheck and tests passing, README updated, and a commit
with no Co-Authored-By or Generated-with trailer.

## Acceptance test

Unsafe fixture: storage-layout warning, upgrade-authorisation finding, privileged-function-change
finding, file and line references, non-zero exit with `--fail-on`. Safe fixture: success with no
high-severity findings.
