# Protocol Guard CI

Self-hosted security CI for Solidity/Foundry pull requests. It compares a pull request against its
base, executes the repository's Foundry checks, and writes a report of **review signals** with
evidence (commands, exit codes, file and line references).

> **It is not an audit and never proves a contract is secure.** A report with no findings means
> "nothing this tool looks for changed", not "this code is safe". See [Limitations](#limitations).

Status: **MVP complete (phases 1 to 3)**. Docs: [install](docs/INSTALL.md),
[threat model and limitations](docs/THREAT_MODEL.md), [plan](PLAN.md).

## Use it in GitHub Actions

```yaml
on: pull_request # never pull_request_target: this runs the PR's tests
permissions: { contents: read, security-events: write }
jobs:
  guard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0, submodules: recursive }
      - uses: YOUR-ORG/protocol-guard-ci@<tag-or-sha> # where you host this repo
        with: { fail-on: high, fuzz-runs: '1000', invariant-runs: '100' }
```

`fail-on: none` (the default) is warning-only. Full workflow: [`examples/workflows/protocol-guard.yml`](examples/workflows/protocol-guard.yml).
The job writes a summary, uploads a `protocol-guard-report` artifact, uploads SARIF for inline
annotations (best effort; not permitted on fork PRs), and only then fails if `fail-on` was met. No
secrets are needed or read. Try it locally with `scripts/make-demo-repo.sh <dir>`.

## Install and run

Requires Node 20+, git and [Foundry](https://getfoundry.sh).

```sh
npm install && npm run build
node dist/cli.js run --repo path/to/foundry-repo --base origin/main --head HEAD \
  --out reports --fuzz-runs 1000 --invariant-runs 100 --fail-on high
```

Options: `--base` (required), `--head` (default `HEAD`), `--repo`, `--out`, `--fuzz-runs`,
`--invariant-runs`, `--skip-tests`, `--timeout <seconds>`, `--fail-on info|low|medium|high|critical|none`.

Exit codes: `0` ok (or warning-only, the default), `1` a finding met `--fail-on`, `2` usage or
environment error. Foundry runs against the **checked-out working tree**, so check out the head
commit before running.

## What Phase 1 reports

- Changed `.sol` files, contracts and public/external functions between base and head (parser-based,
  line-accurate).
- Functions gated by an access modifier (`onlyOwner`, `onlyRole`, `auth`, ...) or an in-body
  `msg.sender` / `hasRole` / `_checkOwner` check; new ones are `high`, modified ones `medium`.
- `forge fmt --check`, `forge build`, `forge test` (unit, fuzz and invariant tests) with commands,
  exit codes and normalised output. Run counts are passed as `FOUNDRY_FUZZ_RUNS` and
  `FOUNDRY_INVARIANT_RUNS`.
- `report.md` and `report.json` (schema `1.0.0`). Output is deterministic: no timestamps, forge
  timings and fuzz averages are stripped, findings are sorted, IDs are `PG-<RULE>-<hash>` and do not
  depend on line numbers.

## What Phase 2 adds

Outputs in `--out`: `report.md`, `report.json` (schema `1.1.0`), `report.sarif` (SARIF 2.1.0 for
GitHub code scanning) and `privilege-map.json`.

- **Storage layout:** `forge inspect <file>:<Contract> storage-layout` at base (in a temporary git
  worktree, removed afterwards) and at head, compared per contract. Slot moved: `critical`.
  Type changed: `high`/`critical`. Variable removed or inserted: `high`. Rename: `medium`. Append
  after the existing layout: `info` (the safe pattern). If forge cannot produce a layout the result is
  `unavailable` with a `medium` finding rather than a silent pass.
- **Upgrade authorisation:** `_authorizeUpgrade` with no access check is `critical`
  (`unprotected-upgrade-authorization`); a changed but gated one is `medium`. Also flagged: ungated
  upgrade entrypoints, new or changed initializers, removed access control, changed inheritance lists.
- **Proxy patterns:** UUPS, transparent, beacon and ERC-1967 slot usage detected textually. If
  initializers exist but no pattern is recognised, an `info` finding says upgrade checks may be incomplete.
- **Risk signals** on added or modified lines only: `delegatecall`, `selfdestruct`, `tx.origin`,
  inline assembly, `unchecked`, low-level `call`/`staticcall`, and low-level calls whose target is a
  parameter of a public function (arbitrary external call). Severity drops one step when the function
  has an access modifier. These are review prompts, never confirmed vulnerabilities.
- **Privilege map:** capabilities (owner, admin, role, upgrader, pauser, guardian) to the functions
  that grant them, with file, line, gate and added/modified/unchanged status.

## Safety properties

- No network access and no telemetry. All external programs run through one `Shell` adapter
  (`src/adapters/shell.ts`) with no shell interpolation.
- Captured output is scrubbed of values from secret-looking environment variables, credentials in
  URLs, RPC-style URLs and 32-byte hex strings before it is stored or printed.

## Tested against OpenZeppelin

Run on a real UUPS contract built on OpenZeppelin Contracts (Upgradeable) 5.1.0 with a gitignored
`lib/`. Safe append: exit 0, `storage-append` info only. Unsafe PR: exit 1 with moved and inserted
storage, ungated `_authorizeUpgrade`, `delegatecall` to a parameter, a new privileged `sweep`, and a
failing `forge test`. Swapped inheritance order: `inheritance-changed` (medium); OZ 5 uses ERC-7201
namespaced storage, so the linear layout is unchanged and the tool does not analyse namespaced slots.
This run exposed a `forge inspect` stale-cache failure, now handled by a `--no-cache` retry. The same
project with `lib/` as real git submodules (gitlinks) gives identical results; a PR that only bumps a
submodule is reported as `dependency-changed` rather than "0 findings".

## Fixtures

`fixtures/<scenario>/{base,head}` are small offline Foundry projects (solc 0.8.28, no dependencies):
`unsafe-combined`, `unsafe-storage-reorder`, `unprotected-upgrade`, `new-privileged-withdraw`, `unsafe-delegatecall`,
`safe-upgrade`, `safe-append`. Integration tests build a temp git repo from each pair.

## Development

```sh
npm run check    # prettier, tsc, vitest (unit + integration; needs git and forge, no network)
```

## Limitations

- Privileged-function detection is syntactic: modifier names and `msg.sender` comparisons.
  Custom access-control schemes can be missed or misclassified.
- Only changes between the two commits are inspected; unchanged code that interacts with changed
  code is not analysed.
- Test results are only as strong as the repository's tests.
- No on-chain state, deployed bytecode, multisig setup or off-chain operations are examined.
- Storage comparison covers contracts defined in changed files that exist at both revisions; a changed
  parent contract that shifts an unchanged child is not detected.
- Proxy-pattern detection is textual; custom proxies are reported as uncertain, not analysed.
- Capability classification (owner vs pauser vs upgrader) uses names and is a hint, not a proof.
- The base worktree reuses the head checkout's `lib/` and `node_modules/`, so a PR that changes a
  dependency, remappings, lockfile or `foundry.toml` gets a `dependency-changed` medium finding: layout
  changes caused by the dependency itself are not detected.

## License

Apache-2.0
