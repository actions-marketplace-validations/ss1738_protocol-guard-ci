# Installation

## GitHub Actions (recommended)

1. Copy [`examples/workflows/protocol-guard.yml`](../examples/workflows/protocol-guard.yml) to
   `.github/workflows/` in your Foundry repository.
2. The example pins `ss1738/protocol-guard-ci@v0.2.0`. If you host your own fork, change the owner. Pinning a full
   commit SHA is safest.
3. Keep `fetch-depth: 0` on `actions/checkout` (the diff needs the base branch) and
   `submodules: recursive` if your dependencies live in `lib/`.
4. Start with `fail-on: none` (warning-only) to see the signal volume, then raise it (for example
   `high`) once the team has triaged the baseline.

Inputs: `base-ref`, `fail-on`, `fuzz-runs`, `invariant-runs`, `skip-tests`, `working-directory`,
`output-dir`, `upload-sarif`, `slither`, `slither-version`, `slither-scope`, `install-foundry` (see [`action.yml`](../action.yml)). Outputs:
`exit-code`, `max-severity`, `report-dir`.

What the job produces: a job summary (`report.md`), an artifact `protocol-guard-report`
(`report.md`, `report.json`, `report.sarif`, `privilege-map.json`) and, when permitted, inline
code-scanning annotations from the SARIF file.

The workflow needs no secrets. Do not give it RPC URLs or keys; tests must run offline. The tool
scrubs secret-looking environment values, URL credentials and 32-byte hex strings from anything it
records, but the safest secret is one that is never provided.

## Accepting known findings: `.protocol-guard-ignore`

Commit a file named `.protocol-guard-ignore` to your **base branch** (usually `main`):

```
# <finding-id> # <required reason>
PG-NEW-PRIVILEGED-FUNCTION-d73e9ee6 # owner is a 3/5 multisig, reviewed 2026-10
```

- The file is read from the **base** revision of each PR, never from the PR itself, so a PR cannot
  suppress findings it introduces. Changes to the file take effect after they are merged. A PR that
  edits it gets an `ignore-file-changed` finding so reviewers look at it.
- Every entry needs a `# reason`. Entries without one, or with a malformed ID, are not applied and
  produce an `ignore-entry-invalid` finding.
- IDs are shown in every report (`PG-<RULE>-<8 hex>`). They depend on the rule, file and symbol, not on
  line numbers, so they survive unrelated edits. One entry hides every future finding with that same ID.
- Only review signals can be suppressed. Failed `forge` steps, a missing Slither and other tooling
  findings cannot.
- Suppressed findings do not count toward `fail-on`. They stay visible in `report.json`
  (`suppressed`), in a "Suppressed Findings" table in `report.md`, and in SARIF with a `suppressions`
  entry. Entries that matched nothing are listed as stale.
- `--ignore-from-head` reads the file from HEAD instead. Use it for local testing only.

## Command line

Requires Node 20+, git and [Foundry](https://getfoundry.sh).

```sh
git clone <this repository> && cd protocol-guard-ci
npm ci && npm run build
cd /path/to/your/foundry-repo && git checkout <head-branch>
node /path/to/protocol-guard-ci/dist/cli.js run --base origin/main --out reports --fail-on high
```

Foundry runs against the checked-out working tree, so check out the head revision first.

## Demo repository

```sh
scripts/make-demo-repo.sh /tmp/pg-demo        # main (safe), unsafe-pr, safe-pr branches
cd /tmp/pg-demo && git checkout unsafe-pr
node ~/protocol-guard-ci/dist/cli.js run --base main --fail-on high   # exits 1
git checkout safe-pr
node ~/protocol-guard-ci/dist/cli.js run --base main --fail-on high   # exits 0
```

## Exit codes

`0` success or warning-only, `1` a finding met `--fail-on`, `2` usage or environment error
(missing `--base`, not a Foundry project, git failure).
