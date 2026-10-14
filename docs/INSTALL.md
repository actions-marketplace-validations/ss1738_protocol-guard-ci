# Installation

## GitHub Actions (recommended)

1. Copy [`examples/workflows/protocol-guard.yml`](../examples/workflows/protocol-guard.yml) to
   `.github/workflows/` in your Foundry repository.
2. Replace `YOUR-ORG/protocol-guard-ci@v0.1.2` with the location where you host this repository and a
   tag or full commit SHA. Pinning a SHA is safest.
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
