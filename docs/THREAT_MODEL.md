# Threat model and security limitations

Protocol Guard CI helps reviewers notice risky changes. It is not an audit, a formal verifier or a
guarantee. **A clean report does not mean a contract is secure.**

## What it is for

A small team using Foundry and GitHub Actions wants every pull request checked, before deployment,
for: storage-layout breaks in upgradeable contracts, weakened upgrade authorisation, new privileged
functions, and a short list of dangerous constructs, with evidence that the repository's own tests ran.

## Assets and trust boundaries

| Asset                       | Risk                                                                                                                                               | Mitigation here                                                                                                                                                                      |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| CI runner and its secrets   | The PR's tests and build run on the runner. Foundry can run arbitrary programs if `ffi = true`, and `forge` compiles attacker-controlled Solidity. | Use the `pull_request` trigger (never `pull_request_target`), no secrets in the job, ephemeral or isolated runners for untrusted forks. The action takes no secrets.                 |
| Secrets in logs and reports | Forge output or an `RPC_URL` env could leak into reports.                                                                                          | Captured output is scrubbed of secret-named env values, URL credentials, RPC-style URLs and 32-byte hex. The action passes inputs through `env`, never interpolates them into shell. |
| Report integrity            | A malicious PR could alter the workflow or the tool.                                                                                               | Run the action from a pinned tag or SHA and protect `.github/workflows/` with CODEOWNERS. The tool runs from the action's repository, not the PR's.                                  |
| Reviewer trust              | A green check is mistaken for safety.                                                                                                              | Every report states it is not an audit; severities describe review urgency.                                                                                                          |

## What it detects (and how)

- Changed contracts and public/external functions: parser output compared with `git diff` line ranges.
- Privileged functions: modifier names (`only*`, `auth`, `requiresAuth`, ...) and in-body `msg.sender`
  or `hasRole` checks. Syntactic only.
- Storage layout: `forge inspect storage-layout` at base and head for contracts in changed files.
- Upgrade authorisation: `_authorizeUpgrade` without a visible gate, upgrade entrypoints, initializers,
  inheritance changes.
- Signals on added or modified lines: `delegatecall`, `selfdestruct`, `tx.origin`, assembly,
  `unchecked`, low-level calls, low-level calls to a function parameter.

## Known limitations and bypasses

- **Custom access control** (bespoke authority contracts, access checks in helper functions, inheritance
  from an unchanged parent) can be missed or misclassified. A function reported as unprivileged may be
  privileged, and the reverse.
- **Unchanged code is not analysed.** A change in a parent contract that shifts a child's layout is not
  detected; neither are interactions between changed and unchanged code.
- **Signals only on changed lines.** A dangerous construct that predates the PR is not reported.
  Indirect risks (reentrancy, oracle manipulation, economic attacks, rounding, access to funds through
  compositions) are out of scope.
- **Textual proxy detection.** Diamond, custom or non-standard proxies are reported as uncertain or not
  at all. ERC-7201 namespaced storage is not understood; layout checks cover linear storage only.
- **Tests prove little.** Passing fuzz and invariant tests depend entirely on the quality of the
  properties and the run counts configured.
- **No deployment checks.** Deployed bytecode, constructor arguments, multisig/timelock configuration,
  proxy admin ownership, initialisation state of live contracts and off-chain operations are not examined.
- **Compiler or tool differences.** Results depend on Foundry's output format; an unexpected format
  yields an "unavailable" finding, not a pass.
- **Adversarial authors.** A determined author can evade pattern matching (for example by obscuring a
  `delegatecall` in assembly or via a helper contract). Treat this as a reviewer aid against mistakes,
  not a defence against a malicious committer.

## Non-goals

No telemetry, no network calls by the tool itself (installing dependencies and Foundry happens in the
workflow), no auto-fixing, no scoring of "security".

## Reporting a vulnerability in this tool

Open a private security advisory on the repository that hosts this code.
