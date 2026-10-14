#!/usr/bin/env bash
# Build a local demo repository with a safe baseline on `main`, an unsafe PR branch and a safe PR branch.
# Usage: [PG_ACTION=owner/repo@ref] scripts/make-demo-repo.sh <empty-or-new-dir>
# PG_ACTION replaces the placeholder action reference in the copied workflow.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="${1:?usage: make-demo-repo.sh <dir>}"
if [ -e "$dest" ] && [ -n "$(ls -A "$dest" 2>/dev/null)" ]; then
  echo "refusing to use non-empty directory: $dest" >&2
  exit 2
fi
mkdir -p "$dest"
dest="$(cd "$dest" && pwd)"
copy() { # <fixture side> <dest>: copy sources without build output
  (cd "$here/fixtures/$1" && tar --exclude=out --exclude=cache -cf - .) | (cd "$2" && tar -xf -)
  # Fixtures pin solc and run offline for the test suite; a fresh CI runner must be allowed to download it.
  sed -i.bak '/^offline = true$/d' "$2/foundry.toml" && rm -f "$2/foundry.toml.bak"
}
g() { git -C "$dest" -c core.hooksPath=/dev/null -c user.name="Demo" -c user.email="demo@example.invalid" "$@"; }
swap() { # replace working tree (except .git and .github) with a fixture side
  find "$dest" -mindepth 1 -maxdepth 1 ! -name .git ! -name .github -exec rm -rf {} +
  copy "$1" "$dest"
}

git init -q -b main "$dest"
copy safe-append/base "$dest"
mkdir -p "$dest/.github/workflows"
cp "$here/examples/workflows/protocol-guard.yml" "$dest/.github/workflows/"
if [ -n "${PG_ACTION:-}" ]; then
  sed -i.bak "s#YOUR-ORG/protocol-guard-ci@v0.1.2#${PG_ACTION}#" "$dest/.github/workflows/protocol-guard.yml" && rm -f "$dest/.github/workflows/protocol-guard.yml.bak"
fi
printf 'out\ncache\n' > "$dest/.gitignore"
g add -A && g commit -q -m "Baseline vault (UUPS-style)"

g checkout -q -b unsafe-pr
swap unsafe-combined/head
g add -A && g commit -q -m "Reorder storage, drop upgrade check, add withdrawAll and execute"

g checkout -q main
g checkout -q -b safe-pr
swap safe-append/head
g add -A && g commit -q -m "Append lastDepositAt"
g checkout -q main
echo "Demo repo at $dest"
echo "  node dist/cli.js run --repo $dest --base main --head unsafe-pr   (checkout unsafe-pr first)"
