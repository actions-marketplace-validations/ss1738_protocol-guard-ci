#!/usr/bin/env bash
# Build a local demo repository with a safe baseline on `main`, an unsafe PR branch and a safe PR branch.
# Usage: scripts/make-demo-repo.sh <empty-or-new-dir>
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
