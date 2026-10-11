#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROBE="$REPO_ROOT/scripts/sandbox/installer-supported-flags.sh"
TMP="$(mktemp -d -t hermes-installer-flags.XXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT INT TERM
FIXTURE="$TMP/repo"
REMOTE="$TMP/upstream.git"

git init -q "$FIXTURE"
git -C "$FIXTURE" config user.name test
git -C "$FIXTURE" config user.email test@example.com
mkdir -p "$FIXTURE/scripts"

printf '%s\n' '#!/bin/sh' > "$FIXTURE/scripts/install.sh"
git -C "$FIXTURE" add scripts/install.sh
git -C "$FIXTURE" commit -q -m ancient
git -C "$FIXTURE" tag v2026.1.1

printf '%s\n' '#!/bin/sh' '# supports --skip-setup' > "$FIXTURE/scripts/install.sh"
git -C "$FIXTURE" commit -qam setup-flag
git -C "$FIXTURE" tag v2026.1.2

printf '%s\n' '#!/bin/sh' '# supports --skip-setup and --skip-browser' > "$FIXTURE/scripts/install.sh"
git -C "$FIXTURE" commit -qam both-flags

git clone -q --bare "$FIXTURE" "$REMOTE"

auto_flags="$($PROBE --repo "$FIXTURE" --upstream "$REMOTE" --ref '')"
[ "$auto_flags" = $'--skip-setup\n--skip-browser' ] || {
  echo "unexpected HEAD flags: $auto_flags" >&2
  exit 1
}

setup_flags="$($PROBE --repo "$FIXTURE" --upstream "$REMOTE" --ref v2026.1.2)"
[ "$setup_flags" = '--skip-setup' ] || {
  echo "unexpected setup-only flags: $setup_flags" >&2
  exit 1
}

ancient_flags="$($PROBE --repo "$FIXTURE" --upstream "$REMOTE" --ref v2026.1.1)"
[ -z "$ancient_flags" ] || {
  echo "unexpected ancient flags: $ancient_flags" >&2
  exit 1
}

echo 'installer-supported-flags tests passed'
