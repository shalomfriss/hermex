#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$REPO_ROOT/scripts/sandbox/pick-release-tags.sh"
TMP="$(mktemp -d -t hermes-pick-release-tags.XXXXXX)"
trap 'rm -rf -- "$TMP"' EXIT INT TERM

REMOTE="$TMP/upstream.git"
WORK="$TMP/work"
git init -q --bare "$REMOTE"
git init -q "$WORK"
git -C "$WORK" config user.name test
git -C "$WORK" config user.email test@example.com
git -C "$WORK" remote add origin "$TMP/empty-origin.git"

mkdir -p "$WORK/hermes_cli/subcommands"
for patch in 1 2 3 4 5 6 7 8 9; do
  if [ "$patch" -eq 1 ]; then
    printf '# release %s predates the restart helper\n' "$patch" > "$WORK/hermes_cli/main.py"
  else
    printf '# release %s\ndef _restart_managed_dashboard_service(): pass\n' \
      "$patch" > "$WORK/hermes_cli/main.py"
    # Keep the helper near the beginning of a realistically large source file.
    # Under pipefail, `git show | grep -q` otherwise misclassifies the tag when
    # grep exits early and git receives SIGPIPE.
    for line in $(seq 1 20000); do
      printf '# filler %s\n' "$line" >> "$WORK/hermes_cli/main.py"
    done
  fi
  printf '%s\n' 'if restart_managed: _m()._restart_managed_dashboard_service(reason)' \
    > "$WORK/hermes_cli/dashboard_procs.py"
  if [ "$patch" -eq 7 ]; then
    printf '%s\n' 'def _reload_process_scan_modules(): pass' \
      > "$WORK/hermes_cli/update_cmd.py"
  else
    printf '# release %s has no mixed-module reload hazard\n' "$patch" \
      > "$WORK/hermes_cli/update_cmd.py"
  fi
  if [ "$patch" -eq 8 ]; then
    printf '%s\n' 'parser.add_argument("--post-swap")' \
      > "$WORK/hermes_cli/subcommands/update.py"
  else
    printf '# release %s has no post-swap handoff\n' "$patch" \
      > "$WORK/hermes_cli/subcommands/update.py"
  fi
  git -C "$WORK" add hermes_cli/main.py
  git -C "$WORK" add hermes_cli/dashboard_procs.py hermes_cli/update_cmd.py \
    hermes_cli/subcommands/update.py
  git -C "$WORK" commit -q -m "release $patch"
  git -C "$WORK" tag "v2026.1.$patch"
done

git -C "$WORK" push -q "$REMOTE" HEAD:refs/heads/main
for patch in 1 2 3 4 5 6 7 8; do
  git -C "$WORK" push -q "$REMOTE" "refs/tags/v2026.1.$patch"
done

installer_tags="$($SCRIPT --repo "$WORK" --remote "$REMOTE" --count 5 --require-count)"
[ "$installer_tags" = '["v2026.1.1","v2026.1.3","v2026.1.5","v2026.1.6","v2026.1.8"]' ] || {
  echo "unexpected installer tags: $installer_tags" >&2
  exit 1
}

update_tags="$($SCRIPT --repo "$WORK" --remote "$REMOTE" --count 5 --require-count --require-update-compat)"
[ "$update_tags" = '["v2026.1.2","v2026.1.3","v2026.1.4","v2026.1.5","v2026.1.6"]' ] || {
  echo "unexpected update tags: $update_tags" >&2
  exit 1
}

if "$SCRIPT" --repo "$WORK" --remote "$REMOTE" --count 6 --require-count --require-update-compat >"$TMP/out" 2>"$TMP/err"; then
  echo 'expected exact-count enforcement to reject a reduced matrix' >&2
  exit 1
fi
grep -q 'only 5 eligible release tags remain; requested 6' "$TMP/err"

echo 'pick-release-tags tests passed'
