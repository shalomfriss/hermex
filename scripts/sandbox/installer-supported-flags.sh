#!/usr/bin/env bash
# Print optional install.sh flags supported by a historical ref, one per line.

set -euo pipefail

REPO=""
UPSTREAM="https://github.com/NousResearch/hermes-agent.git"
REF=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --repo)
      [ "$#" -ge 2 ] || { echo 'error: --repo needs a value' >&2; exit 1; }
      REPO="$2"; shift 2 ;;
    --upstream)
      [ "$#" -ge 2 ] || { echo 'error: --upstream needs a value' >&2; exit 1; }
      UPSTREAM="$2"; shift 2 ;;
    --ref)
      [ "$#" -ge 2 ] || { echo 'error: --ref needs a value' >&2; exit 1; }
      REF="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,30p' "$0"
      exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 1 ;;
  esac
done

if [ -z "$REPO" ]; then
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  REPO="$(git -C "$script_dir" rev-parse --show-toplevel)"
fi

effective_ref="${REF:-HEAD}"
installer="$(git -C "$REPO" show "$effective_ref:scripts/install.sh" 2>/dev/null)" || {
  # Historical refs need not already exist in the checkout. An empty ref means
  # the current candidate's HEAD and must never fall through to an empty fetch.
  [ -n "$REF" ] || exit 1
  git -C "$REPO" fetch -q --depth 1 "$UPSTREAM" "$REF" 2>/dev/null || exit 0
  installer="$(git -C "$REPO" show FETCH_HEAD:scripts/install.sh 2>/dev/null)" || exit 0
}

for flag in --skip-setup --skip-browser; do
  if grep -Fq -- "$flag" <<< "$installer"; then
    printf '%s\n' "$flag"
  fi
done
