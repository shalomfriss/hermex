#!/usr/bin/env bash
# Pick the release tags the install/update E2E should update FROM.
#
# Emits a JSON array of tag names on stdout, suitable for a GitHub Actions
# matrix (`fromJSON`). Choosing at runtime rather than hardcoding keeps the
# matrix honest as releases land: a pinned list silently stops covering the
# newest release the day after it ships, and pins the "oldest" forever even
# after it stops being a version anyone still runs.
#
# Selection: the newest tag, the oldest tag, and evenly spaced tags in between.
# Newest catches "did the last release break updating?", oldest is the longest
# upgrade jump anyone can still make, and the spread samples the migrations in
# between (config-schema bumps, venv layout changes, dependency floors).
#
# Usage:
#   scripts/sandbox/pick-release-tags.sh [--count N] [--repo DIR]
#                                        [--remote NAME_OR_URL]
#                                        [--require-count]
#
#   --count   how many tags to emit (default 5, minimum 1). Fewer tags than
#             requested emits all of them.
#   --repo    repository to read tags from (default: this checkout).
#   --remote  authoritative remote whose live tag refs are eligible (default:
#             origin). A URL is accepted when the checkout's origin is a fork.
#   --require-count  fail instead of emitting fewer tags than requested.
#   --require-update-compat  keep only tags whose updater exposes the dashboard
#             restart helper required by the update-route E2E.
#
# Reads tags from the local checkout, so it needs one fetched with tags
# (actions/checkout with fetch-depth: 0, or `fetch-tags: true`). A shallow
# checkout has no tags and this exits non-zero rather than silently emitting an
# empty matrix.
#
# Only vYYYY.M.D[.N] release tags are considered; the repo also carries
# backup/* and one-off tags that are not releases.

set -euo pipefail

COUNT=5
# Default to the repository containing this script, resolved through its real
# path so a symlinked or copied script still reads the checkout it lives in
# rather than whatever repo the caller happens to be standing in.
REPO=""
REMOTE=origin
REQUIRE_COUNT=0
# When true, require tags whose CLI update path exposes the dashboard restart
# helper referenced by our installed-update E2E. Older tags that predate this
# compatibility shim should be excluded from update-route coverage.
REQUIRE_UPDATE_COMPAT=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --count)
      [ "$#" -ge 2 ] || { echo 'error: --count needs a value' >&2; exit 1; }
      COUNT="$2"; shift 2 ;;
    --repo)
      [ "$#" -ge 2 ] || { echo 'error: --repo needs a value' >&2; exit 1; }
      REPO="$2"; shift 2 ;;
    --remote)
      [ "$#" -ge 2 ] || { echo 'error: --remote needs a value' >&2; exit 1; }
      REMOTE="$2"; shift 2 ;;
    --require-count)
      REQUIRE_COUNT=1; shift ;;
    --require-update-compat)
      REQUIRE_UPDATE_COMPAT=1; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    *) echo "error: unknown argument: $1" >&2; exit 1 ;;
  esac
done
case "$COUNT" in
  ''|*[!0-9]*) echo "error: --count must be a positive integer: $COUNT" >&2; exit 1 ;;
esac
[ "$COUNT" -ge 1 ] || { echo 'error: --count must be at least 1' >&2; exit 1; }

# Resolve the script's own location through symlinks, then ask git which
# worktree that path belongs to. Deriving the repo from the script rather than
# from $PWD means a copied script cannot silently report a different checkout's
# tags, and --show-toplevel keeps it correct when invoked from a subdirectory.
if [ -z "$REPO" ]; then
  script_path="${BASH_SOURCE[0]}"
  if command -v readlink >/dev/null 2>&1; then
    script_path="$(readlink -f "$script_path" 2>/dev/null || printf '%s' "$script_path")"
  fi
  script_dir="$(cd "$(dirname "$script_path")" && pwd)"
  REPO="$(git -C "$script_dir" rev-parse --show-toplevel 2>/dev/null || printf '%s' "$script_dir")"
fi

# sort -V orders v2026.4.8 before v2026.4.13 (numeric), which a plain
# lexicographic sort gets wrong.
mapfile -t all_tags < <(
  git -C "$REPO" tag --list 'v*' \
    | grep -E '^v[0-9]{4}\.[0-9]+\.[0-9]+(\.[0-9]+)?$' \
    | sort -V
)

remote_refs="$(git -C "$REPO" ls-remote --refs "$REMOTE" 'refs/tags/v*' | cut -f2)" || {
  echo "error: could not list release tags from remote $REMOTE" >&2
  exit 1
}

# Exclude tags that no longer resolve from the current remote (stale local tags
# that remain after deletions) and, for update-route selection, tags whose checked
# out main.py does not yet provide the restart helper used by hermes update.
mapfile -t filtered_tags < <(
  for tag in "${all_tags[@]}"; do
    if printf '%s\n' "$remote_refs" | grep -Fxq "refs/tags/$tag"; then
      if [ "$REQUIRE_UPDATE_COMPAT" -eq 1 ]; then
        # Do not use `git show | grep -q` under pipefail: on a large main.py,
        # grep exits after the early match, git receives SIGPIPE, and the tag is
        # falsely rejected. Capture first so both commands report independently.
        compat_source="$(git -C "$REPO" show "$tag:hermes_cli/main.py" 2>/dev/null)" \
          || continue
        if ! grep -Fq '_restart_managed_dashboard_service' <<< "$compat_source"; then
          continue
        fi
      fi
      printf '%s\n' "$tag"
    fi
  done
)

tags=("${filtered_tags[@]}")

total="${#tags[@]}"
if [ "$total" -eq 0 ]; then
  echo "error: no eligible release tags found in $REPO" >&2
  echo '       Fetch tags into the checkout and verify the authoritative remote.' >&2
  exit 1
fi
if [ "$REQUIRE_COUNT" -eq 1 ] && [ "$total" -lt "$COUNT" ]; then
  echo "error: only $total eligible release tags remain; requested $COUNT" >&2
  exit 1
fi

if [ "$total" -le "$COUNT" ]; then
  picked=("${tags[@]}")
elif [ "$COUNT" -eq 1 ]; then
  # One slot means the newest release; there is no span to spread across.
  picked=("${tags[$((total - 1))]}")
else
  # Evenly spaced indices across [0, total-1], endpoints included, so the
  # oldest and newest are always present and the rest are spread between them.
  picked=()
  for slot in $(seq 0 $((COUNT - 1))); do
    # Round to nearest rather than truncate, so the spacing does not bunch
    # toward the oldest end.
    index=$(( (slot * (total - 1) * 2 + (COUNT - 1)) / ((COUNT - 1) * 2) ))
    candidate="${tags[$index]}"
    # Guard against a duplicate if rounding lands twice on the same tag.
    case " ${picked[*]-} " in
      *" $candidate "*) continue ;;
    esac
    picked+=("$candidate")
  done
fi

printf '['
for i in "${!picked[@]}"; do
  [ "$i" -eq 0 ] || printf ','
  printf '"%s"' "${picked[$i]}"
done
printf ']\n'
