# Local CI Capacity Guard

Hermes integration work must start with at least 10 GiB free on the volume that contains the checkout. The 10 GiB value is a hard preflight floor; staging operators should recover to at least 12 GiB before beginning combined Python and frontend verification so the run has working margin.

The canonical Python runner checks this automatically. Root `install:*` wrappers and checks, the JS CI dependency-install path, and Web build/check/test commands also run the same preflight. Use the checked-in `npm run install:root`, `install:web`, `install:tui`, or `install:desktop` wrappers for local dependency changes: npm's own `preinstall` lifecycle runs after dependency extraction on supported npm 10/11, so it cannot prevent an install-time ENOSPC failure. The Dashboard browser acceptance workflow uses the standard runner's maintained Chrome instead of provisioning another browser, enforces the 12 GiB target before dependency installation, and relies on `web`'s `pretest:e2e` hook to enforce it again before the production browser matrix. Browser binaries, disposable IdPs, reverse proxies, and other direct downloads do not otherwise enter an npm lifecycle, so Keycloak/Caddy setup instructions and equivalent direct provisioning entrypoints must run the stricter recovery-target check immediately before and after their download/start step. To inspect capacity without starting work:

```bash
python3 scripts/ci/check_disk_headroom.py
node scripts/ci/check-disk-headroom.mjs
npm run capacity:provision
```

The first two commands enforce the 10 GiB execution floor. `npm run capacity:provision` enforces the 12 GiB recovery target and must run immediately before `playwright install`, Keycloak/Caddy downloads, Docker image pulls, or equivalent browser/IdP provisioning. All checks fail before work starts and print the measured free space, required floor, and safe recovery classes. A one-off stricter check is available with `--minimum-gib`; do not lower the checked-in floor to force a run through.

Run the 12 GiB check again after provisioning and after the browser/IdP acceptance run settles. If it fails, retain the required browser and IdP dependencies and reclaim only the verified-safe classes below before continuing.

## Cleanup lifecycle

Every local integration run owns the dependencies and generated artifacts in its worktree. When a Kanban task is complete:

1. Verify the task is complete and the worktree is clean with `/usr/bin/git -C <worktree> status --porcelain`.
2. Preserve the branch/ref or verify the detached commit is reachable.
3. Confirm no process has that worktree as its current directory.
4. Remove the completed worktree with `/usr/bin/git worktree remove <worktree>` and run `/usr/bin/git worktree prune`.
5. If source must remain for follow-up, remove only lockfile-rebuildable `node_modules`, `.venv`, and generated build directories from that completed inactive worktree.
6. Bound package caches after stress runs with `npm cache clean --force` and `uv cache clean`.
7. Re-run `npm run capacity:provision` and `df -k` after dependencies required by the next verification have been restored. Do not start a browser/IdP acceptance run below the 12 GiB target even though ordinary guarded commands remain permitted down to the 10 GiB hard floor.

Never clean a running, review, or blocked task workspace. Never remove deployment or rollback assets, databases, credentials, audit evidence, Docker state required by staging, model caches, or unrelated user data. Coordinate with concurrent workers before touching a path they use.
