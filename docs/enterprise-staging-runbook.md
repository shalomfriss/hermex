# Enterprise dashboard evaluation staging runbook

This runbook turns the disposable Keycloak/Caddy/ngrok/dashboard proof into a restartable macOS customer-evaluation stack. It is deliberately a staging design. It keeps the same one-process Hermes OIDC contract and stable reserved ngrok URL while adding launchd supervision, dependency-aware startup, health probes, bounded logs, release rollback, protected backups, and a recovery procedure.

Do not use this runbook to claim production readiness. The final release must include every accepted enterprise SSO and frontend remediation layer, not merely the capacity-guard baseline. Never cut over while the 12 GiB provisioning guard is failing.

## Components and trust boundary

Traffic follows this path:

```text
customer browser
  -> reserved ngrok HTTPS endpoint
  -> Caddy on 127.0.0.1:9137
       -> Keycloak on 127.0.0.1:8081 for /realms/* and /resources/*
       -> Hermes dashboard on 127.0.0.1:9138 for all other HTTP and WebSocket traffic
```

Caddy supplies the fixed external Host, `X-Forwarded-Host`, `X-Forwarded-Proto: https`, and `X-Forwarded-Port: 443`. Hermes must configure only loopback addresses under `dashboard.trusted_proxies`. Caddy strips upstream `Server` headers and does not terminate public TLS; ngrok owns the public certificate and stable endpoint. Caddy's reverse proxy preserves WebSocket upgrades and disables response buffering.

The supported staging topology is one dashboard process and one replica. Native authorization codes, browser login state, and WebSocket tickets are process-local. Do not add uvicorn workers or replicas.

## Runtime layout

Choose a durable state root outside every Git worktree, for example:

```text
~/.hermes/enterprise-staging/
  deployment.json             non-secret deployment settings, mode 0600
  Caddyfile                   generated proxy config, mode 0600
  current -> releases/<sha>   active immutable release
  previous -> releases/<sha>  last release for rollback
  releases/<sha>/             exact source plus built hermes_cli/web_dist
  hermes-home/                isolated staging Hermes state
  secrets/keycloak.env        Keycloak bootstrap/runtime settings, mode 0600
  secrets/ngrok.env           optional NGROK_AUTHTOKEN, mode 0600
  logs/*.log                  10 MiB x 6 rotating service logs, mode 0600
  backups/*.tar.gz            protected state backups, mode 0600
  health.json                 last health result, mode 0600
  bin/enterprise-staging      installed supervisor copy
```

`deployment.json`, launchd plists, argv, normal status output, and this repository contain no password, token, cookie, authorization code, client secret, or other credential. The launchd jobs invoke the supervisor, which reads only an allowlisted mode-0600 service secret file. It rejects symlinks, permissive modes, malformed lines, and unknown names.

## Prerequisites and release parity gate

Before creating or changing a release:

1. Wait for the final accepted security and authenticated-frontend remediation head. Record its exact commit SHA.
2. Confirm the checkout and generated `hermes_cli/web_dist` both come from that accepted head.
3. Run the provisioning floor before and after any build, browser install, Keycloak restore, or release extraction:

   ```bash
   python3 scripts/ci/check_disk_headroom.py --minimum-gib 12
   ```

4. Require two settled host-capacity read-backs above the exact 12 GiB floor before cutover.
5. Run the canonical frontend build/test, Python auth tests, browser acceptance, and final PR/CI gate. A green infrastructure baseline does not substitute for the final application layers.

The release directory must be immutable after activation. Copy source with Git-aware tooling so untracked files and credentials cannot enter it, then copy only the production `hermes_cli/web_dist` built from the same accepted head. Verify the release commit and asset manifest before activation.

Before the first supervised start, stop the temporary proof stack and migrate
its isolated `hermes-home` and complete Keycloak `data` directory into the
durable layout. Preserve a mode-0600 backup before moving either tree, verify
the copy byte-for-byte without printing contents, and keep the original until
authenticated restart acceptance passes. The installer refuses to start
without the active release, production index, Hermes config, Keycloak state,
required executables, and a valid private Keycloak secret file.

Activate the prepared release atomically before installation or restart:

```bash
python3 scripts/enterprise_staging.py activate \
  --config "$STATE_ROOT/deployment.json" \
  --release "$STATE_ROOT/releases/<accepted-sha>"
```

## Non-secret configuration

Create `$STATE_ROOT/deployment.json` with mode 0600. All paths must be absolute:

```json
{
  "caddy_command": "/absolute/path/to/caddy",
  "dashboard_port": 9138,
  "dashboard_python": "/absolute/path/to/hermes/python",
  "health_interval_seconds": 60,
  "keycloak_command": "/absolute/path/to/keycloak/bin/kc.sh",
  "keycloak_port": 8081,
  "ngrok_command": "/absolute/path/to/ngrok",
  "proxy_port": 9137,
  "public_url": "https://reserved-name.example.ngrok.app",
  "state_root": "/absolute/path/to/enterprise-staging"
}
```

The supervisor rejects plaintext public URLs, credentials in URLs, port collisions, privileged/invalid ports, relative paths, and health intervals below 15 seconds.

Configure the isolated staging Hermes home with `hermes config set`, not by hand-editing `config.yaml`. At minimum preserve the verified settings:

- exact `dashboard.public_url`;
- `dashboard.oauth.provider: self-hosted`;
- exact Keycloak issuer and public client ID;
- `openid profile email offline_access` scopes;
- fail-closed email, verified-email, domain, group, role, tenant, assurance, MFA, and auth-age policy;
- `dashboard.trusted_proxies: ["127.0.0.1", "::1"]`;
- one process, one replica, process-local topology.

## Secret injection and initial credential creation

Create secret files without a permissive intermediate file:

```bash
umask 077
mkdir -p "$STATE_ROOT/secrets"
printf '%s\n' \
  'KC_BOOTSTRAP_ADMIN_USERNAME=staging-admin' \
  "KC_BOOTSTRAP_ADMIN_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')" \
  "KC_HOSTNAME=$PUBLIC_URL" \
  'KC_HTTP_ENABLED=true' \
  'KC_PROXY_HEADERS=xforwarded' \
  > "$STATE_ROOT/secrets/keycloak.env"
chmod 600 "$STATE_ROOT/secrets/keycloak.env"
```

If ngrok already has a protected account config, omit `ngrok.env`. Otherwise create it with only `NGROK_AUTHTOKEN=<value>` and mode 0600. Never pass the token on the command line.

Do not create shared/default customer credentials. Provision each evaluation user independently in Keycloak, require a password change on first use, and remove disposable automation users before customer access. The synthetic staging `acr`/`amr` claims test Hermes policy enforcement; they are not proof of real production MFA.

## Install and start launchd supervision

From the exact accepted checkout:

```bash
python3 scripts/enterprise_staging.py install \
  --config "$STATE_ROOT/deployment.json"
```

Installation copies the supervisor into the durable state root, regenerates the Caddyfile, installs five user LaunchAgents, and starts them in dependency order:

- Keycloak: restartable, run at login;
- dashboard: waits for local realm readiness, then restartable;
- Caddy: waits for dashboard health, then restartable;
- ngrok: waits for proxy health, then restartable;
- monitor: runs at login and every configured interval.

launchd plists contain no environment secrets. Each long-running job has `RunAtLoad`, `KeepAlive`, a ten-second restart throttle, a 65,536 file-descriptor soft limit, and `/dev/null` launchd output because the wrapper owns protected rotating service logs.

Commands:

```bash
python3 scripts/enterprise_staging.py check --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py status --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py restart --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py stop --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py start --config "$STATE_ROOT/deployment.json"
```

`check` verifies local dashboard, local IdP, local Caddy, public health, public login, public OIDC discovery, and the unauthenticated 401 auth gate. The periodic monitor writes only statuses, byte counts, exception classes, and timestamps to `health.json`.

## Required acceptance matrix

Perform these checks on the exact installed release. Record statuses, asset names, commit SHA, and timestamps only—never credentials, cookies, tokens, request dumps, browser profiles, or raw auth logs.

1. Startup/readiness: stop all five jobs, start them, and wait for `check` to return 0.
2. Dashboard restart: terminate the dashboard child, verify launchd creates a new PID, then verify local/public health and login.
3. IdP outage: stop Keycloak, wait for an already-authenticated session's short ID token to expire, and verify `/api/auth/me` returns 503 while its refresh cookie remains unchanged. Restart Keycloak and rerun `dashboard sso check`.
4. Tunnel restart: terminate ngrok, verify a new PID and the same reserved public URL, then rerun public checks.
5. Proxy/TLS/cookies: verify CSP, HSTS, no-sniff, DENY framing, no-referrer, Permissions-Policy, no-store, absent `Server`, Secure/HttpOnly/SameSite cookies, exact callback URL, and no redirect to HTTP or an internal host.
6. Frontend: fetch every initial/login asset from the production manifest, verify 200 and expected content types, verify a missing asset is a real 404, and run the real-browser core workflow with zero blocking console/network errors.
7. Authentication: verify an admitted real Keycloak browser login, `/api/auth/me`, a normal API, single-use WebSocket ticket consumption, refresh rotation/replay rejection, logout, denied policy identities, Desktop native login/refresh/revoke, and SSO again after a full controlled restart.
8. Host reboot procedure: stop cleanly, reboot the host during an agreed window, log into the launchd user, verify all jobs are loaded and `check` returns 0. A simulated stop/start is not evidence of host reboot recovery.
9. Secret/log audit: confirm secret/config/log/backup modes, scan tracked changes and ordinary/audit logs for sensitive patterns without printing matches, and verify no secret entered Git, board fields, completion summaries, or browser artifacts.
10. Capacity: rerun the committed 12 GiB provisioning guard and take two settled read-backs.

## Backup and restore

Backups contain Keycloak and Hermes identity/session state and must be treated as credentials. Stop the stack first so Keycloak H2 and SQLite files are consistent:

```bash
python3 scripts/enterprise_staging.py stop --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py backup \
  --config "$STATE_ROOT/deployment.json" \
  --output "$STATE_ROOT/backups/pre-change-$(date -u +%Y%m%dT%H%M%SZ).tar.gz"
python3 scripts/enterprise_staging.py start --config "$STATE_ROOT/deployment.json"
```

The archive is mode 0600 and excludes logs, caches, skills, and audio caches. Copy it only into an encrypted, access-controlled backup system. Set and test retention; do not upload it to the board or Git.

Restore only during a stopped maintenance window:

```bash
python3 scripts/enterprise_staging.py stop --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py restore \
  --config "$STATE_ROOT/deployment.json" \
  --input "$STATE_ROOT/backups/<verified-backup>.tar.gz"
python3 scripts/enterprise_staging.py start --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py check --config "$STATE_ROOT/deployment.json"
```

Restore rejects absolute paths, traversal, links, devices, missing manifests, and unexpected archive roots. Test restore into a disposable staging root before relying on it.

## Release rollback

Activation moves `current` atomically and preserves the former target as `previous`. Rollback swaps those links and restarts the complete stack:

```bash
python3 scripts/enterprise_staging.py rollback --config "$STATE_ROOT/deployment.json"
python3 scripts/enterprise_staging.py check --config "$STATE_ROOT/deployment.json"
```

Rollback does not downgrade state automatically. If the new release migrated state incompatibly, stop the stack and restore the pre-change backup before starting the old release. Never delete the previous release or backup until post-cutover authenticated and restart acceptance passes.

## Credential rotation

Rotate one credential class at a time and keep the old value only until verification succeeds:

- Customer users: create/verify a replacement or force a password reset in Keycloak; terminate active sessions; then disable the old credential.
- Keycloak bootstrap administrator: create a named replacement admin, verify login through a local/admin-only path, remove the bootstrap account, then replace/remove the bootstrap environment value. The bootstrap variables are not a long-term admin secret store.
- OIDC confidential client secret: create a new IdP secret, atomically replace the mode-0600 Hermes secret source, restart only the dashboard, verify login/refresh/logout, then revoke the old secret. This staging realm uses a public client and should not have a client secret.
- ngrok token: rotate in ngrok, atomically replace `secrets/ngrok.env`, restart ngrok, verify the reserved URL, then revoke the old token.
- Staging users after an evaluation: revoke sessions, disable/delete users, rotate any credentials exposed to evaluators, and archive only the non-secret evidence.

Use atomic replacement with `umask 077`; never edit a secret in a command that exposes it through shell history or process argv.

## Clean shutdown and recovery

Normal shutdown:

```bash
python3 scripts/enterprise_staging.py stop --config "$STATE_ROOT/deployment.json"
```

Confirm ports 8081, 9137, and 9138 are closed and the reserved public URL is unavailable before maintenance.

Recovery order:

1. Preserve `state_root`, secrets, backups, logs, release links, and Keycloak data.
2. Check disk headroom; do not provision below 12 GiB.
3. Validate executable paths and the active release's exact SHA/assets.
4. Start Keycloak, then dashboard, Caddy, ngrok, and monitor (the supervisor enforces readiness dependencies).
5. Run local/public `check` and `hermes dashboard sso check --json`.
6. If application startup fails, inspect only the bounded protected service log and avoid pasting raw auth output.
7. If state is corrupt, stop, preserve forensic copies, restore the latest verified backup, then retry.
8. If the new release fails, roll back the release; restore state only when compatibility requires it.
9. Re-run authenticated browser/Desktop SSO and frontend acceptance before reopening customer access.

## Staging-only versus production-ready

Staging-only:

- one macOS login session and user LaunchAgents;
- reserved ngrok tunnel rather than organization-owned ingress/DNS;
- Keycloak `start-dev` with H2 rather than a production Keycloak cluster/database;
- single Hermes process with process-local login/code/ticket state;
- local mode-0600 secret files rather than an audited secret manager;
- synthetic assurance/MFA claims and disposable test identities;
- local health JSON without external alert routing or an availability SLO;
- manual encrypted backup export and manual disaster recovery;
- host login is required for user LaunchAgents after reboot.

Production-ready requires, at minimum, organization-owned TLS/DNS/ingress, hardened production Keycloak with a supported external database and backups, audited secret management and rotation, production identity/MFA mappings, external monitoring/alerting, tested disaster recovery and retention, patch/vulnerability management, capacity planning, customer data controls, and a topology whose shared state/sticky routing contract has been explicitly verified. This runbook does not provide or claim those controls.
