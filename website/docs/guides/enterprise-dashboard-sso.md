---
title: "Enterprise Dashboard SSO"
description: "Deploy Hermes Dashboard behind enterprise OIDC with admission policy, preflight checks, proxy hardening, and recovery procedures"
---

# Enterprise Dashboard SSO

Hermes Dashboard supports enterprise sign-in through the bundled self-hosted OIDC provider. It uses authorization code flow with S256 PKCE, verifies signed ID tokens, and applies optional organization policy to the verified claims before a user receives dashboard access.

This guide covers Microsoft Entra ID, Okta, Keycloak, Authentik, and Auth0. The integration is standards-based OIDC; these recipes describe expected configuration but do not imply vendor certification.

:::warning Administrative access
The dashboard is a machine-level administrative surface. An admitted SSO user is an administrator. The group and role settings below are admission controls, not route-level read-only/editor roles.
:::

## Security model

Hermes enforces the following boundaries:

- Discovery issuer, ID-token issuer, and configured issuer must match.
- Authorization, token, JWKS, and revocation endpoints must use HTTPS. Plain HTTP is allowed only for explicit loopback development issuers.
- ID tokens must use an allowed asymmetric algorithm advertised by discovery. HMAC algorithms and `alg=none` are rejected.
- Audience is pinned to the configured client ID. A token with multiple audiences must also carry a matching `azp` claim.
- Login uses state, S256 PKCE, and a cryptographically random nonce.
- Admission policy runs only after cryptographic verification and is re-evaluated on login, session verification, and refresh.
- Authorization denial is terminal HTTP 403. It does not fall through to another provider or start a refresh/re-login loop.
- Provider outages return HTTP 503 without clearing a potentially valid session.
- Browser sessions use HttpOnly, SameSite=Lax cookies. WebSocket tickets are short-lived and single-use.
- Hermes Desktop uses the system browser, a loopback callback, its own PKCE exchange, and the OS keychain. It never embeds IdP credentials.

## 1. Register the OIDC client

Register one web application/client in the IdP:

- Grant type: authorization code
- PKCE: required, S256
- Redirect URI: the exact public dashboard URL plus `/auth/callback`
- Sign-out or revocation: enable when the IdP supports RFC 7009
- ID-token signing: RS256 or ES256
- Scopes: at minimum `openid profile email`; add `groups` or an IdP-specific scope when policy needs those claims

For example, a dashboard served at `https://hermes.example.com` needs this redirect URI:

```text
https://hermes.example.com/auth/callback
```

A path-prefixed deployment must include the prefix exactly:

```text
https://apps.example.com/hermes/auth/callback
```

Choose either client mode:

- Public: no client secret; PKCE authenticates the authorization request.
- Confidential: store the secret in `HERMES_DASHBOARD_OIDC_CLIENT_SECRET`; PKCE remains required. Hermes negotiates `client_secret_basic` or `client_secret_post` from discovery.

Never put a client secret in `config.yaml`.

## 2. Configure Hermes

Use `dashboard.oauth.self_hosted` in `$HERMES_HOME/config.yaml`:

```yaml
dashboard:
  public_url: "https://hermes.example.com"
  oauth:
    provider: self-hosted
    self_hosted:
      issuer: "https://idp.example.com/oauth2/default"
      client_id: "hermes-dashboard"
      scopes: "openid profile email groups offline_access"
      authorization:
        require_email: true
        require_verified_email: true
        allowed_email_domains: ["example.com"]
        groups_claim: "groups"
        required_groups: ["hermes-admins"]
        roles_claim: "realm_access.roles"
        required_roles: []
        tenant_claim: "tid"
        allowed_tenants: []
        acr_claim: "acr"
        allowed_acr_values: []
        amr_claim: "amr"
        require_mfa: false
        max_auth_age_seconds: 0
```

For a confidential client, inject the secret through the environment or your deployment secret store:

```bash
export HERMES_DASHBOARD_OIDC_CLIENT_SECRET='replace-with-secret-store-reference'
```

The issuer and client ID also have deployment overrides:

```bash
export HERMES_DASHBOARD_OIDC_ISSUER='https://idp.example.com/oauth2/default'
export HERMES_DASHBOARD_OIDC_CLIENT_ID='hermes-dashboard'
```

Behavioral policy belongs in `config.yaml`; environment variables are deployment overrides, not the canonical policy surface.

### Admission-policy semantics

All configured policy categories use logical AND:

- `require_email`: require a non-empty string `email` claim.
- `require_verified_email`: require `email_verified` to be the boolean `true`.
- `allowed_email_domains`: allow any listed exact domain, case-insensitively. `evil-example.com` does not match `example.com`.
- `required_groups` and `required_roles`: require every configured value. Map a normalized `hermes-admin` group or role in the IdP when OR semantics are needed.
- `allowed_tenants` and `allowed_acr_values`: allow any configured value.
- `require_mfa`: require `amr` to contain the RFC 8176 `mfa` assurance marker. Individual methods such as `otp`, `hwk`, or `face` do not by themselves prove that multiple independent factors occurred. Prefer `allowed_acr_values` when the IdP provides a stable assurance-level claim.
- `max_auth_age_seconds`: zero disables the check. A positive value requires numeric `auth_time`, sends OIDC `max_age`, and allows 60 seconds of clock skew in either direction; timestamps further in the future are denied.

Claim paths use dot-separated object traversal, such as `realm_access.roles`. A direct key with the complete configured name wins before nested traversal. Array indexes are unsupported. Group and role claims may be one string or a list of strings; malformed configured claims are denied.

Defaults preserve existing behavior: all admission restrictions, including email requirements, are disabled until configured.

## 3. IdP recipes

### Microsoft Entra ID

- Issuer: use a tenant-specific v2 issuer, usually `https://login.microsoftonline.com/<tenant-id>/v2.0`. Do not use `common` when `allowed_tenants` must identify one organization.
- Redirect URI: add the exact Hermes callback under the app registration's Web platform.
- Grant: enable authorization code and require PKCE; do not enable implicit ID-token flow for Hermes.
- Groups: configure a groups claim in Token configuration. Large-directory overage claims do not contain the actual group list and will fail closed when a group policy is configured; use an app role or a group filtered for this application.
- Roles: define an app role and set `roles_claim: "roles"`, or leave role policy disabled.
- Tenant: Entra emits `tid`; keep `tenant_claim: "tid"` and list the tenant ID under `allowed_tenants`.
- MFA: map a predictable Authentication Context into `acr` and use `allowed_acr_values` when possible. Entra's `amr` availability varies by token version and policy.

Example policy:

```yaml
authorization:
  require_email: true
  require_verified_email: true
  tenant_claim: "tid"
  allowed_tenants: ["00000000-0000-0000-0000-000000000000"]
  roles_claim: "roles"
  required_roles: ["Hermes.Administrator"]
  allowed_acr_values: ["c1"]
```

### Okta

- Issuer: use an authorization-server issuer such as `https://example.okta.com/oauth2/default`, not the organization homepage.
- Redirect URI: add the exact Hermes callback to a Web or Native-capable OIDC application as appropriate; the dashboard server client uses authorization code with S256 PKCE.
- Groups: add a groups claim to the authorization server and include the `groups` scope if your claim rule requires it.
- Roles: Okta commonly normalizes administrative access into a group; set `required_groups` rather than inventing a role path unless your authorization server emits one.
- MFA: create an app sign-on policy and map an assurance signal to `acr`, or confirm the emitted `amr` values before enabling `require_mfa`.

```yaml
issuer: "https://example.okta.com/oauth2/default"
scopes: "openid profile email groups offline_access"
authorization:
  require_email: true
  require_verified_email: true
  groups_claim: "groups"
  required_groups: ["hermes-admins"]
```

### Keycloak

- Issuer: `https://keycloak.example.com/realms/<realm>`.
- Client: enable Standard flow, require PKCE method S256, and register the exact callback under Valid redirect URIs.
- Client mode: use Access type/public client without a secret, or confidential client with a secret injected into Hermes.
- Groups: add a Group Membership protocol mapper to the ID token. Choose whether it emits full paths, then configure the exact values Hermes should require.
- Roles: Keycloak realm roles normally appear under `realm_access.roles`; client roles appear under `resource_access.<client-id>.roles`.
- MFA: require OTP/WebAuthn in the browser flow and verify the resulting `acr`/`amr` claims before enabling claim-based enforcement.

```yaml
issuer: "https://keycloak.example.com/realms/company"
authorization:
  require_email: true
  require_verified_email: true
  groups_claim: "groups"
  required_groups: ["/platform/hermes-admins"]
  roles_claim: "realm_access.roles"
  required_roles: ["dashboard-admin"]
```

### Authentik

- Issuer: use the provider's OpenID configuration issuer, usually `https://auth.example.com/application/o/<provider-slug>/`.
- Redirect URI: add the exact callback to the OAuth2/OpenID Provider.
- Client mode: choose public or confidential in the provider and configure Hermes consistently.
- Scopes/claims: attach scope mappings for email, groups, tenant, or assurance claims. Inspect a test ID token before enabling policy.
- Groups: Authentik's default profile/group mappings may differ by provider version; set `groups_claim` to the emitted claim name rather than assuming it.

```yaml
issuer: "https://auth.example.com/application/o/hermes/"
authorization:
  require_email: true
  require_verified_email: true
  groups_claim: "groups"
  required_groups: ["hermes-admins"]
```

### Auth0

- Issuer: `https://<tenant>.<region>.auth0.com/` or the custom-domain issuer advertised by discovery. Keep the configured issuer consistent with the domain used during login.
- Application: use a Regular Web Application, register the exact callback, and enable authorization code flow with PKCE.
- Claims: custom group/role claims often require an Action and a namespaced claim. A URI-shaped direct claim key is supported, but dot-separated traversal treats dots as separators unless the full direct key exists.
- MFA: enforce MFA in the Auth0 policy, then inspect `amr`/`acr` in the signed ID token before enabling a Hermes claim requirement.

```yaml
issuer: "https://example.us.auth0.com/"
authorization:
  require_email: true
  require_verified_email: true
  groups_claim: "https://hermes.example.com/groups"
  required_groups: ["hermes-admins"]
```

## 4. Run preflight diagnostics

Validate configuration, discovery, endpoint security, signing-algorithm compatibility, callback construction, and policy syntax before starting the dashboard:

```bash
hermes dashboard sso check --public-url https://hermes.example.com
```

Use JSON in deployment health checks:

```bash
hermes dashboard sso check --json --public-url https://hermes.example.com
```

Exit status `0` means the configuration and live discovery document are ready. Exit status `1` means configuration, discovery, JWKS metadata, or callback validation failed. The command performs no login and no writes. It reports client mode but never the client secret, tokens, cookies, raw claims, or the full discovery document.

If no public URL is configured, preflight can still validate discovery, but reports callback verification as incomplete. Treat an incomplete callback as a deployment failure before exposing the service.

## 5. Reverse-proxy requirements

Terminate TLS before traffic reaches an internet-facing dashboard and preserve the exact external URL:

- Forward the original scheme and host (`X-Forwarded-Proto`, `X-Forwarded-Host`) and any path prefix (`X-Forwarded-Prefix`).
- Set `dashboard.public_url` to the complete external URL when the proxy chain cannot preserve those values reliably.
- Do not cache `/auth/*`, `/api/auth/*`, WebSocket upgrades, or responses that set cookies.
- Preserve `Set-Cookie` attributes and paths. Do not rewrite secure cookies to plaintext HTTP.
- Allow WebSocket upgrades and keep idle timeouts long enough for dashboard sessions.
- Use sticky routing or shared provider/session state when a load balancer fans out to multiple dashboard processes. Native authorization codes and WebSocket tickets are short-lived, process-local state.
- Keep system clocks synchronized; token expiry, nonce state, and maximum authentication age depend on time.

A minimal nginx location behind TLS resembles:

```nginx
location / {
    proxy_pass http://127.0.0.1:9119;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Prefix "";
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection $connection_upgrade;
    proxy_no_cache 1;
    proxy_cache_bypass 1;
}
```

Adjust the prefix and standard WebSocket map for your nginx layout.

## 6. Stage and verify

Before production:

1. Run preflight and retain only its redacted JSON output.
2. Sign in as one admitted user in a private staging deployment.
3. Confirm `/api/auth/me`, normal dashboard API calls, PTY/WebSocket connectivity, and logout.
4. Connect Hermes Desktop to the same remote URL. Confirm system-browser sign-in, reconnect, and logout/re-auth.
5. Sign in as a user outside the required group/tenant. Confirm a generic 403 and no re-login loop.
6. Remove the admitted user from the required group. Confirm access becomes 403 after ID-token refresh or expiry; this is the upper bound for group-removal propagation.
7. Stop or firewall the IdP. Confirm Hermes returns 503 for sessions it cannot verify instead of clearing them.
8. Rotate an IdP signing key. Confirm discovery/JWKS refresh accepts newly signed tokens without weakening algorithm or issuer checks.
9. Inspect `$HERMES_HOME/logs/dashboard-auth.log` and normal logs for token, cookie, code, nonce, verifier, claim-object, and secret leakage.

## 7. Operations

### Client-secret rotation

Create a second IdP secret when supported, update the deployment secret, restart the dashboard, run preflight, and complete a login before revoking the old secret. Public clients have no client secret to rotate.

### Signing-key rotation

Publish the new key in JWKS before issuing tokens with it. Keep the old key published until old ID tokens expire. Hermes refreshes JWKS when verification encounters a new key ID.

### Session and propagation lifetime

Hermes honors IdP token expiration. Admission policy is evaluated from the signed ID token on login, normal verification, and refresh. A group or role removal therefore takes effect no later than the current ID-token lifetime, and often at the next refresh. Choose short enough ID-token lifetimes for your offboarding objective without creating excessive IdP traffic.

### Audit log

Dashboard auth events are JSON lines in `$HERMES_HOME/logs/dashboard-auth.log`. Access denials record the provider and a stable policy reason such as `group_required` or `tenant_denied`; users receive only a generic forbidden response. Token-like fields, authorization codes, verifiers, nonces, authorization headers, secrets, and raw claims are redacted or excluded.

Forward the file to your normal protected log pipeline if required. Restrict file access because verified identity metadata may be present.

### Break-glass recovery

Prepare and test recovery before enforcing group or role policy:

1. Keep SSH or console access to the host.
2. Bind a recovery dashboard to loopback and reach it through an SSH tunnel, or enable the independent `basic` provider only on a trusted VPN path.
3. Never disable the non-loopback auth gate and never expose a password-only recovery endpoint to the public internet.
4. Relax or remove the misconfigured `authorization` block, restart, run preflight, then restore normal SSO.

## Troubleshooting

- `issuer is required` or `client_id is required`: set both under `dashboard.oauth.self_hosted` or through their deployment overrides.
- Discovery issuer mismatch: use the exact issuer advertised by `/.well-known/openid-configuration`, including tenant/realm/server path.
- Non-HTTPS endpoint: fix the IdP or proxy. Hermes intentionally permits plaintext only for loopback development.
- No signing-algorithm intersection: configure the IdP to sign ID tokens with RS256 or ES256 and advertise it in discovery.
- Callback mismatch at the IdP: compare the registered redirect URI byte-for-byte with preflight's `callback_url`, including scheme, host, port, and path prefix.
- Login succeeds but returns 403: inspect the audit reason and the signed claim mapping at the IdP. Do not log or paste the whole token into tickets.
- `claim_malformed`: a configured group/role claim is not a string or list of strings, a path traverses a non-object, or a policy value has the wrong shape.
- MFA users receive `mfa_required`: verify what the IdP actually emits in `amr`; use an explicit `allowed_acr_values` mapping when available.
- Group removals are not immediate: shorten the IdP ID-token lifetime or force token/session revocation. Hermes cannot observe directory changes not represented in a newly signed token.
- Provider outage returns 503: restore discovery/JWKS/token endpoint reachability. Do not clear cookies or weaken verification as a workaround.

## Rollback

For a policy misconfiguration, remove or relax only the `authorization` keys, restart the dashboard from loopback/SSH access, and re-run preflight. Defaults admit previously valid OIDC users.

For an OIDC protocol or IdP outage, disable only the self-hosted provider and use an already configured independent provider through a trusted path. Do not weaken shared cookie, bearer, or WebSocket gates.

## Limitations

- SAML 2.0 is not implemented. Use the IdP's OIDC application support.
- SCIM is not implemented because Hermes does not maintain a local user directory.
- Admission policy is all-or-nothing administrative access, not fine-grained dashboard RBAC.
- Hermes does not configure IdP applications or claims automatically.

## See also

- [Web Dashboard authentication](../user-guide/features/web-dashboard.md#authentication-gated-mode)
- [Hermes Desktop remote backend](../user-guide/features/web-dashboard.md#connecting-hermes-desktop-to-a-remote-backend)
- [Security](../user-guide/security.md)
