---
sidebar_position: 18
title: "Desktop Native Sign-In (RFC 8252)"
description: "How the Hermes Desktop app signs in to a gated gateway using your system browser and PKCE — no embedded webview, no session cookies"
---

# Desktop Native Sign-In (RFC 8252)

When the Hermes Desktop app connects to a **gated gateway** (a hosted or
self-hosted dashboard that sits behind an OAuth provider), it can sign in two
ways:

1. **Native sign-in (RFC 8252)** — the app opens your **real system browser**,
   you approve in the browser you already trust, and the app receives tokens it
   stores in your OS keychain. **No embedded webview, no browser session
   cookies.** This is the default whenever the gateway supports it.
2. **Embedded sign-in (legacy compatibility)** — the app opens a small in-app
   browser window and captures the gateway's session cookie. Used only when a
   versioned gateway capability explicitly reports no native sign-in.

You don't choose between these — the app detects what the gateway supports and
picks the best one. This page explains what happens and why.

## Why native sign-in

Embedding a browser inside a native app for OAuth has well-known downsides:
the login page can't see your existing browser session (so you re-type
credentials and re-do MFA), password managers and passkeys often don't work,
and the app relies on reading a session cookie out of a private webview. RFC
8252 ("OAuth 2.0 for Native Apps") is the industry best practice that avoids
all of that: **do the authorization in the system browser and hand the app its
own tokens.**

For Hermes specifically, native sign-in means:

- **No embedded webview.** The authorization happens in Safari / Chrome /
  Firefox / Edge — whatever you use — with your logins, extensions, and
  passkeys intact.
- **No session cookies.** The app holds an OAuth **access token** (short-lived)
  and **refresh token**, encrypted at rest via your OS keychain (Electron
  `safeStorage`). REST calls and WebSocket tickets are authenticated with an
  `Authorization: Bearer` header, not a cookie jar.

## How it works

```
Desktop app                Gateway (/auth/native/*)          Nous Portal (IDP)
   │ 1. open loopback 127.0.0.1:<random port>
   │ 2. system browser ─►  /auth/native/authorize
   │    (PKCE challenge)    (starts the normal PKCE login) ─► /oauth/authorize
   │                        ◄──── code ──── /auth/callback ◄──┘
   │                        3. mint one-time gateway code
   │ ◄─ 302 127.0.0.1/cb?code=… ─┘
   │ 4. POST /auth/native/token (code + PKCE verifier)
   │ ◄─ 5. { access_token, refresh_token, refresh_binding, expires_at }
   │ 6. store in OS keychain; use Bearer for REST + WS tickets
```

The gateway **brokers** the flow: it is the authorization server *to the
desktop app* and an OAuth client *to the upstream identity provider* (Nous
Portal). This is required because the upstream `client_id` and permitted
redirect URIs are bound to the gateway's own origin — a desktop app can't be a
direct client of the Portal. The desktop still gets the full RFC 8252
experience: its own PKCE pair, its own loopback redirect, and tokens it owns.

**PKCE (RFC 7636)** protects the loopback hop: the one-time gateway code is
useless without the code verifier, which never leaves the app. The code is
single-use and short-lived.

## Capability detection & fallback

The desktop reads the gateway's public `/api/status` endpoint, which advertises
an `auth_flows_version` plus `auth_flows` array:

| `auth_flows` value | Meaning |
|--------------------|---------|
| v1 + `["cookie", "native_pkce"]` | Gateway supports native sign-in → the app uses it |
| v1 + `["cookie"]` | Gateway explicitly supports only the legacy flow → embedded compatibility mode |
| version/field absent, malformed, timeout, or 5xx | Retryable failure; no auth downgrade |

If native sign-in is advertised but fails — including a blocked loopback
listener, cancellation, timeout, malformed response, or 5xx — the app surfaces
that native failure and keeps the current identity. It never falls back to a
cookie session after a failed native attempt.

## Token lifecycle

- **Access token**: short-lived (minutes). Sent as `Authorization: Bearer` on
  every REST call and when minting a WebSocket ticket.
- **Refresh token**: longer-lived, rotating. When the access token is near
  expiry the app calls `/auth/native/refresh` with the prior signed access
  token and the gateway-minted `refresh_binding`. The gateway verifies the
  prior identity, binds the refresh token to exactly one provider, re-runs the
  current admission policy, and rotates the access token, refresh token, and
  binding together. Concurrent callers for the same gateway and token
  generation share one exchange, so a rotating refresh token is never replayed
  by the app.
- **Upgrade compatibility**: token sets stored by an older Desktop release do
  not contain `refresh_binding`. They fail closed locally and require one fresh
  native sign-in; the app never sends an unbound refresh token or loops on a
  gateway schema error.
- **Terminal expiry**: if the refresh token is dead (expired / revoked /
  reuse-detected), the app clears its stored tokens and prompts a fresh native
  sign-in. It does not switch to a cookie identity.
- **Sign out**: refreshes an expired access token when possible, then asks the
  gateway to revoke the owner-bound IdP refresh token. The app reports the
  gateway's actual `revoked` result and always clears native keychain state and
  any legacy cookie, even when remote revocation is already complete or
  unavailable.
- **Remote file uploads**: supported with native bearer authentication. They
  are explicitly disabled in legacy cookie-only compatibility mode; upgrade
  the gateway rather than weakening the upload credential boundary.

## For gateway operators

Native sign-in is available automatically on any gated gateway with an
interactive session provider registered. No configuration is required — the
`/auth/native/*` routes and the `auth_flows` advertisement are part of the
dashboard-auth subsystem. OAuth providers (e.g. the bundled **Nous** provider)
broker the upstream IDP redirect; password providers (e.g. the bundled
**basic-auth** plugin) land the system browser on the gateway's `/login`
credential form instead — which is what lets OS password managers (macOS
Passwords, etc.) autofill the form, something no embedded desktop webview can
offer. Token-only credentials (e.g. drain) are not interactive sign-ins and do
not advertise `native_pkce`.

The authorize/token/refresh endpoints are public pre-auth bootstrap routes,
like the existing `/auth/*` OAuth routes. Revocation is bearer-authenticated:

- `GET /auth/native/authorize` — starts the brokered PKCE login
- `POST /auth/native/token` — exchanges the loopback code + verifier for tokens
- `POST /auth/native/refresh` — rotates tokens from the app's refresh token
- `POST /api/auth/native/revoke` — identity-bound, best-effort refresh-token revocation

## See also

- [OAuth over SSH / Remote Hosts](./oauth-over-ssh.md) — the loopback-callback
  pattern for provider/MCP OAuth on remote machines.
- [Run Hermes with Nous Portal](./run-hermes-with-nous-portal.md)
