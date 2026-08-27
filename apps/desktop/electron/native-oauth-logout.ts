import { nativeRevokeUrl, type NativeTokenSet, tokenNeedsRefresh } from './native-oauth'

export interface NativeLogoutRequest {
  url: string
  bearer: string
  body: { refresh_token: string; refresh_binding: string; provider: string; user_id: string }
}

export interface NativeLogoutDeps {
  revoke: (request: NativeLogoutRequest) => Promise<unknown>
  clearLocal: () => Promise<void> | void
  refreshTokens?: () => Promise<NativeTokenSet | null>
  nowSeconds?: () => number
}

/** Best-effort remote revoke followed by unconditional keychain/local cleanup. */
export async function runNativeLogout(
  baseUrl: string,
  tokens: NativeTokenSet | null,
  deps: NativeLogoutDeps
): Promise<{ revoked: boolean; error?: string }> {
  let revoked = false
  let error: string | undefined

  try {
    let revocationTokens = tokens
    const now = (deps.nowSeconds || (() => Math.floor(Date.now() / 1000)))()

    if (revocationTokens && tokenNeedsRefresh(revocationTokens, now) && deps.refreshTokens) {
      revocationTokens = await deps.refreshTokens()
    }

    if (
      revocationTokens?.accessToken &&
      revocationTokens.refreshToken &&
      revocationTokens.refreshBinding &&
      revocationTokens.provider &&
      revocationTokens.userId
    ) {
      const response: any = await deps.revoke({
        url: nativeRevokeUrl(baseUrl),
        bearer: revocationTokens.accessToken,
        body: {
          refresh_token: revocationTokens.refreshToken,
          refresh_binding: revocationTokens.refreshBinding,
          provider: revocationTokens.provider,
          user_id: revocationTokens.userId
        }
      })

      revoked = response?.revoked === true
    }
  } catch (reason) {
    error = reason instanceof Error ? reason.message : String(reason)
  } finally {
    await deps.clearLocal()
  }

  return error ? { revoked, error } : { revoked }
}
