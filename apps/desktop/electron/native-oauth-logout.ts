import { nativeRevokeUrl, type NativeTokenSet } from './native-oauth'

export interface NativeLogoutRequest {
  url: string
  bearer: string
  body: { refresh_token: string; provider: string; user_id: string }
}

export interface NativeLogoutDeps {
  revoke: (request: NativeLogoutRequest) => Promise<void>
  clearLocal: () => Promise<void> | void
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
    if (tokens?.accessToken && tokens.refreshToken && tokens.provider && tokens.userId) {
      await deps.revoke({
        url: nativeRevokeUrl(baseUrl),
        bearer: tokens.accessToken,
        body: {
          refresh_token: tokens.refreshToken,
          provider: tokens.provider,
          user_id: tokens.userId
        }
      })
      revoked = true
    }
  } catch (reason) {
    error = reason instanceof Error ? reason.message : String(reason)
  } finally {
    await deps.clearLocal()
  }

  return error ? { revoked, error } : { revoked }
}