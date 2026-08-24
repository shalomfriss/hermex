import { type NativeTokenSet, parseTokenResponse, tokenNeedsRefresh } from './native-oauth'

export interface NativeTokenRefreshDeps {
  load: () => NativeTokenSet | null
  store: (tokens: NativeTokenSet) => void
  clear: () => void
  postRefresh: (body: { refresh_token: string; provider: string }) => Promise<unknown>
  nowSeconds?: () => number
}

export async function ensureNativeAccessTokenWith(
  _baseUrl: string,
  deps: NativeTokenRefreshDeps
): Promise<string | null> {
  const tokens = deps.load()

  if (!tokens) {
    return null
  }

  const now = (deps.nowSeconds || (() => Math.floor(Date.now() / 1000)))()

  if (!tokenNeedsRefresh(tokens, now)) {
    return tokens.accessToken
  }

  if (!tokens.refreshToken) {
    deps.clear()
    const error: any = new Error('Native OAuth session expired; sign in again.')
    error.statusCode = 401
    throw error
  }

  try {
    const body = await deps.postRefresh({
      refresh_token: tokens.refreshToken,
      provider: tokens.provider
    })

    const rotated = parseTokenResponse(body)

    if (tokens.userId && rotated.userId && rotated.userId !== tokens.userId) {
      deps.clear()
      throw new Error('Native OAuth refresh returned a different identity; sign in again.')
    }

    deps.store(rotated)

    return rotated.accessToken
  } catch (error: any) {
    if (error?.statusCode === 401) {
      deps.clear()
      const expired: any = new Error('Native OAuth refresh token was rejected; sign in again.')
      expired.statusCode = 401
      throw expired
    }

    throw error
  }
}
