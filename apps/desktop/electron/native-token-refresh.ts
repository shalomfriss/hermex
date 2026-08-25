import { type NativeTokenSet, parseTokenResponse, tokenNeedsRefresh } from './native-oauth'

export interface NativeTokenRefreshDeps {
  load: () => NativeTokenSet | null
  store: (tokens: NativeTokenSet) => void
  clear: () => void
  postRefresh: (body: {
    access_token: string
    refresh_token: string
    refresh_binding: string
    provider: string
  }) => Promise<unknown>
  nowSeconds?: () => number
}

interface RefreshFlight {
  generation: string
  promise: Promise<string | null>
}

const refreshFlights = new Map<string, RefreshFlight>()

function tokenGeneration(tokens: NativeTokenSet): string {
  return JSON.stringify([
    tokens.provider,
    tokens.userId,
    tokens.accessToken,
    tokens.refreshToken,
    tokens.refreshBinding
  ])
}

export async function ensureNativeAccessTokenWith(
  baseUrl: string,
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

  if (!tokens.refreshBinding) {
    deps.clear()
    const error: any = new Error('Native OAuth session predates secure refresh ownership; sign in again.')
    error.statusCode = 401
    throw error
  }

  const generation = tokenGeneration(tokens)
  const active = refreshFlights.get(baseUrl)

  if (active?.generation === generation) {
    return active.promise
  }

  const flight: RefreshFlight = {
    generation,
    promise: Promise.resolve(null)
  }

  flight.promise = (async () => {
    try {
      const body = await deps.postRefresh({
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        refresh_binding: tokens.refreshBinding,
        provider: tokens.provider
      })

      const rotated = parseTokenResponse(body)
      const latest = deps.load()

      // A login, logout, or newer refresh completed while this exchange was
      // in flight. Never resurrect or overwrite that newer generation.
      if (!latest || tokenGeneration(latest) !== generation) {
        return latest?.accessToken || null
      }

      if (!rotated.refreshToken || !rotated.refreshBinding) {
        deps.clear()
        throw new Error('Native OAuth refresh response is missing secure refresh ownership; sign in again.')
      }

      if (
        !rotated.userId ||
        !rotated.provider ||
        rotated.userId !== tokens.userId ||
        rotated.provider !== tokens.provider
      ) {
        deps.clear()
        throw new Error('Native OAuth refresh returned a different identity; sign in again.')
      }

      deps.store(rotated)

      return rotated.accessToken
    } catch (error: any) {
      if (error?.statusCode === 401) {
        const latest = deps.load()

        if (!latest || tokenGeneration(latest) !== generation) {
          return latest?.accessToken || null
        }

        deps.clear()
        const expired: any = new Error('Native OAuth refresh token was rejected; sign in again.')
        expired.statusCode = 401
        throw expired
      }

      throw error
    } finally {
      if (refreshFlights.get(baseUrl) === flight) {
        refreshFlights.delete(baseUrl)
      }
    }
  })()

  refreshFlights.set(baseUrl, flight)

  return flight.promise
}
