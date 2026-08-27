import assert from 'node:assert/strict'

import { test } from 'vitest'

import type { NativeTokenSet } from './native-oauth'
import { runNativeLogout } from './native-oauth-logout'

const tokens: NativeTokenSet = {
  accessToken: 'AT-current-user',
  refreshToken: 'RT-current-user',
  refreshBinding: 'v1.binding-current-user',
  expiresAt: 1_893_456_000,
  provider: 'nous',
  userId: 'user-1'
}

test('runNativeLogout revokes the refresh token with bearer-bound identity before local cleanup', async () => {
  const events: string[] = []
  let request: any = null

  const result = await runNativeLogout('https://gw.example.com/hermes', tokens, {
    clearLocal: async () => {
      events.push('clear')
    },
    revoke: async value => {
      events.push('revoke')
      request = value

      return { ok: true, revoked: true }
    }
  })

  assert.deepEqual(events, ['revoke', 'clear'])
  assert.equal(request.url, 'https://gw.example.com/hermes/api/auth/native/revoke')
  assert.equal(request.bearer, 'AT-current-user')
  assert.deepEqual(request.body, {
    refresh_token: 'RT-current-user',
    refresh_binding: 'v1.binding-current-user',
    provider: 'nous',
    user_id: 'user-1'
  })
  assert.deepEqual(result, { revoked: true })
})

test('runNativeLogout clears local state even when revocation is unavailable or already failed', async () => {
  let cleared = false

  const result = await runNativeLogout('https://gw.example.com', tokens, {
    clearLocal: async () => {
      cleared = true
    },
    revoke: async () => {
      throw new Error('503: provider unavailable')
    }
  })

  assert.equal(cleared, true)
  assert.equal(result.revoked, false)
  assert.match(result.error || '', /provider unavailable/)
})

test('runNativeLogout is idempotent when there is no stored native session', async () => {
  let revoked = false
  let cleared = false

  const result = await runNativeLogout('https://gw.example.com', null, {
    clearLocal: async () => {
      cleared = true
    },
    revoke: async () => {
      revoked = true
    }
  })

  assert.equal(revoked, false)
  assert.equal(cleared, true)
  assert.deepEqual(result, { revoked: false })
})

test('runNativeLogout reports a successful HTTP response with revoked false truthfully', async () => {
  let cleared = false

  const result = await runNativeLogout('https://gw.example.com', tokens, {
    clearLocal: () => {
      cleared = true
    },
    revoke: async () => ({ ok: true, revoked: false })
  })

  assert.equal(cleared, true)
  assert.deepEqual(result, { revoked: false })
})

test('runNativeLogout refreshes an expired bearer before revoking the rotated token', async () => {
  const expiredTokens: NativeTokenSet = {
    ...tokens,
    accessToken: 'AT-expired',
    refreshToken: 'RT-before-logout',
    refreshBinding: 'v1.binding-before-logout',
    expiresAt: 900
  }

  const refreshedTokens: NativeTokenSet = {
    ...tokens,
    accessToken: 'AT-refreshed',
    refreshToken: 'RT-rotated-before-logout',
    refreshBinding: 'v1.binding-rotated-before-logout',
    expiresAt: 2_000
  }

  let request: any = null
  let refreshCalls = 0

  const result = await runNativeLogout('https://gw.example.com', expiredTokens, {
    clearLocal: () => undefined,
    nowSeconds: () => 1_000,
    refreshTokens: async () => {
      refreshCalls += 1

      return refreshedTokens
    },
    revoke: async value => {
      request = value

      return { ok: true, revoked: true }
    }
  })

  assert.equal(refreshCalls, 1)
  assert.equal(request.bearer, 'AT-refreshed')
  assert.deepEqual(request.body, {
    refresh_token: 'RT-rotated-before-logout',
    refresh_binding: 'v1.binding-rotated-before-logout',
    provider: 'nous',
    user_id: 'user-1'
  })
  assert.deepEqual(result, { revoked: true })
})
