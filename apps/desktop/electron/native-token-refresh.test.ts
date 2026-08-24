import assert from 'node:assert/strict'

import { test } from 'vitest'

import type { NativeTokenSet } from './native-oauth'
import { ensureNativeAccessTokenWith } from './native-token-refresh'

function expired(): NativeTokenSet {
  return {
    accessToken: 'AT-old',
    refreshToken: 'RT-user-1',
    expiresAt: 900,
    provider: 'nous',
    userId: 'user-1'
  }
}

test('native refresh rotates tokens without changing identity', async () => {
  const stored: NativeTokenSet[] = []

  const access = await ensureNativeAccessTokenWith('https://gw.example.com', {
    clear: () => undefined,
    load: () => expired(),
    nowSeconds: () => 1_000,
    postRefresh: async () => ({
      access_token: 'AT-new',
      refresh_token: 'RT-new',
      expires_at: 2_000,
      provider: 'nous',
      user_id: 'user-1'
    }),
    store: tokens => stored.push(tokens)
  })

  assert.equal(access, 'AT-new')
  assert.equal(stored[0]?.userId, 'user-1')
})

test('terminal native refresh rejection clears tokens and throws instead of selecting cookies', async () => {
  let cleared = false
  const rejected: any = new Error('401: session_expired')
  rejected.statusCode = 401

  await assert.rejects(
    ensureNativeAccessTokenWith('https://gw.example.com', {
      clear: () => {
        cleared = true
      },
      load: () => expired(),
      nowSeconds: () => 1_000,
      postRefresh: async () => {
        throw rejected
      },
      store: () => undefined
    }),
    /refresh token was rejected/i
  )
  assert.equal(cleared, true)
})

test('503 native refresh failure preserves tokens and remains retryable', async () => {
  let cleared = false
  const unavailable: any = new Error('503: provider unavailable')
  unavailable.statusCode = 503

  await assert.rejects(
    ensureNativeAccessTokenWith('https://gw.example.com', {
      clear: () => {
        cleared = true
      },
      load: () => expired(),
      nowSeconds: () => 1_000,
      postRefresh: async () => {
        throw unavailable
      },
      store: () => undefined
    }),
    /provider unavailable/i
  )
  assert.equal(cleared, false)
})

test('refresh response for a different user is rejected and clears the poisoned token set', async () => {
  let cleared = false

  await assert.rejects(
    ensureNativeAccessTokenWith('https://gw.example.com', {
      clear: () => {
        cleared = true
      },
      load: () => expired(),
      nowSeconds: () => 1_000,
      postRefresh: async () => ({
        access_token: 'AT-attacker',
        refresh_token: 'RT-attacker',
        expires_at: 2_000,
        provider: 'nous',
        user_id: 'different-user'
      }),
      store: () => undefined
    }),
    /different identity/i
  )

  assert.equal(cleared, true)
})

test('absence of a native token set is the only cookie-compatibility signal', async () => {
  const access = await ensureNativeAccessTokenWith('https://gw.example.com', {
    clear: () => undefined,
    load: () => null,
    nowSeconds: () => 1_000,
    postRefresh: async () => {
      throw new Error('must not refresh')
    },
    store: () => undefined
  })

  assert.equal(access, null)
})
