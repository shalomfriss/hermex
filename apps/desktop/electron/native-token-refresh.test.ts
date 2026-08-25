import assert from 'node:assert/strict'

import { test } from 'vitest'

import type { NativeTokenSet } from './native-oauth'
import { ensureNativeAccessTokenWith } from './native-token-refresh'

function expired(): NativeTokenSet {
  return {
    accessToken: 'AT-old',
    refreshToken: 'RT-user-1',
    refreshBinding: 'v1.binding-old',
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
      refresh_binding: 'v1.binding-new',
      expires_at: 2_000,
      provider: 'nous',
      user_id: 'user-1'
    }),
    store: tokens => stored.push(tokens)
  })

  assert.equal(access, 'AT-new')
  assert.equal(stored[0]?.userId, 'user-1')
  assert.equal(stored[0]?.refreshBinding, 'v1.binding-new')
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

test('403 native refresh denial preserves the bound token set without cookie downgrade', async () => {
  let cleared = false
  const denied: any = new Error('403: group_required')
  denied.statusCode = 403

  await assert.rejects(
    ensureNativeAccessTokenWith('https://gw.example.com', {
      clear: () => {
        cleared = true
      },
      load: () => expired(),
      nowSeconds: () => 1_000,
      postRefresh: async () => {
        throw denied
      },
      store: () => undefined
    }),
    /group_required/i
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
        refresh_binding: 'v1.binding-attacker',
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

test('refresh response missing a rotated owner binding is rejected and cleared', async () => {
  let cleared = false

  await assert.rejects(
    ensureNativeAccessTokenWith('https://missing-binding.example.com', {
      clear: () => {
        cleared = true
      },
      load: () => expired(),
      nowSeconds: () => 1_000,
      postRefresh: async () => ({
        access_token: 'AT-rotated',
        refresh_token: 'RT-rotated',
        expires_at: 2_000,
        provider: 'nous',
        user_id: 'user-1'
      }),
      store: () => undefined
    }),
    /missing secure refresh ownership/i
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

test('a legacy stored token without an owner binding fails closed before network refresh', async () => {
  let cleared = false
  let exchanges = 0

  await assert.rejects(
    ensureNativeAccessTokenWith('https://legacy.example.com', {
      clear: () => {
        cleared = true
      },
      load: () => ({ ...expired(), refreshBinding: '' }),
      nowSeconds: () => 1_000,
      postRefresh: async () => {
        exchanges += 1
        throw new Error('must not send an unbound refresh token')
      },
      store: () => undefined
    }),
    /sign in again/i
  )

  assert.equal(exchanges, 0)
  assert.equal(cleared, true)
})

test('concurrent refresh callers exchange one token generation once', async () => {
  let current = expired()
  let exchanges = 0
  let release!: (body: unknown) => void

  const response = new Promise<unknown>(resolve => {
    release = resolve
  })

  const requestBodies: unknown[] = []

  const deps = {
    clear: () => undefined,
    load: () => current,
    nowSeconds: () => 1_000,
    postRefresh: async (body: unknown) => {
      exchanges += 1
      requestBodies.push(body)

      return response
    },
    store: (tokens: NativeTokenSet) => {
      current = tokens
    }
  }

  const first = ensureNativeAccessTokenWith('https://gw.example.com', deps)
  const second = ensureNativeAccessTokenWith('https://gw.example.com', deps)

  assert.equal(exchanges, 1)
  assert.deepEqual(requestBodies, [
    {
      access_token: 'AT-old',
      refresh_token: 'RT-user-1',
      refresh_binding: 'v1.binding-old',
      provider: 'nous'
    }
  ])

  release({
    access_token: 'AT-rotated',
    refresh_token: 'RT-rotated',
    refresh_binding: 'v1.binding-rotated',
    expires_at: 2_000,
    provider: 'nous',
    user_id: 'user-1'
  })

  assert.deepEqual(await Promise.all([first, second]), ['AT-rotated', 'AT-rotated'])
  assert.equal(current.refreshToken, 'RT-rotated')
})

test('a stale refresh completion cannot overwrite a newer token generation', async () => {
  let current = expired()
  let release!: (body: unknown) => void

  const response = new Promise<unknown>(resolve => {
    release = resolve
  })

  const stored: NativeTokenSet[] = []

  const pending = ensureNativeAccessTokenWith('https://stale.example.com', {
    clear: () => undefined,
    load: () => current,
    nowSeconds: () => 1_000,
    postRefresh: async () => response,
    store: tokens => {
      stored.push(tokens)
      current = tokens
    }
  })

  current = {
    accessToken: 'AT-newer',
    refreshToken: 'RT-newer',
    refreshBinding: 'v1.binding-newer',
    expiresAt: 3_000,
    provider: 'nous',
    userId: 'user-1'
  }
  release({
    access_token: 'AT-stale',
    refresh_token: 'RT-stale',
    refresh_binding: 'v1.binding-stale',
    expires_at: 2_000,
    provider: 'nous',
    user_id: 'user-1'
  })

  assert.equal(await pending, 'AT-newer')
  assert.deepEqual(stored, [])
  assert.equal(current.refreshToken, 'RT-newer')
})
