import assert from 'node:assert/strict'
import test from 'node:test'

import { evaluateHeadroom } from './check-disk-headroom.mjs'

test('accepts the exact minimum', () => {
  const minimum = 10n * 1024n ** 3n
  assert.equal(evaluateHeadroom(minimum, minimum), null)
})

test('fails clearly before ENOSPC below the minimum', () => {
  const minimum = 10n * 1024n ** 3n
  const message = evaluateHeadroom(minimum - 1n, minimum)

  assert.match(message, /ENOSPC/)
  assert.match(message, /10\.00 GiB required/)
  assert.match(message, /completed worktrees/)
})
