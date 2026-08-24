#!/usr/bin/env node

import { statfsSync } from 'node:fs'
import process from 'node:process'
import { pathToFileURL } from 'node:url'

const GIB = 1024n ** 3n
const DEFAULT_MINIMUM_GIB = 10

export function evaluateHeadroom(freeBytes, minimumBytes) {
  if (freeBytes >= minimumBytes) return null
  const freeGiB = Number(freeBytes) / Number(GIB)
  const minimumGiB = Number(minimumBytes) / Number(GIB)
  return (
    `capacity preflight failed before ENOSPC: ${freeGiB.toFixed(2)} GiB available; ` +
    `${minimumGiB.toFixed(2)} GiB required. Remove dependency trees only from clean ` +
    'completed worktrees, prune completed worktrees after preserving their refs, or ' +
    'clear rebuildable package caches. Never clean active workspaces or deployment state.'
  )
}

function parseArgs(argv) {
  let minimumGiB = DEFAULT_MINIMUM_GIB
  let path = process.cwd()
  for (let index = 0; index < argv.length; index += 1) {
    if (argv[index] === '--minimum-gib') {
      minimumGiB = Number(argv[++index])
    } else if (argv[index] === '--path') {
      path = argv[++index]
    } else {
      throw new Error(`unknown argument: ${argv[index]}`)
    }
  }
  if (!Number.isFinite(minimumGiB) || minimumGiB <= 0) {
    throw new Error('--minimum-gib must be greater than zero')
  }
  return { minimumGiB, path }
}

export function main(argv = process.argv.slice(2)) {
  const { minimumGiB, path } = parseArgs(argv)
  const stats = statfsSync(path, { bigint: true })
  const freeBytes = stats.bavail * stats.bsize
  const minimumBytes = BigInt(Math.ceil(minimumGiB * 1024 ** 3))
  const error = evaluateHeadroom(freeBytes, minimumBytes)
  if (error) {
    console.error(`error: ${error}`)
    return 1
  }
  console.log(
    `capacity preflight passed: ${(Number(freeBytes) / Number(GIB)).toFixed(2)} GiB available; ` +
      `${minimumGiB.toFixed(2)} GiB required`,
  )
  return 0
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    process.exitCode = main()
  } catch (error) {
    console.error(`error: ${error.message}`)
    process.exitCode = 2
  }
}
