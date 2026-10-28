import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  writeFileSync
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import path from 'node:path'
import { parseArgs } from 'node:util'
import { fileURLToPath } from 'node:url'

// Only these build/test inputs enter the encrypted snapshot; no original Git history is copied.
export const CANDIDATE_INPUTS = [
  'src',
  'resources',
  'build',
  'config',
  'scripts',
  'crates',
  'e2e',
  'AIwork-Startup-Diagnostic.ps1',
  'Cargo.toml',
  'Cargo.lock',
  'rust-toolchain.toml',
  'CHANGELOG.md',
  '.gitignore',
  '.npmrc',
  '.prettierignore',
  '.prettierrc.yaml',
  'eslint.config.mjs',
  'electron-builder.yml',
  'electron.vite.config.ts',
  'package.json',
  'pnpm-lock.yaml',
  'pnpm-workspace.yaml',
  'playwright.config.ts',
  'tsconfig.json',
  'tsconfig.node.json',
  'tsconfig.web.json',
  'vitest.config.ts'
]

export const EXCLUDED_INPUTS = ['scripts/video-parser-release/ed25519-private.pem']

const HEADER = Buffer.from('NATIVE-CAPSULE-1\n')
const FORBIDDEN =
  /(?:^|\/)(?:node_modules|test-results|playwright-report|\.git)(?:\/|$)|(?:^|\/)\.env(?:\.|$)|\.(?:agekey|pem|p12|pfx|key|sqlite|db)$/i

const NATIVE_TARGETS = {
  'windows-x64': { platform: 'win32', arch: 'x64', runner: 'windows-2022' },
  'macos-arm64': { platform: 'darwin', arch: 'arm64', runner: 'macos-15' },
  'macos-x64': { platform: 'darwin', arch: 'x64', runner: 'macos-15-intel' }
}

export function normalizeNativeTargets(value) {
  const requested = typeof value === 'string' ? value.split(',').map((target) => target.trim()) : []
  const targets =
    requested.length === 1 && requested[0] === 'all' ? Object.keys(NATIVE_TARGETS) : requested
  if (
    targets.length === 0 ||
    !targets.every((target) => Object.hasOwn(NATIVE_TARGETS, target)) ||
    new Set(targets).size !== targets.length
  ) {
    throw new Error('Invalid native target selection')
  }
  return { include: targets.map((target) => ({ target, ...NATIVE_TARGETS[target] })) }
}

export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function git(cwd, args, env = {}) {
  const result = spawnSync('git', args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: 'utf8',
    timeout: 300_000,
    maxBuffer: 16 * 1024 * 1024
  })
  if (result.error || result.status !== 0) throw new Error('Candidate Git operation failed')
  return result.stdout.trim()
}

export function assertCandidatePath(name) {
  if (
    !name ||
    name.includes('\\') ||
    name.split('/').some((part) => part === '..' || part === '.') ||
    path.posix.isAbsolute(name) ||
    FORBIDDEN.test(name) ||
    !CANDIDATE_INPUTS.some((input) => name === input || name.startsWith(`${input}/`))
  ) {
    throw new Error('Candidate file is outside the allowed input set')
  }
}

export function snapshotCandidate({ sourceDirectory, outputDirectory, bundlePath }) {
  const source = path.resolve(sourceDirectory)
  const output = path.resolve(outputDirectory)
  const bundle = path.resolve(bundlePath)
  if (existsSync(output) || existsSync(bundle)) throw new Error('Candidate output already exists')
  if (!path.relative(source, output).startsWith('..')) {
    throw new Error('Candidate snapshot must be outside the source checkout')
  }
  const names = git(source, [
    'ls-files',
    '-z',
    '--cached',
    '--others',
    '--exclude-standard',
    '--',
    ...CANDIDATE_INPUTS,
    ...EXCLUDED_INPUTS.map((name) => `:(exclude)${name}`)
  ])
    .split('\0')
    .filter(Boolean)
    .sort()
  mkdirSync(output, { mode: 0o700 })
  const files = []
  for (const name of names) {
    assertCandidatePath(name)
    const from = path.join(source, name)
    if (!existsSync(from)) continue
    if (!lstatSync(from).isFile()) throw new Error('Candidate inputs must be regular files')
    const to = path.join(output, name)
    mkdirSync(path.dirname(to), { recursive: true })
    copyFileSync(from, to)
    chmodSync(to, lstatSync(from).mode & 0o777)
    files.push({ name, sha256: sha256(readFileSync(to)) })
  }
  const inputDigest = sha256(JSON.stringify(files))
  writeFileSync(
    path.join(output, '.candidate-input.json'),
    `${JSON.stringify({ schemaVersion: 1, originRevision: git(source, ['rev-parse', 'HEAD']), inputDigest, files }, null, 2)}\n`,
    { mode: 0o600 }
  )
  git(output, ['init', '--initial-branch=main'])
  git(output, ['config', 'core.autocrlf', 'false'])
  git(output, ['add', '--force', '--all'])
  git(
    output,
    [
      '-c',
      'user.name=Native Validation',
      '-c',
      'user.email=validation@localhost',
      'commit',
      '-m',
      'Native validation snapshot'
    ],
    { GIT_AUTHOR_DATE: '2000-01-01T00:00:00Z', GIT_COMMITTER_DATE: '2000-01-01T00:00:00Z' }
  )
  git(output, ['bundle', 'create', bundle, 'main'])
  chmodSync(bundle, 0o600)
  return {
    sourceRevision: git(output, ['rev-parse', 'HEAD']),
    inputDigest,
    fileCount: files.length
  }
}

function parseKey(value) {
  if (!/^[A-Za-z0-9+/]{43}=$/.test(value)) throw new Error('Invalid capsule key')
  const key = Buffer.from(value, 'base64')
  if (key.length !== 32) throw new Error('Invalid capsule key')
  return key
}

export function sealCapsule(plaintext, key) {
  const nonce = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', parseKey(key), nonce)
  cipher.setAAD(HEADER)
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([HEADER, nonce, cipher.getAuthTag(), ciphertext])
}

export function openCapsule(capsule, key, expectedSha256) {
  if (!/^[a-f0-9]{64}$/.test(expectedSha256) || sha256(capsule) !== expectedSha256) {
    throw new Error('Capsule digest mismatch')
  }
  if (!capsule.subarray(0, HEADER.length).equals(HEADER) || capsule.length < HEADER.length + 29) {
    throw new Error('Invalid capsule header')
  }
  const decipher = createDecipheriv(
    'aes-256-gcm',
    parseKey(key),
    capsule.subarray(HEADER.length, HEADER.length + 12)
  )
  decipher.setAAD(HEADER)
  decipher.setAuthTag(capsule.subarray(HEADER.length + 12, HEADER.length + 28))
  return Buffer.concat([decipher.update(capsule.subarray(HEADER.length + 28)), decipher.final()])
}

function main() {
  const [command, ...args] = process.argv.slice(2)
  const { values } = parseArgs({
    args,
    options: {
      source: { type: 'string' },
      output: { type: 'string' },
      bundle: { type: 'string' },
      targets: { type: 'string' },
      'key-output': { type: 'string' },
      'expected-sha256': { type: 'string' }
    }
  })
  if (command === 'plan') {
    console.log(JSON.stringify(normalizeNativeTargets(values.targets)))
    return
  }
  if (command === 'snapshot' && values.source && values.output && values.bundle) {
    console.log(
      JSON.stringify(
        snapshotCandidate({
          sourceDirectory: values.source,
          outputDirectory: values.output,
          bundlePath: values.bundle
        })
      )
    )
    return
  }
  if (command === 'seal' && values.bundle && values.output && values['key-output']) {
    const key = randomBytes(32).toString('base64')
    const capsule = sealCapsule(readFileSync(values.bundle), key)
    writeFileSync(values.output, capsule, { mode: 0o600, flag: 'wx' })
    writeFileSync(values['key-output'], key, { mode: 0o600, flag: 'wx' })
    console.log(JSON.stringify({ capsuleSha256: sha256(capsule), bytes: capsule.length }))
    return
  }
  if (command === 'seal-with-key' && values.bundle && values.output) {
    const key = readFileSync(0, 'utf8').trim()
    const capsule = sealCapsule(readFileSync(values.bundle), key)
    writeFileSync(values.output, capsule, { mode: 0o600, flag: 'wx' })
    return
  }
  if (command === 'open' && values.bundle && values.output && values['expected-sha256']) {
    const key = readFileSync(0, 'utf8').trim()
    const plaintext = openCapsule(readFileSync(values.bundle), key, values['expected-sha256'])
    writeFileSync(values.output, plaintext, { mode: 0o600, flag: 'wx' })
    return
  }
  throw new Error('Invalid capsule command or missing required arguments')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main()
  } catch {
    console.error('Native candidate capsule operation failed')
    process.exitCode = 1
  }
}
