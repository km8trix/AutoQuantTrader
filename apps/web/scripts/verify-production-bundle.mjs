#!/usr/bin/env node

/**
 * Offline admission check for one built web bundle.
 *
 * The verifier reads only the checked-in policy, Vite manifest, and filesystem
 * metadata for manifest-referenced files. It never reads asset contents,
 * environment variables, browser state, or runtime service data.
 */

import { constants as filesystemConstants } from 'node:fs'
import { lstat, open, realpath, stat } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const PRODUCTION_BUNDLE_ADMISSION_CONTRACT_VERSION =
  'phase6b-production-bundle-admission-v1'

const MANIFEST_RELATIVE_PATH = '.vite/manifest.json'
const EXACT_POLICY_FIELDS = new Set([
  'contract_version',
  'entry_module',
  'route_modules',
  'required_shared_partitions',
  'max_asset_bytes',
  'max_initial_graph_bytes',
])
const ALLOWED_MANIFEST_FIELDS = new Set([
  'file',
  'src',
  'name',
  'isEntry',
  'isDynamicEntry',
  'imports',
  'dynamicImports',
  'css',
  'assets',
])
const MANDATORY_SHARED_PARTITIONS = [
  'react-runtime',
  'mui-runtime',
  'query-runtime',
]

export class ProductionBundleAdmissionError extends Error {
  constructor(message, options) {
    super(message, options)
    this.name = 'ProductionBundleAdmissionError'
  }
}

function fail(message, cause) {
  throw new ProductionBundleAdmissionError(message, cause === undefined ? undefined : { cause })
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireExactFields(value, expected, subject) {
  const observed = Object.keys(value)
  const unexpected = observed.filter((field) => !expected.has(field))
  const missing = [...expected].filter((field) => !Object.hasOwn(value, field))
  if (unexpected.length > 0 || missing.length > 0) {
    fail(`${subject} must contain exactly the supported fields`)
  }
}

function requireBoundedText(value, subject, maximum = 512) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value !== value.trim() ||
    value.length > maximum ||
    [...value].some((character) => {
      const codePoint = character.codePointAt(0)
      return codePoint < 32 || codePoint === 127
    })
  ) {
    fail(`${subject} must be bounded, non-empty trimmed text`)
  }
  return value
}

function requireModuleId(value, subject) {
  const moduleId = requireBoundedText(value, subject, 1024)
  if (
    moduleId.includes('\\') ||
    path.posix.isAbsolute(moduleId) ||
    moduleId.split('/').some((segment) => segment === '' || segment === '.' || segment === '..') ||
    path.posix.normalize(moduleId) !== moduleId
  ) {
    fail(`${subject} must be a normalized relative module ID`)
  }
  return moduleId
}

function requireAssetPath(value, subject) {
  const assetPath = requireModuleId(value, subject)
  if (assetPath.toLowerCase().startsWith('.vite/')) {
    fail(`${subject} cannot address Vite metadata`)
  }
  return assetPath
}

function requirePositiveSafeInteger(value, subject) {
  if (!Number.isSafeInteger(value) || value <= 0) {
    fail(`${subject} must be a positive safe integer`)
  }
  return value
}

function requireUniqueTextArray(value, subject, itemValidator = requireBoundedText) {
  if (!Array.isArray(value)) {
    fail(`${subject} must be an array`)
  }
  const result = value.map((item, index) => itemValidator(item, `${subject}[${index}]`))
  if (new Set(result).size !== result.length) {
    fail(`${subject} must not contain duplicates`)
  }
  return result
}

function assertNoDuplicateJsonMembers(source, subject) {
  let offset = 0

  function skipWhitespace() {
    while (offset < source.length && /[\t\n\r ]/.test(source[offset])) {
      offset += 1
    }
  }

  function invalidJson() {
    fail(`${subject} is not valid JSON`)
  }

  function parseString() {
    const start = offset
    if (source[offset] !== '"') {
      invalidJson()
    }
    offset += 1
    while (offset < source.length) {
      const character = source[offset]
      if (character === '"') {
        offset += 1
        try {
          return JSON.parse(source.slice(start, offset))
        } catch {
          invalidJson()
        }
      }
      if (character === '\\') {
        offset += 1
        if (offset >= source.length) {
          invalidJson()
        }
        if (source[offset] === 'u') {
          const escape = source.slice(offset + 1, offset + 5)
          if (!/^[0-9a-fA-F]{4}$/.test(escape)) {
            invalidJson()
          }
          offset += 5
          continue
        }
        if (!'"\\/bfnrt'.includes(source[offset])) {
          invalidJson()
        }
      } else if (character.codePointAt(0) < 32) {
        invalidJson()
      }
      offset += 1
    }
    invalidJson()
  }

  function parseValue(depth) {
    if (depth > 128) {
      fail(`${subject} has unsupported nesting depth`)
    }
    skipWhitespace()
    const character = source[offset]
    if (character === '{') {
      offset += 1
      skipWhitespace()
      const keys = new Set()
      if (source[offset] === '}') {
        offset += 1
        return
      }
      while (offset < source.length) {
        skipWhitespace()
        const key = parseString()
        if (keys.has(key)) {
          fail(`${subject} contains duplicate member name ${JSON.stringify(key)}`)
        }
        keys.add(key)
        skipWhitespace()
        if (source[offset] !== ':') {
          invalidJson()
        }
        offset += 1
        parseValue(depth + 1)
        skipWhitespace()
        if (source[offset] === '}') {
          offset += 1
          return
        }
        if (source[offset] !== ',') {
          invalidJson()
        }
        offset += 1
      }
      invalidJson()
    }
    if (character === '[') {
      offset += 1
      skipWhitespace()
      if (source[offset] === ']') {
        offset += 1
        return
      }
      while (offset < source.length) {
        parseValue(depth + 1)
        skipWhitespace()
        if (source[offset] === ']') {
          offset += 1
          return
        }
        if (source[offset] !== ',') {
          invalidJson()
        }
        offset += 1
      }
      invalidJson()
    }
    if (character === '"') {
      parseString()
      return
    }
    for (const literal of ['true', 'false', 'null']) {
      if (source.startsWith(literal, offset)) {
        offset += literal.length
        return
      }
    }
    const number = source.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/)
    if (number === null) {
      invalidJson()
    }
    offset += number[0].length
  }

  parseValue(0)
  skipWhitespace()
  if (offset !== source.length) {
    invalidJson()
  }
}

async function parseJsonFile(filePath, subject) {
  let metadata
  let bytes
  let handle
  try {
    metadata = await lstat(filePath)
    if (metadata.isSymbolicLink() || !metadata.isFile()) {
      fail(`${subject} must be a regular non-symlink file`)
    }
    if (metadata.size <= 1 || metadata.size > 1024 * 1024) {
      fail(`${subject} has an unsupported size`)
    }
    handle = await open(filePath, filesystemConstants.O_RDONLY | filesystemConstants.O_NOFOLLOW)
    const openedMetadata = await handle.stat()
    if (
      !openedMetadata.isFile() ||
      openedMetadata.dev !== metadata.dev ||
      openedMetadata.ino !== metadata.ino ||
      openedMetadata.size !== metadata.size
    ) {
      fail(`${subject} changed before it could be read`)
    }
    bytes = await handle.readFile({ encoding: 'utf8' })
    const openedMetadataAfterRead = await handle.stat()
    const metadataAfterRead = await lstat(filePath)
    if (
      metadataAfterRead.isSymbolicLink() ||
      !metadataAfterRead.isFile() ||
      openedMetadataAfterRead.dev !== openedMetadata.dev ||
      openedMetadataAfterRead.ino !== openedMetadata.ino ||
      openedMetadataAfterRead.size !== openedMetadata.size ||
      openedMetadataAfterRead.mtimeMs !== openedMetadata.mtimeMs ||
      metadataAfterRead.dev !== metadata.dev ||
      metadataAfterRead.ino !== metadata.ino ||
      metadataAfterRead.size !== metadata.size ||
      metadataAfterRead.mtimeMs !== metadata.mtimeMs
    ) {
      fail(`${subject} changed while it was being read`)
    }
  } catch (error) {
    if (error instanceof ProductionBundleAdmissionError) {
      throw error
    }
    fail(`${subject} is unavailable`, error)
  } finally {
    if (handle !== undefined) {
      await handle.close().catch(() => {})
    }
  }
  try {
    assertNoDuplicateJsonMembers(bytes, subject)
    return JSON.parse(bytes)
  } catch (error) {
    if (error instanceof ProductionBundleAdmissionError) {
      throw error
    }
    fail(`${subject} is not valid JSON`, error)
  }
}

function parsePolicy(value) {
  if (!isPlainObject(value)) {
    fail('production bundle policy must be an object')
  }
  requireExactFields(value, EXACT_POLICY_FIELDS, 'production bundle policy')
  if (value.contract_version !== PRODUCTION_BUNDLE_ADMISSION_CONTRACT_VERSION) {
    fail('production bundle policy contract version is unsupported')
  }

  const entryModule = requireModuleId(value.entry_module, 'policy entry_module')
  const routeModules = requireUniqueTextArray(
    value.route_modules,
    'policy route_modules',
    requireModuleId,
  )
  if (routeModules.length !== 11) {
    fail('policy route_modules must contain exactly 11 modules')
  }
  if (routeModules.includes(entryModule)) {
    fail('policy entry_module cannot also be a route module')
  }

  const requiredSharedPartitions = requireUniqueTextArray(
    value.required_shared_partitions,
    'policy required_shared_partitions',
  )
  for (const name of MANDATORY_SHARED_PARTITIONS) {
    if (!requiredSharedPartitions.includes(name)) {
      fail(`policy must require shared partition ${JSON.stringify(name)}`)
    }
  }

  return {
    entryModule,
    routeModules,
    requiredSharedPartitions,
    maxAssetBytes: requirePositiveSafeInteger(
      value.max_asset_bytes,
      'policy max_asset_bytes',
    ),
    maxInitialGraphBytes: requirePositiveSafeInteger(
      value.max_initial_graph_bytes,
      'policy max_initial_graph_bytes',
    ),
  }
}

function optionalText(value, subject) {
  return value === undefined ? undefined : requireBoundedText(value, subject)
}

function optionalBoolean(value, subject) {
  if (value === undefined) {
    return undefined
  }
  if (typeof value !== 'boolean') {
    fail(`${subject} must be a boolean when present`)
  }
  return value
}

function optionalUniqueArray(value, subject, validator) {
  return value === undefined ? [] : requireUniqueTextArray(value, subject, validator)
}

function parseManifest(value) {
  if (!isPlainObject(value) || Object.keys(value).length === 0) {
    fail('Vite manifest must be a non-empty object')
  }

  const entries = new Map()
  const outputOwners = new Map()
  for (const [unvalidatedKey, unvalidatedEntry] of Object.entries(value)) {
    const key = requireModuleId(unvalidatedKey, 'Vite manifest key')
    if (!isPlainObject(unvalidatedEntry)) {
      fail(`Vite manifest entry ${JSON.stringify(key)} must be an object`)
    }
    const unexpected = Object.keys(unvalidatedEntry).filter(
      (field) => !ALLOWED_MANIFEST_FIELDS.has(field),
    )
    if (unexpected.length > 0) {
      fail(`Vite manifest entry ${JSON.stringify(key)} has unsupported fields`)
    }
    if (!Object.hasOwn(unvalidatedEntry, 'file')) {
      fail(`Vite manifest entry ${JSON.stringify(key)} has no output file`)
    }
    const file = requireAssetPath(
      unvalidatedEntry.file,
      `Vite manifest entry ${JSON.stringify(key)} file`,
    )
    const priorOwner = outputOwners.get(file)
    if (priorOwner !== undefined) {
      fail(
        `Vite manifest entries ${JSON.stringify(priorOwner)} and ${JSON.stringify(key)} duplicate output file ${JSON.stringify(file)}`,
      )
    }
    outputOwners.set(file, key)

    entries.set(key, {
      file,
      src:
        unvalidatedEntry.src === undefined
          ? undefined
          : requireModuleId(
              unvalidatedEntry.src,
              `Vite manifest entry ${JSON.stringify(key)} src`,
            ),
      name: optionalText(unvalidatedEntry.name, `Vite manifest entry ${JSON.stringify(key)} name`),
      isEntry: optionalBoolean(
        unvalidatedEntry.isEntry,
        `Vite manifest entry ${JSON.stringify(key)} isEntry`,
      ),
      isDynamicEntry: optionalBoolean(
        unvalidatedEntry.isDynamicEntry,
        `Vite manifest entry ${JSON.stringify(key)} isDynamicEntry`,
      ),
      imports: optionalUniqueArray(
        unvalidatedEntry.imports,
        `Vite manifest entry ${JSON.stringify(key)} imports`,
        requireModuleId,
      ),
      dynamicImports: optionalUniqueArray(
        unvalidatedEntry.dynamicImports,
        `Vite manifest entry ${JSON.stringify(key)} dynamicImports`,
        requireModuleId,
      ),
      css: optionalUniqueArray(
        unvalidatedEntry.css,
        `Vite manifest entry ${JSON.stringify(key)} css`,
        requireAssetPath,
      ),
      assets: optionalUniqueArray(
        unvalidatedEntry.assets,
        `Vite manifest entry ${JSON.stringify(key)} assets`,
        requireAssetPath,
      ),
    })
  }

  for (const [key, entry] of entries) {
    for (const dependency of [...entry.imports, ...entry.dynamicImports]) {
      if (!entries.has(dependency)) {
        fail(
          `Vite manifest entry ${JSON.stringify(key)} references missing module ${JSON.stringify(dependency)}`,
        )
      }
    }
  }
  return entries
}

function requireExactSet(observedValues, expectedValues, subject) {
  const observed = new Set(observedValues)
  const expected = new Set(expectedValues)
  if (
    observed.size !== expected.size ||
    [...observed].some((value) => !expected.has(value))
  ) {
    fail(`${subject} does not match the policy allowlist`)
  }
}

function validateGraph(entries, policy) {
  const entry = entries.get(policy.entryModule)
  if (entry === undefined || entry.isEntry !== true || entry.src !== policy.entryModule) {
    fail('policy entry_module is not the exact Vite entry')
  }
  const entryKeys = [...entries]
    .filter(([, candidate]) => candidate.isEntry === true)
    .map(([key]) => key)
  if (entryKeys.length !== 1 || entryKeys[0] !== policy.entryModule) {
    fail('Vite manifest must contain exactly one policy entry')
  }

  const dynamicEntryKeys = [...entries]
    .filter(([, candidate]) => candidate.isDynamicEntry === true)
    .map(([key]) => key)
  requireExactSet(dynamicEntryKeys, policy.routeModules, 'Vite dynamic entries')
  requireExactSet(entry.dynamicImports, policy.routeModules, 'entry dynamic imports')

  for (const routeModule of policy.routeModules) {
    const route = entries.get(routeModule)
    if (
      route === undefined ||
      route.isDynamicEntry !== true ||
      route.isEntry === true ||
      route.src !== routeModule
    ) {
      fail(`route module ${JSON.stringify(routeModule)} is not a distinct dynamic entry`)
    }
  }
  for (const [key, candidate] of entries) {
    for (const dynamicTarget of candidate.dynamicImports) {
      if (!policy.routeModules.includes(dynamicTarget)) {
        fail(
          `Vite manifest entry ${JSON.stringify(key)} dynamically imports unallowlisted module ${JSON.stringify(dynamicTarget)}`,
        )
      }
      if (entries.get(dynamicTarget)?.isDynamicEntry !== true) {
        fail(`dynamic import target ${JSON.stringify(dynamicTarget)} is not a dynamic entry`)
      }
    }
  }

  const initialGraph = new Set()
  const pending = [policy.entryModule]
  while (pending.length > 0) {
    const key = pending.pop()
    if (initialGraph.has(key)) {
      continue
    }
    initialGraph.add(key)
    const current = entries.get(key)
    if (current === undefined) {
      fail(`initial static graph references missing module ${JSON.stringify(key)}`)
    }
    pending.push(...current.imports)
  }
  for (const routeModule of policy.routeModules) {
    if (initialGraph.has(routeModule)) {
      fail(`route module ${JSON.stringify(routeModule)} is folded into the entry static graph`)
    }
  }

  const partitionKeys = []
  for (const partitionName of policy.requiredSharedPartitions) {
    const matches = [...entries]
      .filter(([, candidate]) => candidate.name === partitionName)
      .map(([key]) => key)
    if (matches.length !== 1) {
      fail(`shared partition ${JSON.stringify(partitionName)} must occur exactly once`)
    }
    const partitionKey = matches[0]
    const partition = entries.get(partitionKey)
    if (
      !initialGraph.has(partitionKey) ||
      partition.isEntry === true ||
      partition.isDynamicEntry === true
    ) {
      fail(`shared partition ${JSON.stringify(partitionName)} is not in the initial static graph`)
    }
    partitionKeys.push(partitionKey)
  }
  if (new Set(partitionKeys).size !== partitionKeys.length) {
    fail('required shared partitions must be distinct manifest entries')
  }
  return initialGraph
}

function isStrictDescendant(rootPath, candidatePath) {
  const relative = path.relative(rootPath, candidatePath)
  return relative !== '' && !relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative)
}

async function resolveAsset(distRealPath, assetPath) {
  const candidate = path.resolve(distRealPath, ...assetPath.split('/'))
  if (!isStrictDescendant(distRealPath, candidate)) {
    fail(`asset ${JSON.stringify(assetPath)} resolves outside dist`)
  }
  let resolved
  let metadata
  let handle
  try {
    let current = distRealPath
    for (const segment of assetPath.split('/')) {
      current = path.join(current, segment)
      const componentMetadata = await lstat(current)
      if (componentMetadata.isSymbolicLink()) {
        fail(`asset ${JSON.stringify(assetPath)} must not traverse a symbolic link`)
      }
    }
    resolved = await realpath(candidate)
    const resolvedMetadata = await stat(resolved)
    handle = await open(candidate, filesystemConstants.O_RDONLY | filesystemConstants.O_NOFOLLOW)
    metadata = await handle.stat()
    if (
      !metadata.isFile() ||
      metadata.dev !== resolvedMetadata.dev ||
      metadata.ino !== resolvedMetadata.ino ||
      metadata.size !== resolvedMetadata.size
    ) {
      fail(`asset ${JSON.stringify(assetPath)} changed before it could be measured`)
    }
    let recheckedComponent = distRealPath
    for (const segment of assetPath.split('/')) {
      recheckedComponent = path.join(recheckedComponent, segment)
      if ((await lstat(recheckedComponent)).isSymbolicLink()) {
        fail(`asset ${JSON.stringify(assetPath)} must not traverse a symbolic link`)
      }
    }
    const resolvedAfterMeasurement = await realpath(candidate)
    const metadataAfterMeasurement = await stat(resolvedAfterMeasurement)
    const openedMetadataAfterMeasurement = await handle.stat()
    if (
      resolvedAfterMeasurement !== resolved ||
      openedMetadataAfterMeasurement.dev !== metadata.dev ||
      openedMetadataAfterMeasurement.ino !== metadata.ino ||
      openedMetadataAfterMeasurement.size !== metadata.size ||
      openedMetadataAfterMeasurement.mtimeMs !== metadata.mtimeMs ||
      metadataAfterMeasurement.dev !== metadata.dev ||
      metadataAfterMeasurement.ino !== metadata.ino ||
      metadataAfterMeasurement.size !== metadata.size ||
      metadataAfterMeasurement.mtimeMs !== metadata.mtimeMs
    ) {
      fail(`asset ${JSON.stringify(assetPath)} changed while it was being measured`)
    }
  } catch (error) {
    if (error instanceof ProductionBundleAdmissionError) {
      throw error
    }
    fail(`asset ${JSON.stringify(assetPath)} is missing or unreadable`, error)
  } finally {
    if (handle !== undefined) {
      await handle.close().catch(() => {})
    }
  }
  if (!isStrictDescendant(distRealPath, resolved) || !metadata.isFile()) {
    fail(`asset ${JSON.stringify(assetPath)} is not a regular file strictly under dist`)
  }
  if (!Number.isSafeInteger(metadata.size) || metadata.size <= 0) {
    fail(`asset ${JSON.stringify(assetPath)} has an unsupported size`)
  }
  return {
    realPath: resolved,
    fileIdentity: `${metadata.dev}:${metadata.ino}`,
    bytes: metadata.size,
  }
}

async function measureAssets(entries, distRealPath, maxAssetBytes) {
  const entryFiles = new Set([...entries.values()].map((entry) => entry.file))
  const supportingFiles = new Set(
    [...entries.values()].flatMap((entry) => [...entry.css, ...entry.assets]),
  )
  for (const supportingFile of supportingFiles) {
    if (entryFiles.has(supportingFile)) {
      fail(`asset ${JSON.stringify(supportingFile)} is duplicated as an entry output`)
    }
  }
  const allAssets = new Set([...entryFiles, ...supportingFiles])
  const measurements = new Map()
  const realPathOwners = new Map()
  const fileIdentityOwners = new Map()
  for (const assetPath of [...allAssets].sort()) {
    const measurement = await resolveAsset(distRealPath, assetPath)
    const priorOwner = realPathOwners.get(measurement.realPath)
    if (priorOwner !== undefined) {
      fail(
        `assets ${JSON.stringify(priorOwner)} and ${JSON.stringify(assetPath)} resolve to the same file`,
      )
    }
    realPathOwners.set(measurement.realPath, assetPath)
    const priorIdentityOwner = fileIdentityOwners.get(measurement.fileIdentity)
    if (priorIdentityOwner !== undefined) {
      fail(
        `assets ${JSON.stringify(priorIdentityOwner)} and ${JSON.stringify(assetPath)} are aliases of the same file`,
      )
    }
    fileIdentityOwners.set(measurement.fileIdentity, assetPath)
    if (measurement.bytes > maxAssetBytes) {
      fail(
        `asset ${JSON.stringify(assetPath)} is ${measurement.bytes} bytes, exceeding ${maxAssetBytes}`,
      )
    }
    measurements.set(assetPath, measurement.bytes)
  }
  return measurements
}

function initialGraphAssetPaths(entries, initialGraph) {
  const paths = new Set()
  for (const key of initialGraph) {
    const entry = entries.get(key)
    paths.add(entry.file)
    for (const assetPath of [...entry.css, ...entry.assets]) {
      paths.add(assetPath)
    }
  }
  return paths
}

/**
 * Verify an already-built Vite production bundle using only offline files.
 */
export async function verifyProductionBundle({ distDirectory, policyPath }) {
  if (typeof distDirectory !== 'string' || typeof policyPath !== 'string') {
    fail('production bundle verification requires distDirectory and policyPath')
  }
  let distRealPath
  try {
    distRealPath = await realpath(path.resolve(distDirectory))
    const metadata = await stat(distRealPath)
    if (!metadata.isDirectory()) {
      fail('production bundle dist path must be a directory')
    }
  } catch (error) {
    if (error instanceof ProductionBundleAdmissionError) {
      throw error
    }
    fail('production bundle dist path is unavailable', error)
  }

  const policy = parsePolicy(await parseJsonFile(path.resolve(policyPath), 'production bundle policy'))
  const manifestPath = path.resolve(distRealPath, ...MANIFEST_RELATIVE_PATH.split('/'))
  if (!isStrictDescendant(distRealPath, manifestPath)) {
    fail('Vite manifest resolves outside dist')
  }
  const manifestRealPath = await realpath(manifestPath).catch((error) => {
    fail('Vite manifest is unavailable', error)
  })
  if (!isStrictDescendant(distRealPath, manifestRealPath)) {
    fail('Vite manifest must resolve strictly under dist')
  }
  const manifestValue = await parseJsonFile(manifestPath, 'Vite manifest')
  const manifestRealPathAfterRead = await realpath(manifestPath).catch((error) => {
    fail('Vite manifest became unavailable after reading', error)
  })
  if (manifestRealPathAfterRead !== manifestRealPath) {
    fail('Vite manifest changed location while it was being read')
  }
  const entries = parseManifest(manifestValue)
  const initialGraph = validateGraph(entries, policy)
  const measurements = await measureAssets(entries, distRealPath, policy.maxAssetBytes)
  const initialAssets = initialGraphAssetPaths(entries, initialGraph)
  const initialGraphBytes = [...initialAssets].reduce((total, assetPath) => {
    const bytes = measurements.get(assetPath)
    if (bytes === undefined) {
      fail(`initial graph asset ${JSON.stringify(assetPath)} was not measured`)
    }
    return total + bytes
  }, 0)
  if (!Number.isSafeInteger(initialGraphBytes)) {
    fail('initial static graph byte total exceeds the safe integer range')
  }
  if (initialGraphBytes > policy.maxInitialGraphBytes) {
    fail(
      `initial static graph is ${initialGraphBytes} bytes, exceeding ${policy.maxInitialGraphBytes}`,
    )
  }

  return Object.freeze({
    contract_version: PRODUCTION_BUNDLE_ADMISSION_CONTRACT_VERSION,
    status: 'production_bundle_admitted',
    route_module_count: policy.routeModules.length,
    required_shared_partition_count: policy.requiredSharedPartitions.length,
    asset_count: measurements.size,
    measured_max_asset_bytes: Math.max(...measurements.values()),
    initial_static_graph_asset_count: initialAssets.size,
    initial_static_graph_bytes: initialGraphBytes,
    max_asset_bytes: policy.maxAssetBytes,
    max_initial_graph_bytes: policy.maxInitialGraphBytes,
    operational_control_authorized: false,
    trading_authorized: false,
    deployment_authorized: false,
  })
}

function parseCliArguments(arguments_) {
  const options = new Map()
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index]
    const value = arguments_[index + 1]
    if (!['--dist', '--policy'].includes(flag) || value === undefined || options.has(flag)) {
      fail('usage: verify-production-bundle.mjs [--dist PATH] [--policy PATH]')
    }
    options.set(flag, value)
  }
  if (arguments_.length % 2 !== 0) {
    fail('usage: verify-production-bundle.mjs [--dist PATH] [--policy PATH]')
  }
  return options
}

async function main() {
  const scriptDirectory = path.dirname(fileURLToPath(import.meta.url))
  const options = parseCliArguments(process.argv.slice(2))
  const result = await verifyProductionBundle({
    distDirectory: options.get('--dist') ?? path.resolve(scriptDirectory, '../dist'),
    policyPath:
      options.get('--policy') ??
      path.resolve(scriptDirectory, '../config/production-bundle-policy.json'),
  })
  process.stdout.write(`${JSON.stringify(result)}\n`)
}

const invokedPath = process.argv[1]
if (invokedPath !== undefined && import.meta.url === pathToFileURL(path.resolve(invokedPath)).href) {
  main().catch((error) => {
    const message =
      error instanceof ProductionBundleAdmissionError
        ? error.message
        : 'production bundle verification failed unexpectedly'
    process.stderr.write(`${message}\n`)
    process.exitCode = 1
  })
}
