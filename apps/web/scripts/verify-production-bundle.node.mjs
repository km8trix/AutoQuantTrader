import assert from 'node:assert/strict'
import { link, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import test from 'node:test'

import {
  ProductionBundleAdmissionError,
  verifyProductionBundle,
} from './verify-production-bundle.mjs'

// Keep these filesystem adversarial cases on Node's built-in runner, not jsdom.

const fixture = JSON.parse(
  await readFile(new URL('./test-fixtures/production-bundle.json', import.meta.url), 'utf8'),
)

function cloneFixture() {
  return structuredClone(fixture)
}

async function materializeFixture(t, mutate = () => {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'aqt-production-bundle-'))
  t.after(async () => {
    await rm(root, { recursive: true, force: true })
  })
  const value = cloneFixture()
  mutate(value)

  const distDirectory = path.join(root, 'dist')
  const manifestPath = path.join(distDirectory, '.vite', 'manifest.json')
  const policyPath = path.join(root, 'production-bundle-policy.json')
  await mkdir(path.dirname(manifestPath), { recursive: true })
  await writeFile(policyPath, `${JSON.stringify(value.policy)}\n`, 'utf8')
  await writeFile(manifestPath, `${JSON.stringify(value.manifest)}\n`, 'utf8')
  for (const [assetPath, size] of Object.entries(value.asset_sizes)) {
    const target = path.join(distDirectory, ...assetPath.split('/'))
    await mkdir(path.dirname(target), { recursive: true })
    await writeFile(target, Buffer.alloc(size, 120))
  }
  return { distDirectory, manifestPath, policyPath, root }
}

async function rejectFixture(t, mutate, pattern) {
  const paths = await materializeFixture(t, mutate)
  await assert.rejects(
    verifyProductionBundle(paths),
    (error) => error instanceof ProductionBundleAdmissionError && pattern.test(error.message),
  )
}

test('admits the exact fixture when both byte ceilings are met at equality', async (t) => {
  const paths = await materializeFixture(t)

  const result = await verifyProductionBundle(paths)

  assert.deepEqual(result, {
    contract_version: 'phase6b-production-bundle-admission-v1',
    status: 'production_bundle_admitted',
    route_module_count: 11,
    required_shared_partition_count: 4,
    asset_count: 16,
    measured_max_asset_bytes: 50,
    initial_static_graph_asset_count: 5,
    initial_static_graph_bytes: 150,
    max_asset_bytes: 50,
    max_initial_graph_bytes: 150,
    operational_control_authorized: false,
    trading_authorized: false,
    deployment_authorized: false,
  })
})

test('rejects byte ceilings only after equality is exceeded', async (t) => {
  await t.test('per-asset overflow', async (t) => {
    await rejectFixture(
      t,
      (value) => {
        value.asset_sizes['assets/vendor.js'] = 51
      },
      /asset .* is 51 bytes, exceeding 50/,
    )
  })

  await t.test('initial static graph overflow', async (t) => {
    await rejectFixture(
      t,
      (value) => {
        value.policy.max_initial_graph_bytes = 149
      },
      /initial static graph is 150 bytes, exceeding 149/,
    )
  })
})

test('requires exactly 11 distinct allowlisted route dynamic entries', async (t) => {
  const cases = [
    {
      name: 'missing dynamic entry',
      mutate(value) {
        value.manifest['src/routes/Route11.tsx'].isDynamicEntry = false
      },
      pattern: /dynamic entries does not match the policy allowlist/,
    },
    {
      name: 'unallowlisted dynamic entry',
      mutate(value) {
        value.manifest['_react.js'].isDynamicEntry = true
      },
      pattern: /dynamic entries does not match the policy allowlist/,
    },
    {
      name: 'route output shared with another route',
      mutate(value) {
        value.manifest['src/routes/Route02.tsx'].file = 'assets/route-01.js'
      },
      pattern: /duplicate output file/,
    },
    {
      name: 'entry dynamic-import allowlist drift',
      mutate(value) {
        value.manifest['index.html'].dynamicImports.pop()
      },
      pattern: /entry dynamic imports does not match the policy allowlist/,
    },
    {
      name: 'policy route count drift',
      mutate(value) {
        value.policy.route_modules.pop()
      },
      pattern: /exactly 11 modules/,
    },
  ]

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      await rejectFixture(t, scenario.mutate, scenario.pattern)
    })
  }
})

test('rejects any route folded into the entry static import graph', async (t) => {
  await rejectFixture(
    t,
    (value) => {
      value.manifest['index.html'].imports.push('src/routes/Route01.tsx')
    },
    /route module .* is folded into the entry static graph/,
  )
})

test('requires each configured shared runtime as a distinct initial partition', async (t) => {
  const cases = [
    {
      name: 'missing named partition',
      mutate(value) {
        value.manifest['_vendor.js'].name = 'other-runtime'
      },
      pattern: /shared partition "vendor-runtime" must occur exactly once/,
    },
    {
      name: 'duplicate named partition',
      mutate(value) {
        value.manifest['_query.js'].name = 'react-runtime'
      },
      pattern: /shared partition "react-runtime" must occur exactly once/,
    },
    {
      name: 'partition outside initial graph',
      mutate(value) {
        value.manifest['index.html'].imports = value.manifest['index.html'].imports.filter(
          (key) => key !== '_query.js',
        )
      },
      pattern: /shared partition "query-runtime" is not in the initial static graph/,
    },
  ]

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      await rejectFixture(t, scenario.mutate, scenario.pattern)
    })
  }
})

test('rejects traversal, missing files, aliases, and symlinks', async (t) => {
  await t.test('traversal', async (t) => {
    await rejectFixture(
      t,
      (value) => {
        value.manifest['_vendor.js'].file = '../vendor.js'
      },
      /normalized relative module ID/,
    )
  })

  await t.test('case-folded Vite metadata path', async (t) => {
    await rejectFixture(
      t,
      (value) => {
        value.manifest['_vendor.js'].file = '.VITE/vendor.js'
      },
      /cannot address Vite metadata/,
    )
  })

  await t.test('missing file', async (t) => {
    await rejectFixture(
      t,
      (value) => {
        delete value.asset_sizes['assets/route-11.js']
      },
      /asset "assets\/route-11\.js" is missing or unreadable/,
    )
  })

  await t.test('direct symbolic link', async (t) => {
    const paths = await materializeFixture(t, (value) => {
      value.manifest['_vendor.js'].file = 'assets/vendor-alias.js'
      value.asset_sizes['assets/vendor-alias.js'] = 50
      delete value.asset_sizes['assets/vendor.js']
    })
    await rm(path.join(paths.distDirectory, 'assets/vendor-alias.js'))
    await symlink(
      path.join(paths.distDirectory, 'assets/react.js'),
      path.join(paths.distDirectory, 'assets/vendor-alias.js'),
    )
    await assert.rejects(
      verifyProductionBundle(paths),
      (error) =>
        error instanceof ProductionBundleAdmissionError && /symbolic link/.test(error.message),
    )
  })

  await t.test('symbolic parent directory escaping dist', async (t) => {
    const paths = await materializeFixture(t, (value) => {
      value.manifest['_vendor.js'].file = 'linked-assets/vendor.js'
      value.asset_sizes['linked-assets/vendor.js'] = 50
      delete value.asset_sizes['assets/vendor.js']
    })
    const outsideDirectory = path.join(paths.root, 'outside-assets')
    await mkdir(outsideDirectory)
    await writeFile(path.join(outsideDirectory, 'vendor.js'), Buffer.alloc(50, 120))
    await rm(path.join(paths.distDirectory, 'linked-assets'), { recursive: true })
    await symlink(outsideDirectory, path.join(paths.distDirectory, 'linked-assets'))

    await assert.rejects(
      verifyProductionBundle(paths),
      (error) =>
        error instanceof ProductionBundleAdmissionError && /symbolic link/.test(error.message),
    )
  })

  await t.test('hard-linked file alias', async (t) => {
    const paths = await materializeFixture(t, (value) => {
      value.manifest['_vendor.js'].file = 'assets/vendor-alias.js'
      value.asset_sizes['assets/vendor-alias.js'] = 50
      delete value.asset_sizes['assets/vendor.js']
    })
    const aliasPath = path.join(paths.distDirectory, 'assets/vendor-alias.js')
    await rm(aliasPath)
    await link(path.join(paths.distDirectory, 'assets/react.js'), aliasPath)

    await assert.rejects(
      verifyProductionBundle(paths),
      (error) =>
        error instanceof ProductionBundleAdmissionError && /aliases of the same file/.test(error.message),
    )
  })
})

test('rejects malformed and dangling manifest structures', async (t) => {
  const cases = [
    {
      name: 'non-array imports',
      mutate(value) {
        value.manifest['_mui.js'].imports = '_react.js'
      },
      pattern: /imports must be an array/,
    },
    {
      name: 'duplicate imports',
      mutate(value) {
        value.manifest['_mui.js'].imports = ['_react.js', '_react.js']
      },
      pattern: /imports must not contain duplicates/,
    },
    {
      name: 'dangling import',
      mutate(value) {
        value.manifest['_mui.js'].imports = ['_missing.js']
      },
      pattern: /references missing module "_missing.js"/,
    },
    {
      name: 'unallowlisted nested dynamic import',
      mutate(value) {
        value.manifest['src/routes/Route01.tsx'].dynamicImports = ['_mui.js']
      },
      pattern: /dynamically imports unallowlisted module "_mui.js"/,
    },
    {
      name: 'unknown manifest field',
      mutate(value) {
        value.manifest['_mui.js'].runtimeSecret = 'must-not-pass'
      },
      pattern: /unsupported fields/,
    },
    {
      name: 'duplicate policy route',
      mutate(value) {
        value.policy.route_modules[10] = value.policy.route_modules[0]
      },
      pattern: /route_modules must not contain duplicates/,
    },
  ]

  for (const scenario of cases) {
    await t.test(scenario.name, async (t) => {
      await rejectFixture(t, scenario.mutate, scenario.pattern)
    })
  }
})

test('rejects invalid JSON without echoing its contents', async (t) => {
  const paths = await materializeFixture(t)
  await writeFile(paths.manifestPath, '{"secret":"do-not-echo",', 'utf8')

  await assert.rejects(
    verifyProductionBundle(paths),
    (error) =>
      error instanceof ProductionBundleAdmissionError &&
      error.message === 'Vite manifest is not valid JSON' &&
      !error.message.includes('do-not-echo'),
  )
})

test('rejects duplicate JSON member names before last-wins parsing', async (t) => {
  await t.test('duplicate manifest module key', async (t) => {
    const paths = await materializeFixture(t)
    const serialized = JSON.stringify(fixture.manifest)
    await writeFile(
      paths.manifestPath,
      `{"_react.js":${JSON.stringify(fixture.manifest['_react.js'])},${serialized.slice(1)}`,
      'utf8',
    )

    await assert.rejects(
      verifyProductionBundle(paths),
      (error) =>
        error instanceof ProductionBundleAdmissionError &&
        /Vite manifest contains duplicate member name "_react\.js"/.test(error.message),
    )
  })

  await t.test('duplicate policy field', async (t) => {
    const paths = await materializeFixture(t)
    const serialized = JSON.stringify(fixture.policy)
    await writeFile(
      paths.policyPath,
      `{"max_asset_bytes":999,${serialized.slice(1)}`,
      'utf8',
    )

    await assert.rejects(
      verifyProductionBundle(paths),
      (error) =>
        error instanceof ProductionBundleAdmissionError &&
        /production bundle policy contains duplicate member name "max_asset_bytes"/.test(
          error.message,
        ),
    )
  })
})
