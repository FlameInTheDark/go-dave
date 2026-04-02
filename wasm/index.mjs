let modulePromise = null

function toURL(value, base = import.meta.url) {
  return value instanceof URL ? value : new URL(String(value), base)
}

function toImportSpecifier(value) {
  return value instanceof URL ? value.href : String(value)
}

async function ensureGoRuntime(options) {
  const existing = globalThis.Go
  if (typeof existing === 'function') {
    return existing
  }

  const runtimeURL = options.wasmExecUrl ?? new URL('./wasm_exec.js', import.meta.url)
  await import(/* @vite-ignore */ toImportSpecifier(runtimeURL))

  const loaded = globalThis.Go
  if (typeof loaded !== 'function') {
    throw new Error('wasm_exec.js loaded but did not register globalThis.Go')
  }

  return loaded
}

async function instantiate(go, url, fetchImpl) {
  const response = await fetchImpl(url)
  const fallback = response.clone()

  try {
    return await WebAssembly.instantiateStreaming(response, go.importObject)
  } catch {
    const bytes = await fallback.arrayBuffer()
    return WebAssembly.instantiate(bytes, go.importObject)
  }
}

export async function loadGoDave(options = {}) {
  if (globalThis.GoDave) {
    return globalThis.GoDave
  }

  if (!modulePromise) {
    modulePromise = (async () => {
      if (globalThis.GoDave) {
        return globalThis.GoDave
      }

      const GoRuntime = options.go ? null : await ensureGoRuntime(options)
      const go = options.go ?? new GoRuntime()
      const url = toURL(options.url ?? new URL('./go-dave.wasm', import.meta.url))
      const fetchImpl = options.fetch ?? globalThis.fetch?.bind(globalThis)
      if (typeof fetchImpl !== 'function') {
        throw new Error('fetch is not available; provide options.fetch to load the WASM module')
      }

      const { instance } = await instantiate(go, url, fetchImpl)
      const runPromise = Promise.resolve(go.run(instance))

      if (!globalThis.GoDave) {
        await Promise.resolve()
      }
      if (!globalThis.GoDave) {
        throw new Error('GoDave module did not initialize')
      }

      void runPromise.catch((error) => {
        console.error('GoDave runtime exited unexpectedly', error)
      })

      return globalThis.GoDave
    })().catch((error) => {
      modulePromise = null
      throw error
    })
  }

  return modulePromise
}

export default loadGoDave
