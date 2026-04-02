let modulePromise = null
let wrappedModule = null

const GO_DAVE_ERROR_MARKER = '__goDaveError'
const MODULE_WRAPPED = Symbol.for('@flameinthedark/go-dave/module-wrapped')
const SESSION_WRAPPED = Symbol.for('@flameinthedark/go-dave/session-wrapped')
const FRAME_METHODS = new Set(['encrypt', 'encryptOpus', 'decrypt'])
const MAX_IDENTICAL_FRAME_WARNINGS = 5
const frameWarningCounts = new Map()

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

function isGoDaveError(value) {
  return Boolean(value) && typeof value === 'object' && value[GO_DAVE_ERROR_MARKER] === true
}

function toGoDaveError(result, context) {
  const prefix = context ? `${context}: ` : ''
  const error = new Error(`${prefix}${result.message ?? 'unknown go-dave error'}`)
  error.name = result.name ?? (result.panic ? 'GoDavePanic' : 'GoDaveError')
  error.goDave = result
  return error
}

function unwrapResult(result, context) {
  if (!isGoDaveError(result)) {
    return result
  }
  throw toGoDaveError(result, context)
}

function describeFrameCall(session, method, args) {
  const sessionId = typeof session?.id === 'number' ? session.id : '?'
  if (method === 'decrypt') {
    return `session ${sessionId} decrypt user=${String(args[0] ?? '')} mediaType=${String(args[1] ?? '')}`
  }
  if (method === 'encrypt') {
    return `session ${sessionId} encrypt mediaType=${String(args[0] ?? '')} codec=${String(args[1] ?? '')}`
  }
  return `session ${sessionId} ${method}`
}

function warnRecoverableFrameDrop(session, method, args, result) {
  const key = `${session?.id ?? '?'}:${method}:${result.message ?? ''}`
  const count = (frameWarningCounts.get(key) ?? 0) + 1
  frameWarningCounts.set(key, count)
  if (count > MAX_IDENTICAL_FRAME_WARNINGS) {
    return
  }

  const suffix = count === MAX_IDENTICAL_FRAME_WARNINGS
    ? ' Further identical warnings will be suppressed.'
    : ''
  globalThis.console?.warn?.(
    `[go-dave] ${describeFrameCall(session, method, args)} dropped a frame: ${result.message ?? 'unknown error'}.${suffix}`,
  )
}

function unwrapSessionResult(session, method, args, result) {
  if (!isGoDaveError(result)) {
    return result
  }
  if (!result.panic && FRAME_METHODS.has(method)) {
    warnRecoverableFrameDrop(session, method, args, result)
    return null
  }
  throw toGoDaveError(result, `GoDaveSession.${method}`)
}

function wrapSession(session) {
  if (!session || typeof session !== 'object' || session[SESSION_WRAPPED]) {
    return session
  }

  for (const key of Reflect.ownKeys(session)) {
    if (typeof key !== 'string') {
      continue
    }
    const value = session[key]
    if (typeof value !== 'function') {
      continue
    }
    const original = value
    session[key] = (...args) => unwrapSessionResult(session, key, args, original.apply(session, args))
  }

  Object.defineProperty(session, SESSION_WRAPPED, {
    value: true,
    configurable: false,
    enumerable: false,
    writable: false,
  })
  return session
}

function wrapModule(module) {
  if (!module || typeof module !== 'object' || module[MODULE_WRAPPED]) {
    wrappedModule = module
    return module
  }

  for (const key of Reflect.ownKeys(module)) {
    if (typeof key !== 'string') {
      continue
    }
    const value = module[key]
    if (typeof value !== 'function') {
      continue
    }
    const original = value
    if (key === 'createSession') {
      module[key] = (...args) => wrapSession(unwrapResult(original.apply(module, args), 'GoDave.createSession'))
      continue
    }
    module[key] = (...args) => unwrapResult(original.apply(module, args), `GoDave.${key}`)
  }

  Object.defineProperty(module, MODULE_WRAPPED, {
    value: true,
    configurable: false,
    enumerable: false,
    writable: false,
  })
  wrappedModule = module
  return module
}

export async function loadGoDave(options = {}) {
  if (wrappedModule) {
    return wrappedModule
  }

  if (globalThis.GoDave) {
    return wrapModule(globalThis.GoDave)
  }

  if (!modulePromise) {
    modulePromise = (async () => {
      if (wrappedModule) {
        return wrappedModule
      }
      if (globalThis.GoDave) {
        return wrapModule(globalThis.GoDave)
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

      return wrapModule(globalThis.GoDave)
    })().catch((error) => {
      modulePromise = null
      wrappedModule = null
      throw error
    })
  }

  return modulePromise
}

export default loadGoDave
