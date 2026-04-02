import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const scriptDir = dirname(fileURLToPath(import.meta.url))
const packageDir = resolve(scriptDir, '..')
const repoRoot = resolve(packageDir, '..')

mkdirSync(packageDir, { recursive: true })

const goRoot = execFileSync('go', ['env', 'GOROOT'], {
  cwd: repoRoot,
  encoding: 'utf8',
}).trim()

copyFileSync(
  join(goRoot, 'lib', 'wasm', 'wasm_exec.js'),
  join(packageDir, 'wasm_exec.js'),
)

execFileSync('go', ['build', '-o', join(packageDir, 'go-dave.wasm'), './cmd/go-dave-wasm'], {
  cwd: repoRoot,
  env: {
    ...process.env,
    GOOS: 'js',
    GOARCH: 'wasm',
  },
  stdio: 'inherit',
})
