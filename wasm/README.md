# Go DAVE WASM

This package exposes the browser and Electron bridge for `go-dave`.

## Install

```bash
npm install @flameinthedark/go-dave
```

The package already includes `go-dave.wasm` and `wasm_exec.js`.

## Load

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

const GoDave = await loadGoDave({
  url: new URL('./go-dave.wasm', import.meta.url),
  wasmExecUrl: new URL('./wasm_exec.js', import.meta.url),
})
```

## Quick start

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

const GoDave = await loadGoDave()
const session = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, userId, channelId)

session.setExternalSender(externalSenderBuffer)

const result = session.processProposals(
  GoDave.ProposalsOperationType.APPEND,
  proposalsBuffer,
  recognizedUserIds,
)

if (result.commit) {
  session.processCommit(result.commit)
}

if (session.getState().ready) {
  const encrypted = session.encryptOpus(packet)
  if (encrypted) {
    const decrypted = session.decrypt(remoteUserId, GoDave.MediaType.AUDIO, encrypted)
    if (decrypted) {
      console.log(decrypted)
    }
  }
}
```

## Notes

- `loadGoDave(...)` is single-flight and safe to call more than once.
- `encrypt(...)`, `encryptOpus(...)`, and `decrypt(...)` return `Uint8Array | null`.
- Recoverable frame-path failures are logged with `console.warn(...)`.
- Call `session.dispose()` when you are done with a session.

## Guides

- [Full browser and Electron guide](https://github.com/FlameInTheDark/go-dave/blob/main/docs/wasm.md)
- [Native Go guide](https://github.com/FlameInTheDark/go-dave/blob/main/docs/native-go.md)
- [TypeScript definitions](https://github.com/FlameInTheDark/go-dave/blob/main/wasm/index.d.ts)
