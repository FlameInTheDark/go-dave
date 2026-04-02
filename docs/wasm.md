# Browser and Electron Guide

## Install

```bash
npm install @flameinthedark/go-dave
```

The package already includes `go-dave.wasm` and `wasm_exec.js`.

## Load the module

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

const GoDave = await loadGoDave({
  url: new URL('./go-dave.wasm', import.meta.url),
  wasmExecUrl: new URL('./wasm_exec.js', import.meta.url),
})
```

`loadGoDave(...)` is single-flight, so repeated calls reuse the same initialized module.

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

if (welcomeBuffer) {
  session.processWelcome(welcomeBuffer)
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

## Important behavior

- `encrypt(...)`, `encryptOpus(...)`, and `decrypt(...)` return `Uint8Array | null`.
- Recoverable frame-path failures are logged with `console.warn(...)`.
- Dropped frames return `null` instead of terminating the WASM runtime.
- Call `session.dispose()` when the page, worker, or Electron view is done with the session.

For transform patterns, passthrough behavior, and dropped-frame handling, see [insertable-streams.md](./insertable-streams.md).

## Useful helpers

Module helpers:

- `GoDave.generateP256Keypair()`
- `GoDave.encodeExternalSenderPackage(signatureKey, userId)`
- `GoDave.encodeMLSMessageVector(messages)`
- `GoDave.encodeKeyPackagePacket(keyPackage)`
- `GoDave.encodeCommitWelcomePacket(commit, welcome?)`
- `GoDave.parseGatewayBinaryPacket(packet)`
- `GoDave.shouldBeCommitter(selfUserId, recognizedUserIds)`

Session helpers:

- `session.getKeyPackagePacket()`
- `session.createAddProposal(keyPackage)`
- `session.handleGatewayBinaryPacket(packet, recognizedUserIds?)`
- `session.handleGatewayBinaryMessage(sequence, opcode, payload, recognizedUserIds?)`
- `session.processProposals(operationType, payload, recognizedUserIds?)`
- `session.processCommit(commit)`
- `session.processWelcome(welcome)`
- `session.getVerificationCode(userId)`
- `session.getPairwiseFingerprint(version, userId)`
- `session.getState()`
- `session.setPassthroughMode(enabled, transitionExpiry?)`

## React + TypeScript

The published package already ships typings.
If you want the browser-facing surface and transform patterns, see [wasm/index.d.ts](../wasm/index.d.ts) and [insertable-streams.md](./insertable-streams.md).

Common pattern:

```tsx
import { useEffect, useRef } from 'react'
import { loadGoDave, type GoDaveSession } from '@flameinthedark/go-dave'

export function useGoDave(userId: string, channelId: string) {
  const sessionRef = useRef<GoDaveSession | null>(null)

  useEffect(() => {
    let cancelled = false

    void loadGoDave().then((GoDave) => {
      if (cancelled) {
        return
      }
      sessionRef.current = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, userId, channelId)
    })

    return () => {
      cancelled = true
      sessionRef.current?.dispose()
      sessionRef.current = null
    }
  }, [channelId, userId])

  return sessionRef
}
```

## Build from source

`sh`:

```sh
GOOS=js GOARCH=wasm go build -o ./wasm/go-dave.wasm ./cmd/go-dave-wasm
cp "$(go env GOROOT)/lib/wasm/wasm_exec.js" ./wasm/wasm_exec.js
```

PowerShell:

```powershell
$goroot = go env GOROOT
GOOS=js GOARCH=wasm go build -o .\wasm\go-dave.wasm .\cmd\go-dave-wasm
Copy-Item (Join-Path $goroot 'lib\wasm\wasm_exec.js') .\wasm\wasm_exec.js
```
