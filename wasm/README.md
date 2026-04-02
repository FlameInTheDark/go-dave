# Go DAVE WASM

This folder contains the browser and Electron bridge for `go-dave`.

It exposes the same core session flow as the native Go package, but with a `Uint8Array`-first API that fits WebRTC transforms and gateway packet handling naturally.

## Build

PowerShell:

```powershell
Copy-Item "$(go env GOROOT)\lib\wasm\wasm_exec.js" .\wasm\
$env:GOOS = 'js'
$env:GOARCH = 'wasm'
go build -o .\wasm\go-dave.wasm .\cmd\go-dave-wasm
```

That gives you:

- `wasm_exec.js` from the Go toolchain runtime
- `go-dave.wasm` built from [`cmd/go-dave-wasm/main.go`](/H:/Projects/Go/src/github.com/FlameInTheDark/go-dave/cmd/go-dave-wasm/main.go)
- [`index.mjs`](/H:/Projects/Go/src/github.com/FlameInTheDark/go-dave/wasm/index.mjs) as the loader
- [`index.d.ts`](/H:/Projects/Go/src/github.com/FlameInTheDark/go-dave/wasm/index.d.ts) for TypeScript consumers

## Load

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

const GoDave = await loadGoDave({
  url: new URL('./go-dave.wasm', import.meta.url),
})
```

`loadGoDave(...)` is single-flight and safe to call more than once. React Strict Mode, HMR, or multiple Electron views will all reuse the same initialized module instance.

If your Electron build loads assets from `file://` instead of an HTTP origin, pass a custom `fetch` implementation that can read local files and keep the same loader API.

## Install with npm

You can install the WASM package directly from this repo path:

```bash
npm install file:../go-dave/wasm
```

The published package name is `@flameinthedark/go-dave`, so once it is on npm the install becomes:

```bash
npm install @flameinthedark/go-dave
```

The package includes `go-dave.wasm` itself together with `wasm_exec.js`. The `prepack` step builds both assets before publish, so consumers do not need Go installed.

## Main WASM API

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
- `session.processProposals(operationType, payload, recognizedUserIds?)`
- `session.processCommit(commit)`
- `session.processWelcome(welcome)`
- `session.encrypt(...)`, `session.encryptOpus(...)`, `session.decrypt(...)`
- `session.getVerificationCode(userId)`
- `session.getPairwiseFingerprint(version, userId)`
- `session.getState()`

Call `session.dispose()` when the page, worker, or Electron view is done with the session.

## End-to-end example

This example creates two sessions locally, performs the MLS join flow, and round-trips an encrypted audio frame.

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

function buildServerPacket(sequence: number, opcode: number, payload: Uint8Array) {
  return new Uint8Array([
    (sequence >> 8) & 0xff,
    sequence & 0xff,
    opcode,
    ...payload,
  ])
}

function encodeMLSVarint(value: number) {
  if (value < 1 << 6) return new Uint8Array([value])
  if (value < 1 << 14) return new Uint8Array([0x40 | (value >> 8), value & 0xff])
  return new Uint8Array([
    0x80 | (value >> 24),
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff,
  ])
}

function encodeOpaqueVector(bytes: Uint8Array) {
  const length = encodeMLSVarint(bytes.length)
  return new Uint8Array([...length, ...bytes])
}

function buildTransitionOpaquePayload(transitionId: number, value: Uint8Array) {
  const opaque = encodeOpaqueVector(value)
  return new Uint8Array([
    (transitionId >> 8) & 0xff,
    transitionId & 0xff,
    ...opaque,
  ])
}

const GoDave = await loadGoDave({
  wasmExecUrl: new URL('./wasm_exec.js', import.meta.url),
  url: new URL('./go-dave.wasm', import.meta.url),
})

const aliceId = '158049329150427136'
const bobId = '158533742254751744'
const channelId = '927310423890473011'
const recognizedUserIds = [aliceId, bobId]

const externalSenderKeyPair = GoDave.generateP256Keypair()
const externalSender = GoDave.encodeExternalSenderPackage(
  externalSenderKeyPair.public,
  '999999999',
)

const alice = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, aliceId, channelId)
const bob = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, bobId, channelId)

alice.handleGatewayBinaryPacket(
  buildServerPacket(1, GoDave.GatewayBinaryOpcode.EXTERNAL_SENDER, externalSender),
)
const bobExternal = bob.handleGatewayBinaryPacket(
  buildServerPacket(1, GoDave.GatewayBinaryOpcode.EXTERNAL_SENDER, externalSender),
)

const addProposal = alice.createAddProposal(bobExternal.keyPackage!)
const proposalsVector = GoDave.encodeMLSMessageVector([addProposal])
const proposalsPayload = new Uint8Array([
  GoDave.ProposalsOperationType.APPEND,
  ...proposalsVector,
])

const proposalsResult = alice.handleGatewayBinaryPacket(
  buildServerPacket(2, GoDave.GatewayBinaryOpcode.PROPOSALS, proposalsPayload),
  recognizedUserIds,
)

const transitionId = 77
alice.handleGatewayBinaryPacket(
  buildServerPacket(
    3,
    GoDave.GatewayBinaryOpcode.ANNOUNCE_COMMIT,
    buildTransitionOpaquePayload(transitionId, proposalsResult.commit!),
  ),
  recognizedUserIds,
)
bob.handleGatewayBinaryPacket(
  buildServerPacket(
    4,
    GoDave.GatewayBinaryOpcode.WELCOME,
    buildTransitionOpaquePayload(transitionId, proposalsResult.welcome!),
  ),
  recognizedUserIds,
)

const encrypted = alice.encryptOpus(new Uint8Array([0x48, 0x69]))
const decrypted = bob.decrypt(aliceId, GoDave.MediaType.AUDIO, encrypted)
const verificationCode = alice.getVerificationCode(bobId)

console.log({
  decrypted: Array.from(decrypted),
  verificationCode,
  aliceState: alice.getState(),
  bobState: bob.getState(),
})

alice.dispose()
bob.dispose()
```

## React + TypeScript

This pattern works well in React because the loader is typed, promise-cached, and does not require a separate side-effect import for `wasm_exec.js`.

```tsx
import { useEffect, useRef, useState } from 'react'
import {
  loadGoDave,
  type GoDaveModule,
  type GoDaveSession,
} from '@flameinthedark/go-dave'

export function useGoDave(userId: string, channelId: string) {
  const [module, setModule] = useState<GoDaveModule | null>(null)
  const sessionRef = useRef<GoDaveSession | null>(null)

  useEffect(() => {
    let cancelled = false

    void loadGoDave({
      wasmExecUrl: new URL('./wasm_exec.js', import.meta.url),
      url: new URL('./go-dave.wasm', import.meta.url),
    }).then((goDave) => {
      if (cancelled) {
        return
      }

      setModule(goDave)
      sessionRef.current = goDave.createSession(
        goDave.DAVE_PROTOCOL_VERSION,
        userId,
        channelId,
      )
      sessionRef.current.setPassthroughMode(true)
    })

    return () => {
      cancelled = true
      sessionRef.current?.dispose()
      sessionRef.current = null
    }
  }, [channelId, userId])

  return {
    module,
    session: sessionRef,
    ready: sessionRef.current?.getState().ready ?? false,
  }
}
```

If you want to consume the published package from another Vite React app:

```ts
import { loadGoDave, type GoDaveModule } from '@flameinthedark/go-dave'
```

## Insertable Streams example

```ts
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
}

export function attachDaveSenderTransform(
  sender: RTCRtpSender & { createEncodedStreams(): { readable: ReadableStream<any>, writable: WritableStream<any> } },
  session: ReturnType<typeof GoDave.createSession>,
  mediaType: number,
  codec: number,
) {
  const { readable, writable } = sender.createEncodedStreams()

  readable
    .pipeThrough(new TransformStream({
      transform(frame, controller) {
        if (!session.getState().ready) {
          controller.enqueue(frame)
          return
        }

        const encrypted = session.encrypt(mediaType, codec, new Uint8Array(frame.data))
        frame.data = toArrayBuffer(encrypted)
        controller.enqueue(frame)
      },
    }))
    .pipeTo(writable)
    .catch(() => {})
}

export function attachDaveReceiverTransform(
  receiver: RTCRtpReceiver & { createEncodedStreams(): { readable: ReadableStream<any>, writable: WritableStream<any> } },
  session: ReturnType<typeof GoDave.createSession>,
  mediaType: number,
  remoteUserId: string,
) {
  const { readable, writable } = receiver.createEncodedStreams()

  readable
    .pipeThrough(new TransformStream({
      transform(frame, controller) {
        try {
          const decrypted = session.decrypt(remoteUserId, mediaType, new Uint8Array(frame.data))
          frame.data = toArrayBuffer(decrypted)
          controller.enqueue(frame)
        } catch (err) {
          if (session.canPassthrough(remoteUserId)) {
            controller.enqueue(frame)
            return
          }
          console.warn('DAVE decrypt failed', remoteUserId, err)
        }
      },
    }))
    .pipeTo(writable)
    .catch(() => {})
}
```
