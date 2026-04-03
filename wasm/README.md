# @flameinthedark/go-dave

`@flameinthedark/go-dave` is the browser and Electron build of `go-dave`. It bundles `go-dave.wasm` and exposes a small DAVE session API for WebRTC insertable streams.

Protocol reference: [daveprotocol.com](https://daveprotocol.com/)

Use it to:

- create and advance DAVE/MLS sessions
- exchange key material with your gateway or voice server
- encrypt outgoing encoded frames before transport encryption
- decrypt incoming encoded frames after transport decryption
- show verification codes and fingerprints to users

## Install

```bash
npm install @flameinthedark/go-dave
```

The package already includes `go-dave.wasm` and `wasm_exec.js`.

## Quick Start

Most integrations only need a single session object and a handful of methods.

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

// Load the bundled WASM runtime once for the whole app.
const GoDave = await loadGoDave()

// Create one session per user in the voice channel.
const session = GoDave.createSession(
  GoDave.DAVE_PROTOCOL_VERSION,
  userId,
  channelId,
)

// Set the external sender announced by the gateway.
session.setExternalSender(externalSenderBuffer)

// Send this key package to your gateway or voice server.
const keyPackage = session.getSerializedKeyPackage()

// Apply proposals as the roster changes.
const result = session.processProposals(
  GoDave.ProposalsOperationType.APPEND,
  proposalsBuffer,
  recognizedUserIds,
)

// Apply the commit produced for this session, or a welcome if you joined through one.
if (result.commit) {
  session.processCommit(result.commit)
}
if (welcomeBuffer) {
  session.processWelcome(welcomeBuffer)
}

// Encrypt outgoing frames and decrypt incoming frames once the session is ready.
if (session.getState().ready) {
  const encryptedPacket = session.encryptOpus(outgoingPacket)
  if (encryptedPacket) {
    console.log('send encrypted packet', encryptedPacket)
  }

  const decryptedPacket = session.decrypt(
    remoteUserId,
    GoDave.MediaType.AUDIO,
    incomingPacket,
  )
  if (decryptedPacket) {
    console.log({ keyPackage, decryptedPacket })
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
- [Overview and concepts](https://github.com/FlameInTheDark/go-dave/blob/main/docs/overview.md)
- [Gateway packet guide](https://github.com/FlameInTheDark/go-dave/blob/main/docs/gateway-packets.md)
- [Insertable Streams and runtime notes](https://github.com/FlameInTheDark/go-dave/blob/main/docs/insertable-streams.md)
- [TypeScript definitions](https://github.com/FlameInTheDark/go-dave/blob/main/wasm/index.d.ts)
