# go-dave

`go-dave` is a DAVE implementation for Go, browsers, and Electron. DAVE is the end-to-end encryption protocol used for encrypted WebRTC voice and video sessions.

Protocol reference: [daveprotocol.com](https://daveprotocol.com/)

Use it to:

- create and advance DAVE/MLS sessions
- exchange key material with your gateway or voice server
- encrypt outgoing encoded audio and video frames
- decrypt incoming encoded audio and video frames
- show verification codes and fingerprints to users

The project ships in two forms:

- native Go: `github.com/FlameInTheDark/go-dave`
- browser and Electron WASM: `@flameinthedark/go-dave`

## Install

```bash
go get github.com/FlameInTheDark/go-dave
```

```bash
npm install @flameinthedark/go-dave
```

## Quick Start

Most integrations only need a single `DAVESession` and a handful of methods.

### Native Go

```go
import dave "github.com/FlameInTheDark/go-dave"

// Create one session per user in the voice channel.
session, err := dave.NewDAVESession(dave.DAVEProtocolVersion, userID, channelID, nil)
if err != nil {
	log.Fatal(err)
}

// Set the external sender announced by the gateway.
if err := session.SetExternalSender(externalSenderBuffer); err != nil {
	log.Fatal(err)
}

// Send this key package to your gateway or voice server.
keyPackage, err := session.GetSerializedKeyPackage()
if err != nil {
	log.Fatal(err)
}

// Apply proposals as the roster changes.
result, err := session.ProcessProposals(
	dave.ProposalsAppend,
	proposalsBuffer,
	recognizedUserIDs,
)
if err != nil {
	log.Fatal(err)
}

// Apply the commit produced for this session, or a welcome if you joined through one.
if result != nil && len(result.Commit) > 0 {
	if err := session.ProcessCommit(result.Commit); err != nil {
		log.Fatal(err)
	}
}
if len(welcomeBuffer) > 0 {
	if err := session.ProcessWelcome(welcomeBuffer); err != nil {
		log.Fatal(err)
	}
}

// Encrypt outgoing frames and decrypt incoming frames once the session is ready.
if session.Ready() {
	encryptedPacket, err := session.EncryptOpus(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}

	decryptedPacket, err := session.Decrypt(remoteUserID, dave.MediaTypeAudio, incomingPacket)
	if err != nil {
		log.Fatal(err)
	}

	_ = keyPackage
	_ = encryptedPacket
	_ = decryptedPacket
}
```

### Browser And Electron

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

`encrypt(...)`, `encryptOpus(...)`, and `decrypt(...)` return `null` in WASM when a frame is intentionally dropped. Recoverable frame-path failures are logged with `console.warn(...)` instead of terminating the runtime.

## Guides

- [Documentation index](./docs/README.md)
- [Overview and concepts](./docs/overview.md)
- [Native Go guide](./docs/native-go.md)
- [Browser and Electron guide](./docs/wasm.md)
- [Gateway packet guide](./docs/gateway-packets.md)
- [Insertable Streams and runtime notes](./docs/insertable-streams.md)
- [Runnable native example](./examples/native/main.go)
