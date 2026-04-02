# go-dave

`go-dave` is a Go implementation of DAVE session management and WebRTC frame encryption.
It includes a native Go API and a WASM package for browser and Electron apps published as `@flameinthedark/go-dave`.

## What it includes

- DAVE/MLS session lifecycle helpers.
- Audio and video frame encryption/decryption for insertable streams.
- Binary packet helpers for gateway opcodes `25` through `30`.
- Pairwise fingerprint and verification code helpers.

## Install

Native Go:

```bash
go get github.com/FlameInTheDark/go-dave
```

Browser or Electron:

```bash
npm install @flameinthedark/go-dave
```

## Quick start

Native Go:

```go
session, err := dave.NewDAVESession(dave.DAVEProtocolVersion, userID, channelID, nil)
if err != nil {
	log.Fatal(err)
}

if err := session.SetExternalSender(externalSenderBuffer); err != nil {
	log.Fatal(err)
}

result, err := session.ProcessProposals(dave.ProposalsAppend, proposalsBuffer, recognizedUserIDs)
if err != nil {
	log.Fatal(err)
}

if result != nil && len(result.Commit) > 0 {
	if err := session.ProcessCommit(result.Commit); err != nil {
		log.Fatal(err)
	}
}

if session.Ready() {
	encrypted, err := session.EncryptOpus(packet)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := session.Decrypt(remoteUserID, dave.MediaTypeAudio, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	_ = decrypted
}
```

Browser or Electron:

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

Recoverable frame-path failures in WASM are logged with `console.warn(...)` and return `null` instead of terminating the runtime.

## Guides

- [Documentation index](./docs/README.md)
- [Native Go guide](./docs/native-go.md)
- [Browser and Electron guide](./docs/wasm.md)
- [Runnable native example](./examples/native/main.go)
