# go-dave

`go-dave` is a Go implementation of DAVE session management and frame encryption for WebRTC.

It provides a native Go API together with a WASM bridge that works well in browser and Electron apps.

The browser and Electron package is published from [`wasm`](./wasm) as `@flameinthedark/go-dave`.

## What it gives you

- MLS session creation and membership handling for DAVE.
- Audio and video frame encryption/decryption for insertable streams.
- Binary packet helpers for opcodes `25` through `30`.
- A WASM bridge with a `Uint8Array`-first API for browser and Electron apps.
- Verification helpers for pairwise fingerprints and displayable verification codes.

## Install

```bash
go get github.com/FlameInTheDark/go-dave
```

```go
import dave "github.com/FlameInTheDark/go-dave"
```

For browser or Electron apps:

```bash
npm install @flameinthedark/go-dave
```

## Quick start

For browser or Electron apps, the simplest flow is:

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

const GoDave = await loadGoDave()
const session = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, userId, channelId)

session.setExternalSender(externalSenderBuffer)

const keyPackage = session.getSerializedKeyPackage()
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
  session.encryptOpus(packet)
  session.decrypt(remoteUserId, GoDave.MediaType.AUDIO, incomingPacket)
}
```

For the full React/TypeScript walkthrough, see [`wasm/README.md`](./wasm/README.md). The lower sections in this README cover native Go flows, packet helpers, and lower-level details.

## Examples

- Runnable native example: [`examples/native/main.go`](./examples/native/main.go)
- Full WASM walkthrough: [`wasm/README.md`](./wasm/README.md)
- The WASM smoke test in [`wasm/smoke_test.mjs`](./wasm/smoke_test.mjs) is also a working end-to-end JS example.

## Core concepts

- A `DAVESession` owns one user's DAVE state for one voice channel.
- The session becomes usable for media encryption after the MLS handshake finishes and `Ready()` becomes `true`.
- This package includes helpers for the binary packet format `[seq:u16][opcode:u8][payload...]`.
- `EncodeExternalSenderPackage(...)` builds the external sender package you pass to opcode `25`.
- `CreateAddProposal(...)` and `EncodeMLSMessageVector(...)` let you build proposal payloads without touching MLS internals.
- `HandleGatewayBinaryPacket(...)` handles incoming packets for opcodes `25`, `27`, `29`, and `30`.
- `GetKeyPackagePacket()` and `EncodeCommitWelcomePacket(...)` build outgoing packets for opcodes `26` and `28`.

## Native Go Example

This is the smallest complete two-session flow using only public `go-dave` APIs.
For a runnable version, see [`examples/native/main.go`](./examples/native/main.go).

```go
package main

import (
	"encoding/binary"
	"fmt"
	"log"

	dave "github.com/FlameInTheDark/go-dave"
)

func main() {
	const (
		aliceUserID          = "158049329150427136"
		bobUserID            = "158533742254751744"
		channelID            = "927310423890473011"
		externalSenderUserID = "999999999"
	)

	externalSenderKeyPair, err := dave.GenerateP256Keypair()
	if err != nil {
		log.Fatal(err)
	}

	externalSender, err := dave.EncodeExternalSenderPackage(
		externalSenderKeyPair.Public,
		externalSenderUserID,
	)
	if err != nil {
		log.Fatal(err)
	}

	alice, err := dave.NewDAVESession(dave.DAVEProtocolVersion, aliceUserID, channelID, nil)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := dave.NewDAVESession(dave.DAVEProtocolVersion, bobUserID, channelID, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Both peers receive opcode 25 from the server.
	_, err = alice.HandleGatewayBinaryPacket(
		buildServerPacket(1, dave.GatewayBinaryOpcodeExternalSender, externalSender),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	bobExternal, err := bob.HandleGatewayBinaryPacket(
		buildServerPacket(1, dave.GatewayBinaryOpcodeExternalSender, externalSender),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Alice proposes Bob's key package and commits the new epoch.
	recognizedUserIDs := []string{aliceUserID, bobUserID}
	addProposal, err := alice.CreateAddProposal(bobExternal.KeyPackage)
	if err != nil {
		log.Fatal(err)
	}
	proposalsVector, err := dave.EncodeMLSMessageVector(addProposal)
	if err != nil {
		log.Fatal(err)
	}
	proposalsPayload := append([]byte{byte(dave.ProposalsAppend)}, proposalsVector...)

	proposalsResult, err := alice.HandleGatewayBinaryPacket(
		buildServerPacket(2, dave.GatewayBinaryOpcodeProposals, proposalsPayload),
		recognizedUserIDs,
	)
	if err != nil {
		log.Fatal(err)
	}

	const transitionID = uint16(77)
	aliceCommitResult, err := alice.HandleGatewayBinaryPacket(
		buildServerPacket(
			3,
			dave.GatewayBinaryOpcodeAnnounceCommit,
			buildTransitionOpaquePayload(transitionID, proposalsResult.Commit),
		),
		recognizedUserIDs,
	)
	if err != nil {
		log.Fatal(err)
	}
	bobWelcomeResult, err := bob.HandleGatewayBinaryPacket(
		buildServerPacket(
			4,
			dave.GatewayBinaryOpcodeWelcome,
			buildTransitionOpaquePayload(transitionID, proposalsResult.Welcome),
		),
		recognizedUserIDs,
	)
	if err != nil {
		log.Fatal(err)
	}

	if aliceCommitResult.SendTransitionReady {
		fmt.Printf("alice marks transition %d ready\n", *aliceCommitResult.TransitionID)
	}
	if bobWelcomeResult.SendTransitionReady {
		fmt.Printf("bob marks transition %d ready\n", *bobWelcomeResult.TransitionID)
	}

	encrypted, err := alice.EncryptOpus([]byte("hello from alice"))
	if err != nil {
		log.Fatal(err)
	}
	decrypted, err := bob.Decrypt(aliceUserID, dave.MediaTypeAudio, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	verificationCode, err := alice.GetVerificationCode(bobUserID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decrypted packet: %q\n", decrypted)
	fmt.Printf("verification code: %s\n", verificationCode)
}

func buildServerPacket(sequence uint16, opcode dave.GatewayBinaryOpcode, payload []byte) []byte {
	packet := make([]byte, 3+len(payload))
	binary.BigEndian.PutUint16(packet[:2], sequence)
	packet[2] = byte(opcode)
	copy(packet[3:], payload)
	return packet
}

func buildTransitionOpaquePayload(transitionID uint16, value []byte) []byte {
	opaque := encodeOpaqueVector(value)

	payload := make([]byte, 2+len(opaque))
	binary.BigEndian.PutUint16(payload[:2], transitionID)
	copy(payload[2:], opaque)
	return payload
}

func encodeOpaqueVector(data []byte) []byte {
	length := encodeMLSVarint(len(data))
	out := make([]byte, len(length)+len(data))
	copy(out, length)
	copy(out[len(length):], data)
	return out
}

func encodeMLSVarint(value int) []byte {
	switch {
	case value < 1<<6:
		return []byte{byte(value)}
	case value < 1<<14:
		return []byte{byte(0x40 | (value >> 8)), byte(value)}
	default:
		return []byte{
			byte(0x80 | (value >> 24)),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
}
```

## Binary packet flow

If you are already receiving raw server packets, `HandleGatewayBinaryPacket(...)` is usually the best entry point.

Server-to-client packets use this layout:

```text
[seq:u16][opcode:u8][payload...]
```

What the helper does for each binary opcode:

- `25` external sender: calls `SetExternalSender(...)`, creates a fresh key package, and returns `KeyPackagePacket`.
- `27` proposals: calls `ProcessProposals(...)` and returns `Commit`, `Welcome`, and `CommitWelcomePacket` if one was created.
- `29` announce commit: applies the commit and tells you to send transition ready.
- `30` welcome: joins the welcome and tells you to send transition ready.

What stays app-specific:

- Choosing transport for outgoing packets.
- Deciding whether this client is the committer.
- Deciding how your app acknowledges transitions or recovers from invalid state.

## Encrypting and decrypting media in Go

Once the session is ready, use `Encrypt(...)` and `Decrypt(...)` for encoded WebRTC frames.

```go
if !session.Ready() {
	return
}

encryptedOpus, err := session.EncryptOpus(opusFrame)
if err != nil {
	log.Fatal(err)
}

decryptedOpus, err := session.Decrypt("1002", dave.MediaTypeAudio, encryptedOpus)
if err != nil {
	log.Fatal(err)
}

_ = decryptedOpus
```

For video or non-Opus audio, use the generic form:

```go
encrypted, err := session.Encrypt(dave.MediaTypeVideo, dave.CodecVP8, encodedFrame)
```

There are also stats helpers if you want telemetry:

```go
encStats := session.GetEncryptionStats(dave.MediaTypeAudio)
decStats, err := session.GetDecryptionStats("1002", dave.MediaTypeAudio)
```

## Verification and privacy code

After the group is established, you can show users a short verification code or compare raw fingerprints.

```go
code, err := session.GetVerificationCode("1002")
if err != nil {
	log.Fatal(err)
}

fingerprint, err := session.GetPairwiseFingerprint(0, "1002")
if err != nil {
	log.Fatal(err)
}

log.Printf("verify with user 1002: %s", code)
log.Printf("pairwise fingerprint: %x", fingerprint)
log.Printf("voice privacy code: %s", session.VoicePrivacyCode())
```

## Browser and Electron via WASM

Build the WASM module:

```bash
GOOS=js GOARCH=wasm go build -o ./wasm/go-dave.wasm ./cmd/go-dave-wasm
```

Copy Go's `wasm_exec.js` next to the generated `.wasm`, then load the wrapper from [`wasm/index.mjs`](./wasm/index.mjs) or import the whole [`wasm`](./wasm) directory as a small ESM package.

```ts
import { loadGoDave } from '@flameinthedark/go-dave'

const GoDave = await loadGoDave({
  url: new URL('./go-dave.wasm', import.meta.url),
})

const session = GoDave.createSession(
  GoDave.DAVE_PROTOCOL_VERSION,
  '1001',
  '9001',
)
```

For the common case, usage can stay at the session level:

```ts
const session = GoDave.createSession(GoDave.DAVE_PROTOCOL_VERSION, userId, channelId)
session.setExternalSender(externalSenderBuffer)

const keyPackage = session.getSerializedKeyPackage()
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
  session.encryptOpus(packet)
  session.decrypt(remoteUserId, GoDave.MediaType.AUDIO, incomingPacket)
}
```

Use `handleGatewayBinaryPacket(...)`, `getKeyPackagePacket()`, and `encodeCommitWelcomePacket(...)` when you want the library to also handle the GoChat binary packet format directly.

Call `session.dispose()` when the page, worker, or Electron view is done with the session.

The WASM API uses browser-native `Uint8Array` and `ArrayBuffer` values.
If your Electron renderer loads assets from `file://`, you can also pass `fetch` in `loadGoDave(...)` to provide a local-file-aware loader.
The published npm package includes `go-dave.wasm` and `wasm_exec.js`, so app consumers do not need to build them locally.

For a React + TypeScript example that uses the same import path and typings, see [`wasm/README.md`](./wasm/README.md).

### WASM session flow

For a longer walkthrough, see [`wasm/README.md`](./wasm/README.md).

This is the same two-session flow as the native example, but through the WASM API.

```ts
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

console.log({ decrypted, verificationCode, aliceState: alice.getState() })
```

### Insertable Streams example

The session works well with encoded transforms in browser and Electron WebRTC.

```ts
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength)
}

export function attachDaveSenderTransform(
  sender: RTCRtpSender & { createEncodedStreams(): { readable: ReadableStream<any>, writable: WritableStream<any> } },
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

For Opus senders you can use the simpler helper:

```ts
const encrypted = session.encryptOpus(opusPacket)
```

## Notes on `recognizedUserIDs`

- Pass a real list when you know which participants are DAVE-capable.
- Pass `nil` in Go or `undefined` in JS if you want to skip recognized-user validation.
- Pass an empty list only if you intentionally want "no recognized users"; this is different from `nil`.

## Useful methods at a glance

- `NewDAVESession(...)`
- `GenerateP256Keypair()`
- `SetExternalSender(...)`
- `EncodeExternalSenderPackage(...)`
- `GetSerializedKeyPackage()`
- `GetKeyPackagePacket()`
- `CreateAddProposal(...)`
- `EncodeMLSMessageVector(...)`
- `ProcessProposals(...)`
- `ProcessCommit(...)`
- `ProcessWelcome(...)`
- `HandleGatewayBinaryPacket(...)`
- `Encrypt(...)`
- `EncryptOpus(...)`
- `Decrypt(...)`
- `GetVerificationCode(...)`
- `GetPairwiseFingerprint(...)`
- `ShouldBeCommitter(...)`

## WASM details

The browser/Electron wrapper and TypeScript typings live here:

- [`wasm/index.mjs`](./wasm/index.mjs)
- [`wasm/index.d.ts`](./wasm/index.d.ts)
- [`wasm/README.md`](./wasm/README.md)
