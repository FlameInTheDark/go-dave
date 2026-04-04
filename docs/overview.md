# Overview and Concepts

## What `go-dave` is

`go-dave` is a DAVE implementation built around one core idea:
one `DAVESession` represents one user in one voice channel.

For the protocol itself, see [daveprotocol.com](https://daveprotocol.com/).

That session owns:

- MLS group state
- membership changes
- frame encryption state
- frame decryption state
- verification helpers

The project exposes the same core behavior in three environments:

- native Go for servers, tools, and backend integrations
- server-side helpers for voice gateways and Pion SFUs through `github.com/FlameInTheDark/go-dave/server`
- WASM for browser and Electron apps through `@flameinthedark/go-dave`

## Transport security layers

DAVE is not a replacement for WebRTC transport security.

In a typical WebRTC stack, the layers look like this:

`ICE -> DTLS -> SRTP -> DAVE -> encoded media`

- `ICE` connects the peers
- `DTLS` authenticates the transport and derives SRTP keys
- `SRTP` protects RTP packets on each hop
- `DAVE` protects the media end to end across the session

That means DAVE and DTLS work together:

- browsers and Electron apps still use the normal `RTCPeerConnection` transport
- Pion servers and native Go peers should still use normal Pion ICE, DTLS, and SRTP
- `go-dave` should be attached above that layer, where you already handle encoded media and DAVE control messages

If you are using Pion, see [server.md](./server.md) for the practical DTLS and transport setup notes.

## Which API should you use?

Use the direct session API if your app already knows how to move gateway payloads around:

- `SetExternalSender(...)`
- `GetSerializedKeyPackage()`
- `ProcessProposals(...)`
- `ProcessCommit(...)`
- `ProcessWelcome(...)`
- `Encrypt(...)`
- `Decrypt(...)`

Use the packet helpers if your app works directly with the binary gateway packets:

- `HandleGatewayBinaryPacket(...)`
- `HandleGatewayBinaryMessage(...)`
- `GetKeyPackagePacket()`
- `EncodeCommitWelcomePacket(...)`
- `EncodeExternalSenderPackage(...)`

Use the WASM package if your app runs in:

- the browser
- Electron
- React web clients using insertable streams

Use the server package if your app is:

- a Go voice gateway
- a Pion-based SFU
- responsible for DAVE membership, transitions, and RTP forwarding

## Typical lifecycle

1. Create a session.
2. Set the external sender package.
3. Exchange key packages and proposals.
4. Apply commit and welcome data.
5. Wait for the session to become ready.
6. Encrypt outgoing media and decrypt incoming media.

## Guides by job

- [Native Go guide](./native-go.md)
- [Server and Pion guide](./server.md)
- [Browser and Electron guide](./wasm.md)
- [Gateway packet guide](./gateway-packets.md)
- [Insertable Streams and runtime notes](./insertable-streams.md)

## Practical starting points

- [examples/native/main.go](../examples/native/main.go) for a runnable Go flow
- [examples/server/main.go](../examples/server/main.go) for a runnable server-side flow
- [wasm/index.d.ts](../wasm/index.d.ts) for the published TypeScript surface
- [docs/insertable-streams.md](./insertable-streams.md) for browser and Electron media handling
