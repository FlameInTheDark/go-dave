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

The project exposes the same core behavior in two environments:

- native Go for servers, tools, and backend integrations
- WASM for browser and Electron apps through `@flameinthedark/go-dave`

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

## Typical lifecycle

1. Create a session.
2. Set the external sender package.
3. Exchange key packages and proposals.
4. Apply commit and welcome data.
5. Wait for the session to become ready.
6. Encrypt outgoing media and decrypt incoming media.

## Guides by job

- [Native Go guide](./native-go.md)
- [Browser and Electron guide](./wasm.md)
- [Gateway packet guide](./gateway-packets.md)
- [Insertable Streams and runtime notes](./insertable-streams.md)

## Practical starting points

- [examples/native/main.go](../examples/native/main.go) for a runnable Go flow
- [wasm/index.d.ts](../wasm/index.d.ts) for the published TypeScript surface
- [docs/insertable-streams.md](./insertable-streams.md) for browser and Electron media handling
