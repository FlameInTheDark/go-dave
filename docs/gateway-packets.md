# Gateway Packet Guide

## When to use this layer

Use the gateway helpers when your app receives and sends the raw binary DAVE packets itself.
If you already separate payloads at a higher layer, the direct session API may be simpler.

## Packet shape

```text
[sequence:u16][opcode:u8][payload...]
```

`go-dave` includes helpers for opcodes `25` through `30`.

## Opcode mapping

- `25` external sender:
  `EncodeExternalSenderPackage(...)` builds the payload, and `HandleGatewayBinaryPacket(...)` consumes it.
- `26` key package:
  `GetKeyPackagePacket()` builds the outgoing packet payload.
- `27` proposals:
  `HandleGatewayBinaryPacket(...)` parses and applies them.
- `28` commit + welcome:
  `EncodeCommitWelcomePacket(...)` builds the outgoing payload.
- `29` announce commit:
  `HandleGatewayBinaryPacket(...)` applies the commit side of a transition.
- `30` welcome:
  `HandleGatewayBinaryPacket(...)` applies the welcome side of a transition.

## Common flow

1. Receive opcode `25` and call `HandleGatewayBinaryPacket(...)`.
2. Send the result from `GetKeyPackagePacket()` or the `KeyPackagePacket` returned by the helper.
3. Decide who should commit.
4. Process proposals and produce commit/welcome data.
5. Send opcode `28`, `29`, or `30` payloads as needed.
6. Mark the transition ready when `SendTransitionReady` is set.

## Recognized user IDs

`recognizedUserIDs` is there to protect proposal handling.

Pass the current roster when:

- processing proposal packets from the gateway
- using `ProcessProposals(...)`
- using `HandleGatewayBinaryPacket(...)`
- using `HandleGatewayBinaryMessage(...)`

That lets the library reject unexpected members during append flows.

## Choosing the committer

Use `ShouldBeCommitter(selfUserID, recognizedUserIDs)` when your app wants a deterministic choice for who produces the commit.

## Useful files

- [gateway.go](../gateway.go)
- [examples/native/main.go](../examples/native/main.go)
