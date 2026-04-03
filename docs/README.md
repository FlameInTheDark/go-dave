# Documentation

Use the top-level [`README.md`](../README.md) for the shortest path.
The guides below cover the longer flows and app integration details.

- [Overview and concepts](./overview.md)
- [Server and Pion guide](./server.md)
- [Native Go guide](./native-go.md)
- [Browser and Electron guide](./wasm.md)
- [Gateway packet guide](./gateway-packets.md)
- [Insertable Streams and runtime notes](./insertable-streams.md)
- [Runnable native example](../examples/native/main.go)
- [WASM TypeScript definitions](../wasm/index.d.ts)

## What to open

- Open [overview.md](./overview.md) if you want the high-level mental model and which entry points to use.
- Open [server.md](./server.md) if you want the server-side coordinator, Pion forwarding flow, or GoChat-style gateway helpers.
- Open [native-go.md](./native-go.md) if you want the Go session lifecycle, packet helpers, media encryption, or verification helpers.
- Open [wasm.md](./wasm.md) if you want browser/Electron usage, React + TypeScript notes, insertable streams, or build-from-source instructions.
- Open [gateway-packets.md](./gateway-packets.md) if your app deals directly with opcode `25` through `30`.
- Open [insertable-streams.md](./insertable-streams.md) if you want transform examples, passthrough behavior, or dropped-frame handling.
