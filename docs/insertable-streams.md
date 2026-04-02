# Insertable Streams and Runtime Notes

## Where this applies

This guide is for browser and Electron apps that encrypt and decrypt encoded WebRTC frames directly inside insertable streams.

## Important runtime behavior

The WASM API is designed to stay alive during noisy real-world media flows.

- `encrypt(...)`, `encryptOpus(...)`, and `decrypt(...)` return `Uint8Array | null`
- recoverable frame-path failures are logged with `console.warn(...)`
- dropped frames return `null`
- unexpected/internal failures still throw

That means your transform code should treat `null` as "skip this frame".

## Sender transform

```ts
function attachDaveSenderTransform(sender, session, mediaType, codec) {
  const { readable, writable } = sender.createEncodedStreams()

  readable
    .pipeThrough(new TransformStream({
      transform(frame, controller) {
        if (!session.getState().ready) {
          controller.enqueue(frame)
          return
        }

        const encrypted = session.encrypt(mediaType, codec, new Uint8Array(frame.data))
        if (!encrypted) {
          return
        }

        frame.data = encrypted.buffer.slice(
          encrypted.byteOffset,
          encrypted.byteOffset + encrypted.byteLength,
        )
        controller.enqueue(frame)
      },
    }))
    .pipeTo(writable)
    .catch(() => {})
}
```

## Receiver transform

```ts
function attachDaveReceiverTransform(receiver, session, mediaType, remoteUserId) {
  const { readable, writable } = receiver.createEncodedStreams()

  readable
    .pipeThrough(new TransformStream({
      transform(frame, controller) {
        const decrypted = session.decrypt(remoteUserId, mediaType, new Uint8Array(frame.data))
        if (!decrypted) {
          if (session.canPassthrough(remoteUserId)) {
            controller.enqueue(frame)
          }
          return
        }

        frame.data = decrypted.buffer.slice(
          decrypted.byteOffset,
          decrypted.byteOffset + decrypted.byteLength,
        )
        controller.enqueue(frame)
      },
    }))
    .pipeTo(writable)
    .catch(() => {})
}
```

## Passthrough mode

`setPassthroughMode(...)` is useful during upgrades or transition windows where plaintext frames may still appear briefly.

- `setPassthroughMode(true)` keeps passthrough enabled
- `setPassthroughMode(false, seconds)` disables it after the transition window
- `setPassthroughMode(false, 0)` disables immediately

## React and Electron notes

- `loadGoDave(...)` is single-flight, so repeated calls reuse the same module
- call `session.dispose()` on unmount or teardown
- if Electron loads from `file://`, pass a custom `fetch` to `loadGoDave(...)`

## Related guides

- [Browser and Electron guide](./wasm.md)
