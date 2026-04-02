# Native Go Guide

## Session lifecycle

The native API revolves around `DAVESession`.
The common flow is:

1. Create a session with `NewDAVESession(...)`.
2. Set the external sender with `SetExternalSender(...)`.
3. Exchange key packages, proposals, commit, and welcome data.
4. Wait for `Ready()` to become `true`.
5. Use `Encrypt(...)` or `Decrypt(...)` for media frames.

## Minimal session flow

```go
session, err := dave.NewDAVESession(dave.DAVEProtocolVersion, userID, channelID, nil)
if err != nil {
	log.Fatal(err)
}

if err := session.SetExternalSender(externalSenderBuffer); err != nil {
	log.Fatal(err)
}

keyPackage, err := session.GetSerializedKeyPackage()
if err != nil {
	log.Fatal(err)
}

result, err := session.ProcessProposals(
	dave.ProposalsAppend,
	proposalsBuffer,
	recognizedUserIDs,
)
if err != nil {
	log.Fatal(err)
}

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

if session.Ready() {
	encrypted, err := session.EncryptOpus(packet)
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := session.Decrypt(remoteUserID, dave.MediaTypeAudio, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	_ = keyPackage
	_ = decrypted
}
```

## Binary packet helpers

Use these helpers when your app works directly with the binary gateway packet format:

- `EncodeExternalSenderPackage(...)`
- `HandleGatewayBinaryPacket(...)`
- `HandleGatewayBinaryMessage(...)`
- `GetKeyPackagePacket()`
- `CreateAddProposal(...)`
- `EncodeMLSMessageVector(...)`
- `EncodeCommitWelcomePacket(...)`
- `ShouldBeCommitter(...)`

For the packet format, opcode mapping, and `recognizedUserIDs` behavior, see [gateway-packets.md](./gateway-packets.md).
If you want a complete two-session flow using only public helpers, start with [examples/native/main.go](../examples/native/main.go).

## Media encryption and decryption

```go
encryptedOpus, err := session.EncryptOpus(opusFrame)
if err != nil {
	log.Fatal(err)
}

decryptedOpus, err := session.Decrypt(remoteUserID, dave.MediaTypeAudio, encryptedOpus)
if err != nil {
	log.Fatal(err)
}

encryptedVideo, err := session.Encrypt(dave.MediaTypeVideo, dave.CodecVP8, encodedFrame)
if err != nil {
	log.Fatal(err)
}

_ = decryptedOpus
_ = encryptedVideo
```

## Verification helpers

```go
code, err := session.GetVerificationCode(remoteUserID)
if err != nil {
	log.Fatal(err)
}

fingerprint, err := session.GetPairwiseFingerprint(0, remoteUserID)
if err != nil {
	log.Fatal(err)
}

fmt.Println(code, fingerprint)
```

## Related files

- [examples/native/main.go](../examples/native/main.go)
- [gateway.go](../gateway.go)
- [session.go](../session.go)
