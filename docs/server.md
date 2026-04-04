# Server And Pion Guide

Use [`github.com/FlameInTheDark/go-dave/server`](../server) when you are building a voice gateway or SFU in Go.

It gives you two main pieces:

- `Coordinator` for the full DAVE control plane
- `TrackForwarder` for simple Pion RTP forwarding with DAVE-aware receiver gating

## Transport Security With Pion

Use Pion's normal transport stack for the hop-by-hop WebRTC security layer.

`go-dave` does not replace:

- ICE
- DTLS
- SRTP

Instead, it sits above that layer and encrypts the encoded media end to end.

In practice, the flow is:

`encoded frame -> DAVE -> RTP packetization -> SRTP via DTLS keys -> network`

On receive, the order is reversed:

`network -> SRTP -> encoded frame -> DAVE -> decoder`

For Pion developers, that means:

- create your `PeerConnection` the normal way
- let Pion handle ICE, DTLS, and SRTP
- plug `go-dave/server` into your gateway signaling and RTP forwarding code

If you want explicit certificate and DTLS configuration, use Pion's built-in APIs such as `GenerateCertificate(...)`, `Configuration.Certificates`, and `SettingEngine.SetAnsweringDTLSRole(...)`.

Typical shape:

```go
import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"

	daveserver "github.com/FlameInTheDark/go-dave/server"
	"github.com/pion/webrtc/v4"
)

privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
if err != nil {
	return err
}

certificate, err := webrtc.GenerateCertificate(privateKey)
if err != nil {
	return err
}

settingEngine := webrtc.SettingEngine{}
if err := settingEngine.SetAnsweringDTLSRole(webrtc.DTLSRoleAuto); err != nil {
	return err
}

api := webrtc.NewAPI(
	webrtc.WithSettingEngine(settingEngine),
)

peerConnection, err := api.NewPeerConnection(webrtc.Configuration{
	Certificates: []webrtc.Certificate{*certificate},
})
if err != nil {
	return err
}

peerConnection.OnTrack(func(remoteTrack *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
	forwarder := daveserver.NewTrackForwarder(peerConnection, remoteTrack)

	_ = receiver
	_ = forwarder
})
```

Notes:

- if you do not provide `Configuration.Certificates`, Pion generates default certificates for the peer connection
- provide your own certificate when you want explicit certificate lifecycle or stable fingerprints
- use `certificate.GetFingerprints()` when you want to expose or log the local DTLS fingerprint
- use Pion transport inspection APIs when you need remote certificate or DTLS state details for diagnostics
- browser clients already do DTLS automatically, so this section mainly matters for Pion-based peers and SFUs

## What The Coordinator Does

`Coordinator` handles the server-side DAVE transition flow:

- track channel membership
- collect key packages
- broadcast proposals
- relay commit and welcome payloads
- drive upgrade and downgrade transitions

Typical shape:

```go
import daveserver "github.com/FlameInTheDark/go-dave/server"

type gatewayBroadcaster struct{}

func (gatewayBroadcaster) SendJSON(sessionID string, op int, payload any) error {
	return nil
}

func (gatewayBroadcaster) SendBinary(sessionID string, payload []byte) error {
	return nil
}

coordinator := daveserver.NewCoordinator(daveserver.Config{
	Enabled: true,
}, gatewayBroadcaster{})

_ = coordinator.Connect(daveserver.Participant{
	SessionID:     "session-a",
	UserID:        1001,
	ChannelID:     5001,
	SignalVersion: daveserver.SignalProtocolVersion,
	DAVESupported: true,
})
```

### The Main Coordinator Methods

- `Connect(...)`
- `Disconnect(...)`
- `HandleKeyPackage(...)`
- `HandleCommitWelcome(...)`
- `HandleTransitionReady(...)`
- `HandleInvalidCommitWelcome(...)`
- `Snapshot(...)`

## What The Track Forwarder Does

`TrackForwarder` is the simple Pion-facing API.

Use one forwarder per inbound `TrackRemote`, then add one destination per receiver.

Each destination can declare:

- whether that receiver supports DAVE
- whether a transition is in flight
- an optional custom packet filter

Typical shape:

```go
forwarder := daveserver.NewTrackForwarder(peerConnection, remoteTrack)

_ = forwarder.AddDestination(receiverID, localTrack, daveserver.DestinationOptions{
	SupportsDAVE: true,
})

_ = forwarder.Forward(ctx)
```

If a receiver does not support DAVE and a transition is in flight, the forwarder automatically drops DAVE protocol frames for that destination.

## Binary Packet Helpers

The server package also includes binary DAVE packet codecs:

- `EncodeExternalSenderPackage(...)`
- `EncodeKeyPackage(...)`
- `EncodeProposals(...)`
- `EncodeCommitWelcome(...)`
- `EncodeAnnounceCommitTransition(...)`
- `EncodeWelcome(...)`
- `DecodeBinaryMessage(...)`

Use those helpers if your gateway speaks opcode `25` through `30` directly.

## Practical Starting Point

Open [examples/server/main.go](../examples/server/main.go) for a small end-to-end usage sketch.
