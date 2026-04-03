# Server And Pion Guide

Use [`github.com/FlameInTheDark/go-dave/server`](../server) when you are building a voice gateway or SFU in Go.

It gives you two main pieces:

- `Coordinator` for the full DAVE control plane
- `TrackForwarder` for simple Pion RTP forwarding with DAVE-aware receiver gating

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
