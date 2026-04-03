package main

import (
	"context"
	"io"
	"log"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"

	daveserver "github.com/FlameInTheDark/go-dave/server"
)

type exampleBroadcaster struct{}

func (exampleBroadcaster) SendJSON(sessionID string, op int, payload any) error {
	log.Printf("send json to %s op=%d payload=%T", sessionID, op, payload)
	return nil
}

func (exampleBroadcaster) SendBinary(sessionID string, payload []byte) error {
	log.Printf("send binary to %s bytes=%d", sessionID, len(payload))
	return nil
}

type exampleReader struct {
	done bool
}

func (r *exampleReader) ReadRTP() (*rtp.Packet, interceptor.Attributes, error) {
	if r.done {
		return nil, interceptor.Attributes{}, io.EOF
	}
	r.done = true
	return &rtp.Packet{Payload: []byte{0x11, 0x22, 0x33}}, interceptor.Attributes{}, nil
}

type exampleWriter struct{}

func (exampleWriter) WriteRTP(packet *rtp.Packet) error {
	log.Printf("forwarded RTP payload bytes=%d", len(packet.Payload))
	return nil
}

type examplePeerState struct{}

func (examplePeerState) ConnectionState() webrtc.PeerConnectionState {
	return webrtc.PeerConnectionStateConnected
}

func main() {
	// Create one coordinator for your voice gateway.
	coordinator := daveserver.NewCoordinator(daveserver.Config{
		Enabled: true,
	}, exampleBroadcaster{})

	// Register connected sessions so the coordinator can drive the DAVE control plane.
	_ = coordinator.Connect(daveserver.Participant{
		SessionID:     "session-a",
		UserID:        1001,
		ChannelID:     5001,
		SignalVersion: daveserver.SignalProtocolVersion,
		DAVESupported: true,
	})
	_ = coordinator.Connect(daveserver.Participant{
		SessionID:     "session-b",
		UserID:        1002,
		ChannelID:     5001,
		SignalVersion: daveserver.SignalProtocolVersion,
		DAVESupported: true,
	})

	// Use one TrackForwarder per inbound Pion track.
	forwarder := daveserver.NewTrackForwarder(examplePeerState{}, &exampleReader{})
	_ = forwarder.AddDestination("receiver-a", exampleWriter{}, daveserver.DestinationOptions{
		SupportsDAVE: true,
	})
	_ = forwarder.AddDestination("receiver-b", exampleWriter{}, daveserver.DestinationOptions{
		SupportsDAVE:       false,
		TransitionInFlight: true,
	})
	_ = forwarder.Forward(context.Background())
}
