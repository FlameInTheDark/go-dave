package server

import (
	"context"
	"io"
	"testing"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

type fakeRTPReader struct {
	packets []*rtp.Packet
	index   int
}

func (f *fakeRTPReader) ReadRTP() (*rtp.Packet, interceptor.Attributes, error) {
	if f.index >= len(f.packets) {
		return nil, interceptor.Attributes{}, io.EOF
	}
	packet := f.packets[f.index]
	f.index++
	return packet, interceptor.Attributes{}, nil
}

type recordingRTPWriter struct {
	payloads [][]byte
}

func (w *recordingRTPWriter) WriteRTP(packet *rtp.Packet) error {
	w.payloads = append(w.payloads, append([]byte(nil), packet.Payload...))
	return nil
}

type fakePeerConnectionState struct {
	state webrtc.PeerConnectionState
}

func (f fakePeerConnectionState) ConnectionState() webrtc.PeerConnectionState {
	return f.state
}

func TestTrackForwarderDropsProtocolFramesForUnsupportedDestination(t *testing.T) {
	protocolPayload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0xFA, 0xFA}
	plainPayload := []byte{0x11, 0x22, 0x33}

	reader := &fakeRTPReader{
		packets: []*rtp.Packet{
			{Payload: protocolPayload},
			{Payload: plainPayload},
		},
	}
	plainWriter := &recordingRTPWriter{}
	daveWriter := &recordingRTPWriter{}

	forwarder := NewTrackForwarder(fakePeerConnectionState{state: webrtc.PeerConnectionStateConnected}, reader)
	if err := forwarder.AddDestination("plain", plainWriter, DestinationOptions{
		SupportsDAVE:       false,
		TransitionInFlight: true,
	}); err != nil {
		t.Fatalf("AddDestination(plain): %v", err)
	}
	if err := forwarder.AddDestination("dave", daveWriter, DestinationOptions{
		SupportsDAVE:       true,
		TransitionInFlight: true,
	}); err != nil {
		t.Fatalf("AddDestination(dave): %v", err)
	}

	if err := forwarder.Forward(context.Background()); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	if got := len(plainWriter.payloads); got != 1 {
		t.Fatalf("plain destination payload count = %d, want 1", got)
	}
	if got := len(daveWriter.payloads); got != 2 {
		t.Fatalf("dave destination payload count = %d, want 2", got)
	}
	if string(plainWriter.payloads[0]) != string(plainPayload) {
		t.Fatalf("plain destination payload = %x, want %x", plainWriter.payloads[0], plainPayload)
	}
}

func TestForwardTrackSingleDestination(t *testing.T) {
	reader := &fakeRTPReader{
		packets: []*rtp.Packet{
			{Payload: []byte{0x01, 0x02}},
		},
	}
	writer := &recordingRTPWriter{}

	if err := ForwardTrack(context.Background(), fakePeerConnectionState{state: webrtc.PeerConnectionStateConnected}, reader, writer, DestinationOptions{}); err != nil {
		t.Fatalf("ForwardTrack: %v", err)
	}
	if got := len(writer.payloads); got != 1 {
		t.Fatalf("writer payload count = %d, want 1", got)
	}
}

func TestLooksLikeProtocolFrame(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x0B, 0xFA, 0xFA}
	if !LooksLikeProtocolFrame(payload) {
		t.Fatal("expected payload to look like a protocol frame")
	}
	if !ShouldDropForReceiver(payload, false, true) {
		t.Fatal("expected payload to be dropped for a non-DAVE receiver during transition")
	}
}
