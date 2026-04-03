package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/pion/interceptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v4"
)

// RTPReader reads RTP packets. *webrtc.TrackRemote satisfies this interface.
type RTPReader interface {
	ReadRTP() (*rtp.Packet, interceptor.Attributes, error)
}

// RTPWriter writes RTP packets. *webrtc.TrackLocalStaticRTP satisfies this
// interface.
type RTPWriter interface {
	WriteRTP(*rtp.Packet) error
}

// PeerConnectionStateProvider reports the state of a Pion peer connection.
// *webrtc.PeerConnection satisfies this interface.
type PeerConnectionStateProvider interface {
	ConnectionState() webrtc.PeerConnectionState
}

// RTPPacketFilter decides whether a packet should be dropped before it is
// forwarded.
type RTPPacketFilter func(*rtp.Packet) (drop bool, err error)

// DestinationOptions control how packets are forwarded to one receiver.
type DestinationOptions struct {
	SupportsDAVE       bool
	TransitionInFlight bool
	Filter             RTPPacketFilter
}

type forwardDestination struct {
	id     string
	writer RTPWriter
	opts   DestinationOptions
}

// TrackForwarder forwards one inbound RTP stream to one or more Pion writers.
//
// The forwarder automatically applies DAVE protocol-frame dropping for
// receivers that do not support DAVE while a transition is in flight.
type TrackForwarder struct {
	pc PeerConnectionStateProvider

	mu           sync.RWMutex
	remote       RTPReader
	destinations map[string]forwardDestination
	onWriteError func(destinationID string, err error)
}

// NewTrackForwarder creates a forwarder for one inbound Pion track.
func NewTrackForwarder(pc PeerConnectionStateProvider, remote RTPReader) *TrackForwarder {
	return &TrackForwarder{
		pc:           pc,
		remote:       remote,
		destinations: make(map[string]forwardDestination),
	}
}

// SetWriteErrorHandler configures a callback for per-destination write errors.
//
// When the handler is nil, the first write error stops forwarding.
func (f *TrackForwarder) SetWriteErrorHandler(handler func(destinationID string, err error)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.onWriteError = handler
}

// AddDestination adds or replaces one RTP destination.
func (f *TrackForwarder) AddDestination(id string, writer RTPWriter, opts DestinationOptions) error {
	if id == "" {
		return fmt.Errorf("destination id is required")
	}
	if writer == nil {
		return fmt.Errorf("destination writer is required")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	f.destinations[id] = forwardDestination{id: id, writer: writer, opts: opts}
	return nil
}

// UpdateDestination updates the forwarding options for one destination.
func (f *TrackForwarder) UpdateDestination(id string, opts DestinationOptions) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	dest, ok := f.destinations[id]
	if !ok {
		return false
	}
	dest.opts = opts
	f.destinations[id] = dest
	return true
}

// RemoveDestination removes one RTP destination.
func (f *TrackForwarder) RemoveDestination(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.destinations, id)
}

// Forward starts the RTP read loop and runs until the context is cancelled,
// the peer connection closes, or the inbound reader ends.
//
// Filters and writers must treat the packet as read-only.
func (f *TrackForwarder) Forward(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	f.mu.RLock()
	remote := f.remote
	f.mu.RUnlock()
	if remote == nil {
		return fmt.Errorf("remote RTP reader is not configured")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if f.isPeerClosed() {
			return nil
		}

		packet, _, err := remote.ReadRTP()
		if err != nil {
			switch {
			case errors.Is(err, io.EOF):
				return nil
			case ctx.Err() != nil:
				return ctx.Err()
			case f.isPeerClosed():
				return nil
			default:
				return fmt.Errorf("read RTP packet: %w", err)
			}
		}
		if packet == nil {
			return fmt.Errorf("read RTP packet: packet is nil")
		}

		destinations, onWriteError := f.snapshotDestinations()
		for _, dest := range destinations {
			if ShouldDropForReceiver(packet.Payload, dest.opts.SupportsDAVE, dest.opts.TransitionInFlight) {
				continue
			}
			if dest.opts.Filter != nil {
				drop, err := dest.opts.Filter(packet)
				if err != nil {
					return fmt.Errorf("destination %s filter: %w", dest.id, err)
				}
				if drop {
					continue
				}
			}
			if err := dest.writer.WriteRTP(packet); err != nil {
				if onWriteError != nil {
					onWriteError(dest.id, err)
					continue
				}
				return fmt.Errorf("destination %s write RTP: %w", dest.id, err)
			}
		}
	}
}

// ForwardTrack is a convenience helper for the common one-reader, one-writer
// case.
func ForwardTrack(ctx context.Context, pc PeerConnectionStateProvider, remote RTPReader, local RTPWriter, opts DestinationOptions) error {
	forwarder := NewTrackForwarder(pc, remote)
	if err := forwarder.AddDestination("default", local, opts); err != nil {
		return err
	}
	return forwarder.Forward(ctx)
}

func (f *TrackForwarder) isPeerClosed() bool {
	if f.pc == nil {
		return false
	}
	switch f.pc.ConnectionState() {
	case webrtc.PeerConnectionStateClosed, webrtc.PeerConnectionStateFailed:
		return true
	default:
		return false
	}
}

func (f *TrackForwarder) snapshotDestinations() ([]forwardDestination, func(destinationID string, err error)) {
	f.mu.RLock()
	defer f.mu.RUnlock()

	out := make([]forwardDestination, 0, len(f.destinations))
	for _, dest := range f.destinations {
		out = append(out, dest)
	}
	return out, f.onWriteError
}
