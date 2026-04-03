package server

import "bytes"

const (
	// MagicMarkerHigh is the high byte of the DAVE protocol-frame marker.
	MagicMarkerHigh = 0xFA
	// MagicMarkerLow is the low byte of the DAVE protocol-frame marker.
	MagicMarkerLow = 0xFA
	// MagicMarker is the 16-bit marker placed at the end of DAVE protocol
	// frames.
	MagicMarker = uint16(0xFAFA)
	// MinSupplementalDataBytes is the smallest valid DAVE supplemental trailer.
	MinSupplementalDataBytes = 11
)

var silencePacket = []byte{0xF8, 0xFF, 0xFE}

// HasMagicMarker reports whether payload ends with the DAVE frame marker.
func HasMagicMarker(payload []byte) bool {
	if len(payload) < 3 {
		return false
	}
	return payload[len(payload)-2] == MagicMarkerHigh && payload[len(payload)-1] == MagicMarkerLow
}

// LooksLikeProtocolFrame reports whether payload looks like a DAVE-encrypted
// protocol frame.
func LooksLikeProtocolFrame(payload []byte) bool {
	if len(payload) < MinSupplementalDataBytes {
		return false
	}
	if !HasMagicMarker(payload) {
		return false
	}
	supplementalSize := int(payload[len(payload)-3])
	if supplementalSize < MinSupplementalDataBytes {
		return false
	}
	if supplementalSize > len(payload) {
		return false
	}
	return true
}

// ShouldDropForReceiver reports whether a payload should be dropped for a
// receiver that cannot handle DAVE protocol frames during a transition.
func ShouldDropForReceiver(payload []byte, receiverSupportsDAVE bool, transitionInFlight bool) bool {
	return transitionInFlight && !receiverSupportsDAVE && LooksLikeProtocolFrame(payload)
}

// IsSilencePacket reports whether payload is the Opus comfort-noise silence
// packet.
func IsSilencePacket(payload []byte) bool {
	return bytes.Equal(payload, silencePacket)
}
