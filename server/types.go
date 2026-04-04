package server

import "time"

// SignalProtocolVersion is the voice gateway protocol version
// that supports DAVE transitions.
const SignalProtocolVersion = 2

// MaxProtocolVersion is the highest DAVE media protocol version supported by
// this package.
const MaxProtocolVersion = 1

// Voice gateway JSON opcodes used by the DAVE server-side flow.
const (
	OpClientsConnect           = 11
	OpClientDisconnect         = 13
	OpDAVEPrepareTransition    = 21
	OpDAVEExecuteTransition    = 22
	OpDAVETransitionReady      = 23
	OpDAVEPrepareEpoch         = 24
	OpDAVEInvalidCommitWelcome = 31
)

// Config controls server-side DAVE coordination.
type Config struct {
	Enabled             bool
	RequiredByDefault   bool
	TransitionTimeout   time.Duration
	OldRatchetRetention time.Duration
	AllowAV1            bool
}

// IdentityKey describes the identity key metadata announced by a client.
type IdentityKey struct {
	Type      string
	PublicKey []byte
	Version   uint32
}

// Participant describes one voice session connected to the server.
type Participant struct {
	SessionID                 string
	UserID                    int64
	ChannelID                 int64
	SignalVersion             int
	DAVESupported             bool
	SupportsEncodedTransforms bool
	MaxDAVEProtocolVersion    int
	IdentityKey               *IdentityKey
}

// Snapshot is a stable view of a channel's current DAVE state.
type Snapshot struct {
	ProtocolVersion int
	Epoch           uint64
	Transitioning   bool
}

// ClientsConnect announces the current channel roster to a joining client.
type ClientsConnect struct {
	UserIDs []string `json:"user_ids"`
}

// ClientDisconnect announces that a user left the voice channel.
type ClientDisconnect struct {
	UserID string `json:"user_id"`
}

// PrepareTransition tells clients to prepare for a protocol-mode transition.
type PrepareTransition struct {
	ProtocolVersion int    `json:"protocol_version"`
	TransitionID    uint16 `json:"transition_id"`
}

// ExecuteTransition tells clients to activate a prepared transition.
type ExecuteTransition struct {
	TransitionID uint16 `json:"transition_id"`
}

// TransitionReady acknowledges that a client prepared its media path.
type TransitionReady struct {
	TransitionID uint16 `json:"transition_id"`
}

// PrepareEpoch starts an upgrade or group-recreation flow for a DAVE epoch.
type PrepareEpoch struct {
	ProtocolVersion int    `json:"protocol_version"`
	Epoch           uint64 `json:"epoch"`
}

// InvalidCommitWelcome asks the server to recreate group state after a client
// failed to import a commit or welcome.
type InvalidCommitWelcome struct {
	TransitionID uint16 `json:"transition_id"`
}

// Broadcaster sends server-generated DAVE control-plane messages to clients.
type Broadcaster interface {
	SendJSON(sessionID string, op int, payload any) error
	SendBinary(sessionID string, payload []byte) error
}

// Timer matches the stop behavior needed by the coordinator.
type Timer interface {
	Stop() bool
}

// Clock abstracts timer creation so tests can control transition timing.
type Clock interface {
	AfterFunc(time.Duration, func()) Timer
}

type realClock struct{}

func (realClock) AfterFunc(d time.Duration, fn func()) Timer {
	return time.AfterFunc(d, fn)
}
