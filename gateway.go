package dave

import (
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/thomas-vilte/mls-go/credentials"
)

const maxMLSVarintValue = 1<<30 - 1

// GatewayBinaryOpcode is the GoChat binary DAVE opcode.
type GatewayBinaryOpcode uint8

const (
	GatewayBinaryOpcodeExternalSender GatewayBinaryOpcode = 25
	GatewayBinaryOpcodeKeyPackage     GatewayBinaryOpcode = 26
	GatewayBinaryOpcodeProposals      GatewayBinaryOpcode = 27
	GatewayBinaryOpcodeCommitWelcome  GatewayBinaryOpcode = 28
	GatewayBinaryOpcodeAnnounceCommit GatewayBinaryOpcode = 29
	GatewayBinaryOpcodeWelcome        GatewayBinaryOpcode = 30
)

// GatewayBinaryPacket is a server-to-client DAVE packet in GoChat wire format:
// [seq:u16][opcode:u8][payload...].
type GatewayBinaryPacket struct {
	Sequence uint16
	Opcode   GatewayBinaryOpcode
	Payload  []byte
}

// GatewayBinaryResult contains the useful output produced while handling an
// inbound binary DAVE message.
type GatewayBinaryResult struct {
	Sequence uint16
	Opcode   GatewayBinaryOpcode

	KeyPackage       []byte
	KeyPackagePacket []byte

	Commit              []byte
	Welcome             []byte
	CommitWelcomePacket []byte

	TransitionID        *uint16
	SendTransitionReady bool
}

// ParseGatewayBinaryPacket parses a server-to-client GoChat DAVE packet.
func ParseGatewayBinaryPacket(data []byte) (*GatewayBinaryPacket, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("gateway binary packet too short: got %d bytes", len(data))
	}

	return &GatewayBinaryPacket{
		Sequence: binary.BigEndian.Uint16(data[:2]),
		Opcode:   GatewayBinaryOpcode(data[2]),
		Payload:  append([]byte(nil), data[3:]...),
	}, nil
}

// EncodeKeyPackagePacket wraps an MLS key package in the client-to-server
// GoChat wire format: [opcode:u8][opaqueVec(keyPackage)].
func EncodeKeyPackagePacket(keyPackage []byte) ([]byte, error) {
	if len(keyPackage) == 0 {
		return nil, fmt.Errorf("key package cannot be empty")
	}

	opaque, err := encodeOpaqueVector(keyPackage)
	if err != nil {
		return nil, err
	}

	packet := make([]byte, 1+len(opaque))
	packet[0] = byte(GatewayBinaryOpcodeKeyPackage)
	copy(packet[1:], opaque)
	return packet, nil
}

// EncodeCommitWelcomePacket wraps a commit and optional welcome in the
// client-to-server GoChat wire format:
// [opcode:u8][opaqueVec(commit)][opaqueVec(welcome)?].
func EncodeCommitWelcomePacket(commit []byte, welcome []byte) ([]byte, error) {
	if len(commit) == 0 {
		return nil, fmt.Errorf("commit cannot be empty")
	}

	commitOpaque, err := encodeOpaqueVector(commit)
	if err != nil {
		return nil, fmt.Errorf("encode commit: %w", err)
	}

	var welcomeOpaque []byte
	if len(welcome) > 0 {
		welcomeOpaque, err = encodeOpaqueVector(welcome)
		if err != nil {
			return nil, fmt.Errorf("encode welcome: %w", err)
		}
	}

	packet := make([]byte, 1+len(commitOpaque)+len(welcomeOpaque))
	packet[0] = byte(GatewayBinaryOpcodeCommitWelcome)
	copy(packet[1:], commitOpaque)
	copy(packet[1+len(commitOpaque):], welcomeOpaque)
	return packet, nil
}

// EncodeExternalSenderPackage builds an external sender package encoded as
// [opaqueVec(signatureKey)][Credential].
func EncodeExternalSenderPackage(signatureKey []byte, userID string) ([]byte, error) {
	if len(signatureKey) == 0 {
		return nil, fmt.Errorf("signature key cannot be empty")
	}

	userIDNum, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse user id %q: %w", userID, err)
	}

	signatureKeyOpaque, err := encodeOpaqueVector(signatureKey)
	if err != nil {
		return nil, fmt.Errorf("encode signature key: %w", err)
	}

	credential := credentials.NewBasicCredentialFromUint64(userIDNum)
	packet := make([]byte, 0, len(signatureKeyOpaque)+len(credential.Marshal()))
	packet = append(packet, signatureKeyOpaque...)
	packet = append(packet, credential.Marshal()...)
	return packet, nil
}

// EncodeMLSMessageVector wraps one or more concatenated MLS messages in the
// opaque vector format expected by ProcessProposals.
func EncodeMLSMessageVector(messages ...[]byte) ([]byte, error) {
	if len(messages) == 0 {
		return nil, fmt.Errorf("at least one MLS message is required")
	}

	totalSize := 0
	for i, message := range messages {
		if len(message) == 0 {
			return nil, fmt.Errorf("MLS message %d cannot be empty", i)
		}
		totalSize += len(message)
	}

	vector := make([]byte, 0, totalSize)
	for _, message := range messages {
		vector = append(vector, message...)
	}
	return encodeOpaqueVector(vector)
}

// ShouldBeCommitter returns whether selfUserID is the lowest numeric user id
// among the recognized DAVE-capable participants.
func ShouldBeCommitter(selfUserID string, recognizedUserIDs []string) bool {
	selfID, err := strconv.ParseUint(selfUserID, 10, 64)
	if err != nil {
		return false
	}

	for _, candidate := range recognizedUserIDs {
		candidateID, err := strconv.ParseUint(candidate, 10, 64)
		if err != nil {
			continue
		}
		if candidateID < selfID {
			return false
		}
	}

	return true
}

// GetKeyPackagePacket creates a new MLS key package and returns it already
// wrapped as a client-to-server GoChat DAVE packet.
func (s *DAVESession) GetKeyPackagePacket() ([]byte, error) {
	keyPackage, err := s.GetSerializedKeyPackage()
	if err != nil {
		return nil, err
	}
	return EncodeKeyPackagePacket(keyPackage)
}

// HandleGatewayBinaryPacket parses and handles an inbound server-to-client
// GoChat DAVE packet.
func (s *DAVESession) HandleGatewayBinaryPacket(packet []byte, recognizedUserIDs []string) (*GatewayBinaryResult, error) {
	parsed, err := ParseGatewayBinaryPacket(packet)
	if err != nil {
		return nil, err
	}
	return s.HandleGatewayBinaryMessage(parsed.Sequence, parsed.Opcode, parsed.Payload, recognizedUserIDs)
}

// HandleGatewayBinaryMessage handles a parsed inbound server-to-client GoChat
// DAVE message and returns any follow-up data the client may want to send or
// act on.
func (s *DAVESession) HandleGatewayBinaryMessage(sequence uint16, opcode GatewayBinaryOpcode, payload []byte, recognizedUserIDs []string) (*GatewayBinaryResult, error) {
	if s == nil {
		return nil, fmt.Errorf("session is nil")
	}

	result := &GatewayBinaryResult{
		Sequence: sequence,
		Opcode:   opcode,
	}

	switch opcode {
	case GatewayBinaryOpcodeExternalSender:
		if err := s.SetExternalSender(payload); err != nil {
			return nil, err
		}

		keyPackage, err := s.GetSerializedKeyPackage()
		if err != nil {
			return nil, err
		}
		keyPackagePacket, err := EncodeKeyPackagePacket(keyPackage)
		if err != nil {
			return nil, err
		}

		result.KeyPackage = keyPackage
		result.KeyPackagePacket = keyPackagePacket
		return result, nil

	case GatewayBinaryOpcodeProposals:
		if len(payload) == 0 {
			return nil, fmt.Errorf("proposals payload is missing operation type")
		}

		commitWelcome, err := s.ProcessProposals(ProposalsOperationType(payload[0]), payload[1:], recognizedUserIDs)
		if err != nil {
			return nil, err
		}
		if commitWelcome == nil {
			return result, nil
		}

		result.Commit = append([]byte(nil), commitWelcome.Commit...)
		result.Welcome = append([]byte(nil), commitWelcome.Welcome...)

		if len(result.Commit) > 0 {
			packet, err := EncodeCommitWelcomePacket(result.Commit, result.Welcome)
			if err != nil {
				return nil, err
			}
			result.CommitWelcomePacket = packet
		}

		return result, nil

	case GatewayBinaryOpcodeAnnounceCommit:
		transitionID, commit, err := decodeTransitionOpaquePacket(payload)
		if err != nil {
			return nil, fmt.Errorf("decode commit transition: %w", err)
		}
		if err := s.ProcessCommit(commit); err != nil {
			return nil, err
		}

		result.TransitionID = transitionID
		result.SendTransitionReady = true
		return result, nil

	case GatewayBinaryOpcodeWelcome:
		transitionID, welcome, err := decodeTransitionOpaquePacket(payload)
		if err != nil {
			return nil, fmt.Errorf("decode welcome transition: %w", err)
		}
		if err := s.ProcessWelcome(welcome); err != nil {
			return nil, err
		}

		result.TransitionID = transitionID
		result.SendTransitionReady = true
		return result, nil

	case GatewayBinaryOpcodeKeyPackage, GatewayBinaryOpcodeCommitWelcome:
		return nil, fmt.Errorf("opcode %d is client-originated and should not be received from the server", opcode)

	default:
		return nil, fmt.Errorf("unsupported gateway binary opcode %d", opcode)
	}
}

func decodeTransitionOpaquePacket(payload []byte) (*uint16, []byte, error) {
	if len(payload) < 2 {
		return nil, nil, fmt.Errorf("payload too short")
	}

	transitionID := binary.BigEndian.Uint16(payload[:2])
	value, next, err := readOpaqueVectorAt(payload, 2)
	if err != nil {
		return nil, nil, err
	}
	if next != len(payload) {
		return nil, nil, fmt.Errorf("payload contains %d trailing bytes", len(payload)-next)
	}

	return &transitionID, value, nil
}

func encodeOpaqueVector(data []byte) ([]byte, error) {
	if len(data) > maxMLSVarintValue {
		return nil, fmt.Errorf("opaque vector too large: %d bytes", len(data))
	}

	lengthBytes := writeMLSVarint(uint32(len(data)))
	value := make([]byte, len(lengthBytes)+len(data))
	copy(value, lengthBytes)
	copy(value[len(lengthBytes):], data)
	return value, nil
}

func writeMLSVarint(value uint32) []byte {
	switch {
	case value < 1<<6:
		return []byte{byte(value)}
	case value < 1<<14:
		return []byte{
			byte(0x40 | (value >> 8)),
			byte(value),
		}
	default:
		return []byte{
			byte(0x80 | (value >> 24)),
			byte(value >> 16),
			byte(value >> 8),
			byte(value),
		}
	}
}
