package server

import (
	"encoding/binary"
	"fmt"

	dave "github.com/FlameInTheDark/go-dave"
)

// BinaryOpcode is a GoChat-style DAVE binary opcode.
type BinaryOpcode = dave.GatewayBinaryOpcode

// GoChat DAVE binary opcodes.
const (
	OpcodeExternalSenderPackage BinaryOpcode = dave.GatewayBinaryOpcodeExternalSender
	OpcodeKeyPackage            BinaryOpcode = dave.GatewayBinaryOpcodeKeyPackage
	OpcodeProposals             BinaryOpcode = dave.GatewayBinaryOpcodeProposals
	OpcodeCommitWelcome         BinaryOpcode = dave.GatewayBinaryOpcodeCommitWelcome
	OpcodeAnnounceCommit        BinaryOpcode = dave.GatewayBinaryOpcodeAnnounceCommit
	OpcodeWelcome               BinaryOpcode = dave.GatewayBinaryOpcodeWelcome
)

// ProposalsOperationType controls how a proposals packet should be applied.
type ProposalsOperationType = dave.ProposalsOperationType

// Proposal operation kinds used by GoChat DAVE packets.
const (
	ProposalsAppend ProposalsOperationType = dave.ProposalsAppend
	ProposalsRevoke ProposalsOperationType = dave.ProposalsRevoke
)

// CredentialTypeBasic is the basic MLS credential type used for external
// sender identities.
const CredentialTypeBasic uint16 = 1

// ExternalSender describes the external sender payload carried in opcode 25.
type ExternalSender struct {
	SignatureKey   []byte
	CredentialType uint16
	Identity       []byte
}

// ExternalSenderPackage is a server-to-client opcode 25 packet payload.
type ExternalSenderPackage struct {
	SequenceNumber uint16
	ExternalSender ExternalSender
}

// KeyPackage is a client-to-server opcode 26 packet payload.
type KeyPackage struct {
	Payload []byte
}

// Proposals is a server-to-client opcode 27 packet payload.
type Proposals struct {
	SequenceNumber   uint16
	OperationType    ProposalsOperationType
	ProposalMessages [][]byte
	ProposalRefs     [][]byte
}

// CommitWelcome is a client-to-server opcode 28 packet payload.
type CommitWelcome struct {
	Commit  []byte
	Welcome []byte
}

// AnnounceCommitTransition is a server-to-client opcode 29 packet payload.
type AnnounceCommitTransition struct {
	SequenceNumber uint16
	TransitionID   uint16
	Commit         []byte
}

// Welcome is a server-to-client opcode 30 packet payload.
type Welcome struct {
	SequenceNumber uint16
	TransitionID   uint16
	Welcome        []byte
}

// DecodedBinaryMessage is the parsed form of a binary DAVE message.
type DecodedBinaryMessage struct {
	Opcode         BinaryOpcode
	SequenceNumber uint16
	TransitionID   uint16
	OperationType  ProposalsOperationType
	ExternalSender *ExternalSender
	Payloads       [][]byte
	Commit         []byte
	Welcome        []byte
}

// EncodeExternalSenderPackage encodes a server-to-client opcode 25 packet.
func EncodeExternalSenderPackage(msg ExternalSenderPackage) ([]byte, error) {
	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, msg.SequenceNumber)
	out = append(out, byte(OpcodeExternalSenderPackage))
	var err error
	out, err = writeOpaqueVec(out, msg.ExternalSender.SignatureKey)
	if err != nil {
		return nil, err
	}
	out = binary.BigEndian.AppendUint16(out, msg.ExternalSender.CredentialType)
	out, err = writeOpaqueVec(out, msg.ExternalSender.Identity)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeKeyPackage encodes a client-to-server opcode 26 packet.
func EncodeKeyPackage(msg KeyPackage) ([]byte, error) {
	if len(msg.Payload) == 0 {
		return nil, fmt.Errorf("key package payload is empty")
	}
	out := []byte{byte(OpcodeKeyPackage)}
	out, err := writeOpaqueVec(out, msg.Payload)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeProposals encodes a server-to-client opcode 27 packet.
func EncodeProposals(msg Proposals) ([]byte, error) {
	out := make([]byte, 0, 64)
	out = binary.BigEndian.AppendUint16(out, msg.SequenceNumber)
	out = append(out, byte(OpcodeProposals), byte(msg.OperationType))
	var (
		payload []byte
		err     error
	)
	switch msg.OperationType {
	case ProposalsAppend:
		payload, err = encodeMLSMessageVector(msg.ProposalMessages)
	case ProposalsRevoke:
		payload, err = encodeOpaqueVectorList(msg.ProposalRefs)
	default:
		return nil, fmt.Errorf("unknown proposals operation type %d", msg.OperationType)
	}
	if err != nil {
		return nil, err
	}
	return append(out, payload...), nil
}

// EncodeCommitWelcome encodes a client-to-server opcode 28 packet.
func EncodeCommitWelcome(msg CommitWelcome) ([]byte, error) {
	if len(msg.Commit) == 0 {
		return nil, fmt.Errorf("commit payload is empty")
	}
	out := []byte{byte(OpcodeCommitWelcome)}
	var err error
	out, err = writeOpaqueVec(out, msg.Commit)
	if err != nil {
		return nil, err
	}
	if len(msg.Welcome) > 0 {
		out, err = writeOpaqueVec(out, msg.Welcome)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// EncodeAnnounceCommitTransition encodes a server-to-client opcode 29 packet.
func EncodeAnnounceCommitTransition(msg AnnounceCommitTransition) ([]byte, error) {
	if len(msg.Commit) == 0 {
		return nil, fmt.Errorf("commit payload is empty")
	}
	out := make([]byte, 0, 32)
	out = binary.BigEndian.AppendUint16(out, msg.SequenceNumber)
	out = append(out, byte(OpcodeAnnounceCommit))
	out = binary.BigEndian.AppendUint16(out, msg.TransitionID)
	var err error
	out, err = writeOpaqueVec(out, msg.Commit)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// EncodeWelcome encodes a server-to-client opcode 30 packet.
func EncodeWelcome(msg Welcome) ([]byte, error) {
	if len(msg.Welcome) == 0 {
		return nil, fmt.Errorf("welcome payload is empty")
	}
	out := make([]byte, 0, 32)
	out = binary.BigEndian.AppendUint16(out, msg.SequenceNumber)
	out = append(out, byte(OpcodeWelcome))
	out = binary.BigEndian.AppendUint16(out, msg.TransitionID)
	var err error
	out, err = writeOpaqueVec(out, msg.Welcome)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// DecodeBinaryMessage decodes a GoChat-style DAVE binary message.
func DecodeBinaryMessage(raw []byte) (*DecodedBinaryMessage, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("binary message is empty")
	}
	switch BinaryOpcode(raw[0]) {
	case OpcodeKeyPackage:
		payload, n, err := readOpaqueVec(raw[1:])
		if err != nil {
			return nil, err
		}
		if 1+n != len(raw) {
			return nil, fmt.Errorf("key package contains trailing bytes")
		}
		return &DecodedBinaryMessage{Opcode: OpcodeKeyPackage, Payloads: [][]byte{payload}}, nil
	case OpcodeCommitWelcome:
		commit, n, err := readOpaqueVec(raw[1:])
		if err != nil {
			return nil, err
		}
		msg := &DecodedBinaryMessage{Opcode: OpcodeCommitWelcome, Commit: commit}
		offset := 1 + n
		if offset < len(raw) {
			welcome, m, err := readOpaqueVec(raw[offset:])
			if err != nil {
				return nil, err
			}
			if offset+m != len(raw) {
				return nil, fmt.Errorf("commit welcome contains trailing bytes")
			}
			msg.Welcome = welcome
		}
		return msg, nil
	}

	if len(raw) < 3 {
		return nil, fmt.Errorf("binary message too short")
	}
	msg := &DecodedBinaryMessage{
		SequenceNumber: binary.BigEndian.Uint16(raw[:2]),
		Opcode:         BinaryOpcode(raw[2]),
	}
	switch msg.Opcode {
	case OpcodeExternalSenderPackage:
		offset := 3
		signatureKey, n, err := readOpaqueVec(raw[offset:])
		if err != nil {
			return nil, err
		}
		offset += n
		if offset+2 > len(raw) {
			return nil, fmt.Errorf("external sender missing credential type")
		}
		credentialType := binary.BigEndian.Uint16(raw[offset : offset+2])
		offset += 2
		identity, m, err := readOpaqueVec(raw[offset:])
		if err != nil {
			return nil, err
		}
		offset += m
		if offset != len(raw) {
			return nil, fmt.Errorf("external sender package contains trailing bytes")
		}
		msg.ExternalSender = &ExternalSender{
			SignatureKey:   signatureKey,
			CredentialType: credentialType,
			Identity:       identity,
		}
		return msg, nil
	case OpcodeProposals:
		if len(raw) < 4 {
			return nil, fmt.Errorf("proposals message too short")
		}
		msg.OperationType = ProposalsOperationType(raw[3])
		switch msg.OperationType {
		case ProposalsAppend:
			payload, n, err := readOpaqueVec(raw[4:])
			if err != nil {
				return nil, err
			}
			if 4+n != len(raw) {
				return nil, fmt.Errorf("proposals append contains trailing bytes")
			}
			msg.Payloads = [][]byte{payload}
			return msg, nil
		case ProposalsRevoke:
			payloads, n, err := decodeOpaqueVectorList(raw[4:])
			if err != nil {
				return nil, err
			}
			if 4+n != len(raw) {
				return nil, fmt.Errorf("proposals revoke contains trailing bytes")
			}
			msg.Payloads = payloads
			return msg, nil
		default:
			return nil, fmt.Errorf("unknown proposals operation type %d", msg.OperationType)
		}
	case OpcodeAnnounceCommit:
		if len(raw) < 5 {
			return nil, fmt.Errorf("announce commit transition too short")
		}
		msg.TransitionID = binary.BigEndian.Uint16(raw[3:5])
		commit, n, err := readOpaqueVec(raw[5:])
		if err != nil {
			return nil, err
		}
		if 5+n != len(raw) {
			return nil, fmt.Errorf("announce commit transition contains trailing bytes")
		}
		msg.Commit = commit
		return msg, nil
	case OpcodeWelcome:
		if len(raw) < 5 {
			return nil, fmt.Errorf("welcome message too short")
		}
		msg.TransitionID = binary.BigEndian.Uint16(raw[3:5])
		welcome, n, err := readOpaqueVec(raw[5:])
		if err != nil {
			return nil, err
		}
		if 5+n != len(raw) {
			return nil, fmt.Errorf("welcome message contains trailing bytes")
		}
		msg.Welcome = welcome
		return msg, nil
	default:
		return nil, fmt.Errorf("unknown binary opcode %d", msg.Opcode)
	}
}

func encodeOpaqueVectorList(values [][]byte) ([]byte, error) {
	body := make([]byte, 0, 64)
	var err error
	for _, value := range values {
		body, err = writeOpaqueVec(body, value)
		if err != nil {
			return nil, err
		}
	}
	return writeOpaqueVec(nil, body)
}

func encodeMLSMessageVector(values [][]byte) ([]byte, error) {
	body := make([]byte, 0, 64)
	for _, value := range values {
		body = append(body, value...)
	}
	return writeOpaqueVec(nil, body)
}

func decodeOpaqueVectorList(raw []byte) ([][]byte, int, error) {
	body, n, err := readOpaqueVec(raw)
	if err != nil {
		return nil, 0, err
	}
	out := make([][]byte, 0)
	for offset := 0; offset < len(body); {
		item, consumed, err := readOpaqueVec(body[offset:])
		if err != nil {
			return nil, 0, err
		}
		offset += consumed
		out = append(out, item)
	}
	return out, n, nil
}

func writeOpaqueVec(dst []byte, value []byte) ([]byte, error) {
	if len(value) >= 1<<30 {
		return nil, fmt.Errorf("opaque vector exceeds 30 bits")
	}
	out, err := writeVarint(dst, uint32(len(value)))
	if err != nil {
		return nil, err
	}
	out = append(out, value...)
	return out, nil
}

func readOpaqueVec(raw []byte) ([]byte, int, error) {
	n, consumed, err := readVarint(raw)
	if err != nil {
		return nil, 0, err
	}
	if len(raw[consumed:]) < int(n) {
		return nil, 0, fmt.Errorf("opaque vector truncated")
	}
	start := consumed
	end := start + int(n)
	return append([]byte(nil), raw[start:end]...), end, nil
}

func writeVarint(dst []byte, n uint32) ([]byte, error) {
	switch {
	case n < 1<<6:
		return append(dst, byte(n)), nil
	case n < 1<<14:
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, 0b01<<14|uint16(n))
		return append(dst, buf...), nil
	case n < 1<<30:
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 0b10<<30|n)
		return append(dst, buf...), nil
	default:
		return nil, fmt.Errorf("varint exceeds 30 bits")
	}
}

func readVarint(raw []byte) (uint32, int, error) {
	if len(raw) == 0 {
		return 0, 0, fmt.Errorf("varint truncated")
	}
	prefix := raw[0] >> 6
	if prefix == 3 {
		return 0, 0, fmt.Errorf("invalid varint prefix")
	}
	byteCount := 1 << prefix
	if len(raw) < byteCount {
		return 0, 0, fmt.Errorf("varint truncated")
	}
	value := uint32(raw[0] & 0x3F)
	for i := 1; i < byteCount; i++ {
		value = (value << 8) | uint32(raw[i])
	}
	return value, byteCount, nil
}
