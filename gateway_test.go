package dave

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestParseGatewayBinaryPacket(t *testing.T) {
	packet, err := ParseGatewayBinaryPacket([]byte{0x12, 0x34, byte(GatewayBinaryOpcodeExternalSender), 0xaa, 0xbb})
	if err != nil {
		t.Fatalf("ParseGatewayBinaryPacket() failed: %v", err)
	}

	if packet.Sequence != 0x1234 {
		t.Fatalf("unexpected sequence: %d", packet.Sequence)
	}
	if packet.Opcode != GatewayBinaryOpcodeExternalSender {
		t.Fatalf("unexpected opcode: %d", packet.Opcode)
	}
	if !bytes.Equal(packet.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("unexpected payload: %#v", packet.Payload)
	}
}

func TestEncodeGatewayPackets(t *testing.T) {
	keyPackagePacket, err := EncodeKeyPackagePacket([]byte{0xaa, 0xbb, 0xcc})
	if err != nil {
		t.Fatalf("EncodeKeyPackagePacket() failed: %v", err)
	}
	if keyPackagePacket[0] != byte(GatewayBinaryOpcodeKeyPackage) {
		t.Fatalf("unexpected key package opcode: %d", keyPackagePacket[0])
	}
	keyPackagePayload, err := readOpaqueVector(keyPackagePacket[1:])
	if err != nil {
		t.Fatalf("failed to decode key package payload: %v", err)
	}
	if !bytes.Equal(keyPackagePayload, []byte{0xaa, 0xbb, 0xcc}) {
		t.Fatalf("unexpected key package payload: %#v", keyPackagePayload)
	}

	commitWelcomePacket, err := EncodeCommitWelcomePacket([]byte{0x01, 0x02}, []byte{0x03, 0x04})
	if err != nil {
		t.Fatalf("EncodeCommitWelcomePacket() failed: %v", err)
	}
	if commitWelcomePacket[0] != byte(GatewayBinaryOpcodeCommitWelcome) {
		t.Fatalf("unexpected commit/welcome opcode: %d", commitWelcomePacket[0])
	}
	commit, next, err := readOpaqueVectorAt(commitWelcomePacket, 1)
	if err != nil {
		t.Fatalf("failed to decode commit: %v", err)
	}
	if !bytes.Equal(commit, []byte{0x01, 0x02}) {
		t.Fatalf("unexpected commit bytes: %#v", commit)
	}
	welcome, next, err := readOpaqueVectorAt(commitWelcomePacket, next)
	if err != nil {
		t.Fatalf("failed to decode welcome: %v", err)
	}
	if next != len(commitWelcomePacket) {
		t.Fatalf("unexpected trailing bytes in commit/welcome packet: %d", len(commitWelcomePacket)-next)
	}
	if !bytes.Equal(welcome, []byte{0x03, 0x04}) {
		t.Fatalf("unexpected welcome bytes: %#v", welcome)
	}
}

func TestHandleGatewayBinaryMessages(t *testing.T) {
	session := createTestSession(t, SessionStatusInactive)

	externalResult, err := session.HandleGatewayBinaryPacket(
		buildGatewayServerPacket(7, GatewayBinaryOpcodeExternalSender, testExternalSender),
		nil,
	)
	if err != nil {
		t.Fatalf("HandleGatewayBinaryPacket(external sender) failed: %v", err)
	}
	if externalResult.Sequence != 7 {
		t.Fatalf("unexpected external sender sequence: %d", externalResult.Sequence)
	}
	if len(externalResult.KeyPackage) == 0 || len(externalResult.KeyPackagePacket) == 0 {
		t.Fatal("expected key package output after handling external sender")
	}
	if session.Status() != SessionStatusPending {
		t.Fatalf("unexpected session status after external sender: %d", session.Status())
	}

	proposalsPayload := append([]byte{byte(ProposalsAppend)}, testAppendingProposals...)
	proposalsResult, err := session.HandleGatewayBinaryMessage(8, GatewayBinaryOpcodeProposals, proposalsPayload, nil)
	if err != nil {
		t.Fatalf("HandleGatewayBinaryMessage(proposals) failed: %v", err)
	}
	if len(proposalsResult.Commit) == 0 {
		t.Fatal("expected proposals handling to return a commit")
	}
	if len(proposalsResult.CommitWelcomePacket) == 0 {
		t.Fatal("expected commit/welcome packet to be pre-encoded")
	}

	commitPayload := buildTransitionOpaquePayload(42, proposalsResult.Commit)
	commitResult, err := session.HandleGatewayBinaryMessage(9, GatewayBinaryOpcodeAnnounceCommit, commitPayload, nil)
	if err != nil {
		t.Fatalf("HandleGatewayBinaryMessage(commit) failed: %v", err)
	}
	if commitResult.TransitionID == nil || *commitResult.TransitionID != 42 {
		t.Fatalf("unexpected transition id: %#v", commitResult.TransitionID)
	}
	if !commitResult.SendTransitionReady {
		t.Fatal("expected commit handling to request TransitionReady")
	}
	if session.Status() != SessionStatusActive {
		t.Fatalf("unexpected session status after commit: %d", session.Status())
	}
}

func TestShouldBeCommitter(t *testing.T) {
	if !ShouldBeCommitter("5", []string{"7", "9", "5"}) {
		t.Fatal("expected lowest user id to be the committer")
	}
	if ShouldBeCommitter("5", []string{"4", "5", "9"}) {
		t.Fatal("expected lower recognized id to win committer election")
	}
	if ShouldBeCommitter("not-a-number", []string{"4"}) {
		t.Fatal("invalid self user id should never elect a committer")
	}
}

func buildGatewayServerPacket(sequence uint16, opcode GatewayBinaryOpcode, payload []byte) []byte {
	packet := make([]byte, 3+len(payload))
	binary.BigEndian.PutUint16(packet[:2], sequence)
	packet[2] = byte(opcode)
	copy(packet[3:], payload)
	return packet
}

func buildTransitionOpaquePayload(transitionID uint16, value []byte) []byte {
	opaque, err := encodeOpaqueVector(value)
	if err != nil {
		panic(err)
	}

	payload := make([]byte, 2+len(opaque))
	binary.BigEndian.PutUint16(payload[:2], transitionID)
	copy(payload[2:], opaque)
	return payload
}
