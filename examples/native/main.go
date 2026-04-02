package main

import (
	"encoding/binary"
	"fmt"
	"log"

	dave "github.com/FlameInTheDark/go-dave"
)

const (
	aliceUserID          = "158049329150427136"
	bobUserID            = "158533742254751744"
	channelID            = "927310423890473011"
	externalSenderUserID = "999999999"
)

func main() {
	externalSenderKeyPair, err := dave.GenerateP256Keypair()
	if err != nil {
		log.Fatal(err)
	}

	externalSender, err := dave.EncodeExternalSenderPackage(
		externalSenderKeyPair.Public,
		externalSenderUserID,
	)
	if err != nil {
		log.Fatal(err)
	}

	alice, err := dave.NewDAVESession(dave.DAVEProtocolVersion, aliceUserID, channelID, nil)
	if err != nil {
		log.Fatal(err)
	}
	bob, err := dave.NewDAVESession(dave.DAVEProtocolVersion, bobUserID, channelID, nil)
	if err != nil {
		log.Fatal(err)
	}

	aliceExternal, err := alice.HandleGatewayBinaryPacket(
		buildServerPacket(1, dave.GatewayBinaryOpcodeExternalSender, externalSender),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}
	bobExternal, err := bob.HandleGatewayBinaryPacket(
		buildServerPacket(1, dave.GatewayBinaryOpcodeExternalSender, externalSender),
		nil,
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("alice key package packet: %d bytes\n", len(aliceExternal.KeyPackagePacket))
	fmt.Printf("bob key package packet: %d bytes\n", len(bobExternal.KeyPackagePacket))

	recognizedUserIDs := []string{aliceUserID, bobUserID}

	addProposal, err := alice.CreateAddProposal(bobExternal.KeyPackage)
	if err != nil {
		log.Fatal(err)
	}

	proposalsVector, err := dave.EncodeMLSMessageVector(addProposal)
	if err != nil {
		log.Fatal(err)
	}

	proposalsPayload := append([]byte{byte(dave.ProposalsAppend)}, proposalsVector...)
	proposalsResult, err := alice.HandleGatewayBinaryPacket(
		buildServerPacket(2, dave.GatewayBinaryOpcodeProposals, proposalsPayload),
		recognizedUserIDs,
	)
	if err != nil {
		log.Fatal(err)
	}

	const transitionID = uint16(77)

	aliceCommitResult, err := alice.HandleGatewayBinaryPacket(
		buildServerPacket(
			3,
			dave.GatewayBinaryOpcodeAnnounceCommit,
			buildTransitionOpaquePayload(transitionID, proposalsResult.Commit),
		),
		recognizedUserIDs,
	)
	if err != nil {
		log.Fatal(err)
	}
	bobWelcomeResult, err := bob.HandleGatewayBinaryPacket(
		buildServerPacket(
			4,
			dave.GatewayBinaryOpcodeWelcome,
			buildTransitionOpaquePayload(transitionID, proposalsResult.Welcome),
		),
		recognizedUserIDs,
	)
	if err != nil {
		log.Fatal(err)
	}

	if aliceCommitResult.SendTransitionReady && aliceCommitResult.TransitionID != nil {
		fmt.Printf("alice marks transition %d ready\n", *aliceCommitResult.TransitionID)
	}
	if bobWelcomeResult.SendTransitionReady && bobWelcomeResult.TransitionID != nil {
		fmt.Printf("bob marks transition %d ready\n", *bobWelcomeResult.TransitionID)
	}

	encrypted, err := alice.EncryptOpus([]byte("hello from alice"))
	if err != nil {
		log.Fatal(err)
	}

	decrypted, err := bob.Decrypt(aliceUserID, dave.MediaTypeAudio, encrypted)
	if err != nil {
		log.Fatal(err)
	}

	verificationCode, err := alice.GetVerificationCode(bobUserID)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("decrypted packet: %q\n", decrypted)
	fmt.Printf("verification code: %s\n", verificationCode)
}

func buildServerPacket(sequence uint16, opcode dave.GatewayBinaryOpcode, payload []byte) []byte {
	packet := make([]byte, 3+len(payload))
	binary.BigEndian.PutUint16(packet[:2], sequence)
	packet[2] = byte(opcode)
	copy(packet[3:], payload)
	return packet
}

func buildTransitionOpaquePayload(transitionID uint16, value []byte) []byte {
	opaque := encodeOpaqueVector(value)

	payload := make([]byte, 2+len(opaque))
	binary.BigEndian.PutUint16(payload[:2], transitionID)
	copy(payload[2:], opaque)
	return payload
}

func encodeOpaqueVector(data []byte) []byte {
	length := encodeMLSVarint(len(data))
	out := make([]byte, len(length)+len(data))
	copy(out, length)
	copy(out[len(length):], data)
	return out
}

func encodeMLSVarint(value int) []byte {
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
