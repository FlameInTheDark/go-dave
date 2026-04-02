package dave

import (
	"bytes"
	"strconv"
	"testing"
)

func TestSessionEndToEndRoundTripAcrossCodecs(t *testing.T) {
	alice, bob := createActiveSessionPair(t)

	if !alice.Ready() || !bob.Ready() {
		t.Fatalf("expected both sessions to be ready, got alice=%t bob=%t", alice.Ready(), bob.Ready())
	}

	if !bytes.Equal(alice.GetEpochAuthenticator(), bob.GetEpochAuthenticator()) {
		t.Fatal("expected both sessions to agree on epoch authenticator")
	}
	if alice.VoicePrivacyCode() == "" || alice.VoicePrivacyCode() != bob.VoicePrivacyCode() {
		t.Fatalf("expected matching non-empty voice privacy codes, got alice=%q bob=%q", alice.VoicePrivacyCode(), bob.VoicePrivacyCode())
	}

	aliceVerificationCode, err := alice.GetVerificationCode(bob.UserID())
	if err != nil {
		t.Fatalf("alice GetVerificationCode() failed: %v", err)
	}
	bobVerificationCode, err := bob.GetVerificationCode(alice.UserID())
	if err != nil {
		t.Fatalf("bob GetVerificationCode() failed: %v", err)
	}
	if aliceVerificationCode != bobVerificationCode {
		t.Fatalf("expected matching verification codes, got alice=%q bob=%q", aliceVerificationCode, bobVerificationCode)
	}

	aliceFingerprint, err := alice.GetPairwiseFingerprint(0, bob.UserID())
	if err != nil {
		t.Fatalf("alice GetPairwiseFingerprint() failed: %v", err)
	}
	bobFingerprint, err := bob.GetPairwiseFingerprint(0, alice.UserID())
	if err != nil {
		t.Fatalf("bob GetPairwiseFingerprint() failed: %v", err)
	}
	if !bytes.Equal(aliceFingerprint, bobFingerprint) {
		t.Fatal("expected matching pairwise fingerprints")
	}

	directions := []struct {
		name     string
		sender   *DAVESession
		receiver *DAVESession
	}{
		{name: "alice_to_bob", sender: alice, receiver: bob},
		{name: "bob_to_alice", sender: bob, receiver: alice},
	}

	cases := []struct {
		name      string
		mediaType MediaType
		codec     Codec
		frame     []byte
	}{
		{
			name:      "opus_audio",
			mediaType: MediaTypeAudio,
			codec:     CodecOpus,
			frame:     []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f},
		},
		{
			name:      "vp8_video",
			mediaType: MediaTypeVideo,
			codec:     CodecVP8,
			frame:     []byte{0x00, 0x00, 0x00, 0x9d, 0x01, 0x2a, 0x00, 0x00, 0x00, 0x00, 0xde, 0xad, 0xbe, 0xef},
		},
		{
			name:      "vp9_video",
			mediaType: MediaTypeVideo,
			codec:     CodecVP9,
			frame:     []byte{0x90, 0x91, 0x92, 0x93, 0x94, 0x95},
		},
		{
			name:      "h264_video",
			mediaType: MediaTypeVideo,
			codec:     CodecH264,
			frame:     []byte{0x00, 0x00, 0x00, 0x01, 0x65, 0xff, 0xaa, 0xbb, 0xcc},
		},
		{
			name:      "h265_video",
			mediaType: MediaTypeVideo,
			codec:     CodecH265,
			frame:     []byte{0x00, 0x00, 0x00, 0x01, 0x02, 0x01, 0xaa, 0xbb, 0xcc},
		},
		{
			name:      "av1_video",
			mediaType: MediaTypeVideo,
			codec:     CodecAV1,
			frame:     []byte{0x08, 0xaa, 0xbb, 0xcc},
		},
	}

	for _, direction := range directions {
		direction := direction
		for _, tc := range cases {
			tc := tc
			t.Run(direction.name+"_"+tc.name, func(t *testing.T) {
				beforeEnc := direction.sender.GetEncryptionStats(tc.mediaType)
				beforeDec, err := direction.receiver.GetDecryptionStats(direction.sender.UserID(), tc.mediaType)
				if err != nil {
					t.Fatalf("GetDecryptionStats(before) failed: %v", err)
				}

				encrypted, err := direction.sender.Encrypt(tc.mediaType, tc.codec, tc.frame)
				if err != nil {
					t.Fatalf("Encrypt() failed: %v", err)
				}
				if bytes.Equal(encrypted, tc.frame) {
					t.Fatal("expected encrypted frame to differ from plaintext")
				}
				if len(encrypted) <= len(tc.frame) {
					t.Fatalf("expected encrypted frame to grow, got plaintext=%d encrypted=%d", len(tc.frame), len(encrypted))
				}

				decrypted, err := direction.receiver.Decrypt(direction.sender.UserID(), tc.mediaType, encrypted)
				if err != nil {
					t.Fatalf("Decrypt() failed: %v", err)
				}
				if !bytes.Equal(decrypted, tc.frame) {
					t.Fatalf("round-trip mismatch:\nplaintext=%x\ndecrypted=%x", tc.frame, decrypted)
				}

				afterEnc := direction.sender.GetEncryptionStats(tc.mediaType)
				if afterEnc.Successes != beforeEnc.Successes+1 {
					t.Fatalf("expected encryption success count to increase by 1, got before=%d after=%d", beforeEnc.Successes, afterEnc.Successes)
				}
				if afterEnc.Failures != beforeEnc.Failures {
					t.Fatalf("expected encryption failures to stay unchanged, got before=%d after=%d", beforeEnc.Failures, afterEnc.Failures)
				}

				afterDec, err := direction.receiver.GetDecryptionStats(direction.sender.UserID(), tc.mediaType)
				if err != nil {
					t.Fatalf("GetDecryptionStats(after) failed: %v", err)
				}
				if afterDec.Successes != beforeDec.Successes+1 {
					t.Fatalf("expected decryption success count to increase by 1, got before=%d after=%d", beforeDec.Successes, afterDec.Successes)
				}
				if afterDec.Failures != beforeDec.Failures {
					t.Fatalf("expected decryption failures to stay unchanged, got before=%d after=%d", beforeDec.Failures, afterDec.Failures)
				}
			})
		}
	}
}

func TestGatewayBinaryEndToEndRoundTrip(t *testing.T) {
	externalSender := buildTestExternalSenderPackage(t, 999999999)

	alice := createTestSession(t, SessionStatusInactive)
	bob, err := NewDAVESession(DAVEProtocolVersion, testOtherUserID, testChannelID, nil)
	if err != nil {
		t.Fatalf("NewDAVESession(bob) failed: %v", err)
	}

	aliceExternal, err := alice.HandleGatewayBinaryPacket(
		buildGatewayServerPacket(1, GatewayBinaryOpcodeExternalSender, externalSender),
		nil,
	)
	if err != nil {
		t.Fatalf("alice HandleGatewayBinaryPacket(external sender) failed: %v", err)
	}
	if len(aliceExternal.KeyPackagePacket) == 0 {
		t.Fatal("expected alice external sender handling to return a key package packet")
	}

	bobExternal, err := bob.HandleGatewayBinaryPacket(
		buildGatewayServerPacket(1, GatewayBinaryOpcodeExternalSender, externalSender),
		nil,
	)
	if err != nil {
		t.Fatalf("bob HandleGatewayBinaryPacket(external sender) failed: %v", err)
	}
	if len(bobExternal.KeyPackage) == 0 || len(bobExternal.KeyPackagePacket) == 0 {
		t.Fatal("expected bob external sender handling to return key package data")
	}

	proposalsVector := buildAddProposalVector(t, alice, bob)
	proposalsPayload := append([]byte{byte(ProposalsAppend)}, proposalsVector...)
	recognized := []string{alice.UserID(), bob.UserID()}

	proposalsResult, err := alice.HandleGatewayBinaryMessage(2, GatewayBinaryOpcodeProposals, proposalsPayload, recognized)
	if err != nil {
		t.Fatalf("alice HandleGatewayBinaryMessage(proposals) failed: %v", err)
	}
	if len(proposalsResult.Commit) == 0 || len(proposalsResult.Welcome) == 0 || len(proposalsResult.CommitWelcomePacket) == 0 {
		t.Fatalf("expected proposals handling to return commit, welcome, and packet, got %#v", proposalsResult)
	}

	commitResult, err := alice.HandleGatewayBinaryMessage(
		3,
		GatewayBinaryOpcodeAnnounceCommit,
		buildTransitionOpaquePayload(55, proposalsResult.Commit),
		recognized,
	)
	if err != nil {
		t.Fatalf("alice HandleGatewayBinaryMessage(commit) failed: %v", err)
	}
	if !commitResult.SendTransitionReady || commitResult.TransitionID == nil || *commitResult.TransitionID != 55 {
		t.Fatalf("unexpected commit result: %#v", commitResult)
	}

	welcomeResult, err := bob.HandleGatewayBinaryMessage(
		4,
		GatewayBinaryOpcodeWelcome,
		buildTransitionOpaquePayload(55, proposalsResult.Welcome),
		recognized,
	)
	if err != nil {
		t.Fatalf("bob HandleGatewayBinaryMessage(welcome) failed: %v", err)
	}
	if !welcomeResult.SendTransitionReady || welcomeResult.TransitionID == nil || *welcomeResult.TransitionID != 55 {
		t.Fatalf("unexpected welcome result: %#v", welcomeResult)
	}

	if !alice.Ready() || !bob.Ready() {
		t.Fatalf("expected both sessions to be ready after gateway flow, got alice=%t bob=%t", alice.Ready(), bob.Ready())
	}

	frame := []byte{0x12, 0x34, 0x56, 0x78, 0x9a}
	encrypted, err := alice.EncryptOpus(frame)
	if err != nil {
		t.Fatalf("alice EncryptOpus() failed: %v", err)
	}
	decrypted, err := bob.Decrypt(alice.UserID(), MediaTypeAudio, encrypted)
	if err != nil {
		t.Fatalf("bob Decrypt() failed: %v", err)
	}
	if !bytes.Equal(decrypted, frame) {
		t.Fatalf("gateway round-trip mismatch:\nplaintext=%x\ndecrypted=%x", frame, decrypted)
	}
}

func createActiveSessionPair(t *testing.T) (*DAVESession, *DAVESession) {
	t.Helper()

	externalSender := buildTestExternalSenderPackage(t, 999999999)

	alice := createTestSession(t, SessionStatusInactive)
	bob, err := NewDAVESession(DAVEProtocolVersion, testOtherUserID, testChannelID, nil)
	if err != nil {
		t.Fatalf("NewDAVESession(bob) failed: %v", err)
	}

	if err := alice.SetExternalSender(externalSender); err != nil {
		t.Fatalf("alice SetExternalSender() failed: %v", err)
	}
	if err := bob.SetExternalSender(externalSender); err != nil {
		t.Fatalf("bob SetExternalSender() failed: %v", err)
	}
	if _, err := bob.GetSerializedKeyPackage(); err != nil {
		t.Fatalf("bob GetSerializedKeyPackage() failed: %v", err)
	}

	proposalsVector := buildAddProposalVector(t, alice, bob)
	commitWelcome, err := alice.ProcessProposals(
		ProposalsAppend,
		proposalsVector,
		[]string{alice.UserID(), bob.UserID()},
	)
	if err != nil {
		t.Fatalf("alice ProcessProposals() failed: %v", err)
	}
	if commitWelcome == nil || len(commitWelcome.Commit) == 0 || len(commitWelcome.Welcome) == 0 {
		t.Fatalf("expected non-empty commit/welcome, got %#v", commitWelcome)
	}

	if err := alice.ProcessCommit(commitWelcome.Commit); err != nil {
		t.Fatalf("alice ProcessCommit() failed: %v", err)
	}
	if err := bob.ProcessWelcome(commitWelcome.Welcome); err != nil {
		t.Fatalf("bob ProcessWelcome() failed: %v", err)
	}

	return alice, bob
}

func buildAddProposalVector(t *testing.T, sender *DAVESession, joiner *DAVESession) []byte {
	t.Helper()

	if joiner == nil {
		t.Fatal("joiner session is nil")
	}
	keyPackage, err := joiner.GetSerializedKeyPackage()
	if err != nil {
		t.Fatalf("joiner GetSerializedKeyPackage() failed: %v", err)
	}

	proposal, err := sender.CreateAddProposal(keyPackage)
	if err != nil {
		t.Fatalf("CreateAddProposal() failed: %v", err)
	}

	vector, err := EncodeMLSMessageVector(proposal)
	if err != nil {
		t.Fatalf("EncodeMLSMessageVector() failed: %v", err)
	}
	return vector
}

func buildTestExternalSenderPackage(t *testing.T, userID uint64) []byte {
	t.Helper()

	signingKeyPair, err := GenerateP256Keypair()
	if err != nil {
		t.Fatalf("GenerateP256Keypair() failed: %v", err)
	}
	packet, err := EncodeExternalSenderPackage(signingKeyPair.Public, strconv.FormatUint(userID, 10))
	if err != nil {
		t.Fatalf("EncodeExternalSenderPackage() failed: %v", err)
	}
	return packet
}
