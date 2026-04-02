package dave

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/binary"
	"fmt"
	"strconv"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	mlsext "github.com/thomas-vilte/mls-go/extensions"
	"github.com/thomas-vilte/mls-go/framing"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

func buildSessionState(
	protocolVersion uint16,
	userID string,
	channelID string,
	keyPair *SigningKeyPair,
) (
	uint64,
	uint64,
	ciphersuite.CipherSuite,
	*SigningKeyPair,
	*ecdsa.PrivateKey,
	*credentials.CredentialWithKey,
	*keypackages.KeyPackage,
	*keypackages.KeyPackagePrivateKeys,
	error,
) {
	userIDNum, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return 0, 0, 0, nil, nil, nil, nil, nil, fmt.Errorf("parse user id %q: %w", userID, err)
	}
	channelIDNum, err := strconv.ParseUint(channelID, 10, 64)
	if err != nil {
		return 0, 0, 0, nil, nil, nil, nil, nil, fmt.Errorf("parse channel id %q: %w", channelID, err)
	}

	cipherSuite, err := protocolVersionToCipherSuite(protocolVersion)
	if err != nil {
		return 0, 0, 0, nil, nil, nil, nil, nil, err
	}

	signingPair := keyPair
	if signingPair == nil {
		signingPair, err = GenerateP256Keypair()
		if err != nil {
			return 0, 0, 0, nil, nil, nil, nil, nil, err
		}
	}
	priv, err := parseSigningKeyPair(signingPair)
	if err != nil {
		return 0, 0, 0, nil, nil, nil, nil, nil, err
	}

	credWithKey := &credentials.CredentialWithKey{
		Credential:        credentials.NewBasicCredentialFromUint64(userIDNum),
		SignatureKey:      &priv.PublicKey,
		PrivateKey:        priv,
		SignatureKeyBytes: append([]byte(nil), signingPair.Public...),
	}
	memberKeyPackage, memberPrivKeys, err := keypackages.Generate(credWithKey, cipherSuite, keypackages.InfiniteLifetime())
	if err != nil {
		return 0, 0, 0, nil, nil, nil, nil, nil, fmt.Errorf("generate member key package: %w", err)
	}

	return userIDNum, channelIDNum, cipherSuite, signingPair, priv, credWithKey, memberKeyPackage, memberPrivKeys, nil
}

func protocolVersionToCipherSuite(protocolVersion uint16) (ciphersuite.CipherSuite, error) {
	switch protocolVersion {
	case DAVEProtocolVersion:
		return ciphersuite.MLS128DHKEMP256, nil
	default:
		return 0, fmt.Errorf("unsupported DAVE protocol version %d", protocolVersion)
	}
}

func parseExternalSender(data []byte) (*externalSender, error) {
	signatureKey, next, err := readOpaqueVectorAt(data, 0)
	if err != nil {
		return nil, fmt.Errorf("read external sender signature key: %w", err)
	}
	credentialData := data[next:]
	if len(credentialData) == 0 {
		return nil, fmt.Errorf("external sender credential is empty")
	}

	credential, err := credentials.UnmarshalCredential(credentialData)
	if err != nil {
		return nil, fmt.Errorf("parse external sender credential: %w", err)
	}
	if credential.CredentialType != credentials.BasicCredential {
		return nil, fmt.Errorf("external sender must use a basic credential")
	}
	if len(credential.Marshal()) != len(credentialData) {
		return nil, fmt.Errorf("external sender credential contains trailing bytes")
	}
	publicKey, err := ciphersuite.NewSignaturePublicKey(signatureKey).ToECDSA()
	if err != nil {
		return nil, fmt.Errorf("parse external sender public key: %w", err)
	}

	return &externalSender{
		signatureKey: append([]byte(nil), signatureKey...),
		credential:   credential,
		publicKey:    publicKey,
	}, nil
}

func userIDFromCredential(credential *credentials.Credential) (uint64, error) {
	if credential == nil {
		return 0, fmt.Errorf("credential is nil")
	}
	if credential.CredentialType != credentials.BasicCredential {
		return 0, fmt.Errorf("expected basic credential, got %s", credential.CredentialType.String())
	}
	if len(credential.Identity) != 8 {
		return 0, fmt.Errorf("expected 8-byte user id, got %d bytes", len(credential.Identity))
	}
	return binary.BigEndian.Uint64(credential.Identity), nil
}

func channelIDBytes(channelID uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, channelID)
	return buf
}

func uint64ToLEBytes(value uint64) []byte {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, value)
	return buf
}

func readOpaqueVector(data []byte) ([]byte, error) {
	value, next, err := readOpaqueVectorAt(data, 0)
	if err != nil {
		return nil, err
	}
	if next != len(data) {
		return nil, fmt.Errorf("vector contains %d trailing bytes", len(data)-next)
	}
	return value, nil
}

func readOpaqueVectorAt(data []byte, offset int) ([]byte, int, error) {
	length, size, err := readMLSVarint(data, offset)
	if err != nil {
		return nil, offset, err
	}
	start := offset + size
	end := start + int(length)
	if start < 0 || end < start || end > len(data) {
		return nil, offset, fmt.Errorf("buffer underrun: need %d bytes from offset %d, have %d", length, start, len(data)-start)
	}
	return append([]byte(nil), data[start:end]...), end, nil
}

func readMLSVarint(data []byte, offset int) (uint32, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("buffer underrun")
	}
	first := data[offset]
	prefix := first >> 6
	switch prefix {
	case 0:
		return uint32(first & 0x3F), 1, nil
	case 1:
		if offset+2 > len(data) {
			return 0, 0, fmt.Errorf("buffer underrun")
		}
		return uint32(first&0x3F)<<8 | uint32(data[offset+1]), 2, nil
	case 2:
		if offset+4 > len(data) {
			return 0, 0, fmt.Errorf("buffer underrun")
		}
		return uint32(first&0x3F)<<24 | uint32(data[offset+1])<<16 | uint32(data[offset+2])<<8 | uint32(data[offset+3]), 4, nil
	default:
		return 0, 0, fmt.Errorf("invalid MLS varint prefix 0x%02x", first)
	}
}

func consumeMLSMessage(data []byte) ([]byte, []byte, error) {
	if len(data) < 4 {
		return nil, nil, fmt.Errorf("MLS message too short")
	}
	if binary.BigEndian.Uint16(data[:2]) != uint16(keypackages.MLS10) {
		return nil, nil, fmt.Errorf("unsupported MLS version %d", binary.BigEndian.Uint16(data[:2]))
	}

	offset := 2
	switch framing.WireFormat(binary.BigEndian.Uint16(data[offset:])) {
	case framing.WireFormatPublicMessage:
		n, err := publicProposalMessageLength(data[offset:])
		if err != nil {
			return nil, nil, err
		}
		total := offset + n
		return append([]byte(nil), data[:total]...), data[total:], nil
	case framing.WireFormatPrivateMessage:
		n, err := privateProposalMessageLength(data[offset:])
		if err != nil {
			return nil, nil, err
		}
		total := offset + n
		return append([]byte(nil), data[:total]...), data[total:], nil
	default:
		return nil, nil, fmt.Errorf("proposal vector contains unsupported wire format %d", binary.BigEndian.Uint16(data[offset:]))
	}
}

func publicProposalMessageLength(data []byte) (int, error) {
	offset := 0
	if len(data) < 2 {
		return 0, fmt.Errorf("public message too short")
	}
	if framing.WireFormat(binary.BigEndian.Uint16(data[offset:])) != framing.WireFormatPublicMessage {
		return 0, fmt.Errorf("expected public message")
	}
	offset += 2

	_, next, err := readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read public message group id: %w", err)
	}
	offset = next

	if offset+8 > len(data) {
		return 0, fmt.Errorf("public message missing epoch")
	}
	offset += 8

	if offset >= len(data) {
		return 0, fmt.Errorf("public message missing sender")
	}
	senderType := framing.SenderType(data[offset])
	offset++
	switch senderType {
	case framing.SenderTypeMember, framing.SenderTypeExternal:
		if offset+4 > len(data) {
			return 0, fmt.Errorf("public message sender truncated")
		}
		offset += 4
	case framing.SenderTypeNewMemberProposal, framing.SenderTypeNewMemberCommit:
	default:
		return 0, fmt.Errorf("invalid sender type %d", senderType)
	}

	_, next, err = readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read public message authenticated data: %w", err)
	}
	offset = next

	if offset >= len(data) {
		return 0, fmt.Errorf("public message missing content type")
	}
	if framing.ContentType(data[offset]) != framing.ContentTypeProposal {
		return 0, fmt.Errorf("proposal vector contained content type %d", data[offset])
	}
	offset++

	n, err := proposalLength(data[offset:])
	if err != nil {
		return 0, fmt.Errorf("read proposal body: %w", err)
	}
	offset += n

	_, next, err = readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read proposal signature: %w", err)
	}
	offset = next

	if senderType == framing.SenderTypeMember {
		_, next, err = readOpaqueVectorAt(data, offset)
		if err != nil {
			return 0, fmt.Errorf("read proposal membership tag: %w", err)
		}
		offset = next
	}

	return offset, nil
}

func privateProposalMessageLength(data []byte) (int, error) {
	offset := 0
	if len(data) < 2 {
		return 0, fmt.Errorf("private message too short")
	}
	if framing.WireFormat(binary.BigEndian.Uint16(data[offset:])) != framing.WireFormatPrivateMessage {
		return 0, fmt.Errorf("expected private message")
	}
	offset += 2

	_, next, err := readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read private message group id: %w", err)
	}
	offset = next

	if offset+8 > len(data) {
		return 0, fmt.Errorf("private message missing epoch")
	}
	offset += 8

	if offset >= len(data) {
		return 0, fmt.Errorf("private message missing content type")
	}
	if framing.ContentType(data[offset]) != framing.ContentTypeProposal {
		return 0, fmt.Errorf("proposal vector contained content type %d", data[offset])
	}
	offset++

	_, next, err = readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read private message authenticated data: %w", err)
	}
	offset = next

	_, next, err = readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read private message sender data: %w", err)
	}
	offset = next

	_, next, err = readOpaqueVectorAt(data, offset)
	if err != nil {
		return 0, fmt.Errorf("read private message ciphertext: %w", err)
	}
	offset = next

	return offset, nil
}

func proposalLength(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("proposal too short")
	}

	offset := 2
	switch group.ProposalType(binary.BigEndian.Uint16(data[:2])) {
	case group.ProposalTypeAdd:
		n, err := exactRoundTripLength(data[offset:], func(candidate []byte) ([]byte, error) {
			kp, err := keypackages.UnmarshalKeyPackage(candidate)
			if err != nil {
				return nil, err
			}
			return kp.Marshal(), nil
		})
		if err == nil {
			return offset + n, nil
		}

		_, next, wrapErr := readOpaqueVectorAt(data, offset)
		if wrapErr != nil {
			return 0, fmt.Errorf("parse add proposal: %w", err)
		}
		return next, nil
	case group.ProposalTypeUpdate:
		n, err := exactRoundTripLength(data[offset:], func(candidate []byte) ([]byte, error) {
			leaf, err := keypackages.UnmarshalLeafNode(candidate)
			if err != nil {
				return nil, err
			}
			return leaf.Marshal(), nil
		})
		if err == nil {
			return offset + n, nil
		}

		_, next, wrapErr := readOpaqueVectorAt(data, offset)
		if wrapErr != nil {
			return 0, fmt.Errorf("parse update proposal: %w", err)
		}
		return next, nil
	case group.ProposalTypeRemove:
		if len(data) < offset+4 {
			return 0, fmt.Errorf("remove proposal truncated")
		}
		return offset + 4, nil
	case group.ProposalTypePreSharedKey:
		if len(data) < offset+1 {
			return 0, fmt.Errorf("PSK proposal truncated")
		}
		pskType := data[offset]
		offset++
		if pskType == 2 {
			if len(data) < offset+1 {
				return 0, fmt.Errorf("PSK proposal missing usage")
			}
			offset++
			_, next, err := readOpaqueVectorAt(data, offset)
			if err != nil {
				return 0, err
			}
			offset = next
			if len(data) < offset+8 {
				return 0, fmt.Errorf("PSK proposal missing epoch")
			}
			offset += 8
		} else {
			_, next, err := readOpaqueVectorAt(data, offset)
			if err != nil {
				return 0, err
			}
			offset = next
		}
		_, next, err := readOpaqueVectorAt(data, offset)
		if err != nil {
			return 0, err
		}
		return next, nil
	case group.ProposalTypeReInit:
		_, next, err := readOpaqueVectorAt(data, offset)
		if err != nil {
			return 0, err
		}
		offset = next
		if len(data) < offset+4 {
			return 0, fmt.Errorf("reinit proposal truncated")
		}
		offset += 4
		_, next, err = readOpaqueVectorAt(data, offset)
		if err != nil {
			return 0, err
		}
		return next, nil
	case group.ProposalTypeExternalInit, group.ProposalTypeGroupContextExtensions:
		_, next, err := readOpaqueVectorAt(data, offset)
		if err != nil {
			return 0, err
		}
		return next, nil
	default:
		return 0, fmt.Errorf("unknown proposal type %d", binary.BigEndian.Uint16(data[:2]))
	}
}

func exactRoundTripLength(data []byte, roundTrip func([]byte) ([]byte, error)) (int, error) {
	for size := 1; size <= len(data); size++ {
		encoded, err := roundTrip(data[:size])
		if err != nil {
			continue
		}
		if bytes.Equal(encoded, data[:size]) {
			return size, nil
		}
	}
	return 0, fmt.Errorf("unable to determine encoded length")
}

func marshalStagedCommit(stagedCommit *group.StagedCommit) ([]byte, error) {
	if stagedCommit == nil {
		return nil, fmt.Errorf("staged commit is nil")
	}
	ac := stagedCommit.AuthenticatedContent()
	if ac == nil {
		return nil, fmt.Errorf("staged commit has no authenticated content")
	}

	message := framing.NewMLSMessagePublic(&framing.PublicMessage{
		Content:       ac.Content,
		Auth:          ac.Auth,
		MembershipTag: stagedCommit.MembershipTag(),
	})
	return message.Marshal(), nil
}

func parseInlineCredential(data []byte) (*credentials.Credential, int, error) {
	if len(data) == 0 {
		return nil, 0, fmt.Errorf("credential data is empty")
	}

	credential, err := credentials.UnmarshalCredential(data)
	if err != nil {
		return nil, 0, err
	}

	size := len(credential.Marshal())
	if size > len(data) {
		return nil, 0, fmt.Errorf("credential exceeds available data")
	}

	return credential, size, nil
}

func marshalExternalSendersExtension(senders ...*externalSender) ([]byte, error) {
	var inner []byte
	for _, sender := range senders {
		if sender == nil {
			return nil, fmt.Errorf("external sender is nil")
		}
		if len(sender.signatureKey) == 0 {
			return nil, fmt.Errorf("external sender signature key is empty")
		}
		if sender.credential == nil {
			return nil, fmt.Errorf("external sender credential is nil")
		}

		signatureKey, err := encodeOpaqueVector(sender.signatureKey)
		if err != nil {
			return nil, fmt.Errorf("encode external sender signature key: %w", err)
		}

		inner = append(inner, signatureKey...)
		inner = append(inner, sender.credential.Marshal()...)
	}

	return encodeOpaqueVector(inner)
}

func parseExternalSendersExtensionData(data []byte) ([]*externalSender, error) {
	inner, err := readOpaqueVector(data)
	if err != nil {
		return nil, fmt.Errorf("read external senders vector: %w", err)
	}

	senders := make([]*externalSender, 0)
	for len(inner) > 0 {
		signatureKey, next, err := readOpaqueVectorAt(inner, 0)
		if err != nil {
			return nil, fmt.Errorf("read external sender signature key: %w", err)
		}

		credential, consumed, err := parseInlineCredential(inner[next:])
		if err != nil {
			return nil, fmt.Errorf("read external sender credential: %w", err)
		}

		publicKey, err := ciphersuite.NewSignaturePublicKey(signatureKey).ToECDSA()
		if err != nil {
			return nil, fmt.Errorf("parse external sender public key: %w", err)
		}

		senders = append(senders, &externalSender{
			signatureKey: append([]byte(nil), signatureKey...),
			credential:   credential,
			publicKey:    publicKey,
		})

		inner = inner[next+consumed:]
	}

	return senders, nil
}

func verifyJoinedExternalSender(joinedGroup *group.Group, expected *externalSender) error {
	if joinedGroup == nil {
		return fmt.Errorf("joined group is nil")
	}
	if expected == nil {
		return fmt.Errorf("expected external sender is nil")
	}

	context := joinedGroup.GroupContext()
	if context == nil {
		return fmt.Errorf("joined group has no group context")
	}

	var senders []*externalSender
	for _, candidate := range context.Extensions {
		if candidate.Type != mlsext.ExtensionTypeExternalSenders {
			continue
		}
		parsed, err := parseExternalSendersExtensionData(candidate.Data)
		if err != nil {
			return fmt.Errorf("parse external senders extension: %w", err)
		}
		senders = parsed
		break
	}
	if senders == nil {
		return fmt.Errorf("missing external senders extension")
	}
	if len(senders) != 1 {
		return fmt.Errorf("expected exactly one external sender, got %d", len(senders))
	}

	sender := senders[0]
	if sender.credential == nil {
		return fmt.Errorf("joined group external sender has no credential")
	}
	if !bytes.Equal(sender.credential.Marshal(), expected.credential.Marshal()) {
		return fmt.Errorf("joined group external sender credential mismatch")
	}
	if sender.publicKey == nil {
		return fmt.Errorf("joined group external sender has no public key")
	}
	gotECDH, err := sender.publicKey.ECDH()
	if err != nil {
		return fmt.Errorf("convert joined external sender key: %w", err)
	}
	expectedECDH, err := expected.publicKey.ECDH()
	if err != nil {
		return fmt.Errorf("convert expected external sender key: %w", err)
	}
	if !bytes.Equal(gotECDH.Bytes(), expectedECDH.Bytes()) {
		return fmt.Errorf("joined group external sender public key mismatch")
	}
	return nil
}

func (s *DAVESession) createPendingGroupLocked() error {
	if s.externalSender == nil {
		return fmt.Errorf("external sender is not set")
	}

	externalSenderData, err := marshalExternalSendersExtension(s.externalSender)
	if err != nil {
		return fmt.Errorf("serialize external sender extension: %w", err)
	}

	newGroup, err := group.NewGroupWithExtensions(
		group.NewGroupID(channelIDBytes(s.channelIDNum)),
		s.cipherSuite,
		s.memberKeyPackage,
		s.memberPrivKeys,
		[]group.Extension{{
			Type: mlsext.ExtensionTypeExternalSenders,
			Data: externalSenderData,
		}},
	)
	if err != nil {
		return fmt.Errorf("create pending group: %w", err)
	}

	s.group = newGroup
	s.status = SessionStatusPending
	s.ready = false
	s.privacyCode = ""
	s.pendingGroupState = nil
	return nil
}

func (s *DAVESession) updateRatchetsLocked() error {
	if s.group == nil {
		return fmt.Errorf("group is nil")
	}

	currentMembers := make(map[uint64]struct{})
	for _, member := range s.group.GetMembers() {
		userID, err := userIDFromCredential(member.Credential)
		if err != nil {
			return err
		}
		currentMembers[userID] = struct{}{}

		baseSecret, err := s.group.Export(userMediaKeyBaseLabel, uint64ToLEBytes(userID), aesGCM128KeyBytes)
		if err != nil {
			return fmt.Errorf("export base secret for user %d: %w", userID, err)
		}
		ratchet := newHashRatchet(baseSecret)

		if userID == s.userIDNum {
			s.encryptor.setKeyRatchet(ratchet)
			continue
		}

		decryptor := s.decryptors[userID]
		if decryptor == nil {
			decryptor = newDecryptor()
			s.decryptors[userID] = decryptor
		}
		decryptor.transitionToKeyRatchet(ratchet)
		decryptor.transitionToPassthroughMode(s.passthroughMode, s.passthroughTransition)
	}

	for userID := range s.decryptors {
		if _, ok := currentMembers[userID]; !ok {
			delete(s.decryptors, userID)
		}
	}

	privacyCode, err := GenerateDisplayableCode(s.group.EpochAuthenticator(), 30, 5)
	if err != nil {
		return fmt.Errorf("generate voice privacy code: %w", err)
	}
	s.privacyCode = privacyCode
	s.ready = true
	return nil
}

func (s *DAVESession) processProposalsLocked(
	operationType ProposalsOperationType,
	payload []byte,
	recognizedUserIDs []string,
) (*CommitWelcome, error) {
	if s.group == nil {
		return nil, fmt.Errorf("session has no group")
	}

	if len(s.pendingGroupState) > 0 {
		restoredGroup, err := group.UnmarshalGroupState(s.pendingGroupState)
		if err != nil {
			return nil, fmt.Errorf("restore group before processing proposals: %w", err)
		}
		s.group = restoredGroup
	}

	var recognized map[uint64]struct{}
	if recognizedUserIDs != nil {
		recognized = make(map[uint64]struct{}, len(recognizedUserIDs))
		for _, rawUserID := range recognizedUserIDs {
			userID, err := strconv.ParseUint(rawUserID, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("parse recognized user id %q: %w", rawUserID, err)
			}
			recognized[userID] = struct{}{}
		}
	}

	vector, err := readOpaqueVector(payload)
	if err != nil {
		return nil, fmt.Errorf("parse proposals vector: %w", err)
	}

	switch operationType {
	case ProposalsAppend:
		for len(vector) > 0 {
			messageBytes, rest, err := consumeMLSMessage(vector)
			if err != nil {
				return nil, fmt.Errorf("parse MLS proposal message: %w", err)
			}
			vector = rest

			message, err := framing.UnmarshalMLSMessage(messageBytes)
			if err != nil {
				return nil, fmt.Errorf("unmarshal MLS proposal message: %w", err)
			}

			if publicMessage, ok := message.AsPublic(); ok {
				if publicMessage.Content.ContentType() != framing.ContentTypeProposal {
					return nil, fmt.Errorf("received public MLS message with content type %d", publicMessage.Content.ContentType())
				}
				if recognized != nil {
					body, ok := publicMessage.Content.Body.(framing.ProposalBody)
					if !ok {
						return nil, fmt.Errorf("invalid public proposal body")
					}
					proposal, err := group.UnmarshalProposal(body.Data)
					if err != nil {
						return nil, fmt.Errorf("unmarshal public proposal: %w", err)
					}
					if proposal.Type == group.ProposalTypeAdd && proposal.Add != nil && proposal.Add.KeyPackage != nil && proposal.Add.KeyPackage.LeafNode != nil {
						userID, err := userIDFromCredential(proposal.Add.KeyPackage.LeafNode.Credential)
						if err != nil {
							return nil, err
						}
						if _, ok := recognized[userID]; !ok {
							return nil, fmt.Errorf("proposal contained unexpected user %d", userID)
						}
					}
				}
				if err := s.group.ProcessPublicMessage(publicMessage); err != nil {
					return nil, fmt.Errorf("process public proposal message: %w", err)
				}
				continue
			}

			privateMessage, ok := message.AsPrivate()
			if !ok {
				return nil, fmt.Errorf("proposal message is neither public nor private")
			}
			if privateMessage.ContentType != framing.ContentTypeProposal {
				return nil, fmt.Errorf("received private MLS message with content type %d", privateMessage.ContentType)
			}
			if err := s.group.ProcessPrivateMessage(privateMessage); err != nil {
				return nil, fmt.Errorf("process private proposal message: %w", err)
			}
		}
	case ProposalsRevoke:
		for len(vector) > 0 {
			ref, next, err := readOpaqueVectorAt(vector, 0)
			if err != nil {
				return nil, fmt.Errorf("parse proposal ref: %w", err)
			}
			vector = vector[next:]
			s.group.RevokeProposal(ref)
		}
	default:
		return nil, fmt.Errorf("unsupported proposal operation type %d", operationType)
	}

	storedProposals := s.group.StoredProposals()
	if len(storedProposals) == 0 {
		s.group.ClearProposals()
		s.pendingGroupState = nil
		s.pendingStagedCommit = nil
		if s.ready {
			s.status = SessionStatusActive
		} else {
			s.status = SessionStatusPending
		}
		return nil, nil
	}

	pendingState, err := s.group.MarshalState()
	if err != nil {
		return nil, fmt.Errorf("snapshot group before commit: %w", err)
	}
	stagedCommit, err := s.group.Commit(s.sigPrivKey, s.sigPubKey, nil)
	if err != nil {
		return nil, fmt.Errorf("create commit from proposals: %w", err)
	}
	commitBytes, err := marshalStagedCommit(stagedCommit)
	if err != nil {
		return nil, err
	}

	s.pendingGroupState = pendingState
	s.pendingStagedCommit = stagedCommit
	s.status = SessionStatusAwaitingResponse

	var welcomeBytes []byte
	var addKeyPackages []*keypackages.KeyPackage
	for _, proposal := range stagedCommit.Proposals() {
		if proposal.Type == group.ProposalTypeAdd && proposal.Add != nil && proposal.Add.KeyPackage != nil {
			addKeyPackages = append(addKeyPackages, proposal.Add.KeyPackage)
		}
	}
	if len(addKeyPackages) > 0 {
		welcomeGroup, err := group.UnmarshalGroupState(pendingState)
		if err != nil {
			return nil, fmt.Errorf("restore group for welcome creation: %w", err)
		}
		joinerSecret := stagedCommit.JoinerSecret()
		if err := welcomeGroup.MergeCommit(stagedCommit); err != nil {
			return nil, fmt.Errorf("merge staged commit before welcome creation: %w", err)
		}

		welcome, err := welcomeGroup.CreateWelcomeWithOptions(addKeyPackages, group.CreateWelcomeOptions{
			JoinerSecret:  joinerSecret,
			SignerPrivKey: s.sigPrivKey,
			PskIDs:        stagedCommit.PskIDs(),
			PskSecret:     stagedCommit.RawPskSecret(),
			StagedCommit:  stagedCommit,
		})
		if err != nil {
			return nil, fmt.Errorf("create welcome from staged commit: %w", err)
		}
		welcomeBytes = welcome.Marshal()
	}

	return &CommitWelcome{
		Commit:  commitBytes,
		Welcome: welcomeBytes,
	}, nil
}

func (s *DAVESession) processWelcomeLocked(welcome []byte) error {
	if s.group != nil && s.status == SessionStatusActive {
		return fmt.Errorf("session already has an active group")
	}
	if s.externalSender == nil {
		return fmt.Errorf("external sender is not set")
	}
	if s.joinKeyPackage == nil || s.joinPrivKeys == nil {
		return fmt.Errorf("join key package is not initialized")
	}

	parsedWelcome, err := group.UnmarshalWelcome(welcome)
	if err != nil {
		return fmt.Errorf("unmarshal welcome: %w", err)
	}
	joinedGroup, err := group.JoinFromWelcome(parsedWelcome, s.joinKeyPackage, s.joinPrivKeys, nil)
	if err != nil {
		return fmt.Errorf("join group from welcome: %w", err)
	}
	if err := verifyJoinedExternalSender(joinedGroup, s.externalSender); err != nil {
		return err
	}

	s.group = joinedGroup
	s.status = SessionStatusActive
	s.pendingGroupState = nil
	s.pendingStagedCommit = nil
	s.joinKeyPackage = nil
	s.joinPrivKeys = nil
	return s.updateRatchetsLocked()
}

func (s *DAVESession) processCommitLocked(commit []byte) error {
	if s.group == nil {
		return fmt.Errorf("session has no group")
	}
	if s.status == SessionStatusPending {
		return fmt.Errorf("session is still waiting for a welcome")
	}

	message, err := framing.UnmarshalMLSMessage(commit)
	if err != nil {
		return fmt.Errorf("unmarshal commit message: %w", err)
	}

	mergePending := false
	if publicMessage, ok := message.AsPublic(); ok {
		mergePending = publicMessage.Content.Sender.Type == framing.SenderTypeMember &&
			publicMessage.Content.Sender.LeafIndex == uint32(s.group.OwnLeafIndex()) &&
			s.pendingStagedCommit != nil
	}
	if len(s.pendingGroupState) > 0 {
		restoredGroup, err := group.UnmarshalGroupState(s.pendingGroupState)
		if err != nil {
			return fmt.Errorf("restore group before processing commit: %w", err)
		}
		s.group = restoredGroup
	}

	switch {
	case mergePending:
		if err := s.group.MergeCommit(s.pendingStagedCommit); err != nil {
			return fmt.Errorf("merge own pending commit: %w", err)
		}
	case message.PublicMessage != nil:
		if message.PublicMessage.Content.ContentType() != framing.ContentTypeCommit {
			return fmt.Errorf("expected commit public message, got content type %d", message.PublicMessage.Content.ContentType())
		}
		if err := s.group.ProcessPublicMessage(message.PublicMessage); err != nil {
			return fmt.Errorf("process public commit: %w", err)
		}
	case message.PrivateMessage != nil:
		if message.PrivateMessage.ContentType != framing.ContentTypeCommit {
			return fmt.Errorf("expected commit private message, got content type %d", message.PrivateMessage.ContentType)
		}
		if err := s.group.ProcessPrivateMessage(message.PrivateMessage); err != nil {
			return fmt.Errorf("process private commit: %w", err)
		}
	default:
		return fmt.Errorf("commit message is neither public nor private")
	}

	s.pendingGroupState = nil
	s.pendingStagedCommit = nil
	s.status = SessionStatusActive
	return s.updateRatchetsLocked()
}
