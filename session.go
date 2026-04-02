package dave

import (
	"crypto/ecdsa"
	"fmt"
	"strconv"
	"sync"

	"github.com/thomas-vilte/mls-go/ciphersuite"
	"github.com/thomas-vilte/mls-go/credentials"
	"github.com/thomas-vilte/mls-go/group"
	"github.com/thomas-vilte/mls-go/keypackages"
)

type DAVESession struct {
	mu sync.RWMutex

	protocolVersion uint16
	userID          string
	channelID       string
	userIDNum       uint64
	channelIDNum    uint64
	cipherSuite     ciphersuite.CipherSuite

	signingKey  *SigningKeyPair
	credWithKey *credentials.CredentialWithKey
	sigPrivKey  *ciphersuite.SignaturePrivateKey
	sigPubKey   *ciphersuite.SignaturePublicKey

	memberKeyPackage *keypackages.KeyPackage
	memberPrivKeys   *keypackages.KeyPackagePrivateKeys
	joinKeyPackage   *keypackages.KeyPackage
	joinPrivKeys     *keypackages.KeyPackagePrivateKeys

	externalSender *externalSender
	group          *group.Group
	status         SessionStatus
	ready          bool
	privacyCode    string

	encryptor  *encryptor
	decryptors map[uint64]*decryptor

	pendingGroupState   []byte
	pendingStagedCommit *group.StagedCommit

	passthroughMode       bool
	passthroughTransition uint32
}

type externalSender struct {
	signatureKey []byte
	credential   *credentials.Credential
	publicKey    *ecdsa.PublicKey
}

func NewDAVESession(protocolVersion uint16, userID string, channelID string, keyPair *SigningKeyPair) (*DAVESession, error) {
	userIDNum, channelIDNum, cipherSuite, signingPair, priv, credWithKey, memberKeyPackage, memberPrivKeys, err := buildSessionState(protocolVersion, userID, channelID, keyPair)
	if err != nil {
		return nil, err
	}

	session := &DAVESession{
		protocolVersion: protocolVersion,
		userID:          userID,
		channelID:       channelID,
		userIDNum:       userIDNum,
		channelIDNum:    channelIDNum,
		cipherSuite:     cipherSuite,
		signingKey: &SigningKeyPair{
			Private: append([]byte(nil), signingPair.Private...),
			Public:  append([]byte(nil), signingPair.Public...),
		},
		credWithKey:           credWithKey,
		sigPrivKey:            ciphersuite.NewSignaturePrivateKey(priv),
		sigPubKey:             ciphersuite.NewSignaturePublicKey(signingPair.Public),
		memberKeyPackage:      memberKeyPackage,
		memberPrivKeys:        memberPrivKeys,
		status:                SessionStatusInactive,
		encryptor:             newEncryptor(),
		decryptors:            make(map[uint64]*decryptor),
		passthroughMode:       false,
		passthroughTransition: 10,
	}
	return session, nil
}

func (s *DAVESession) Reinit(protocolVersion uint16, userID string, channelID string, keyPair *SigningKeyPair) error {
	newSession, err := NewDAVESession(protocolVersion, userID, channelID, keyPair)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	externalSender := s.externalSender
	passthroughMode := s.passthroughMode
	passthroughTransition := s.passthroughTransition

	s.protocolVersion = newSession.protocolVersion
	s.userID = newSession.userID
	s.channelID = newSession.channelID
	s.userIDNum = newSession.userIDNum
	s.channelIDNum = newSession.channelIDNum
	s.cipherSuite = newSession.cipherSuite
	s.signingKey = newSession.signingKey
	s.credWithKey = newSession.credWithKey
	s.sigPrivKey = newSession.sigPrivKey
	s.sigPubKey = newSession.sigPubKey
	s.memberKeyPackage = newSession.memberKeyPackage
	s.memberPrivKeys = newSession.memberPrivKeys
	s.joinKeyPackage = newSession.joinKeyPackage
	s.joinPrivKeys = newSession.joinPrivKeys
	s.externalSender = externalSender
	s.group = newSession.group
	s.status = newSession.status
	s.ready = newSession.ready
	s.privacyCode = newSession.privacyCode
	s.encryptor = newSession.encryptor
	s.decryptors = newSession.decryptors
	s.pendingGroupState = newSession.pendingGroupState
	s.pendingStagedCommit = newSession.pendingStagedCommit
	s.passthroughMode = passthroughMode
	s.passthroughTransition = passthroughTransition

	if s.externalSender != nil {
		return s.createPendingGroupLocked()
	}
	return nil
}

func (s *DAVESession) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.group = nil
	s.status = SessionStatusInactive
	s.ready = false
	s.privacyCode = ""
	s.pendingGroupState = nil
	s.pendingStagedCommit = nil
	s.joinKeyPackage = nil
	s.joinPrivKeys = nil
	s.encryptor = newEncryptor()
	s.decryptors = make(map[uint64]*decryptor)
	return nil
}

func (s *DAVESession) ProtocolVersion() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.protocolVersion
}

func (s *DAVESession) UserID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.userID
}

func (s *DAVESession) ChannelID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.channelID
}

func (s *DAVESession) Epoch() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.group == nil {
		return 0
	}
	return uint64(s.group.Epoch())
}

func (s *DAVESession) OwnLeafIndex() (uint32, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.group == nil {
		return 0, false
	}
	return uint32(s.group.OwnLeafIndex()), true
}

func (s *DAVESession) Ciphersuite() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return uint16(s.cipherSuite)
}

func (s *DAVESession) Status() SessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.status
}

func (s *DAVESession) Ready() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ready
}

func (s *DAVESession) VoicePrivacyCode() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.privacyCode
}

func (s *DAVESession) GetEpochAuthenticator() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.group == nil {
		return nil
	}
	return s.group.EpochAuthenticator()
}

func (s *DAVESession) SetExternalSender(data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.status == SessionStatusAwaitingResponse || s.status == SessionStatusActive {
		return fmt.Errorf("cannot set external sender while already in a live group")
	}

	externalSender, err := parseExternalSender(data)
	if err != nil {
		return err
	}
	s.externalSender = externalSender
	return s.createPendingGroupLocked()
}

func (s *DAVESession) GetSerializedKeyPackage() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	keyPackage, privKeys, err := keypackages.Generate(s.credWithKey, s.cipherSuite, keypackages.InfiniteLifetime())
	if err != nil {
		return nil, fmt.Errorf("generate join key package: %w", err)
	}
	s.joinKeyPackage = keyPackage
	s.joinPrivKeys = privKeys
	return keyPackage.Marshal(), nil
}

func (s *DAVESession) CreateAddProposal(keyPackage []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.group == nil {
		return nil, fmt.Errorf("session has no group")
	}
	if s.sigPrivKey == nil {
		return nil, fmt.Errorf("session signing key is not initialized")
	}
	if len(keyPackage) == 0 {
		return nil, fmt.Errorf("key package cannot be empty")
	}

	parsedKeyPackage, err := keypackages.UnmarshalKeyPackage(keyPackage)
	if err != nil {
		return nil, fmt.Errorf("unmarshal key package: %w", err)
	}

	proposal := &group.Proposal{
		Type: group.ProposalTypeAdd,
		Add: &group.AddProposal{
			KeyPackage: parsedKeyPackage,
		},
	}

	message, err := s.group.SignProposalAsPublicMessage(proposal, s.sigPrivKey)
	if err != nil {
		return nil, fmt.Errorf("sign add proposal: %w", err)
	}
	return message, nil
}

func (s *DAVESession) ProcessProposals(operationType ProposalsOperationType, payload []byte, recognizedUserIDs []string) (*CommitWelcome, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processProposalsLocked(operationType, payload, recognizedUserIDs)
}

func (s *DAVESession) ProcessWelcome(welcome []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processWelcomeLocked(welcome)
}

func (s *DAVESession) ProcessCommit(commit []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.processCommitLocked(commit)
}

func (s *DAVESession) GetVerificationCode(userID string) (string, error) {
	fingerprint, err := s.GetPairwiseFingerprint(0, userID)
	if err != nil {
		return "", err
	}
	return GenerateDisplayableCode(fingerprint, 45, 5)
}

func (s *DAVESession) GetPairwiseFingerprint(version uint16, userID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.status == SessionStatusPending || s.group == nil {
		return nil, fmt.Errorf("session has no established group")
	}
	remoteUserID, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse remote user id %q: %w", userID, err)
	}

	var remoteSignatureKey []byte
	for _, member := range s.group.GetMembers() {
		memberUserID, err := userIDFromCredential(member.Credential)
		if err != nil {
			return nil, err
		}
		if memberUserID == remoteUserID {
			remoteSignatureKey = s.group.MemberSigningKey(member.LeafIndex)
			if len(remoteSignatureKey) == 0 && member.KeyPackage != nil && member.KeyPackage.LeafNode != nil {
				remoteSignatureKey = append([]byte(nil), member.KeyPackage.LeafNode.SignatureKeyBytes...)
			}
			break
		}
	}
	if len(remoteSignatureKey) == 0 {
		return nil, fmt.Errorf("user %s is not in the group or has no signature key", userID)
	}

	return GeneratePairwiseFingerprint(version, s.signingKey.Public, s.userIDNum, remoteSignatureKey, remoteUserID)
}

func (s *DAVESession) Encrypt(mediaType MediaType, codec Codec, packet []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.ready {
		return nil, fmt.Errorf("session is not ready")
	}
	if isOpusSilencePacket(packet) {
		return append([]byte(nil), packet...), nil
	}
	return s.encryptor.encrypt(mediaType, codec, packet)
}

func (s *DAVESession) EncryptOpus(packet []byte) ([]byte, error) {
	return s.Encrypt(MediaTypeAudio, CodecOpus, packet)
}

func (s *DAVESession) GetEncryptionStats(mediaType MediaType) EncryptionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.encryptor.statsFor(mediaType)
}

func (s *DAVESession) Decrypt(userID string, mediaType MediaType, packet []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	userIDNum, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse user id %q: %w", userID, err)
	}
	decryptor := s.decryptors[userIDNum]
	if decryptor == nil {
		return nil, fmt.Errorf("no decryptor exists for user %s", userID)
	}
	return decryptor.decrypt(mediaType, packet)
}

func (s *DAVESession) GetDecryptionStats(userID string, mediaType MediaType) (DecryptionStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userIDNum, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return DecryptionStats{}, fmt.Errorf("parse user id %q: %w", userID, err)
	}
	decryptor := s.decryptors[userIDNum]
	if decryptor == nil {
		return DecryptionStats{}, fmt.Errorf("no decryptor exists for user %s", userID)
	}
	return decryptor.statsFor(mediaType), nil
}

func (s *DAVESession) GetUserIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.group == nil {
		return nil
	}
	members := s.group.GetMembers()
	userIDs := make([]string, 0, len(members))
	for _, member := range members {
		userID, err := userIDFromCredential(member.Credential)
		if err != nil {
			continue
		}
		userIDs = append(userIDs, strconv.FormatUint(userID, 10))
	}
	return userIDs
}

func (s *DAVESession) CanPassthrough(userID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	userIDNum, err := strconv.ParseUint(userID, 10, 64)
	if err != nil {
		return false
	}
	decryptor := s.decryptors[userIDNum]
	return decryptor != nil && decryptor.canPassthrough()
}

func (s *DAVESession) SetPassthroughMode(mode bool, transitionExpirySeconds ...uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()

	expiry := uint32(10)
	if len(transitionExpirySeconds) > 0 {
		expiry = transitionExpirySeconds[0]
	}
	s.passthroughMode = mode
	s.passthroughTransition = expiry
	for _, decryptor := range s.decryptors {
		decryptor.transitionToPassthroughMode(mode, expiry)
	}
}
