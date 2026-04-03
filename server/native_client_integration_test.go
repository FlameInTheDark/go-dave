package server

import (
	"bytes"
	"fmt"
	"sort"
	"strconv"
	"testing"

	clientdave "github.com/FlameInTheDark/go-dave"
)

type nativeClientBroadcaster struct {
	coordinator  *Coordinator
	clients      map[string]*clientdave.DAVESession
	participants map[string]Participant
	jsonCounts   map[int]int
	binCounts    map[BinaryOpcode]int

	transitionProtocols map[uint16]int
	lastTransitionID    uint16
}

func newNativeClientBroadcaster(
	clients map[string]*clientdave.DAVESession,
	participants map[string]Participant,
) *nativeClientBroadcaster {
	return &nativeClientBroadcaster{
		clients:             clients,
		participants:        participants,
		jsonCounts:          make(map[int]int),
		binCounts:           make(map[BinaryOpcode]int),
		transitionProtocols: make(map[uint16]int),
	}
}

func (b *nativeClientBroadcaster) SendJSON(sessionID string, op int, payload any) error {
	b.jsonCounts[op]++

	session := b.clients[sessionID]
	if session == nil {
		return nil
	}

	switch op {
	case OpDAVEPrepareEpoch:
		prepare, ok := payload.(PrepareEpoch)
		if !ok {
			return fmt.Errorf("unexpected prepare epoch payload type %T", payload)
		}

		// Native apps typically stage the next session separately. For this
		// integration harness we model that by resetting the current session
		// before the fresh external sender/key package exchange begins.
		if err := session.Reset(); err != nil {
			return fmt.Errorf("reset native client %s for prepare epoch: %w", sessionID, err)
		}
		session.SetPassthroughMode(prepare.ProtocolVersion == 0, 0)

	case OpDAVEPrepareTransition:
		prepare, ok := payload.(PrepareTransition)
		if !ok {
			return fmt.Errorf("unexpected prepare transition payload type %T", payload)
		}

		b.transitionProtocols[prepare.TransitionID] = prepare.ProtocolVersion
		session.SetPassthroughMode(true, 0)
		if err := b.coordinator.HandleTransitionReady(sessionID, prepare.TransitionID); err != nil {
			return fmt.Errorf("coordinator handle transition ready for %s: %w", sessionID, err)
		}

	case OpDAVEExecuteTransition:
		execute, ok := payload.(ExecuteTransition)
		if !ok {
			return fmt.Errorf("unexpected execute transition payload type %T", payload)
		}

		protocolVersion, tracked := b.transitionProtocols[execute.TransitionID]
		if tracked && protocolVersion == 0 {
			if err := session.Reset(); err != nil {
				return fmt.Errorf("reset native client %s after downgrade: %w", sessionID, err)
			}
			session.SetPassthroughMode(true, 0)
		} else if tracked {
			session.SetPassthroughMode(false, 0)
		}
	}

	return nil
}

func (b *nativeClientBroadcaster) SendBinary(sessionID string, payload []byte) error {
	msg, err := DecodeBinaryMessage(payload)
	if err != nil {
		return fmt.Errorf("decode server binary message for %s: %w", sessionID, err)
	}
	b.binCounts[msg.Opcode]++
	if msg.Opcode == OpcodeAnnounceCommit || msg.Opcode == OpcodeWelcome {
		b.lastTransitionID = msg.TransitionID
	}

	session, ok := b.clients[sessionID]
	if !ok {
		return fmt.Errorf("unknown native client session %q", sessionID)
	}

	recognized := b.recognizedUserIDs()
	if msg.Opcode == OpcodeProposals && !clientdave.ShouldBeCommitter(session.UserID(), recognized) {
		return nil
	}

	result, err := session.HandleGatewayBinaryPacket(payload, recognized)
	if err != nil {
		return fmt.Errorf("native client %s handle gateway binary packet: %w", sessionID, err)
	}

	if len(result.KeyPackagePacket) > 0 {
		clientMessage, err := DecodeBinaryMessage(result.KeyPackagePacket)
		if err != nil {
			return fmt.Errorf("decode key package packet from %s: %w", sessionID, err)
		}
		if clientMessage.Opcode != OpcodeKeyPackage || len(clientMessage.Payloads) != 1 {
			return fmt.Errorf("unexpected key package packet from %s", sessionID)
		}
		if err := b.coordinator.HandleKeyPackage(sessionID, clientMessage.Payloads[0]); err != nil {
			return fmt.Errorf("coordinator handle key package for %s: %w", sessionID, err)
		}
	}

	if len(result.CommitWelcomePacket) > 0 && clientdave.ShouldBeCommitter(session.UserID(), recognized) {
		clientMessage, err := DecodeBinaryMessage(result.CommitWelcomePacket)
		if err != nil {
			return fmt.Errorf("decode commit/welcome packet from %s: %w", sessionID, err)
		}
		if clientMessage.Opcode != OpcodeCommitWelcome {
			return fmt.Errorf("unexpected commit/welcome opcode from %s: %d", sessionID, clientMessage.Opcode)
		}
		if err := b.coordinator.HandleCommitWelcome(sessionID, clientMessage.Commit, clientMessage.Welcome); err != nil {
			return fmt.Errorf("coordinator handle commit/welcome for %s: %w", sessionID, err)
		}
	}

	if result.SendTransitionReady && result.TransitionID != nil {
		if err := b.coordinator.HandleTransitionReady(sessionID, *result.TransitionID); err != nil {
			return fmt.Errorf("coordinator handle transition ready for %s: %w", sessionID, err)
		}
	}

	return nil
}

func (b *nativeClientBroadcaster) setParticipant(participant Participant) {
	b.participants[participant.SessionID] = participant
}

func (b *nativeClientBroadcaster) deleteParticipant(sessionID string) {
	delete(b.participants, sessionID)
}

func (b *nativeClientBroadcaster) recognizedUserIDs() []string {
	userIDs := make([]int64, 0, len(b.participants))
	for _, participant := range b.participants {
		if participant.SignalVersion != SignalProtocolVersion || !participant.DAVESupported {
			continue
		}
		userIDs = append(userIDs, participant.UserID)
	}
	sort.Slice(userIDs, func(i, j int) bool { return userIDs[i] < userIDs[j] })

	out := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		out = append(out, strconv.FormatInt(userID, 10))
	}
	return out
}

type nativeIntegrationHarness struct {
	t           *testing.T
	channelID   int64
	coordinator *Coordinator
	broadcaster *nativeClientBroadcaster
	clients     map[string]*clientdave.DAVESession
}

func newNativeIntegrationHarness(t *testing.T, channelID int64) *nativeIntegrationHarness {
	t.Helper()

	alice := mustNewNativeSession(t, 501, channelID)
	bob := mustNewNativeSession(t, 502, channelID)

	participants := map[string]Participant{
		"alice": {
			SessionID:     "alice",
			UserID:        501,
			ChannelID:     channelID,
			SignalVersion: SignalProtocolVersion,
			DAVESupported: true,
		},
		"bob": {
			SessionID:     "bob",
			UserID:        502,
			ChannelID:     channelID,
			SignalVersion: SignalProtocolVersion,
			DAVESupported: true,
		},
	}
	clients := map[string]*clientdave.DAVESession{
		"alice": alice,
		"bob":   bob,
	}

	broadcaster := newNativeClientBroadcaster(clients, participants)
	coordinator := NewCoordinator(Config{Enabled: true}, broadcaster)
	broadcaster.coordinator = coordinator

	return &nativeIntegrationHarness{
		t:           t,
		channelID:   channelID,
		coordinator: coordinator,
		broadcaster: broadcaster,
		clients:     clients,
	}
}

func (h *nativeIntegrationHarness) connect(sessionID string) {
	h.t.Helper()

	participant, ok := h.broadcaster.participants[sessionID]
	if !ok {
		h.t.Fatalf("unknown participant %q", sessionID)
	}
	if err := h.coordinator.Connect(participant); err != nil {
		h.t.Fatalf("Connect(%s): %v", sessionID, err)
	}
}

func (h *nativeIntegrationHarness) connectParticipant(participant Participant) {
	h.t.Helper()

	h.broadcaster.setParticipant(participant)
	if err := h.coordinator.Connect(participant); err != nil {
		h.t.Fatalf("Connect(%s): %v", participant.SessionID, err)
	}
}

func (h *nativeIntegrationHarness) disconnect(sessionID string) {
	h.t.Helper()

	h.broadcaster.deleteParticipant(sessionID)
	if err := h.coordinator.Disconnect(sessionID); err != nil {
		h.t.Fatalf("Disconnect(%s): %v", sessionID, err)
	}
}

func (h *nativeIntegrationHarness) snapshot() Snapshot {
	h.t.Helper()
	return h.coordinator.Snapshot(h.channelID)
}

func (h *nativeIntegrationHarness) assertActive(epoch uint64) {
	h.t.Helper()

	snapshot := h.snapshot()
	if snapshot.ProtocolVersion != MaxProtocolVersion {
		h.t.Fatalf("snapshot protocol version = %d, want %d", snapshot.ProtocolVersion, MaxProtocolVersion)
	}
	if snapshot.Epoch != epoch {
		h.t.Fatalf("snapshot epoch = %d, want %d", snapshot.Epoch, epoch)
	}
	if snapshot.Transitioning {
		h.t.Fatalf("expected transition to be complete, got snapshot %+v", snapshot)
	}

	alice := h.clients["alice"]
	bob := h.clients["bob"]
	if !alice.Ready() || !bob.Ready() {
		h.t.Fatalf("expected both native sessions to be ready, got alice=%t bob=%t", alice.Ready(), bob.Ready())
	}
	if !bytes.Equal(alice.GetEpochAuthenticator(), bob.GetEpochAuthenticator()) {
		h.t.Fatal("expected both native sessions to agree on the epoch authenticator")
	}
	if alice.VoicePrivacyCode() == "" || alice.VoicePrivacyCode() != bob.VoicePrivacyCode() {
		h.t.Fatalf("expected matching non-empty voice privacy codes, got alice=%q bob=%q", alice.VoicePrivacyCode(), bob.VoicePrivacyCode())
	}
}

func (h *nativeIntegrationHarness) assertInactive() {
	h.t.Helper()

	snapshot := h.snapshot()
	if snapshot.ProtocolVersion != 0 || snapshot.Epoch != 0 || snapshot.Transitioning {
		h.t.Fatalf("expected transport-only snapshot, got %+v", snapshot)
	}

	for sessionID, session := range h.clients {
		if session.Ready() {
			h.t.Fatalf("expected %s session to be inactive after downgrade", sessionID)
		}
		if session.VoicePrivacyCode() != "" {
			h.t.Fatalf("expected %s voice privacy code to be cleared, got %q", sessionID, session.VoicePrivacyCode())
		}
		if auth := session.GetEpochAuthenticator(); len(auth) != 0 {
			h.t.Fatalf("expected %s epoch authenticator to be cleared, got %x", sessionID, auth)
		}
	}
}

func (h *nativeIntegrationHarness) assertRoundTrip(senderID, receiverID string) {
	h.t.Helper()

	sender := h.clients[senderID]
	receiver := h.clients[receiverID]
	frame := []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f}
	encrypted, err := sender.EncryptOpus(frame)
	if err != nil {
		h.t.Fatalf("%s EncryptOpus(): %v", senderID, err)
	}
	decrypted, err := receiver.Decrypt(sender.UserID(), clientdave.MediaTypeAudio, encrypted)
	if err != nil {
		h.t.Fatalf("%s Decrypt(%s): %v", receiverID, senderID, err)
	}
	if !bytes.Equal(decrypted, frame) {
		h.t.Fatalf("server/native round-trip mismatch: got %x want %x", decrypted, frame)
	}
}

func mustNewNativeSession(t *testing.T, userID int64, channelID int64) *clientdave.DAVESession {
	t.Helper()

	session, err := clientdave.NewDAVESession(
		clientdave.DAVEProtocolVersion,
		strconv.FormatInt(userID, 10),
		strconv.FormatInt(channelID, 10),
		nil,
	)
	if err != nil {
		t.Fatalf("NewDAVESession(%d): %v", userID, err)
	}
	return session
}

func TestCoordinatorNativeClientsEndToEnd(t *testing.T) {
	h := newNativeIntegrationHarness(t, 4242)

	h.connect("alice")
	h.connect("bob")

	h.assertActive(1)
	h.assertRoundTrip("alice", "bob")

	if got := h.broadcaster.jsonCounts[OpClientsConnect]; got != 2 {
		t.Fatalf("clients connect json count = %d, want 2", got)
	}
	if got := h.broadcaster.jsonCounts[OpDAVEPrepareEpoch]; got != 2 {
		t.Fatalf("prepare epoch json count = %d, want 2", got)
	}
	if got := h.broadcaster.jsonCounts[OpDAVEExecuteTransition]; got != 2 {
		t.Fatalf("execute transition json count = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeExternalSenderPackage]; got != 2 {
		t.Fatalf("external sender binary count = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeProposals]; got != 2 {
		t.Fatalf("proposals binary count = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeAnnounceCommit]; got != 1 {
		t.Fatalf("announce commit binary count = %d, want 1", got)
	}
	if got := h.broadcaster.binCounts[OpcodeWelcome]; got != 1 {
		t.Fatalf("welcome binary count = %d, want 1", got)
	}
}

func TestCoordinatorNativeClientsDowngradeAndReupgrade(t *testing.T) {
	h := newNativeIntegrationHarness(t, 4242)

	h.connect("alice")
	h.connect("bob")
	h.assertActive(1)

	prepareTransitionBefore := h.broadcaster.jsonCounts[OpDAVEPrepareTransition]
	executeTransitionBefore := h.broadcaster.jsonCounts[OpDAVEExecuteTransition]

	h.connectParticipant(Participant{
		SessionID:     "legacy",
		UserID:        700,
		ChannelID:     h.channelID,
		SignalVersion: 1,
		DAVESupported: false,
	})

	if got := h.broadcaster.jsonCounts[OpDAVEPrepareTransition] - prepareTransitionBefore; got != 2 {
		t.Fatalf("prepare transition delta = %d, want 2", got)
	}
	if got := h.broadcaster.jsonCounts[OpDAVEExecuteTransition] - executeTransitionBefore; got != 2 {
		t.Fatalf("execute transition delta after downgrade = %d, want 2", got)
	}
	h.assertInactive()

	prepareEpochBefore := h.broadcaster.jsonCounts[OpDAVEPrepareEpoch]
	executeTransitionBefore = h.broadcaster.jsonCounts[OpDAVEExecuteTransition]
	externalSenderBefore := h.broadcaster.binCounts[OpcodeExternalSenderPackage]
	proposalsBefore := h.broadcaster.binCounts[OpcodeProposals]
	announceBefore := h.broadcaster.binCounts[OpcodeAnnounceCommit]
	welcomeBefore := h.broadcaster.binCounts[OpcodeWelcome]

	h.disconnect("legacy")

	if got := h.broadcaster.jsonCounts[OpDAVEPrepareEpoch] - prepareEpochBefore; got != 2 {
		t.Fatalf("prepare epoch delta after legacy disconnect = %d, want 2", got)
	}
	if got := h.broadcaster.jsonCounts[OpDAVEExecuteTransition] - executeTransitionBefore; got != 2 {
		t.Fatalf("execute transition delta after re-upgrade = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeExternalSenderPackage] - externalSenderBefore; got != 2 {
		t.Fatalf("external sender delta after re-upgrade = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeProposals] - proposalsBefore; got != 2 {
		t.Fatalf("proposals delta after re-upgrade = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeAnnounceCommit] - announceBefore; got != 1 {
		t.Fatalf("announce commit delta after re-upgrade = %d, want 1", got)
	}
	if got := h.broadcaster.binCounts[OpcodeWelcome] - welcomeBefore; got != 1 {
		t.Fatalf("welcome delta after re-upgrade = %d, want 1", got)
	}

	h.assertActive(1)
	h.assertRoundTrip("bob", "alice")
}

func TestCoordinatorNativeClientsInvalidCommitWelcomeRecreatesGroup(t *testing.T) {
	h := newNativeIntegrationHarness(t, 4242)

	h.connect("alice")
	h.connect("bob")
	h.assertActive(1)

	initialAuthenticator := append([]byte(nil), h.clients["alice"].GetEpochAuthenticator()...)
	lastTransitionID := h.broadcaster.lastTransitionID
	if lastTransitionID == 0 {
		t.Fatal("expected initial upgrade to record a transition id")
	}

	prepareEpochBefore := h.broadcaster.jsonCounts[OpDAVEPrepareEpoch]
	executeTransitionBefore := h.broadcaster.jsonCounts[OpDAVEExecuteTransition]
	externalSenderBefore := h.broadcaster.binCounts[OpcodeExternalSenderPackage]
	proposalsBefore := h.broadcaster.binCounts[OpcodeProposals]
	announceBefore := h.broadcaster.binCounts[OpcodeAnnounceCommit]
	welcomeBefore := h.broadcaster.binCounts[OpcodeWelcome]

	if err := h.coordinator.HandleInvalidCommitWelcome("alice", lastTransitionID); err != nil {
		t.Fatalf("HandleInvalidCommitWelcome(alice): %v", err)
	}

	if got := h.broadcaster.jsonCounts[OpDAVEPrepareEpoch] - prepareEpochBefore; got != 2 {
		t.Fatalf("prepare epoch delta after invalid commit/welcome = %d, want 2", got)
	}
	if got := h.broadcaster.jsonCounts[OpDAVEExecuteTransition] - executeTransitionBefore; got != 2 {
		t.Fatalf("execute transition delta after invalid commit/welcome = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeExternalSenderPackage] - externalSenderBefore; got != 2 {
		t.Fatalf("external sender delta after invalid commit/welcome = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeProposals] - proposalsBefore; got != 2 {
		t.Fatalf("proposals delta after invalid commit/welcome = %d, want 2", got)
	}
	if got := h.broadcaster.binCounts[OpcodeAnnounceCommit] - announceBefore; got != 1 {
		t.Fatalf("announce commit delta after invalid commit/welcome = %d, want 1", got)
	}
	if got := h.broadcaster.binCounts[OpcodeWelcome] - welcomeBefore; got != 1 {
		t.Fatalf("welcome delta after invalid commit/welcome = %d, want 1", got)
	}

	h.assertActive(2)
	h.assertRoundTrip("alice", "bob")
	if bytes.Equal(initialAuthenticator, h.clients["alice"].GetEpochAuthenticator()) {
		t.Fatal("expected recreated group to have a new epoch authenticator")
	}
}
