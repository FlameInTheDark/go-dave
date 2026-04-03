package server

import (
	crand "crypto/rand"
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Coordinator manages server-side DAVE transitions for one or more channels.
type Coordinator struct {
	clock       Clock
	rng         io.Reader
	broadcaster Broadcaster

	sessionToChannel map[string]int64
	channels         map[int64]*channelState
	cfg              Config
	mu               sync.Mutex
}

type channelState struct {
	participants   map[string]*Participant
	keyPackages    map[string]*keyPackage
	externalSender *externalSender
	active         *transitionState

	currentProtocolVersion int
	currentEpoch           uint64
	id                     int64
	groupEstablished       bool

	nextTransitionID uint16
	nextSequence     uint16
}

type transitionState struct {
	timer               Timer
	expectedKeyPackages map[string]bool
	expectedReady       map[string]bool
	kind                transitionKind
	stage               transitionStage
	targetEpoch         uint64
	targetProtocol      int
	id                  uint16
}

type transitionKind string

const (
	transitionKindUpgrade   transitionKind = "upgrade"
	transitionKindDowngrade transitionKind = "downgrade"
	transitionKindRecreate  transitionKind = "recreate"
)

type transitionStage string

const (
	transitionStageAwaitKeyPackages transitionStage = "await_key_packages"
	transitionStageAwaitCommit      transitionStage = "await_commit"
	transitionStageAwaitReady       transitionStage = "await_ready"
)

type outboundAction struct {
	jsonData  any
	sessionID string
	binary    []byte
	op        int
}

// NewCoordinator creates a new server-side DAVE coordinator.
func NewCoordinator(cfg Config, broadcaster Broadcaster) *Coordinator {
	if cfg.TransitionTimeout <= 0 {
		cfg.TransitionTimeout = 2 * time.Second
	}
	if cfg.OldRatchetRetention <= 0 {
		cfg.OldRatchetRetention = 10 * time.Second
	}
	return &Coordinator{
		cfg:              cfg,
		clock:            realClock{},
		rng:              crand.Reader,
		broadcaster:      broadcaster,
		sessionToChannel: make(map[string]int64),
		channels:         make(map[int64]*channelState),
	}
}

// PreviewProtocolVersion reports the protocol version a new participant should
// expect for the given channel.
func (c *Coordinator) PreviewProtocolVersion(channelID int64, supportsDAVE bool) int {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.cfg.Enabled || !supportsDAVE {
		return 0
	}
	ch := c.channels[channelID]
	if ch == nil {
		return 0
	}
	if ch.currentProtocolVersion == MaxProtocolVersion && !ch.hasUnsupportedParticipant() {
		return MaxProtocolVersion
	}
	return 0
}

// Snapshot returns the current DAVE state for a channel.
func (c *Coordinator) Snapshot(channelID int64) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	ch := c.channels[channelID]
	if ch == nil {
		return Snapshot{}
	}
	return Snapshot{
		ProtocolVersion: ch.currentProtocolVersion,
		Epoch:           ch.currentEpoch,
		Transitioning:   ch.active != nil,
	}
}

// Connect registers a participant with the coordinator and broadcasts any
// resulting membership or DAVE transition updates.
func (c *Coordinator) Connect(participant Participant) error {
	actions := make([]outboundAction, 0)

	c.mu.Lock()
	ch := c.getOrCreateChannelLocked(participant.ChannelID)
	isNewUser := !ch.hasUserLocked(participant.UserID)
	ch.participants[participant.SessionID] = participant.clone()
	c.sessionToChannel[participant.SessionID] = participant.ChannelID

	if participant.SignalVersion == SignalProtocolVersion {
		if existing := ch.sortedUniqueUserIDsLocked(participant.SessionID); len(existing) > 0 {
			actions = append(actions, outboundAction{
				sessionID: participant.SessionID,
				op:        OpClientsConnect,
				jsonData:  ClientsConnect{UserIDs: stringifyUserIDs(existing)},
			})
		}
		if isNewUser {
			for _, target := range ch.voiceGatewaySessionIDsLocked(participant.SessionID) {
				actions = append(actions, outboundAction{
					sessionID: target,
					op:        OpClientsConnect,
					jsonData:  ClientsConnect{UserIDs: []string{strconv.FormatInt(participant.UserID, 10)}},
				})
			}
		}
	}

	actions = append(actions, c.reevaluateLocked(ch, "connect")...)
	c.mu.Unlock()

	return c.dispatch(actions)
}

// Disconnect removes a participant from the coordinator and broadcasts any
// resulting membership or DAVE transition updates.
func (c *Coordinator) Disconnect(sessionID string) error {
	actions := make([]outboundAction, 0)

	c.mu.Lock()
	channelID, ok := c.sessionToChannel[sessionID]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	delete(c.sessionToChannel, sessionID)

	ch := c.channels[channelID]
	if ch == nil {
		c.mu.Unlock()
		return nil
	}
	participant, ok := ch.participants[sessionID]
	if !ok {
		c.mu.Unlock()
		return nil
	}
	delete(ch.participants, sessionID)
	delete(ch.keyPackages, sessionID)

	if ch.active != nil {
		delete(ch.active.expectedKeyPackages, sessionID)
		delete(ch.active.expectedReady, sessionID)
	}

	if participant.SignalVersion == SignalProtocolVersion && !ch.hasUserLocked(participant.UserID) {
		payload := ClientDisconnect{UserID: strconv.FormatInt(participant.UserID, 10)}
		for _, target := range ch.voiceGatewaySessionIDsLocked("") {
			actions = append(actions, outboundAction{
				sessionID: target,
				op:        OpClientDisconnect,
				jsonData:  payload,
			})
		}
	}

	if ch.active != nil {
		switch {
		case ch.active.stage == transitionStageAwaitKeyPackages && len(ch.active.expectedKeyPackages) > 0 && ch.haveAllKeyPackagesLocked():
			actions = append(actions, c.broadcastProposalsLocked(ch)...)
		case ch.active.stage == transitionStageAwaitReady && ch.haveAllReadyLocked():
			actions = append(actions, c.executeTransitionLocked(ch)...)
		}
	}

	if len(ch.participants) == 0 {
		c.stopTransitionLocked(ch)
		delete(c.channels, channelID)
		c.mu.Unlock()
		return c.dispatch(actions)
	}

	actions = append(actions, c.reevaluateLocked(ch, "disconnect")...)
	c.mu.Unlock()

	return c.dispatch(actions)
}

// HandleKeyPackage records a client key package and advances the coordinator
// when the channel has all required packages.
func (c *Coordinator) HandleKeyPackage(sessionID string, payload []byte) error {
	actions := make([]outboundAction, 0)

	c.mu.Lock()
	ch, participant, ok := c.lookupParticipantLocked(sessionID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown session")
	}
	if !participant.DAVESupported {
		c.mu.Unlock()
		return fmt.Errorf("session does not support dave")
	}
	kp, err := parseAndValidateKeyPackage(payload, participant.UserID)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	ch.keyPackages[sessionID] = kp

	if ch.active == nil || ch.active.targetProtocol != MaxProtocolVersion {
		c.mu.Unlock()
		return nil
	}
	if ch.active.stage != transitionStageAwaitKeyPackages {
		c.mu.Unlock()
		return nil
	}
	if !ch.haveAllKeyPackagesLocked() {
		c.mu.Unlock()
		return nil
	}

	actions = append(actions, c.broadcastProposalsLocked(ch)...)
	c.mu.Unlock()

	return c.dispatch(actions)
}

// HandleCommitWelcome validates and broadcasts a commit/welcome produced by a
// channel participant.
func (c *Coordinator) HandleCommitWelcome(sessionID string, commit []byte, welcome []byte) error {
	if err := validateCommit(commit); err != nil {
		return err
	}
	if len(welcome) > 0 {
		if err := validateWelcome(welcome); err != nil {
			return err
		}
	}

	actions := make([]outboundAction, 0)

	c.mu.Lock()
	ch, participant, ok := c.lookupParticipantLocked(sessionID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown session")
	}
	if !participant.DAVESupported {
		c.mu.Unlock()
		return fmt.Errorf("session does not support dave")
	}
	if ch.active == nil || ch.active.stage != transitionStageAwaitCommit {
		c.mu.Unlock()
		return fmt.Errorf("unexpected commit welcome")
	}

	ch.active.stage = transitionStageAwaitReady
	ch.active.expectedReady = make(map[string]bool)
	for _, target := range ch.daveSessionIDsLocked() {
		ch.active.expectedReady[target] = false
	}

	if len(welcome) > 0 {
		announceBytes, err := EncodeAnnounceCommitTransition(AnnounceCommitTransition{
			SequenceNumber: ch.nextSequenceLocked(),
			TransitionID:   ch.active.id,
			Commit:         commit,
		})
		if err != nil {
			c.mu.Unlock()
			return err
		}
		actions = append(actions, outboundAction{sessionID: sessionID, binary: announceBytes})

		for _, target := range ch.daveSessionIDsLocked() {
			if target == sessionID {
				continue
			}
			payload, err := EncodeWelcome(Welcome{
				SequenceNumber: ch.nextSequenceLocked(),
				TransitionID:   ch.active.id,
				Welcome:        welcome,
			})
			if err != nil {
				c.mu.Unlock()
				return err
			}
			actions = append(actions, outboundAction{sessionID: target, binary: payload})
		}
	} else {
		announceBytes, err := EncodeAnnounceCommitTransition(AnnounceCommitTransition{
			SequenceNumber: ch.nextSequenceLocked(),
			TransitionID:   ch.active.id,
			Commit:         commit,
		})
		if err != nil {
			c.mu.Unlock()
			return err
		}
		for _, target := range ch.daveSessionIDsLocked() {
			actions = append(actions, outboundAction{sessionID: target, binary: announceBytes})
		}
	}

	transitionID := ch.active.id
	ch.active.timer = c.clock.AfterFunc(c.cfg.TransitionTimeout, func() {
		_ = c.executeTransitionByID(ch.id, transitionID)
	})
	c.mu.Unlock()

	return c.dispatch(actions)
}

// HandleTransitionReady records that a client prepared its media path for a
// transition.
func (c *Coordinator) HandleTransitionReady(sessionID string, transitionID uint16) error {
	actions := make([]outboundAction, 0)

	c.mu.Lock()
	ch, _, ok := c.lookupParticipantLocked(sessionID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown session")
	}
	if ch.active == nil || ch.active.id != transitionID || ch.active.stage != transitionStageAwaitReady {
		c.mu.Unlock()
		return fmt.Errorf("unexpected transition ready")
	}
	ch.active.expectedReady[sessionID] = true
	if ch.haveAllReadyLocked() {
		actions = append(actions, c.executeTransitionLocked(ch)...)
	}
	c.mu.Unlock()

	return c.dispatch(actions)
}

// HandleInvalidCommitWelcome triggers a fresh group recreation after a client
// failed to import commit/welcome data.
func (c *Coordinator) HandleInvalidCommitWelcome(sessionID string, transitionID uint16) error {
	actions := make([]outboundAction, 0)

	c.mu.Lock()
	ch, participant, ok := c.lookupParticipantLocked(sessionID)
	if !ok {
		c.mu.Unlock()
		return fmt.Errorf("unknown session")
	}
	if !participant.DAVESupported {
		c.mu.Unlock()
		return fmt.Errorf("session does not support dave")
	}
	if ch.active != nil && ch.active.id != transitionID {
		c.mu.Unlock()
		return fmt.Errorf("transition mismatch")
	}
	delete(ch.keyPackages, sessionID)
	actions = append(actions, c.beginGroupRecreationLocked(ch, transitionKindRecreate)...)
	c.mu.Unlock()

	return c.dispatch(actions)
}

func (c *Coordinator) executeTransitionByID(channelID int64, transitionID uint16) error {
	actions := make([]outboundAction, 0)

	c.mu.Lock()
	ch := c.channels[channelID]
	if ch == nil || ch.active == nil || ch.active.id != transitionID {
		c.mu.Unlock()
		return nil
	}
	actions = append(actions, c.executeTransitionLocked(ch)...)
	c.mu.Unlock()

	return c.dispatch(actions)
}

func (c *Coordinator) reevaluateLocked(ch *channelState, reason string) []outboundAction {
	switch {
	case !c.cfg.Enabled:
		if ch.currentProtocolVersion != 0 || ch.active != nil {
			return c.beginDowngradeLocked(ch)
		}
		return nil
	case ch.hasUnsupportedParticipant():
		if ch.currentProtocolVersion == MaxProtocolVersion || (ch.active != nil && ch.active.targetProtocol == MaxProtocolVersion) {
			return c.beginDowngradeLocked(ch)
		}
		return nil
	}

	daveSessions := ch.daveSessionIDsLocked()
	if len(daveSessions) < 2 {
		return nil
	}

	if ch.currentProtocolVersion == 0 {
		return c.beginGroupRecreationLocked(ch, transitionKindUpgrade)
	}
	if reason == "connect" || reason == "disconnect" {
		return c.beginGroupRecreationLocked(ch, transitionKindRecreate)
	}
	return nil
}

func (c *Coordinator) beginGroupRecreationLocked(ch *channelState, kind transitionKind) []outboundAction {
	if !c.cfg.Enabled {
		return nil
	}
	sessions := ch.daveSessionIDsLocked()
	if len(sessions) == 0 {
		return nil
	}
	if ch.hasUnsupportedParticipant() {
		return nil
	}
	if ch.active != nil && ch.active.targetProtocol == MaxProtocolVersion {
		return nil
	}

	c.stopTransitionLocked(ch)
	if ch.externalSender == nil {
		externalSender, err := c.newExternalSenderLocked()
		if err != nil {
			return nil
		}
		ch.externalSender = externalSender
	}

	ch.active = &transitionState{
		id:                  ch.nextTransitionIDLocked(),
		kind:                kind,
		targetProtocol:      MaxProtocolVersion,
		targetEpoch:         max(ch.currentEpoch+1, 1),
		stage:               transitionStageAwaitKeyPackages,
		expectedKeyPackages: make(map[string]bool),
	}
	for _, sessionID := range sessions {
		delete(ch.keyPackages, sessionID)
		ch.active.expectedKeyPackages[sessionID] = false
	}

	actions := make([]outboundAction, 0, len(sessions)*2)
	prepare := PrepareEpoch{
		ProtocolVersion: MaxProtocolVersion,
		Epoch:           ch.active.targetEpoch,
	}
	for _, target := range sessions {
		actions = append(actions, outboundAction{sessionID: target, op: OpDAVEPrepareEpoch, jsonData: prepare})
	}

	externalSenderBytes, err := EncodeExternalSenderPackage(ExternalSenderPackage{
		SequenceNumber: ch.nextSequenceLocked(),
		ExternalSender: ExternalSender{
			SignatureKey:   append([]byte(nil), ch.externalSender.PublicKey...),
			CredentialType: CredentialTypeBasic,
			Identity:       append([]byte(nil), ch.externalSender.Identity...),
		},
	})
	if err == nil {
		for _, target := range sessions {
			actions = append(actions, outboundAction{sessionID: target, binary: externalSenderBytes})
		}
	}
	return actions
}

func (c *Coordinator) beginDowngradeLocked(ch *channelState) []outboundAction {
	if ch.currentProtocolVersion == 0 && (ch.active == nil || ch.active.targetProtocol == 0) {
		return nil
	}

	sessions := ch.daveSessionIDsLocked()
	c.stopTransitionLocked(ch)
	ch.active = &transitionState{
		id:             ch.nextTransitionIDLocked(),
		kind:           transitionKindDowngrade,
		targetProtocol: 0,
		targetEpoch:    0,
		stage:          transitionStageAwaitReady,
		expectedReady:  make(map[string]bool),
	}
	for _, sessionID := range sessions {
		ch.active.expectedReady[sessionID] = false
	}

	if len(sessions) == 0 {
		ch.currentProtocolVersion = 0
		ch.currentEpoch = 0
		ch.groupEstablished = false
		ch.active = nil
		return nil
	}

	actions := make([]outboundAction, 0, len(sessions))
	payload := PrepareTransition{
		ProtocolVersion: 0,
		TransitionID:    ch.active.id,
	}
	for _, target := range sessions {
		actions = append(actions, outboundAction{sessionID: target, op: OpDAVEPrepareTransition, jsonData: payload})
	}
	ch.active.timer = c.clock.AfterFunc(c.cfg.TransitionTimeout, func() {
		_ = c.executeTransitionByID(ch.id, payload.TransitionID)
	})
	return actions
}

func (c *Coordinator) broadcastProposalsLocked(ch *channelState) []outboundAction {
	if ch.active == nil || ch.active.stage != transitionStageAwaitKeyPackages {
		return nil
	}

	ch.active.stage = transitionStageAwaitCommit
	targets := ch.daveSessionIDsLocked()
	actions := make([]outboundAction, 0, len(targets))
	for _, target := range targets {
		payloads := make([][]byte, 0, len(targets)-1)
		for _, sessionID := range sortedKeys(ch.active.expectedKeyPackages) {
			if sessionID == target {
				continue
			}
			kp := ch.keyPackages[sessionID]
			if kp == nil {
				continue
			}
			proposal, _, err := buildExternalAddProposal(ch.id, 0, 0, ch.externalSender, kp)
			if err != nil {
				return nil
			}
			payloads = append(payloads, proposal)
		}
		if len(payloads) == 0 {
			continue
		}
		proposalsBytes, err := EncodeProposals(Proposals{
			SequenceNumber:   ch.nextSequenceLocked(),
			OperationType:    ProposalsAppend,
			ProposalMessages: payloads,
		})
		if err != nil {
			return nil
		}
		actions = append(actions, outboundAction{sessionID: target, binary: proposalsBytes})
	}
	return actions
}

func (c *Coordinator) executeTransitionLocked(ch *channelState) []outboundAction {
	if ch.active == nil {
		return nil
	}
	transitionID := ch.active.id
	c.stopTransitionLocked(ch)

	if ch.active.targetProtocol == MaxProtocolVersion {
		ch.currentProtocolVersion = MaxProtocolVersion
		ch.currentEpoch = ch.active.targetEpoch
		ch.groupEstablished = true
	} else {
		ch.currentProtocolVersion = 0
		ch.currentEpoch = 0
		ch.groupEstablished = false
	}

	actions := make([]outboundAction, 0, len(ch.daveSessionIDsLocked()))
	payload := ExecuteTransition{TransitionID: transitionID}
	for _, target := range ch.daveSessionIDsLocked() {
		actions = append(actions, outboundAction{sessionID: target, op: OpDAVEExecuteTransition, jsonData: payload})
	}
	ch.active = nil
	return actions
}

func (c *Coordinator) dispatch(actions []outboundAction) error {
	for _, action := range actions {
		var err error
		switch {
		case len(action.binary) > 0:
			err = c.broadcaster.SendBinary(action.sessionID, action.binary)
		case action.op != 0:
			err = c.broadcaster.SendJSON(action.sessionID, action.op, action.jsonData)
		default:
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *Coordinator) getOrCreateChannelLocked(channelID int64) *channelState {
	if ch := c.channels[channelID]; ch != nil {
		return ch
	}
	ch := &channelState{
		id:                     channelID,
		participants:           make(map[string]*Participant),
		keyPackages:            make(map[string]*keyPackage),
		currentProtocolVersion: 0,
	}
	c.channels[channelID] = ch
	return ch
}

func (c *Coordinator) lookupParticipantLocked(sessionID string) (*channelState, *Participant, bool) {
	channelID, ok := c.sessionToChannel[sessionID]
	if !ok {
		return nil, nil, false
	}
	ch := c.channels[channelID]
	if ch == nil {
		return nil, nil, false
	}
	participant, ok := ch.participants[sessionID]
	return ch, participant, ok
}

func (c *Coordinator) newExternalSenderLocked() (*externalSender, error) {
	return newExternalSender([]byte("go-dave-server"))
}

func (c *Coordinator) stopTransitionLocked(ch *channelState) {
	if ch.active != nil && ch.active.timer != nil {
		ch.active.timer.Stop()
		ch.active.timer = nil
	}
}

func (p Participant) clone() *Participant {
	cp := p
	if p.IdentityKey != nil {
		keyCopy := *p.IdentityKey
		keyCopy.PublicKey = append([]byte(nil), p.IdentityKey.PublicKey...)
		cp.IdentityKey = &keyCopy
	}
	return &cp
}

func (c *channelState) nextTransitionIDLocked() uint16 {
	c.nextTransitionID++
	if c.nextTransitionID == 0 {
		c.nextTransitionID = 1
	}
	return c.nextTransitionID
}

func (c *channelState) nextSequenceLocked() uint16 {
	c.nextSequence++
	return c.nextSequence
}

func (c *channelState) daveSessionIDsLocked() []string {
	out := make([]string, 0, len(c.participants))
	for sessionID, participant := range c.participants {
		if participant.DAVESupported && participant.SignalVersion == SignalProtocolVersion {
			out = append(out, sessionID)
		}
	}
	sort.Strings(out)
	return out
}

func (c *channelState) voiceGatewaySessionIDsLocked(exclude string) []string {
	out := make([]string, 0, len(c.participants))
	for sessionID, participant := range c.participants {
		if participant.SignalVersion != SignalProtocolVersion || sessionID == exclude {
			continue
		}
		out = append(out, sessionID)
	}
	sort.Strings(out)
	return out
}

func (c *channelState) hasUnsupportedParticipant() bool {
	for _, participant := range c.participants {
		if participant.SignalVersion != SignalProtocolVersion || !participant.DAVESupported {
			return true
		}
	}
	return false
}

func (c *channelState) sortedUniqueUserIDsLocked(excludeSessionID string) []int64 {
	uniq := make(map[int64]struct{})
	for sessionID, participant := range c.participants {
		if sessionID == excludeSessionID {
			continue
		}
		uniq[participant.UserID] = struct{}{}
	}
	out := make([]int64, 0, len(uniq))
	for userID := range uniq {
		out = append(out, userID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (c *channelState) hasUserLocked(userID int64) bool {
	for _, participant := range c.participants {
		if participant.UserID == userID {
			return true
		}
	}
	return false
}

func (c *channelState) haveAllKeyPackagesLocked() bool {
	if c.active == nil {
		return false
	}
	for sessionID := range c.active.expectedKeyPackages {
		if c.keyPackages[sessionID] == nil {
			return false
		}
	}
	return true
}

func (c *channelState) haveAllReadyLocked() bool {
	if c.active == nil {
		return false
	}
	for _, ready := range c.active.expectedReady {
		if !ready {
			return false
		}
	}
	return true
}

func stringifyUserIDs(userIDs []int64) []string {
	out := make([]string, 0, len(userIDs))
	for _, userID := range userIDs {
		out = append(out, strconv.FormatInt(userID, 10))
	}
	return out
}

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for key := range values {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
