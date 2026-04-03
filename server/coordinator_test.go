package server

import "testing"

type recordedJSONAction struct {
	sessionID string
	op        int
	payload   any
}

type recordedBinaryAction struct {
	sessionID string
	payload   []byte
}

type recordingBroadcaster struct {
	jsons    []recordedJSONAction
	binaries []recordedBinaryAction
}

func (r *recordingBroadcaster) SendJSON(sessionID string, op int, payload any) error {
	r.jsons = append(r.jsons, recordedJSONAction{sessionID: sessionID, op: op, payload: payload})
	return nil
}

func (r *recordingBroadcaster) SendBinary(sessionID string, payload []byte) error {
	r.binaries = append(r.binaries, recordedBinaryAction{
		sessionID: sessionID,
		payload:   append([]byte(nil), payload...),
	})
	return nil
}

func (r *recordingBroadcaster) take() ([]recordedJSONAction, []recordedBinaryAction) {
	jsons := append([]recordedJSONAction(nil), r.jsons...)
	binaries := append([]recordedBinaryAction(nil), r.binaries...)
	r.jsons = nil
	r.binaries = nil
	return jsons, binaries
}

func TestCoordinatorUpgradeAndDowngrade(t *testing.T) {
	b := &recordingBroadcaster{}
	c := NewCoordinator(Config{Enabled: true}, b)

	p1 := Participant{
		SessionID:     "s1",
		UserID:        501,
		ChannelID:     42,
		SignalVersion: SignalProtocolVersion,
		DAVESupported: true,
	}
	p2 := Participant{
		SessionID:     "s2",
		UserID:        502,
		ChannelID:     42,
		SignalVersion: SignalProtocolVersion,
		DAVESupported: true,
	}

	if err := c.Connect(p1); err != nil {
		t.Fatalf("Connect(p1): %v", err)
	}
	jsons, binaries := b.take()
	if len(jsons) != 0 || len(binaries) != 0 {
		t.Fatalf("unexpected actions after first connect: %d json %d binary", len(jsons), len(binaries))
	}

	if err := c.Connect(p2); err != nil {
		t.Fatalf("Connect(p2): %v", err)
	}
	jsons, binaries = b.take()
	if got := countJSONOp(jsons, OpClientsConnect); got != 2 {
		t.Fatalf("clients connect count = %d, want 2", got)
	}
	if got := countJSONOp(jsons, OpDAVEPrepareEpoch); got != 2 {
		t.Fatalf("prepare epoch count = %d, want 2", got)
	}
	if got := countBinaryOp(t, binaries, OpcodeExternalSenderPackage); got != 2 {
		t.Fatalf("external sender count = %d, want 2", got)
	}

	if err := c.HandleKeyPackage("s1", mustFixtureKeyPackage(t, 501)); err != nil {
		t.Fatalf("HandleKeyPackage(s1): %v", err)
	}
	jsons, binaries = b.take()
	if len(jsons) != 0 || len(binaries) != 0 {
		t.Fatalf("unexpected actions after first key package: %d json %d binary", len(jsons), len(binaries))
	}

	if err := c.HandleKeyPackage("s2", mustFixtureKeyPackage(t, 502)); err != nil {
		t.Fatalf("HandleKeyPackage(s2): %v", err)
	}
	_, binaries = b.take()
	if got := countBinaryOp(t, binaries, OpcodeProposals); got != 2 {
		t.Fatalf("proposals count = %d, want 2", got)
	}

	commit := []byte{0x10, 0x11, 0x12, 0x13}
	welcome := []byte{0x20, 0x21, 0x22, 0x23}
	if err := c.HandleCommitWelcome("s1", commit, welcome); err != nil {
		t.Fatalf("HandleCommitWelcome: %v", err)
	}
	_, binaries = b.take()
	if got := countBinaryOp(t, binaries, OpcodeAnnounceCommit); got != 1 {
		t.Fatalf("announce commit count = %d, want 1", got)
	}
	if got := countBinaryOp(t, binaries, OpcodeWelcome); got != 1 {
		t.Fatalf("welcome count = %d, want 1", got)
	}

	var transitionID uint16
	for _, action := range binaries {
		msg, err := DecodeBinaryMessage(action.payload)
		if err != nil {
			t.Fatalf("DecodeBinaryMessage: %v", err)
		}
		if msg.Opcode == OpcodeAnnounceCommit || msg.Opcode == OpcodeWelcome {
			transitionID = msg.TransitionID
			break
		}
	}
	if transitionID == 0 {
		t.Fatal("expected transition id")
	}

	if err := c.HandleTransitionReady("s1", transitionID); err != nil {
		t.Fatalf("HandleTransitionReady(s1): %v", err)
	}
	jsons, binaries = b.take()
	if len(jsons) != 0 || len(binaries) != 0 {
		t.Fatalf("unexpected actions after first ready: %d json %d binary", len(jsons), len(binaries))
	}

	if err := c.HandleTransitionReady("s2", transitionID); err != nil {
		t.Fatalf("HandleTransitionReady(s2): %v", err)
	}
	jsons, _ = b.take()
	if got := countJSONOp(jsons, OpDAVEExecuteTransition); got != 2 {
		t.Fatalf("execute transition count = %d, want 2", got)
	}

	snap := c.Snapshot(42)
	if snap.ProtocolVersion != MaxProtocolVersion || snap.Epoch != 1 || snap.Transitioning {
		t.Fatalf("snapshot after upgrade = %+v", snap)
	}

	p3 := Participant{
		SessionID:     "legacy",
		UserID:        700,
		ChannelID:     42,
		SignalVersion: 1,
		DAVESupported: false,
	}
	if err := c.Connect(p3); err != nil {
		t.Fatalf("Connect(p3): %v", err)
	}
	jsons, _ = b.take()
	if got := countJSONOp(jsons, OpDAVEPrepareTransition); got != 2 {
		t.Fatalf("prepare transition count = %d, want 2", got)
	}

	var downgradeID uint16
	for _, action := range jsons {
		if action.op != OpDAVEPrepareTransition {
			continue
		}
		payload, ok := action.payload.(PrepareTransition)
		if !ok {
			t.Fatalf("prepare transition payload type = %T", action.payload)
		}
		downgradeID = payload.TransitionID
	}
	if downgradeID == 0 {
		t.Fatal("expected downgrade transition id")
	}

	if err := c.HandleTransitionReady("s1", downgradeID); err != nil {
		t.Fatalf("HandleTransitionReady(s1,downgrade): %v", err)
	}
	b.take()
	if err := c.HandleTransitionReady("s2", downgradeID); err != nil {
		t.Fatalf("HandleTransitionReady(s2,downgrade): %v", err)
	}
	jsons, _ = b.take()
	if got := countJSONOp(jsons, OpDAVEExecuteTransition); got != 2 {
		t.Fatalf("execute transition count after downgrade = %d, want 2", got)
	}

	snap = c.Snapshot(42)
	if snap.ProtocolVersion != 0 || snap.Epoch != 0 || snap.Transitioning {
		t.Fatalf("snapshot after downgrade = %+v", snap)
	}
}

func countJSONOp(actions []recordedJSONAction, op int) int {
	count := 0
	for _, action := range actions {
		if action.op == op {
			count++
		}
	}
	return count
}

func countBinaryOp(t *testing.T, actions []recordedBinaryAction, op BinaryOpcode) int {
	t.Helper()

	count := 0
	for _, action := range actions {
		msg, err := DecodeBinaryMessage(action.payload)
		if err != nil {
			t.Fatalf("DecodeBinaryMessage: %v", err)
		}
		if msg.Opcode == op {
			count++
		}
	}
	return count
}
