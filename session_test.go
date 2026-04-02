package dave

import (
	"bytes"
	"encoding/hex"
	"testing"
)

const (
	testChannelID   = "927310423890473011"
	testMyUserID    = "158049329150427136"
	testOtherUserID = "158533742254751744"
)

var (
	testExternalSender     = mustDecodeHex("404104ca1a2b102501d0672bd45ed74ffb83e078b2ba5b12c3f69fad56f083b6a35fc989c6736b5852b5aecdfcdf206e156d3d1dba8e3e5b2f89fc0c16f11614e84e4a00010100")
	testAppendingProposals = mustDecodeHex("41f000010001080cde77eadc823033000000000000000002000000000002000100010002404104a61acd34ff0548e6f767cc4df9619b51ba5814d52ee558284fc554405768e9e741ba32276414941b7c0190dcb5dfc3349a168f1247ecbdf6fc69f3eecab3765d404104f44da24e5aa9f73796fa38be115556e6b7d4f6ba55d2ecc3f1b9d198af6237e3fc8fc635996b6c76e77b4acace33f5cfd745ad0d540dd6f03f0da85c82e14714404104e7793985ed074af49568b53cf2e3974688279f02ee8d7c7df099ce3c7a1a28e747f59a7c7c23e9ef4f7815fb3469f39ea124f8b76712c41b763a55b867e6b48b00010802333999400200000200010200020000020001010000000000000000ffffffffffffffff0040483046022100d874dc777d4ede7e6d3374f737bc1394ac0ffd0635abdc9d02b3e359e059466a022100e62e97aefd5c6b32ff0ac5c5159dbe94f6f5a01bd0dd14a9dcc4d1e6248972ac004047304502205168abdf8d83a48daf8d5960afb305022de707c7496087feb43004c9fd2be5e80221008312a6f6df1ff593671a39f9966f6d1caef43e0c6d53c74300ba089ceeecfbf440473045022100cdbe804ba06a9be17615fe3c7f9055f31a6d0ea9402dd9fda6d109e9a3cb632b022067409e59f6b7f0a3eddd330a092a6c13d99d12abaebe0d6d40a0dae435c2a7a2")
	testRevokingProposals  = mustDecodeHex("212062386ffb20b28f556b2465c0a2520ba2b074fca00e94b2fdebc0496d544cd6c0")
	testSilenceFrame       = []byte(opusSilencePacket)
)

func TestNewDAVESession(t *testing.T) {
	session := createTestSession(t, SessionStatusInactive)

	if session.ProtocolVersion() != DAVEProtocolVersion {
		t.Fatalf("unexpected protocol version: %d", session.ProtocolVersion())
	}
	if session.UserID() != testMyUserID {
		t.Fatalf("unexpected user id: %s", session.UserID())
	}
	if session.ChannelID() != testChannelID {
		t.Fatalf("unexpected channel id: %s", session.ChannelID())
	}
	if session.Status() != SessionStatusInactive {
		t.Fatalf("unexpected status: %d", session.Status())
	}
}

func TestSetExternalSenderAndKeyPackages(t *testing.T) {
	session := createTestSession(t, SessionStatusInactive)

	if err := session.SetExternalSender(testExternalSender); err != nil {
		t.Fatalf("SetExternalSender() failed: %v", err)
	}
	if session.Status() != SessionStatusPending {
		t.Fatalf("unexpected status after external sender: %d", session.Status())
	}

	first, err := session.GetSerializedKeyPackage()
	if err != nil {
		t.Fatalf("GetSerializedKeyPackage() failed: %v", err)
	}
	second, err := session.GetSerializedKeyPackage()
	if err != nil {
		t.Fatalf("second GetSerializedKeyPackage() failed: %v", err)
	}

	if len(first) < 300 {
		t.Fatalf("unexpectedly small key package: %d bytes", len(first))
	}
	if bytes.Equal(first, second) {
		t.Fatal("expected newly generated key packages to differ")
	}
}

func TestProcessProposalsAndCommit(t *testing.T) {
	session := createTestSession(t, SessionStatusPending)

	commitWelcome, err := session.ProcessProposals(ProposalsAppend, testAppendingProposals, nil)
	if err != nil {
		t.Fatalf("ProcessProposals(APPEND) failed: %v", err)
	}
	if commitWelcome == nil || len(commitWelcome.Commit) == 0 {
		t.Fatal("expected a commit to be returned")
	}
	if len(commitWelcome.Welcome) == 0 {
		t.Fatal("expected a welcome to be returned")
	}
	if session.Status() != SessionStatusAwaitingResponse {
		t.Fatalf("unexpected status after proposals: %d", session.Status())
	}

	if _, err := createTestSession(t, SessionStatusPending).ProcessProposals(
		ProposalsAppend,
		testAppendingProposals,
		[]string{testOtherUserID},
	); err != nil {
		t.Fatalf("recognized user IDs should be accepted: %v", err)
	}

	if _, err := createTestSession(t, SessionStatusPending).ProcessProposals(
		ProposalsAppend,
		testAppendingProposals,
		[]string{},
	); err == nil {
		t.Fatal("expected unrecognized proposal add to fail")
	}

	revokedSession := createTestSession(t, SessionStatusPending)
	if _, err := revokedSession.ProcessProposals(ProposalsAppend, testAppendingProposals, nil); err != nil {
		t.Fatalf("ProcessProposals(APPEND) on revoked session failed: %v", err)
	}
	if result, err := revokedSession.ProcessProposals(ProposalsRevoke, testRevokingProposals, nil); err != nil {
		t.Fatalf("ProcessProposals(REVOKE) failed: %v", err)
	} else if result != nil {
		t.Fatalf("expected revoked proposals path to produce no commit, got %#v", result)
	}
	if revokedSession.Status() == SessionStatusAwaitingResponse {
		t.Fatal("revoking pending proposals should clear the awaiting-response state")
	}

	if err := session.ProcessCommit(commitWelcome.Commit); err != nil {
		t.Fatalf("ProcessCommit() failed: %v", err)
	}
	if session.Status() != SessionStatusActive {
		t.Fatalf("unexpected status after commit: %d", session.Status())
	}
	if !session.Ready() {
		t.Fatal("session should be ready after processing commit")
	}
}

func TestActiveSessionHelpers(t *testing.T) {
	active := createTestSession(t, SessionStatusActive)

	if active.VoicePrivacyCode() == "" {
		t.Fatal("expected non-empty voice privacy code on active session")
	}

	userIDs := active.GetUserIDs()
	if len(userIDs) != 2 {
		t.Fatalf("unexpected member count: %d", len(userIDs))
	}
	memberSet := map[string]struct{}{}
	for _, userID := range userIDs {
		memberSet[userID] = struct{}{}
	}
	if _, ok := memberSet[testMyUserID]; !ok {
		t.Fatalf("expected user ids to contain %s, got %#v", testMyUserID, userIDs)
	}
	if _, ok := memberSet[testOtherUserID]; !ok {
		t.Fatalf("unexpected user ids: %#v", userIDs)
	}

	encrypted, err := active.EncryptOpus(testSilenceFrame)
	if err != nil {
		t.Fatalf("EncryptOpus() failed: %v", err)
	}
	if !bytes.Equal(encrypted, testSilenceFrame) {
		t.Fatal("expected opus silence frame to pass through encryption unchanged")
	}

	decrypted, err := active.Decrypt(testOtherUserID, MediaTypeAudio, testSilenceFrame)
	if err != nil {
		t.Fatalf("Decrypt() failed: %v", err)
	}
	if !bytes.Equal(decrypted, testSilenceFrame) {
		t.Fatal("expected opus silence frame to pass through decryption unchanged")
	}

	encryptionStats := active.GetEncryptionStats(MediaTypeAudio)
	if encryptionStats != (EncryptionStats{}) {
		t.Fatalf("unexpected initial encryption stats: %#v", encryptionStats)
	}

	decryptionStats, err := active.GetDecryptionStats(testOtherUserID, MediaTypeAudio)
	if err != nil {
		t.Fatalf("GetDecryptionStats() failed: %v", err)
	}
	if decryptionStats != (DecryptionStats{}) {
		t.Fatalf("unexpected initial decryption stats: %#v", decryptionStats)
	}
}

func createTestSession(t *testing.T, status SessionStatus) *DAVESession {
	t.Helper()

	session, err := NewDAVESession(DAVEProtocolVersion, testMyUserID, testChannelID, nil)
	if err != nil {
		t.Fatalf("NewDAVESession() failed: %v", err)
	}

	switch status {
	case SessionStatusInactive:
		return session
	case SessionStatusPending:
		if err := session.SetExternalSender(testExternalSender); err != nil {
			t.Fatalf("SetExternalSender() failed: %v", err)
		}
		if _, err := session.GetSerializedKeyPackage(); err != nil {
			t.Fatalf("GetSerializedKeyPackage() failed: %v", err)
		}
		return session
	case SessionStatusAwaitingResponse:
		session = createTestSession(t, SessionStatusPending)
		if _, err := session.ProcessProposals(ProposalsAppend, testAppendingProposals, nil); err != nil {
			t.Fatalf("ProcessProposals() failed: %v", err)
		}
		return session
	case SessionStatusActive:
		session = createTestSession(t, SessionStatusPending)
		commitWelcome, err := session.ProcessProposals(ProposalsAppend, testAppendingProposals, nil)
		if err != nil {
			t.Fatalf("ProcessProposals() failed: %v", err)
		}
		if err := session.ProcessCommit(commitWelcome.Commit); err != nil {
			t.Fatalf("ProcessCommit() failed: %v", err)
		}
		return session
	default:
		t.Fatalf("unsupported test session status %d", status)
		return nil
	}
}

func mustDecodeHex(value string) []byte {
	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}
	return decoded
}
