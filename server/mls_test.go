package server

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseAndValidateKeyPackage(t *testing.T) {
	kp, err := parseAndValidateKeyPackage(mustFixtureKeyPackage(t, 501), 501)
	if err != nil {
		t.Fatalf("parseAndValidateKeyPackage: %v", err)
	}
	if kp.UserID != 501 {
		t.Fatalf("UserID = %d, want 501", kp.UserID)
	}
	if got := int64(binary.BigEndian.Uint64(kp.Identity)); got != 501 {
		t.Fatalf("identity user id = %d, want 501", got)
	}
	if len(kp.SignatureKey) == 0 {
		t.Fatal("expected signature key bytes")
	}
	if len(kp.Inner) == 0 || len(kp.Raw) == 0 {
		t.Fatal("expected raw and inner key package bytes")
	}
}

func TestParseAndValidateKeyPackageRejectsWrongUser(t *testing.T) {
	_, err := parseAndValidateKeyPackage(mustFixtureKeyPackage(t, 501), 999)
	if err == nil {
		t.Fatal("expected wrong-user key package validation error")
	}
	if !strings.Contains(err.Error(), "does not match authenticated user") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildExternalAddProposal(t *testing.T) {
	sender, err := newExternalSender([]byte("go-dave-server"))
	if err != nil {
		t.Fatalf("newExternalSender: %v", err)
	}
	kp, err := parseAndValidateKeyPackage(mustFixtureKeyPackage(t, 502), 502)
	if err != nil {
		t.Fatalf("parseAndValidateKeyPackage: %v", err)
	}

	proposal, ref, err := buildExternalAddProposal(100, 0, 7, sender, kp)
	if err != nil {
		t.Fatalf("buildExternalAddProposal: %v", err)
	}
	if len(ref) == 0 {
		t.Fatal("expected non-empty proposal ref")
	}
	if got := binary.BigEndian.Uint16(proposal[:2]); got != protocolVersionMLS10 {
		t.Fatalf("proposal version = %d, want %d", got, protocolVersionMLS10)
	}
	if got := binary.BigEndian.Uint16(proposal[2:4]); got != wireFormatPublicMessage {
		t.Fatalf("proposal wire format = %d, want %d", got, wireFormatPublicMessage)
	}

	offset := 4
	groupID, err := readOpaque(proposal, &offset)
	if err != nil {
		t.Fatalf("read group id: %v", err)
	}
	if got := int64(binary.BigEndian.Uint64(groupID)); got != 100 {
		t.Fatalf("group id = %d, want 100", got)
	}
	if got := readUint64(proposal, &offset); got != 0 {
		t.Fatalf("epoch = %d, want 0", got)
	}
	if got := proposal[offset]; got != senderTypeExternal {
		t.Fatalf("sender type = %d, want %d", got, senderTypeExternal)
	}
	offset++
	if got := binary.BigEndian.Uint32(proposal[offset : offset+4]); got != 7 {
		t.Fatalf("sender index = %d, want 7", got)
	}
	offset += 4
	if _, err := readOpaque(proposal, &offset); err != nil {
		t.Fatalf("read authenticated data: %v", err)
	}
	if got := proposal[offset]; got != contentTypeProposal {
		t.Fatalf("content type = %d, want %d", got, contentTypeProposal)
	}
	offset++
	if got := readUint16(proposal, &offset); got != proposalTypeAdd {
		t.Fatalf("proposal type = %d, want %d", got, proposalTypeAdd)
	}
	if remaining := proposal[offset:]; len(remaining) < len(kp.Inner) || string(remaining[:len(kp.Inner)]) != string(kp.Inner) {
		t.Fatal("proposal does not contain the expected key package payload")
	}
	offset += len(kp.Inner)
	if _, err := readOpaque(proposal, &offset); err != nil {
		t.Fatalf("read auth data signature: %v", err)
	}
	if offset != len(proposal) {
		t.Fatalf("proposal contains trailing bytes: %d", len(proposal)-offset)
	}
}
