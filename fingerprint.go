package dave

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

var fingerprintSalt = [16]byte{
	0x24, 0xca, 0xb1, 0x7a, 0x7a, 0xf8, 0xec, 0x2b,
	0x82, 0xb4, 0x12, 0xb9, 0x2d, 0xab, 0x19, 0x2e,
}

func GenerateKeyFingerprint(version uint16, key []byte, userID uint64) ([]byte, error) {
	if version != 0 {
		return nil, fmt.Errorf("unsupported fingerprint version %d", version)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key fingerprint requires a non-empty key")
	}

	out := make([]byte, 0, 2+len(key)+8)
	out = binary.BigEndian.AppendUint16(out, version)
	out = append(out, key...)
	out = binary.BigEndian.AppendUint64(out, userID)
	return out, nil
}

func GeneratePairwiseFingerprint(version uint16, localKey []byte, localUserID uint64, remoteKey []byte, remoteUserID uint64) ([]byte, error) {
	localFingerprint, err := GenerateKeyFingerprint(version, localKey, localUserID)
	if err != nil {
		return nil, err
	}
	remoteFingerprint, err := GenerateKeyFingerprint(version, remoteKey, remoteUserID)
	if err != nil {
		return nil, err
	}

	fingerprints := [][]byte{localFingerprint, remoteFingerprint}
	if bytes.Compare(fingerprints[0], fingerprints[1]) > 0 {
		fingerprints[0], fingerprints[1] = fingerprints[1], fingerprints[0]
	}

	output, err := scrypt.Key(bytes.Join(fingerprints, nil), fingerprintSalt[:], 1<<14, 8, 2, 64)
	if err != nil {
		return nil, fmt.Errorf("derive pairwise fingerprint: %w", err)
	}
	return output, nil
}
