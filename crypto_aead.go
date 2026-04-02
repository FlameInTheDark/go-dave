package dave

import (
	"bytes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

var errMessageAuthFailed = errors.New("cipher: message authentication failed")

// truncatedGCMAEAD keeps the 8-byte on-wire tag used by DAVE while relying on
// the standard library's AES-GCM implementation to generate and verify the
// underlying authentication tag.
type truncatedGCMAEAD struct {
	block cipher.Block
	full  cipher.AEAD
}

func newTruncatedGCMAEAD(block cipher.Block) (cipher.AEAD, error) {
	full, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &truncatedGCMAEAD{
		block: block,
		full:  full,
	}, nil
}

func (a *truncatedGCMAEAD) NonceSize() int {
	return a.full.NonceSize()
}

func (a *truncatedGCMAEAD) Overhead() int {
	return aesGCM128TruncatedTagBytes
}

func (a *truncatedGCMAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != a.NonceSize() {
		panic("crypto/cipher: incorrect GCM nonce size")
	}

	full := a.full.Seal(nil, nonce, plaintext, additionalData)
	ciphertextLen := len(full) - a.full.Overhead()

	out := make([]byte, len(dst)+ciphertextLen+aesGCM128TruncatedTagBytes)
	copy(out, dst)
	copy(out[len(dst):], full[:ciphertextLen])
	copy(out[len(dst)+ciphertextLen:], full[ciphertextLen:ciphertextLen+aesGCM128TruncatedTagBytes])
	return out
}

func (a *truncatedGCMAEAD) Open(dst, nonce, ciphertextWithTag, additionalData []byte) ([]byte, error) {
	if len(nonce) != a.NonceSize() {
		panic("crypto/cipher: incorrect GCM nonce size")
	}
	if len(ciphertextWithTag) < aesGCM128TruncatedTagBytes {
		return nil, errMessageAuthFailed
	}

	ciphertextLen := len(ciphertextWithTag) - aesGCM128TruncatedTagBytes
	ciphertext := ciphertextWithTag[:ciphertextLen]
	tag := ciphertextWithTag[ciphertextLen:]

	plaintext := make([]byte, len(ciphertext))
	a.decryptCTR(nonce, plaintext, ciphertext)

	recomputed := a.full.Seal(nil, nonce, plaintext, additionalData)
	if len(recomputed) != ciphertextLen+a.full.Overhead() {
		return nil, errMessageAuthFailed
	}
	if !bytes.Equal(recomputed[:ciphertextLen], ciphertext) {
		return nil, errMessageAuthFailed
	}
	if subtle.ConstantTimeCompare(
		recomputed[ciphertextLen:ciphertextLen+aesGCM128TruncatedTagBytes],
		tag,
	) != 1 {
		return nil, errMessageAuthFailed
	}

	out := make([]byte, len(dst)+len(plaintext))
	copy(out, dst)
	copy(out[len(dst):], plaintext)
	return out, nil
}

func (a *truncatedGCMAEAD) decryptCTR(nonce, dst, src []byte) {
	counter := make([]byte, aesGCM128NonceBytes+4)
	copy(counter, nonce)
	counter[len(counter)-1] = 2

	stream := cipher.NewCTR(a.block, counter)
	stream.XORKeyStream(dst, src)
}
