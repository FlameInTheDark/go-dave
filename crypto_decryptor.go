package dave

import (
	"container/list"
	"fmt"
	"time"
)

type decryptor struct {
	cryptorManagers        *list.List
	allowPassthroughUntil  time.Time
	hasPassthroughDeadline bool
	stats                  map[MediaType]*DecryptionStats
}

func newDecryptor() *decryptor {
	return &decryptor{
		cryptorManagers:        list.New(),
		hasPassthroughDeadline: true,
		stats: map[MediaType]*DecryptionStats{
			MediaTypeAudio: {},
			MediaTypeVideo: {},
		},
	}
}

func (d *decryptor) statsFor(mediaType MediaType) DecryptionStats {
	if stats, ok := d.stats[mediaType]; ok && stats != nil {
		return *stats
	}
	return DecryptionStats{}
}

func (d *decryptor) decrypt(mediaType MediaType, encryptedFrame []byte) ([]byte, error) {
	stats := d.stats[mediaType]
	if stats == nil {
		return nil, fmt.Errorf("unsupported media type %d", mediaType)
	}

	start := time.Now()
	defer func() {
		stats.Duration += uint32(time.Since(start).Microseconds())
	}()

	if isOpusSilencePacket(encryptedFrame) {
		return append([]byte(nil), encryptedFrame...), nil
	}

	d.cleanupExpiredCryptorManagers()

	var localFrame inboundFrameProcessor
	localFrame.parseFrame(encryptedFrame)
	if !localFrame.encrypted && d.canPassthrough() {
		stats.Passthroughs++
		return append([]byte(nil), encryptedFrame...), nil
	}
	if !localFrame.encrypted {
		stats.Failures++
		return nil, fmt.Errorf("received unencrypted frame while passthrough is disabled")
	}

	for it := d.cryptorManagers.Front(); it != nil; it = it.Next() {
		manager := it.Value.(*cipherManager)
		stats.Attempts++
		if d.decryptWithManager(manager, &localFrame) {
			stats.Successes++
			out := make([]byte, len(encryptedFrame))
			frameLength := localFrame.reconstructFrame(out)
			return out[:frameLength], nil
		}
	}

	stats.Failures++
	return nil, fmt.Errorf("no valid decryptor found")
}

func (d *decryptor) decryptWithManager(manager *cipherManager, frame *inboundFrameProcessor) bool {
	var nonceBuffer [aesGCM128NonceBytes]byte
	copy(nonceBuffer[aesGCM128TruncatedSyncNonceOffset:aesGCM128TruncatedSyncNonceOffset+aesGCM128TruncatedSyncNonceBytes], uint32ToLEBytes(frame.truncatedNonce))

	generation := manager.computeWrappedGeneration(frame.truncatedNonce >> ratchetGenerationShiftBits)
	if !manager.canProcessNonce(generation, frame.truncatedNonce) {
		return false
	}

	cryptor, ok := manager.getCipher(generation)
	if !ok {
		return false
	}

	ciphertextWithTag := make([]byte, 0, len(frame.ciphertext)+len(frame.tag))
	ciphertextWithTag = append(ciphertextWithTag, frame.ciphertext...)
	ciphertextWithTag = append(ciphertextWithTag, frame.tag...)

	plaintext, err := cryptor.Open(nil, nonceBuffer[:], ciphertextWithTag, frame.authenticated)
	if err != nil {
		return false
	}
	frame.plaintext = append(frame.plaintext[:0], plaintext...)
	manager.reportCipherSuccess(generation, frame.truncatedNonce)
	return true
}

func (d *decryptor) transitionToKeyRatchet(ratchet *hashRatchet) {
	d.updateCryptorManagerExpiry(time.Now().Add(10 * time.Second))
	d.cryptorManagers.PushBack(newCipherManager(ratchet))
}

func (d *decryptor) transitionToPassthroughMode(mode bool, transitionExpiry uint32) {
	if mode {
		d.hasPassthroughDeadline = false
		return
	}
	newExpiry := time.Now().Add(time.Duration(transitionExpiry) * time.Second)
	if !d.hasPassthroughDeadline || newExpiry.After(d.allowPassthroughUntil) {
		d.allowPassthroughUntil = newExpiry
		d.hasPassthroughDeadline = true
	}
}

func (d *decryptor) canPassthrough() bool {
	return !d.hasPassthroughDeadline || time.Now().Before(d.allowPassthroughUntil)
}

func (d *decryptor) updateCryptorManagerExpiry(expiry time.Time) {
	for it := d.cryptorManagers.Front(); it != nil; it = it.Next() {
		it.Value.(*cipherManager).updateExpiry(expiry)
	}
}

func (d *decryptor) cleanupExpiredCryptorManagers() {
	for {
		front := d.cryptorManagers.Front()
		if front == nil || !front.Value.(*cipherManager).isExpired() {
			return
		}
		d.cryptorManagers.Remove(front)
	}
}
