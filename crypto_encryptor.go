package dave

import (
	"container/list"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"time"
)

type encryptor struct {
	ratchet              *hashRatchet
	cryptor              cipher.AEAD
	currentKeyGeneration uint32
	truncatedNonce       uint32
	stats                map[MediaType]*EncryptionStats
}

func newEncryptor() *encryptor {
	return &encryptor{
		stats: map[MediaType]*EncryptionStats{
			MediaTypeAudio: {},
			MediaTypeVideo: {},
		},
	}
}

func (e *encryptor) setKeyRatchet(ratchet *hashRatchet) {
	e.ratchet = ratchet
	e.cryptor = nil
	e.currentKeyGeneration = 0
	e.truncatedNonce = 0
}

func (e *encryptor) statsFor(mediaType MediaType) EncryptionStats {
	if stats, ok := e.stats[mediaType]; ok && stats != nil {
		return *stats
	}
	return EncryptionStats{}
}

func (e *encryptor) encrypt(mediaType MediaType, codec Codec, frame []byte) ([]byte, error) {
	stats := e.stats[mediaType]
	if stats == nil {
		return nil, fmt.Errorf("unsupported media type %d", mediaType)
	}
	if e.ratchet == nil {
		stats.Failures++
		return nil, fmt.Errorf("encryptor is not initialized")
	}

	start := time.Now()
	defer func() {
		stats.Duration += uint32(time.Since(start).Microseconds())
	}()

	var processor outboundFrameProcessor
	if err := processFrame(&processor, frame, codec); err != nil {
		stats.Failures++
		return nil, err
	}
	processor.ciphertextBytes = make([]byte, len(processor.encryptedBytes))

	unencryptedRanges := processor.unencryptedRanges
	rangesPayloadSize := rangesSize(unencryptedRanges)
	frameSize := len(processor.encryptedBytes) + len(processor.unencryptedBytes)

	maxFrameSize := frameSize + aesGCM128TruncatedTagBytes + leb128Size(uint64(^uint32(0))) + rangesPayloadSize + 1 + len(markerBytes) + transformPaddingBytes
	encryptedFrame := make([]byte, maxFrameSize)
	var nonceBuffer [aesGCM128NonceBytes]byte

	const maxCiphertextValidationRetries = 10
	for attempt := 1; attempt <= maxCiphertextValidationRetries; attempt++ {
		cryptor, truncatedNonce, err := e.nextCryptor()
		if err != nil {
			stats.Failures++
			return nil, err
		}
		stats.Attempts++
		if uint32(attempt) > stats.MaxAttempts {
			stats.MaxAttempts = uint32(attempt)
		}

		copy(processor.ciphertextBytes, processor.encryptedBytes)
		copy(nonceBuffer[aesGCM128TruncatedSyncNonceOffset:aesGCM128TruncatedSyncNonceOffset+aesGCM128TruncatedSyncNonceBytes], uint32ToLEBytes(truncatedNonce))

		sealed := cryptor.Seal(nil, nonceBuffer[:], processor.ciphertextBytes, processor.unencryptedBytes)
		copy(processor.ciphertextBytes, sealed[:len(processor.ciphertextBytes)])
		copy(encryptedFrame[frameSize:frameSize+aesGCM128TruncatedTagBytes], sealed[len(processor.ciphertextBytes):])

		reconstructedSize, err := processor.reconstructFrame(encryptedFrame)
		if err != nil {
			stats.Failures++
			return nil, err
		}

		nonceSize := leb128Size(uint64(truncatedNonce))
		nonceBuf := encryptedFrame[frameSize+aesGCM128TruncatedTagBytes : frameSize+aesGCM128TruncatedTagBytes+nonceSize]
		if writeLEB128(nonceBuf, uint64(truncatedNonce)) != nonceSize {
			stats.Failures++
			return nil, fmt.Errorf("failed to serialize truncated nonce")
		}

		rangesBufStart := frameSize + aesGCM128TruncatedTagBytes + nonceSize
		rangesBuf := encryptedFrame[rangesBufStart : rangesBufStart+rangesPayloadSize]
		if serializeRanges(unencryptedRanges, rangesBuf) != rangesPayloadSize {
			stats.Failures++
			return nil, fmt.Errorf("failed to serialize unencrypted ranges")
		}

		supplemental := supplementalBytes + nonceSize + rangesPayloadSize
		if supplemental > 255 {
			stats.Failures++
			return nil, fmt.Errorf("supplemental bytes exceed uint8")
		}
		supplementalIndex := rangesBufStart + rangesPayloadSize
		encryptedFrame[supplementalIndex] = byte(supplemental)
		copy(encryptedFrame[supplementalIndex+1:supplementalIndex+1+len(markerBytes)], markerBytes)

		totalSize := reconstructedSize + aesGCM128TruncatedTagBytes + nonceSize + rangesPayloadSize + 1 + len(markerBytes)
		if validateEncryptedFrame(&processor, encryptedFrame[:totalSize]) {
			stats.Successes++
			return append([]byte(nil), encryptedFrame[:totalSize]...), nil
		}
	}

	stats.Failures++
	return nil, fmt.Errorf("failed to validate encrypted frame")
}

func (e *encryptor) nextCryptor() (cipher.AEAD, uint32, error) {
	if e.ratchet == nil {
		return nil, 0, fmt.Errorf("ratchet is nil")
	}
	e.truncatedNonce++
	generation := computeWrappedGeneration(e.currentKeyGeneration, e.truncatedNonce>>ratchetGenerationShiftBits)
	if generation != e.currentKeyGeneration || e.cryptor == nil {
		key, _, err := e.ratchet.get(generation)
		if err != nil {
			return nil, 0, err
		}
		cryptor, err := newAEADCipher(key)
		if err != nil {
			return nil, 0, err
		}
		e.currentKeyGeneration = generation
		e.cryptor = cryptor
	}
	return e.cryptor, e.truncatedNonce, nil
}

type expiringCipher struct {
	cipher cipher.AEAD
	expiry time.Time
	hasTTL bool
}

type cipherManager struct {
	clock                func() time.Time
	keyRatchet           *hashRatchet
	cryptorGenerations   map[uint32]*expiringCipher
	ratchetCreation      time.Time
	ratchetExpiry        time.Time
	hasRatchetExpiry     bool
	oldestGeneration     uint32
	newestGeneration     uint32
	newestProcessedNonce uint64
	hasProcessedNonce    bool
	missingNonces        *list.List
}

func newCipherManager(ratchet *hashRatchet) *cipherManager {
	now := time.Now()
	return &cipherManager{
		clock:              time.Now,
		keyRatchet:         ratchet,
		cryptorGenerations: make(map[uint32]*expiringCipher),
		ratchetCreation:    now,
		missingNonces:      list.New(),
	}
}

func (m *cipherManager) canProcessNonce(generation uint32, nonce uint32) bool {
	if !m.hasProcessedNonce {
		return true
	}
	wrapped := computeWrappedBigNonce(generation, nonce)
	if wrapped > m.newestProcessedNonce {
		return true
	}
	for it := m.missingNonces.Front(); it != nil; it = it.Next() {
		if it.Value.(uint64) == wrapped {
			return true
		}
	}
	return false
}

func (m *cipherManager) getCipher(generation uint32) (cipher.AEAD, bool) {
	m.cleanupExpiredCiphers()
	if generation < m.oldestGeneration || generation > m.newestGeneration+maxGenerationGap {
		return nil, false
	}

	ratchetLifetimeSec := uint64(m.clock().Sub(m.ratchetCreation).Seconds())
	maxLifetimeFrames := maxFramesPerSecond * ratchetLifetimeSec
	maxLifetimeGenerations := maxLifetimeFrames >> ratchetGenerationShiftBits
	if generation > uint32(maxLifetimeGenerations) {
		return nil, false
	}

	cryptor, ok := m.cryptorGenerations[generation]
	if !ok {
		key, _, err := m.keyRatchet.get(generation)
		if err != nil {
			return nil, false
		}
		aead, err := newAEADCipher(key)
		if err != nil {
			return nil, false
		}
		cryptor = &expiringCipher{cipher: aead}
		if generation < m.newestGeneration {
			cryptor.expiry = m.clock().Add(10 * time.Second)
			cryptor.hasTTL = true
		}
		m.cryptorGenerations[generation] = cryptor
	}

	return cryptor.cipher, true
}

func (m *cipherManager) reportCipherSuccess(generation uint32, nonce uint32) {
	wrapped := computeWrappedBigNonce(generation, nonce)
	if !m.hasProcessedNonce {
		m.newestProcessedNonce = wrapped
		m.hasProcessedNonce = true
	} else if wrapped > m.newestProcessedNonce {
		oldestMissing := uint64(0)
		if wrapped > maxMissingNonces {
			oldestMissing = wrapped - maxMissingNonces
		}
		for {
			front := m.missingNonces.Front()
			if front == nil || front.Value.(uint64) >= oldestMissing {
				break
			}
			m.missingNonces.Remove(front)
		}
		start := m.newestProcessedNonce + 1
		if start < oldestMissing {
			start = oldestMissing
		}
		for i := start; i < wrapped; i++ {
			m.missingNonces.PushBack(i)
		}
		m.newestProcessedNonce = wrapped
	} else {
		for it := m.missingNonces.Front(); it != nil; it = it.Next() {
			if it.Value.(uint64) == wrapped {
				m.missingNonces.Remove(it)
				break
			}
		}
	}

	if generation <= m.newestGeneration {
		return
	}
	m.newestGeneration = generation
	expiry := m.clock().Add(10 * time.Second)
	for generationKey, cryptor := range m.cryptorGenerations {
		if generationKey < m.newestGeneration {
			cryptor.expiry = expiry
			cryptor.hasTTL = true
		}
	}
}

func (m *cipherManager) computeWrappedGeneration(generation uint32) uint32 {
	return computeWrappedGeneration(m.oldestGeneration, generation)
}

func (m *cipherManager) updateExpiry(expiry time.Time) {
	m.ratchetExpiry = expiry
	m.hasRatchetExpiry = true
}

func (m *cipherManager) isExpired() bool {
	return m.hasRatchetExpiry && m.clock().After(m.ratchetExpiry)
}

func (m *cipherManager) cleanupExpiredCiphers() {
	now := m.clock()
	for generation, cryptor := range m.cryptorGenerations {
		if cryptor.hasTTL && now.After(cryptor.expiry) {
			delete(m.cryptorGenerations, generation)
		}
	}
	for m.oldestGeneration < m.newestGeneration {
		if _, ok := m.cryptorGenerations[m.oldestGeneration]; ok {
			break
		}
		m.keyRatchet.erase(m.oldestGeneration)
		m.oldestGeneration++
	}
}

func computeWrappedGeneration(oldest uint32, generation uint32) uint32 {
	remainder := oldest % generationWrap
	extra := uint32(0)
	if generation < remainder {
		extra = 1
	}
	factor := oldest/generationWrap + extra
	return factor*generationWrap + generation
}

func computeWrappedBigNonce(generation uint32, nonce uint32) uint64 {
	masked := uint64(nonce) & ((1 << ratchetGenerationShiftBits) - 1)
	return (uint64(generation) << ratchetGenerationShiftBits) | masked
}

func newAEADCipher(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create AES block: %w", err)
	}
	cryptor, err := newTruncatedGCMAEAD(block)
	if err != nil {
		return nil, fmt.Errorf("create AES-GCM cipher: %w", err)
	}
	return cryptor, nil
}

func uint32ToLEBytes(value uint32) []byte {
	return []byte{
		byte(value),
		byte(value >> 8),
		byte(value >> 16),
		byte(value >> 24),
	}
}
