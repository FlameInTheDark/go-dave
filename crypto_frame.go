package dave

import "fmt"

const (
	aesGCM128KeyBytes                 = 16
	aesGCM128NonceBytes               = 12
	aesGCM128TruncatedSyncNonceBytes  = 4
	aesGCM128TruncatedSyncNonceOffset = aesGCM128NonceBytes - aesGCM128TruncatedSyncNonceBytes
	ratchetGenerationBytes            = 1
	aesGCM128TruncatedTagBytes        = 8
	ratchetGenerationShiftBits        = 8 * (aesGCM128TruncatedSyncNonceBytes - ratchetGenerationBytes)
	supplementalBytes                 = aesGCM128TruncatedTagBytes + 1 + 2
	maxGenerationGap                  = 250
	maxMissingNonces                  = 1000
	maxFramesPerSecond                = 50 + 2*60
	generationWrap                    = 1 << (8 * ratchetGenerationBytes)
)

var markerBytes = []byte{0xfa, 0xfa}

type frameRange struct {
	offset int
	size   int
}

type outboundFrameProcessor struct {
	frameCodec        Codec
	frameIndex        int
	unencryptedBytes  []byte
	encryptedBytes    []byte
	ciphertextBytes   []byte
	unencryptedRanges []frameRange
}

func (p *outboundFrameProcessor) reset() {
	p.frameCodec = CodecUnknown
	p.frameIndex = 0
	p.unencryptedBytes = p.unencryptedBytes[:0]
	p.encryptedBytes = p.encryptedBytes[:0]
	p.ciphertextBytes = p.ciphertextBytes[:0]
	p.unencryptedRanges = p.unencryptedRanges[:0]
}

func (p *outboundFrameProcessor) addUnencryptedBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	if n := len(p.unencryptedRanges); n > 0 {
		last := &p.unencryptedRanges[n-1]
		if last.offset+last.size == p.frameIndex {
			last.size += len(data)
		} else {
			p.unencryptedRanges = append(p.unencryptedRanges, frameRange{offset: p.frameIndex, size: len(data)})
		}
	} else {
		p.unencryptedRanges = append(p.unencryptedRanges, frameRange{offset: p.frameIndex, size: len(data)})
	}
	p.unencryptedBytes = append(p.unencryptedBytes, data...)
	p.frameIndex += len(data)
}

func (p *outboundFrameProcessor) addEncryptedBytes(data []byte) {
	if len(data) == 0 {
		return
	}
	p.encryptedBytes = append(p.encryptedBytes, data...)
	p.frameIndex += len(data)
}

func (p *outboundFrameProcessor) reconstructFrame(dst []byte) (int, error) {
	if len(p.unencryptedBytes)+len(p.ciphertextBytes) > len(dst) {
		return 0, fmt.Errorf("destination frame is too small")
	}
	return reconstructRanges(p.unencryptedRanges, p.unencryptedBytes, p.ciphertextBytes, dst), nil
}

type inboundFrameProcessor struct {
	encrypted         bool
	originalSize      int
	truncatedNonce    uint32
	unencryptedRanges []frameRange
	authenticated     []byte
	ciphertext        []byte
	plaintext         []byte
	tag               []byte
}

func (p *inboundFrameProcessor) clear() {
	p.encrypted = false
	p.originalSize = 0
	p.truncatedNonce = ^uint32(0)
	p.unencryptedRanges = p.unencryptedRanges[:0]
	p.authenticated = p.authenticated[:0]
	p.ciphertext = p.ciphertext[:0]
	p.plaintext = p.plaintext[:0]
	p.tag = p.tag[:0]
}

func (p *inboundFrameProcessor) parseFrame(frame []byte) {
	p.clear()

	const minSupplementalBytesSize = aesGCM128TruncatedTagBytes + 1 + 2
	if len(frame) < minSupplementalBytesSize {
		return
	}
	if len(frame) < len(markerBytes) || string(frame[len(frame)-len(markerBytes):]) != string(markerBytes) {
		return
	}

	bytesSize := int(frame[len(frame)-len(markerBytes)-1])
	if len(frame) < bytesSize || bytesSize < minSupplementalBytesSize {
		return
	}
	supplemental := frame[len(frame)-bytesSize:]
	p.tag = append(p.tag[:0], supplemental[:aesGCM128TruncatedTagBytes]...)

	nonceAndRanges := supplemental[aesGCM128TruncatedTagBytes : len(supplemental)-1-len(markerBytes)]
	nonce, nonceSize, ok := readLEB128(nonceAndRanges)
	if !ok {
		return
	}
	p.truncatedNonce = uint32(nonce)

	if nonceSize < len(nonceAndRanges) {
		ranges, ok := deserializeRanges(nonceAndRanges[nonceSize:])
		if !ok || !validateRanges(ranges, len(frame)) {
			return
		}
		p.unencryptedRanges = append(p.unencryptedRanges[:0], ranges...)
	}

	p.originalSize = len(frame)
	actualFrameSize := len(frame) - bytesSize
	frameIndex := 0
	for _, r := range p.unencryptedRanges {
		encryptedBytes := r.offset - frameIndex
		if encryptedBytes > 0 {
			p.ciphertext = append(p.ciphertext, frame[frameIndex:frameIndex+encryptedBytes]...)
		}
		p.authenticated = append(p.authenticated, frame[r.offset:r.offset+r.size]...)
		frameIndex = r.offset + r.size
	}
	if frameIndex < actualFrameSize {
		p.ciphertext = append(p.ciphertext, frame[frameIndex:actualFrameSize]...)
	}
	p.plaintext = append(p.plaintext[:0], make([]byte, len(p.ciphertext))...)
	p.encrypted = true
}

func (p *inboundFrameProcessor) reconstructFrame(dst []byte) int {
	if !p.encrypted || len(p.authenticated)+len(p.plaintext) > len(dst) {
		return 0
	}
	return reconstructRanges(p.unencryptedRanges, p.authenticated, p.plaintext, dst)
}

func rangesSize(ranges []frameRange) int {
	size := 0
	for _, r := range ranges {
		size += leb128Size(uint64(r.offset))
		size += leb128Size(uint64(r.size))
	}
	return size
}

func serializeRanges(ranges []frameRange, dst []byte) int {
	written := 0
	for _, r := range ranges {
		rangeSize := leb128Size(uint64(r.offset)) + leb128Size(uint64(r.size))
		if rangeSize > len(dst)-written {
			break
		}
		written += writeLEB128(dst[written:], uint64(r.offset))
		written += writeLEB128(dst[written:], uint64(r.size))
	}
	return written
}

func deserializeRanges(src []byte) ([]frameRange, bool) {
	ranges := make([]frameRange, 0)
	for offset := 0; offset < len(src); {
		rangeOffset, consumed, ok := readLEB128(src[offset:])
		if !ok {
			return nil, false
		}
		offset += consumed
		rangeSize, consumed, ok := readLEB128(src[offset:])
		if !ok {
			return nil, false
		}
		offset += consumed
		ranges = append(ranges, frameRange{offset: int(rangeOffset), size: int(rangeSize)})
	}
	return ranges, true
}

func validateRanges(ranges []frameRange, frameSize int) bool {
	for i, r := range ranges {
		maxEnd := frameSize
		if i+1 < len(ranges) {
			maxEnd = ranges[i+1].offset
		}
		if r.offset+r.size > maxEnd {
			return false
		}
	}
	return true
}

func reconstructRanges(ranges []frameRange, rangeBytes []byte, otherBytes []byte, dst []byte) int {
	frameIndex := 0
	rangeBytesIndex := 0
	otherBytesIndex := 0

	for _, r := range ranges {
		if r.offset > frameIndex {
			size := r.offset - frameIndex
			copy(dst[frameIndex:frameIndex+size], otherBytes[otherBytesIndex:otherBytesIndex+size])
			otherBytesIndex += size
			frameIndex += size
		}

		copy(dst[frameIndex:frameIndex+r.size], rangeBytes[rangeBytesIndex:rangeBytesIndex+r.size])
		rangeBytesIndex += r.size
		frameIndex += r.size
	}

	if otherBytesIndex < len(otherBytes) {
		size := len(otherBytes) - otherBytesIndex
		copy(dst[frameIndex:frameIndex+size], otherBytes[otherBytesIndex:])
		frameIndex += size
	}
	return frameIndex
}
